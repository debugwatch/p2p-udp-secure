#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Peer-to-peer chat over UDP with NAT hole punching + passphrase encryption.

No server, no install, NO dependencies -- pure Python standard library.
Runs on plain `python3 p2p.py`, or via `uvx --from git+<repo-url> connect`.

Both machines run the same command and enter the SAME passphrase:

    python3 p2p.py connect

Each prints a short token (your public ip:port, via STUN). Swap tokens, paste
the other machine's, and you're connected. Messages are encrypted with a key
derived from the shared passphrase. Progress logs go to stderr (P2P_QUIET=1
silences them).

Crypto note: this is encrypt-then-MAC using only the standard library
(scrypt key derivation, an HMAC-SHA256 keystream, HMAC-SHA256 authentication
tags). It gives real confidentiality and integrity against eavesdroppers and
tampering, but it is NOT an audited transport like DTLS/TLS -- for that use the
dist-webrtc variant. There is no forward secrecy; the passphrase is the key.

LAN / testing: set P2P_ADDR=host:port to skip STUN and advertise that address.
"""
import base64
import getpass
import hashlib
import hmac
import os
import socket
import struct
import sys
import threading
import time

STUN_HOST, STUN_PORT = "stun.l.google.com", 19302
STUN_MAGIC = 0x2112A442
CTRL, DATA = b"\x00", b"\x01"  # packet type prefixes

_T0 = time.monotonic()
_QUIET = os.environ.get("P2P_QUIET")


def log(*parts):
    if not _QUIET:
        print(f"[{time.monotonic() - _T0:6.2f}s] [p2p]", *parts, file=sys.stderr, flush=True)


# --- authenticated encryption (stdlib only) -------------------------------

def derive_key(passphrase):
    return hashlib.scrypt(
        passphrase.encode("utf-8"), salt=b"p2p-udp-secure-v1",
        n=2 ** 14, r=8, p=1, dklen=32,
    )


def _keystream(key, nonce, n):
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hmac.new(key, nonce + struct.pack(">I", counter), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:n])


def seal(key, plaintext):
    nonce = os.urandom(8)
    ks = _keystream(key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = hmac.new(key, b"p2p" + nonce + ct, hashlib.sha256).digest()[:16]
    return nonce + tag + ct


def unseal(key, blob):
    if len(blob) < 24:
        return None
    nonce, tag, ct = blob[:8], blob[8:24], blob[24:]
    expect = hmac.new(key, b"p2p" + nonce + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expect):
        return None  # forged or wrong passphrase
    ks = _keystream(key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


# --- STUN ------------------------------------------------------------------

def stun_request(sock):
    """Send a STUN Binding Request; return (public_ip, public_port)."""
    txid = os.urandom(12)
    req = struct.pack(">HHI12s", 0x0001, 0, STUN_MAGIC, txid)
    ip = socket.gethostbyname(STUN_HOST)
    log(f"STUN: querying {STUN_HOST} ({ip}:{STUN_PORT}) for our public address")
    addr = (ip, STUN_PORT)
    sock.settimeout(1.0)
    for attempt in range(1, 6):
        sock.sendto(req, addr)
        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            log(f"STUN: no reply (attempt {attempt}/5), retrying")
            continue
        got = _parse_stun(data, txid)
        if got:
            sock.settimeout(None)
            return got
    raise RuntimeError("no STUN response (is outbound UDP blocked?)")


def _parse_stun(data, txid):
    if len(data) < 20:
        return None
    _, mlen, magic, rtxid = struct.unpack(">HHI12s", data[:20])
    if magic != STUN_MAGIC or rtxid != txid:
        return None
    i, end = 20, 20 + mlen
    while i + 4 <= end:
        atype, alen = struct.unpack(">HH", data[i:i + 4])
        val = data[i + 4:i + 4 + alen]
        i += 4 + alen + ((4 - alen % 4) % 4)
        if atype in (0x0020, 0x0001) and len(val) >= 8:  # (XOR-)MAPPED-ADDRESS
            port = struct.unpack(">H", val[2:4])[0]
            ip_raw = val[4:8]
            if atype == 0x0020:  # XOR-MAPPED-ADDRESS
                port ^= STUN_MAGIC >> 16
                ip_raw = bytes(b ^ m for b, m in zip(ip_raw, struct.pack(">I", STUN_MAGIC)))
            return socket.inet_ntoa(ip_raw), port
    return None


# --- transport -------------------------------------------------------------

def enc_token(ip, port):
    return base64.urlsafe_b64encode(f"{ip}:{port}".encode()).decode()


def dec_token(blob):
    ip, port = base64.urlsafe_b64decode(blob.strip()).decode().rsplit(":", 1)
    return ip, int(port)


def setup_socket():
    """Bind a UDP socket and return (sock, (advertised_ip, advertised_port))."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    override = os.environ.get("P2P_ADDR")
    if override:  # LAN / test: skip STUN, advertise+bind this address
        host, port = override.rsplit(":", 1)
        sock.bind((host, int(port)))
        log(f"LAN mode: bound and advertising {host}:{port} (STUN skipped)")
        return sock, (host, int(port))
    sock.bind(("", 0))
    log(f"bound local UDP socket on port {sock.getsockname()[1]}")
    return sock, stun_request(sock)


def read_token(prompt):
    print(prompt, flush=True)
    line = sys.stdin.readline()
    return None if line == "" else line.strip()


def run_session(sock, peer, key, timeout=30):
    """Hole punch and chat. Probe every 0.5s until a packet arrives (path open),
    then drop to a 15s keepalive. Control packets (probe/keepalive) are plaintext;
    chat payloads are sealed with the passphrase-derived key."""
    stop = threading.Event()
    connected = threading.Event()

    def sender():
        log(f"hole punching: probing {peer[0]}:{peer[1]} every 0.5s until connected")
        while not stop.is_set():
            try:
                sock.sendto(CTRL + b"ka", peer)
            except OSError:
                break
            if connected.is_set():
                log("send: keepalive -> peer")
            stop.wait(0.5 if not connected.is_set() else 15)

    def receiver():
        sock.settimeout(0.5)
        while not stop.is_set():
            try:
                pkt, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if not connected.is_set():
                log(f"got first packet from {addr[0]}:{addr[1]} -> path open")
                connected.set()
            if pkt[:1] == DATA:
                msg = unseal(key, pkt[1:])
                if msg is None:
                    log("recv: DROPPED packet (bad MAC -> wrong passphrase or tampered)")
                    continue
                log(f"recv: {len(pkt) - 1} encrypted bytes -> {len(msg)} bytes decrypted (MAC ok)")
                sys.stdout.write("< " + msg.decode("utf-8", "replace") + "\n")
                sys.stdout.flush()
            else:
                log("recv: keepalive/probe from peer")

    threading.Thread(target=sender, daemon=True).start()
    threading.Thread(target=receiver, daemon=True).start()

    if not connected.wait(timeout):
        stop.set()
        raise RuntimeError("could not reach peer (symmetric NAT/firewall? would need a relay)")
    print("[connected] type a message and press Enter to send\n", flush=True)
    try:
        for line in sys.stdin:
            payload = seal(key, line.rstrip("\n").encode())
            sock.sendto(DATA + payload, peer)
            log(f"send: encrypted {len(payload)} bytes -> peer")
    finally:
        stop.set()


def connect():
    log("starting (mode: encrypted UDP hole punch)")
    # Prompt interactively; P2P_PASS allows non-interactive/scripted use.
    passphrase = os.environ.get("P2P_PASS") or getpass.getpass(
        "Shared passphrase (must match on both machines): ")
    if not passphrase:
        sys.exit("A passphrase is required.")
    log("deriving key from passphrase (scrypt n=2^14)...")
    key = derive_key(passphrase)
    log("key ready")

    sock, (ip, port) = setup_socket()
    log(f"our endpoint is {ip}:{port}")
    token = enc_token(ip, port)
    print("\n----- TOKEN (send this to the other machine) -----", flush=True)
    print(token, flush=True)
    print("----- end TOKEN -----\n", flush=True)
    blob = read_token("Paste the other machine's token, then Enter:")
    if not blob:
        sys.exit("No token given.")
    peer = dec_token(blob)
    log(f"peer endpoint decoded: {peer[0]}:{peer[1]}")
    run_session(sock, peer, key)


def connect_cmd():
    try:
        connect()
    except KeyboardInterrupt:
        sys.exit(130)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "connect"
    if cmd == "connect":
        connect_cmd()
    else:
        sys.exit("usage: p2p connect")


if __name__ == "__main__":
    main()
