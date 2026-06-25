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
derived from the shared passphrase.

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
    addr = (socket.gethostbyname(STUN_HOST), STUN_PORT)
    sock.settimeout(1.0)
    for _ in range(5):
        sock.sendto(req, addr)
        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
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
        return sock, (host, int(port))
    sock.bind(("", 0))
    return sock, stun_request(sock)


def hole_punch(sock, peer, timeout=30):
    """Spray packets at the peer until one comes back, opening the NAT path."""
    sock.settimeout(0.5)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock.sendto(CTRL + b"syn", peer)
        except OSError:
            pass
        try:
            sock.recvfrom(2048)
            return  # heard from the peer -> path is open
        except socket.timeout:
            continue
    raise RuntimeError("could not reach peer (symmetric NAT/firewall? would need a relay)")


def read_token(prompt):
    print(prompt, flush=True)
    line = sys.stdin.readline()
    return None if line == "" else line.strip()


def chat(sock, peer, key):
    print("[connected] type a message and press Enter to send\n", flush=True)
    stop = threading.Event()

    def receiver():
        sock.settimeout(1.0)
        while not stop.is_set():
            try:
                pkt, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if pkt[:1] == DATA:
                msg = unseal(key, pkt[1:])
                if msg is None:
                    continue  # wrong passphrase or tampered -> drop
                sys.stdout.write("< " + msg.decode("utf-8", "replace") + "\n")
                sys.stdout.flush()

    def keepalive():  # keep the NAT mapping alive
        while not stop.wait(15):
            try:
                sock.sendto(CTRL + b"ka", peer)
            except OSError:
                break

    threading.Thread(target=receiver, daemon=True).start()
    threading.Thread(target=keepalive, daemon=True).start()
    try:
        for line in sys.stdin:
            sock.sendto(DATA + seal(key, line.rstrip("\n").encode()), peer)
    finally:
        stop.set()


def connect():
    # Prompt interactively; P2P_PASS allows non-interactive/scripted use.
    passphrase = os.environ.get("P2P_PASS") or getpass.getpass(
        "Shared passphrase (must match on both machines): ")
    if not passphrase:
        sys.exit("A passphrase is required.")
    key = derive_key(passphrase)

    sock, (ip, port) = setup_socket()
    token = enc_token(ip, port)
    print("\n----- TOKEN (send this to the other machine) -----", flush=True)
    print(token, flush=True)
    print("----- end TOKEN -----\n", flush=True)
    blob = read_token("Paste the other machine's token, then Enter:")
    if not blob:
        sys.exit("No token given.")
    peer = dec_token(blob)
    hole_punch(sock, peer)
    chat(sock, peer, key)


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
