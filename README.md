# p2p-udp-secure

Peer-to-peer chat over UDP with NAT hole punching **and passphrase encryption** —
**no server, no install, no dependencies**, one file of pure Python standard library.

## Use it

Runs on plain Python 3.10+ (`python3 p2p.py connect`), or with no clone via
[uv](https://docs.astral.sh/uv/):

**Both machines run the same command and enter the SAME passphrase:**
```
uvx --from git+https://github.com/debugwatch/p2p-udp-secure connect
```
or just:
```
python3 p2p.py connect
```

1. Enter a shared passphrase (agree on it out-of-band; both must match).
2. Each side prints a short **token** (your public `ip:port`, found via STUN).
3. Swap tokens and paste the other machine's when asked.
4. Both print `[connected]` — type a line, press Enter; it arrives encrypted.

If the passphrases don't match, messages simply fail their integrity check and
are silently dropped (you'll see no `<` lines).

## Encryption

Encrypt-then-MAC using only the standard library:
- key = `scrypt(passphrase)` (32 bytes)
- keystream = `HMAC-SHA256(key, nonce ‖ counter)` blocks, XORed with the plaintext
- tag = `HMAC-SHA256(key, "p2p" ‖ nonce ‖ ciphertext)[:16]`, verified in constant time

This provides real confidentiality and tamper-detection against eavesdroppers,
but it is **not** an audited transport like DTLS/TLS and has **no forward secrecy**
(the passphrase is the long-term key). If you need vetted transport security or
browser interop, use **dist-webrtc**.

## LAN / no-STUN mode

Set `P2P_ADDR=host:port` to skip STUN and advertise that address (LAN or local test):
```
P2P_ADDR=127.0.0.1:9001 python3 p2p.py connect   # peer A
P2P_ADDR=127.0.0.1:9002 python3 p2p.py connect   # peer B
```

## Logs

Progress logs (STUN, endpoints, hole-punch probes, encrypt/decrypt with MAC
results) print to **stderr**; set `P2P_QUIET=1` to silence them. A wrong
passphrase shows up as `DROPPED packet (bad MAC ...)` lines. Logs never touch
the token or chat on stdout.

## NAT note

Hole punching works through common cone NATs. If **both** peers are behind
symmetric NAT it won't connect — that needs a TURN relay (use **dist-webrtc**).
Delivery is best-effort (UDP): packets can drop; there's no retransmission.
