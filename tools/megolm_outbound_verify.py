#!/usr/bin/env python3
"""
Verify Megolm outbound encryption using values from ESP serial log.

Paste the session key (shared via to-device) and the ciphertext
from the encrypted event. This script decrypts and shows all
intermediate values for comparison with the ESP log.

Usage:
  1. Get "Session key export" R0..R3 from ESP log
  2. Get "ct_b64[0..19]" from ESP log (or full ciphertext from Element debug)
  3. Paste below and run
"""

import base64
import hashlib
import hmac
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as crypto_padding
except ImportError:
    print("pip install cryptography")
    sys.exit(1)

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
    HAS_NACL = True
except ImportError:
    HAS_NACL = False


def b64d(s):
    p = 4 - len(s) % 4
    if p < 4: s += '=' * p
    return base64.b64decode(s)

def b64e(data):
    return base64.b64encode(data).rstrip(b'=').decode()

def hkdf(ikm, length, salt=b'', info=b''):
    if not salt: salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b''; t = b''; c = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        okm += t; c += 1
    return okm[:length]

def aes_decrypt(key, iv, ct):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    u = crypto_padding.PKCS7(128).unpadder()
    return u.update(padded) + u.finalize()

def decode_varint(buf, off):
    val = 0; shift = 0; pos = off
    while pos < len(buf):
        b = buf[pos]; val |= (b & 0x7F) << shift; pos += 1
        if (b & 0x80) == 0: return val, pos
        shift += 7
    return val, pos


# ============================================================
# PASTE VALUES FROM ESP SERIAL LOG
# ============================================================

# Session key export R values (4 bytes hex each from the log)
# These are the INITIAL ratchet values shared via to-device
R0_HEX_4 = ""  # e.g. "a1b2c3d4"
R1_HEX_4 = ""
R2_HEX_4 = ""
R3_HEX_4 = ""

# Full session key base64 from the to-device m.room_key content
# (if available, overrides R values above)
SESSION_KEY_B64 = "AgAAAAC0mY4lRxZB8F+N722vWM0M1xWV7k3zV7Hvj3yKsOTc7GBUOP2Fy+MN32EkB1VzM9n0AMa14W8bgoVlyMn6f1ZfiNqz+o9FHQibbRc8m8hdv24YksDx6MrlMgqluwg/16am5e52eG1zcuy0Vy9per+Wa9PCP84HM/16SKXUJo33kA"

# The ciphertext from the m.room.encrypted event (full base64)
CIPHERTEXT_B64 = "AwgAEqABcwnI7Neh5PTwqTn3nEVqxmQ6hb4r2QB0rFS4bDzsi5kXr3T86XecKxjAOmZJOpHbP5YhOXiJ+kOS+xXsRWqOiZ6nlOm7kVN5KQGJzFj4IKtSsrWO288TgvJwvLxWQi1+zSJzaxBPFs2dgGWw1/p1rl4Nxh/0rg887mf4dzjPywDbfFEt1njdY0ffK6sId3uStVztTbIJ7S3B0v5R4laahXjfjrHxOmNUjQEVvDvIlwkWUvmmhkJTeXh/wFh3F49+OMoGaEkJtUxgDxicfaQRzk+FxkwSLqOZyAMV7IdF0QB89CYSnoVMDw"

# Or just the first 20 chars to verify wire format
CIPHERTEXT_B64_PREFIX = ""

# ============================================================

if SESSION_KEY_B64:
    sk = b64d(SESSION_KEY_B64)
    print(f"Session key: {len(sk)} bytes, version=0x{sk[0]:02x}")
    counter = int.from_bytes(sk[1:5], 'big')
    R = [sk[5+i*32:5+(i+1)*32] for i in range(4)]
    ed_pub = sk[133:165]
    print(f"  counter={counter}")
    print(f"  R0={R[0][:4].hex()} R1={R[1][:4].hex()} R2={R[2][:4].hex()} R3={R[3][:4].hex()}")
    print(f"  ed25519_pub={b64e(ed_pub)[:20]}...")
    print(f"  session_id={b64e(ed_pub)}")

    # Derive keys for message 0 (counter=0, no advance needed)
    ikm = R[0] + R[1] + R[2] + R[3]
    expanded = hkdf(ikm, 80, salt=b'', info=b'MEGOLM_KEYS')
    aes_key = expanded[:32]
    hmac_key = expanded[32:64]
    iv = expanded[64:80]
    print(f"\n  Keys for msg_index=0:")
    print(f"  aes={aes_key[:4].hex()} hmac={hmac_key[:4].hex()} iv={iv[:4].hex()}")

if CIPHERTEXT_B64:
    ct_raw = b64d(CIPHERTEXT_B64)
    print(f"\nCiphertext: {len(ct_raw)} bytes")
    print(f"  Version: 0x{ct_raw[0]:02x}")
    print(f"  First 8: {ct_raw[:8].hex()}")
    print(f"  Last 8 (sig tail): {ct_raw[-8:].hex()}")

    # Parse: payload + 8-byte HMAC + 64-byte signature
    sig = ct_raw[-64:]
    mac = ct_raw[-72:-64]
    payload = ct_raw[:-72]
    print(f"  Payload: {len(payload)} bytes, MAC: {mac.hex()}, Sig: {sig[:8].hex()}...")

    # Parse payload protobuf
    pos = 0
    if payload[pos] != 0x03:
        print(f"  ERROR: version 0x{payload[pos]:02x}, expected 0x03!")
    pos += 1

    msg_index = None
    aes_ct = None
    while pos < len(payload):
        tag = payload[pos]; pos += 1
        fn = tag >> 3; wt = tag & 7
        if wt == 0:
            val, pos = decode_varint(payload, pos)
            if fn == 1: msg_index = val
            print(f"  Field {fn} varint: {val}")
        elif wt == 2:
            length, pos = decode_varint(payload, pos)
            data = payload[pos:pos+length]; pos += length
            if fn == 2: aes_ct = data
            print(f"  Field {fn} bytes: {length} bytes")

    if msg_index is not None:
        print(f"\n  msg_index={msg_index}")
    if aes_ct is not None:
        print(f"  AES ciphertext: {len(aes_ct)} bytes, mod16={len(aes_ct)%16}")

    # If we have the session key, try to decrypt
    if SESSION_KEY_B64 and aes_ct is not None:
        # Verify HMAC
        exp_mac = hmac.new(hmac_key, payload, hashlib.sha256).digest()[:8]
        print(f"\n  HMAC check: expected={exp_mac.hex()}, actual={mac.hex()}, match={exp_mac == mac}")

        # Try decrypt
        try:
            pt = aes_decrypt(aes_key, iv, aes_ct)
            print(f"\n  === DECRYPT SUCCESS ===")
            print(f"  Plaintext ({len(pt)} bytes): {pt[:100].decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"\n  === DECRYPT FAILED: {e} ===")

elif CIPHERTEXT_B64_PREFIX:
    prefix_bytes = b64d(CIPHERTEXT_B64_PREFIX + "A" * (4 - len(CIPHERTEXT_B64_PREFIX) % 4))
    print(f"\nCiphertext prefix ({len(CIPHERTEXT_B64_PREFIX)} b64 chars):")
    print(f"  First bytes: {prefix_bytes[:8].hex()}")
    print(f"  Version: 0x{prefix_bytes[0]:02x} (should be 0x03)")
    print(f"  Tag[1]: 0x{prefix_bytes[1]:02x} (should be 0x08 for msg_index)")

if not SESSION_KEY_B64 and not CIPHERTEXT_B64 and not CIPHERTEXT_B64_PREFIX:
    print("Paste values from ESP serial log into this script.")
    print("Look for:")
    print("  'Session key export: counter=0, R0=... R1=... R2=... R3=...'")
    print("  'Outbound: session_id=..., ct_b64[0..19]=...'")
    print("  Or the full session_key base64 from the to-device m.room_key JSON")
