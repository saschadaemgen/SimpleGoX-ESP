#!/usr/bin/env python3
"""
Verify Olm decryption using real data from the ESP serial log.

USAGE:
1. Flash the ESP and send a message from Element
2. Copy the debug dump from the serial log
3. Paste the values below
4. Run: python olm_decrypt_real.py

This script manually implements the Olm decryption to find
exactly where our ESP code diverges.
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
    from nacl.bindings import crypto_scalarmult as curve25519_scalarmult
except ImportError:
    print("pip install pynacl")
    sys.exit(1)


def b64decode_unpadded(s):
    """Decode unpadded base64"""
    padding = 4 - len(s) % 4
    if padding < 4:
        s += '=' * padding
    return base64.b64decode(s)


def b64encode_unpadded(data):
    return base64.b64encode(data).rstrip(b'=').decode()


def hkdf_sha256(ikm, length, salt=b'', info=b''):
    if not salt:
        salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b''
    t = b''
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def aes_256_cbc_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = crypto_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def decode_varint(buf, offset):
    value = 0
    shift = 0
    pos = offset
    while pos < len(buf):
        b = buf[pos]
        value |= (b & 0x7F) << shift
        pos += 1
        if (b & 0x80) == 0:
            return value, pos
        shift += 7
    return value, pos


def hex4(data):
    return data[:4].hex()


def hex8(data):
    return data[:8].hex()


# ============================================================
# PASTE VALUES FROM ESP SERIAL LOG HERE
# ============================================================

# The complete base64 body from CT_B64_START>>...<<CT_B64_END
CT_B64 = "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"

# Our Curve25519 private key (hex, 64 chars)
OUR_CURVE25519_PRIVATE_HEX = "109bc519839890bab8890fbd0756ccb61106efa195d9280c88061735b9c7f566"

# The OTK that was used (we'll try all of them)
# Format: list of (public_b64, private_hex) tuples
OTKS = [
    ("zbpoMqiwLw38GiRIbhMjHtzMQX3e+GWba6lLonFl9mA", "8e20a1eb8c2ea722e5ceaa8096e261aa90289f2d264371b26892086fd7b76f4a"),
]

# If you know which OTK was used (from the pre-key OTK field), put it here
KNOWN_OTK_PRIVATE_HEX = "8e20a1eb8c2ea722e5ceaa8096e261aa90289f2d264371b26892086fd7b76f4a"

# ============================================================

if not CT_B64:
    print("ERROR: Paste the CT_B64 value from the ESP serial log!")
    print()
    print("Look for lines like:")
    print("  W matrix_e2ee: CT_B64_START>>AwogXYZ...<<CT_B64_END")
    print("  W matrix_e2ee: OUR_CURVE25519_PRIVATE=abcdef...")
    print("  W matrix_e2ee: OTK[0] id=1 pub=XYZ priv=abcdef...")
    print()
    print("Then fill in the values at the top of this script and run again.")
    sys.exit(1)

# Decode the pre-key message
ct_raw = b64decode_unpadded(CT_B64)
print(f"Pre-key message: {len(ct_raw)} bytes")
print(f"  Version: 0x{ct_raw[0]:02x}")

# Parse pre-key message protobuf
pos = 1  # skip version
otk_pub = None
base_key = None
identity_key = None
inner_msg = None

while pos < len(ct_raw):
    tag = ct_raw[pos]
    pos += 1
    field_num = tag >> 3
    wire_type = tag & 0x07

    if wire_type == 2:  # length-delimited
        length, pos = decode_varint(ct_raw, pos)
        data = ct_raw[pos:pos+length]
        pos += length

        if field_num == 1:
            otk_pub = data
            print(f"  Field 1 (OTK pub): {hex8(data)} ({b64encode_unpadded(data)[:20]}...)")
        elif field_num == 2:
            base_key = data
            print(f"  Field 2 (base/eph): {hex8(data)} ({b64encode_unpadded(data)[:20]}...)")
        elif field_num == 3:
            identity_key = data
            print(f"  Field 3 (identity): {hex8(data)} ({b64encode_unpadded(data)[:20]}...)")
        elif field_num == 4:
            inner_msg = data
            print(f"  Field 4 (inner): {len(data)} bytes")
    elif wire_type == 0:  # varint
        val, pos = decode_varint(ct_raw, pos)
        print(f"  Field {field_num} (varint): {val}")

if inner_msg is None:
    print("ERROR: Could not find inner message in pre-key!")
    sys.exit(1)

# Parse inner message: strip 8-byte HMAC from end
inner_payload = inner_msg[:-8]
inner_hmac = inner_msg[-8:]
print(f"\nInner message: {len(inner_msg)} bytes (payload={len(inner_payload)}, hmac={inner_hmac.hex()})")

# Parse inner message protobuf
pos = 0
if inner_payload[pos] != 0x03:
    print(f"ERROR: Inner message version 0x{inner_payload[pos]:02x}, expected 0x03")
pos += 1

ratchet_key = None
chain_index = None
ciphertext = None

while pos < len(inner_payload):
    tag = inner_payload[pos]
    pos += 1
    field_num = tag >> 3
    wire_type = tag & 0x07

    if wire_type == 2:
        length, pos = decode_varint(inner_payload, pos)
        data = inner_payload[pos:pos+length]
        pos += length
        if field_num == 1:
            ratchet_key = data
            print(f"  Ratchet key: {hex8(data)}")
        elif field_num == 4:
            ciphertext = data
            print(f"  Ciphertext: {len(data)} bytes, mod16={len(data)%16}, first4={hex4(data)}")
    elif wire_type == 0:
        val, pos = decode_varint(inner_payload, pos)
        if field_num == 2:
            chain_index = val
            print(f"  Chain index: {val}")

if ciphertext is None:
    print("ERROR: No ciphertext found in inner message!")
    sys.exit(1)

# Find the right OTK private key
our_identity_private = bytes.fromhex(OUR_CURVE25519_PRIVATE_HEX) if OUR_CURVE25519_PRIVATE_HEX else None
otk_private = bytes.fromhex(KNOWN_OTK_PRIVATE_HEX) if KNOWN_OTK_PRIVATE_HEX else None

if otk_private is None and OTKS:
    otk_pub_b64 = b64encode_unpadded(otk_pub) if otk_pub else ""
    for pub_b64, priv_hex in OTKS:
        if pub_b64 == otk_pub_b64:
            otk_private = bytes.fromhex(priv_hex)
            print(f"\nFound matching OTK: {pub_b64[:20]}...")
            break

if our_identity_private is None or otk_private is None:
    print("\nERROR: Need OUR_CURVE25519_PRIVATE_HEX and the matching OTK private key!")
    sys.exit(1)

# 3DH (Bob's perspective)
# S = ECDH(E_B, I_A) || ECDH(I_B, E_A) || ECDH(E_B, E_A)
print(f"\n--- 3DH ---")
dh1 = curve25519_scalarmult(otk_private, identity_key)
dh2 = curve25519_scalarmult(our_identity_private, base_key)
dh3 = curve25519_scalarmult(otk_private, base_key)
S = dh1 + dh2 + dh3

print(f"DH1 = ECDH(E_B, I_A): {hex8(dh1)}")
print(f"DH2 = ECDH(I_B, E_A): {hex8(dh2)}")
print(f"DH3 = ECDH(E_B, E_A): {hex8(dh3)}")
print(f"S[0..7]: {hex8(S)}")

# Initial key derivation
derived = hkdf_sha256(S, 64, salt=b'', info=b'OLM_ROOT')
root_key = derived[:32]
chain_key = derived[32:]
print(f"\nroot_key[0..3]: {hex4(root_key)}")
print(f"chain_key[0..3]: {hex4(chain_key)}")

# Advance chain to chain_index
for i in range(chain_index):
    _skip = hmac.new(chain_key, b'\x01', hashlib.sha256).digest()
    chain_key = hmac.new(chain_key, b'\x02', hashlib.sha256).digest()
    print(f"  Skip chain step {i}")

# Get message key
msg_key = hmac.new(chain_key, b'\x01', hashlib.sha256).digest()
next_chain = hmac.new(chain_key, b'\x02', hashlib.sha256).digest()
print(f"\nmsg_key[0..3]: {hex4(msg_key)}")
print(f"chain_key[0..3]: {hex4(next_chain)}")

# Expand message key
expanded = hkdf_sha256(msg_key, 80, salt=b'', info=b'OLM_KEYS')
aes_key = expanded[:32]
hmac_key_derived = expanded[32:64]
iv = expanded[64:80]
print(f"\naes_key[0..3]: {hex4(aes_key)}")
print(f"iv[0..3]: {hex4(iv)}")
print(f"iv full: {iv.hex()}")
print(f"ciphertext len: {len(ciphertext)}, mod16: {len(ciphertext)%16}")

# Verify HMAC
expected_hmac = hmac.new(hmac_key_derived, inner_payload[:1] + inner_payload[1:], hashlib.sha256).digest()[:8]
# Actually HMAC is over the version+protobuf (everything before the 8-byte MAC)
full_payload_for_hmac = inner_msg[:-8]  # = inner_payload
expected_hmac = hmac.new(hmac_key_derived, full_payload_for_hmac, hashlib.sha256).digest()[:8]
print(f"\nHMAC verification:")
print(f"  Expected: {expected_hmac.hex()}")
print(f"  Actual:   {inner_hmac.hex()}")
print(f"  Match: {expected_hmac == inner_hmac}")

# Decrypt
try:
    plaintext = aes_256_cbc_decrypt(aes_key, iv, ciphertext)
    print(f"\n=== DECRYPTION SUCCESSFUL ===")
    print(f"Plaintext ({len(plaintext)} bytes):")
    print(f"  {plaintext.decode('utf-8', errors='replace')[:200]}")
except Exception as e:
    print(f"\n=== DECRYPTION FAILED ===")
    print(f"Error: {e}")
    print(f"\nThis means either:")
    print(f"  1. Wrong keys (3DH computed different S)")
    print(f"  2. Wrong chain_index advancement")
    print(f"  3. Ciphertext is corrupted or truncated")
    print(f"  4. The inner message parsing is wrong (ciphertext boundaries)")
    print()
    print(f"Ciphertext first 32 bytes: {ciphertext[:32].hex()}")
    print(f"Ciphertext last 16 bytes:  {ciphertext[-16:].hex()}")
