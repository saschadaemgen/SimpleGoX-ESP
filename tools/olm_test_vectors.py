#!/usr/bin/env python3
"""
Generate Olm test vectors with ALL intermediate values.
Compare these byte-for-byte with ESP32 serial output to find the bug.

Requirements: pip install python-olm

This script creates an Alice->Bob Olm session, encrypts a message,
and dumps every intermediate value. The ESP must reproduce these
exact values to decrypt correctly.
"""

import json
import base64
import hashlib
import hmac
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# We need to manually implement the Olm primitives to dump intermediates,
# because python-olm doesn't expose them.
# Instead, we use the cryptography library directly.

try:
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.signing import SigningKey, VerifyKey
    from nacl.bindings import (
        crypto_scalarmult as crypto_scalarmult_curve25519,
        crypto_sign_ed25519_pk_to_curve25519,
        crypto_sign_ed25519_sk_to_curve25519,
    )
    import nacl.utils
except ImportError:
    print("pip install pynacl cryptography")
    exit(1)


def b64(data):
    """Unpadded base64 encode"""
    return base64.b64encode(data).rstrip(b'=').decode()


def hkdf_sha256(ikm, length, salt=b'', info=b''):
    """HKDF-SHA-256 per RFC 5869"""
    # Extract
    if not salt:
        salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # Expand
    okm = b''
    t = b''
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def aes_256_cbc_decrypt(key, iv, ciphertext):
    """AES-256-CBC decrypt with PKCS7 unpadding"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes_256_cbc_encrypt(key, iv, plaintext):
    """AES-256-CBC encrypt with PKCS7 padding"""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def hex8(data):
    """First 8 bytes as hex"""
    return data[:8].hex()


def hex4(data):
    """First 4 bytes as hex"""
    return data[:4].hex()


def varint_encode(value):
    """Protobuf varint encoding"""
    result = []
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def encode_olm_inner_message(ratchet_key, chain_index, ciphertext, hmac_key):
    """Encode an Olm inner message (version 3)"""
    buf = b'\x03'  # version
    # Field 1: ratchet_key (tag=0x0A, length-delimited)
    buf += b'\x0a' + varint_encode(32) + ratchet_key
    # Field 2: chain_index (tag=0x10, varint)
    buf += b'\x10' + varint_encode(chain_index)
    # Field 4: ciphertext (tag=0x22, length-delimited)
    buf += b'\x22' + varint_encode(len(ciphertext)) + ciphertext
    # 8-byte truncated HMAC
    mac = hmac.new(hmac_key, buf, hashlib.sha256).digest()[:8]
    buf += mac
    return buf


def encode_olm_prekey_message(one_time_key, base_key, identity_key, inner_message):
    """Encode an Olm pre-key message (version 3)"""
    buf = b'\x03'  # version
    # Field 1: one_time_key
    buf += b'\x0a' + varint_encode(32) + one_time_key
    # Field 2: base_key (ephemeral)
    buf += b'\x12' + varint_encode(32) + base_key
    # Field 3: identity_key
    buf += b'\x1a' + varint_encode(32) + identity_key
    # Field 4: inner message
    buf += b'\x22' + varint_encode(len(inner_message)) + inner_message
    return buf


print("=" * 60)
print("OLM TEST VECTOR GENERATOR")
print("=" * 60)

# --- Generate keys ---

# Bob (the ESP) - identity key
bob_signing = SigningKey.generate()
bob_signing_pub = bob_signing.verify_key
# Ed25519 sk is 64 bytes in libsodium: seed(32) + public(32)
bob_ed25519_sk_full = bytes(bob_signing) + bytes(bob_signing_pub)
bob_identity_private = crypto_sign_ed25519_sk_to_curve25519(bob_ed25519_sk_full)
bob_identity_public = crypto_sign_ed25519_pk_to_curve25519(bytes(bob_signing_pub))

# Bob one-time key
bob_otk_private = nacl.utils.random(32)
# Clamp for Curve25519
bob_otk_private_bytes = bytearray(bob_otk_private)
bob_otk_private_bytes[0] &= 248
bob_otk_private_bytes[31] &= 127
bob_otk_private_bytes[31] |= 64
bob_otk_private = bytes(bob_otk_private_bytes)
bob_otk_public = PrivateKey(bob_otk_private).public_key._public_key

# Alice (Element) - identity key
alice_signing = SigningKey.generate()
alice_signing_pub = alice_signing.verify_key
alice_ed25519_sk_full = bytes(alice_signing) + bytes(alice_signing_pub)
alice_identity_private = crypto_sign_ed25519_sk_to_curve25519(alice_ed25519_sk_full)
alice_identity_public = crypto_sign_ed25519_pk_to_curve25519(bytes(alice_signing_pub))

# Alice ephemeral key
alice_ephemeral_private = nacl.utils.random(32)
alice_eph_private_bytes = bytearray(alice_ephemeral_private)
alice_eph_private_bytes[0] &= 248
alice_eph_private_bytes[31] &= 127
alice_eph_private_bytes[31] |= 64
alice_ephemeral_private = bytes(alice_eph_private_bytes)
alice_ephemeral_public = PrivateKey(alice_ephemeral_private).public_key._public_key

print("\n--- KEYS ---")
print(f"Bob identity private:  {hex8(bob_identity_private)}")
print(f"Bob identity public:   {hex8(bob_identity_public)} ({b64(bob_identity_public)})")
print(f"Bob OTK private:       {hex8(bob_otk_private)}")
print(f"Bob OTK public:        {hex8(bob_otk_public)} ({b64(bob_otk_public)})")
print(f"Alice identity private:{hex8(alice_identity_private)}")
print(f"Alice identity public: {hex8(alice_identity_public)} ({b64(alice_identity_public)})")
print(f"Alice ephemeral priv:  {hex8(alice_ephemeral_private)}")
print(f"Alice ephemeral pub:   {hex8(alice_ephemeral_public)} ({b64(alice_ephemeral_public)})")

# --- 3DH (Alice's perspective) ---
# S = ECDH(I_A, E_B) || ECDH(E_A, I_B) || ECDH(E_A, E_B)

dh1 = crypto_scalarmult_curve25519(alice_identity_private, bob_otk_public)
dh2 = crypto_scalarmult_curve25519(alice_ephemeral_private, bob_identity_public)
dh3 = crypto_scalarmult_curve25519(alice_ephemeral_private, bob_otk_public)
S_alice = dh1 + dh2 + dh3

print("\n--- 3DH (ALICE) ---")
print(f"DH1 = ECDH(I_A, E_B): {hex8(dh1)}")
print(f"DH2 = ECDH(E_A, I_B): {hex8(dh2)}")
print(f"DH3 = ECDH(E_A, E_B): {hex8(dh3)}")
print(f"S = DH1||DH2||DH3:    {hex8(S_alice)}")

# --- 3DH (Bob's perspective) ---
# S = ECDH(E_B, I_A) || ECDH(I_B, E_A) || ECDH(E_B, E_A)

dh1_bob = crypto_scalarmult_curve25519(bob_otk_private, alice_identity_public)
dh2_bob = crypto_scalarmult_curve25519(bob_identity_private, alice_ephemeral_public)
dh3_bob = crypto_scalarmult_curve25519(bob_otk_private, alice_ephemeral_public)
S_bob = dh1_bob + dh2_bob + dh3_bob

print("\n--- 3DH (BOB) ---")
print(f"DH1 = ECDH(E_B, I_A): {hex8(dh1_bob)}")
print(f"DH2 = ECDH(I_B, E_A): {hex8(dh2_bob)}")
print(f"DH3 = ECDH(E_B, E_A): {hex8(dh3_bob)}")
print(f"S = DH1||DH2||DH3:    {hex8(S_bob)}")
print(f"S match: {S_alice == S_bob}")

assert S_alice == S_bob, "3DH shared secrets don't match!"

# --- Initial HKDF ---
# HKDF(salt=0, ikm=S, info="OLM_ROOT", L=64)
# NOTE: salt=0 means no salt (empty), which HKDF treats as HashLen zeros

derived = hkdf_sha256(S_alice, 64, salt=b'', info=b'OLM_ROOT')
root_key_0 = derived[:32]
chain_key_0 = derived[32:]

print("\n--- INITIAL KEY DERIVATION ---")
print(f"HKDF(S, 'OLM_ROOT', 64):")
print(f"  root_key:  {hex8(root_key_0)}")
print(f"  chain_key: {hex8(chain_key_0)}")

# --- Alice sends first message ---
# chain_ratchet: message_key = HMAC(chain_key, 0x01)
#                next_chain   = HMAC(chain_key, 0x02)

message_key_0 = hmac.new(chain_key_0, b'\x01', hashlib.sha256).digest()
next_chain_0 = hmac.new(chain_key_0, b'\x02', hashlib.sha256).digest()

print("\n--- CHAIN RATCHET (message 0) ---")
print(f"message_key = HMAC(chain, 0x01): {hex8(message_key_0)}")
print(f"next_chain  = HMAC(chain, 0x02): {hex8(next_chain_0)}")

# --- Expand message key ---
# HKDF(salt=0, ikm=message_key, info="OLM_KEYS", L=80)

expanded = hkdf_sha256(message_key_0, 80, salt=b'', info=b'OLM_KEYS')
aes_key = expanded[:32]
hmac_key = expanded[32:64]
iv = expanded[64:80]

print("\n--- MESSAGE KEY EXPANSION ---")
print(f"HKDF(msg_key, 'OLM_KEYS', 80):")
print(f"  aes_key:  {hex8(aes_key)}")
print(f"  hmac_key: {hex8(hmac_key)}")
print(f"  iv:       {iv.hex()}")

# --- Encrypt ---
plaintext = b'{"type":"m.room_key","content":{"algorithm":"m.megolm.v1.aes-sha2","room_id":"!test:example.com","session_id":"test_session","session_key":"dGVzdA"}}'

ciphertext = aes_256_cbc_encrypt(aes_key, iv, plaintext)

print(f"\n--- ENCRYPTION ---")
print(f"plaintext ({len(plaintext)} bytes): {plaintext[:60]}...")
print(f"ciphertext ({len(ciphertext)} bytes): {hex8(ciphertext)}")

# --- Build inner message ---
inner_msg = encode_olm_inner_message(
    alice_ephemeral_public,  # ratchet_key = ephemeral for first message
    0,                        # chain_index = 0
    ciphertext,
    hmac_key
)

print(f"\n--- INNER MESSAGE ---")
print(f"inner message ({len(inner_msg)} bytes)")
print(f"  version: 0x{inner_msg[0]:02x}")
print(f"  first 8: {inner_msg[:8].hex()}")
print(f"  last 8 (HMAC): {inner_msg[-8:].hex()}")

# --- Build pre-key message ---
prekey_msg = encode_olm_prekey_message(
    bob_otk_public,
    alice_ephemeral_public,
    alice_identity_public,
    inner_msg
)

print(f"\n--- PRE-KEY MESSAGE ---")
print(f"pre-key message ({len(prekey_msg)} bytes)")
print(f"  version: 0x{prekey_msg[0]:02x}")
print(f"  base64: {b64(prekey_msg)[:40]}...")

# --- Verify Bob can decrypt ---
print("\n--- BOB DECRYPTION VERIFICATION ---")

# Bob derives the same keys
derived_bob = hkdf_sha256(S_bob, 64, salt=b'', info=b'OLM_ROOT')
root_key_bob = derived_bob[:32]
chain_key_bob = derived_bob[32:]

message_key_bob = hmac.new(chain_key_bob, b'\x01', hashlib.sha256).digest()
expanded_bob = hkdf_sha256(message_key_bob, 80, salt=b'', info=b'OLM_KEYS')
aes_key_bob = expanded_bob[:32]
iv_bob = expanded_bob[64:80]

print(f"Bob root_key:    {hex8(root_key_bob)} (match: {root_key_bob == root_key_0})")
print(f"Bob chain_key:   {hex8(chain_key_bob)} (match: {chain_key_bob == chain_key_0})")
print(f"Bob message_key: {hex8(message_key_bob)} (match: {message_key_bob == message_key_0})")
print(f"Bob aes_key:     {hex8(aes_key_bob)} (match: {aes_key_bob == aes_key})")
print(f"Bob iv:          {iv_bob.hex()} (match: {iv_bob == iv})")

decrypted = aes_256_cbc_decrypt(aes_key_bob, iv_bob, ciphertext)
print(f"Decrypted: {decrypted[:60]}...")
print(f"Match: {decrypted == plaintext}")

# --- ESP comparison values ---
print("\n" + "=" * 60)
print("VALUES TO COMPARE WITH ESP SERIAL OUTPUT")
print("=" * 60)
print(f"Bob inputs to create_inbound:")
print(f"  our_otk_priv[0..3]:    {hex4(bob_otk_private)}")
print(f"  our_id_priv[0..3]:     {hex4(bob_identity_private)}")
print(f"  their_id_pub[0..3]:    {hex4(alice_identity_public)}")
print(f"  their_eph_pub[0..3]:   {hex4(alice_ephemeral_public)}")
print(f"After 3DH:")
print(f"  S[0..7]:               {hex8(S_bob)}")
print(f"  root_key[0..3]:        {hex4(root_key_bob)}")
print(f"  recv_chain[0..3]:      {hex4(chain_key_bob)}")
print(f"After chain_ratchet(chain_index=0):")
print(f"  msg_key[0..3]:         {hex4(message_key_bob)}")
print(f"  chain_key[0..3]:       {hex4(next_chain_0)}")
print(f"After expand_message_key:")
print(f"  aes_key[0..3]:         {hex4(aes_key_bob)}")
print(f"  iv[0..3]:              {hex4(iv_bob)}")
print(f"Ciphertext:")
print(f"  ct[0..3]:              {hex4(ciphertext)}")
print(f"  ct_len:                {len(ciphertext)}")
