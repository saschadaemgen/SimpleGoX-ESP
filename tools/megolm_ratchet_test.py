#!/usr/bin/env python3
"""
Megolm 4-stage ratchet verification.

Paste the initial R0..R3 values from the ESP log (from the session key
shared via to-device), then this script computes what each ratchet state
should be at each message index. Compare with ESP output.

Usage:
  1. Get the initial ratchet values from the ESP to-device session key
     (the 128 bytes = 4x32 from the Megolm session export)
  2. Or get them from the ESP log "BEFORE advance" at msg_index=0
  3. Paste as hex below
  4. Run: python megolm_ratchet_test.py
"""

import hmac
import hashlib
import sys

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

def hex4(data):
    return data[:4].hex()

# Megolm ratchet masks
MASKS = [0x00FFFFFF, 0x0000FFFF, 0x000000FF, 0x00000000]

def megolm_advance(R, counter):
    """Advance the 4-stage Megolm ratchet by one step.

    The hash happens based on the NEW counter (after increment).
    At counter 0->1: no hash (no bits rolled over).
    At counter 255->256: R3 self-hashes (low byte rolled to 0).
    At counter 65535->65536: R2 self-hashes, R3 derived from R2.
    """
    new_counter = counter + 1

    # Find highest-level part that triggers at the new counter
    h = -1
    for i in range(4):
        if (new_counter & MASKS[i]) == 0:
            h = i
            break

    if h >= 0:
        for j in range(h, 4):
            idx_byte = bytes([j])
            if j == h:
                R[j] = hmac.new(R[h], idx_byte, hashlib.sha256).digest()
            else:
                R[j] = hmac.new(R[h], idx_byte, hashlib.sha256).digest()

    return new_counter

def megolm_derive_keys(R):
    """Derive AES key, HMAC key, and IV from ratchet state."""
    ikm = R[0] + R[1] + R[2] + R[3]
    expanded = hkdf_sha256(ikm, 80, salt=b'', info=b'MEGOLM_KEYS')
    aes_key = expanded[:32]
    hmac_key = expanded[32:64]
    iv = expanded[64:80]
    return aes_key, hmac_key, iv


# ============================================================
# PASTE INITIAL RATCHET VALUES FROM ESP LOG HERE
# These are the R0..R3 values at counter=0 (before any advance)
# Get them from the "BEFORE advance" log at msg_index=0
# ============================================================

# Format: full 32-byte hex strings (64 hex chars each)
# If you only have the first 4 bytes, put them here and set PARTIAL=True
PARTIAL = True

R0_HEX = ""  # e.g. "b0d7db49" (4 bytes) or full 64-char hex
R1_HEX = ""
R2_HEX = ""
R3_HEX = ""

# If you have the full session key base64 from the to-device sharing,
# paste it here instead (overrides the above):
SESSION_KEY_B64 = ""

if SESSION_KEY_B64:
    import base64
    sk = base64.b64decode(SESSION_KEY_B64 + '==')
    # Format: [version 0x02][4B counter BE][R0 32B][R1 32B][R2 32B][R3 32B][ed25519 32B][sig 64B]
    counter_start = int.from_bytes(sk[1:5], 'big')
    R0_HEX = sk[5:37].hex()
    R1_HEX = sk[37:69].hex()
    R2_HEX = sk[69:101].hex()
    R3_HEX = sk[101:133].hex()
    PARTIAL = False
    print(f"Session key: counter={counter_start}")

if not R0_HEX:
    print("ERROR: Paste the initial R0..R3 values from the ESP log!")
    print()
    print("Look for the line:")
    print("  BEFORE advance: R0=XXXXXXXX R1=XXXXXXXX R2=XXXXXXXX R3=XXXXXXXX")
    print("at msg_index=0 (the first message)")
    print()
    print("Paste the 4-byte hex values into R0_HEX..R3_HEX and set PARTIAL=True")
    print("Or paste the full 32-byte hex values and set PARTIAL=False")
    sys.exit(1)

if PARTIAL:
    # Pad with zeros for testing (won't match real values but shows the algorithm)
    print("WARNING: Using partial R values (4 bytes padded with zeros)")
    print("Results will NOT match real ESP values. Use full 32-byte values for exact match.")
    R = [
        bytes.fromhex(R0_HEX.ljust(64, '0')),
        bytes.fromhex(R1_HEX.ljust(64, '0')),
        bytes.fromhex(R2_HEX.ljust(64, '0')),
        bytes.fromhex(R3_HEX.ljust(64, '0')),
    ]
else:
    R = [
        bytes.fromhex(R0_HEX),
        bytes.fromhex(R1_HEX),
        bytes.fromhex(R2_HEX),
        bytes.fromhex(R3_HEX),
    ]

counter = 0
print(f"\n{'='*70}")
print(f"MEGOLM RATCHET STATE VERIFICATION")
print(f"{'='*70}")

# Show initial state and derive keys for message 0
print(f"\n--- Message index 0 (initial state, no advance) ---")
print(f"  R0={hex4(R[0])} R1={hex4(R[1])} R2={hex4(R[2])} R3={hex4(R[3])}")
aes, hmac_k, iv = megolm_derive_keys(R)
print(f"  aes={hex4(aes)} iv={hex4(iv)}")

# Advance and show state for messages 1..5
for msg_idx in range(1, 6):
    # Advance ratchet
    print(f"\n--- Advancing from counter={counter} ---")
    print(f"  counter & masks: R0={counter & MASKS[0]:08x} R1={counter & MASKS[1]:08x} R2={counter & MASKS[2]:08x} R3={counter & MASKS[3]:08x}")

    h = 3
    for i in range(4):
        if (counter & MASKS[i]) == 0:
            h = i
            break
    print(f"  h={h} (R{h} self-hashes, R{h+1}..R3 derived from R{h})")

    counter = megolm_advance(R, counter)

    print(f"\n--- Message index {msg_idx} (after {msg_idx} advance(s)) ---")
    print(f"  R0={hex4(R[0])} R1={hex4(R[1])} R2={hex4(R[2])} R3={hex4(R[3])}")
    aes, hmac_k, iv = megolm_derive_keys(R)
    print(f"  aes={hex4(aes)} iv={hex4(iv)}")

print(f"\n{'='*70}")
print(f"Compare these R0..R3 and aes/iv values with ESP serial output")
print(f"The first mismatch shows the bug")
print(f"{'='*70}")
