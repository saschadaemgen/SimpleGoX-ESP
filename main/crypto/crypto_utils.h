#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/* Initialize crypto subsystem (calls sodium_init) */
esp_err_t crypto_utils_init(void);

/* Base64 unpadded encode/decode (Matrix standard) */
int crypto_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_size);
int crypto_base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_size);
size_t crypto_base64_encoded_len(size_t in_len);

/* HKDF-SHA-256 (RFC 5869). salt=NULL means zero-filled. */
esp_err_t crypto_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                              const uint8_t *salt, size_t salt_len,
                              const uint8_t *info, size_t info_len,
                              uint8_t *okm, size_t okm_len);

/* HMAC-SHA-256. Output is always 32 bytes. */
esp_err_t crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                              const uint8_t *data, size_t data_len,
                              uint8_t *mac_out);

/* AES-256-CBC with PKCS#7 padding. out_len returns actual bytes written. */
esp_err_t crypto_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                                     const uint8_t *in, size_t in_len,
                                     uint8_t *out, size_t out_size, size_t *out_len);
esp_err_t crypto_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                                     const uint8_t *in, size_t in_len,
                                     uint8_t *out, size_t out_size, size_t *out_len);

/* SHA-256. Output is always 32 bytes. */
esp_err_t crypto_sha256(const uint8_t *data, size_t data_len, uint8_t *hash_out);

/* Cryptographic random bytes */
void crypto_random_bytes(uint8_t *buf, size_t len);

/* Secure memory wipe */
void crypto_wipe(void *buf, size_t len);

/*
 * Ed25519 and Curve25519 wrappers using internal SRAM buffers.
 * Avoids IDFGH-7139 crash when libsodium + HW-SHA operates
 * on PSRAM-backed memory (ESP32-S3 with SPIRAM).
 */
esp_err_t crypto_ed25519_keypair(uint8_t pk_out[32], uint8_t sk_out[64]);
esp_err_t crypto_ed25519_sign(const uint8_t sk[64],
                               const uint8_t *message, size_t message_len,
                               uint8_t sig_out[64]);
esp_err_t crypto_ed25519_verify(const uint8_t pk[32],
                                 const uint8_t *message, size_t message_len,
                                 const uint8_t sig[64]);

/* Curve25519 ECDH with SRAM-safe key copies */
esp_err_t crypto_curve25519_scalarmult(uint8_t out[32],
                                        const uint8_t scalar[32],
                                        const uint8_t point[32]);
esp_err_t crypto_curve25519_base(uint8_t pk_out[32],
                                  const uint8_t sk[32]);

#endif /* CRYPTO_UTILS_H */
