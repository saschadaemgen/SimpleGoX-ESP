#include "crypto_utils.h"

#include <string.h>
#include "esp_log.h"
#include "sodium.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/cipher.h"
#include "mbedtls/sha256.h"

static const char *TAG = "crypto_utils";

esp_err_t crypto_utils_init(void)
{
    if (sodium_init() < 0) {
        ESP_LOGE(TAG, "sodium_init failed");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Crypto subsystem initialized");
    return ESP_OK;
}

/* Base64 unpadded (Matrix standard) */

size_t crypto_base64_encoded_len(size_t in_len)
{
    /* Unpadded base64: ceil(in_len * 4 / 3) + 1 for null terminator */
    return sodium_base64_ENCODED_LEN(in_len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
}

int crypto_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_size)
{
    if (in == NULL || out == NULL) {
        return -1;
    }
    size_t needed = crypto_base64_encoded_len(in_len);
    if (out_size < needed) {
        return -1;
    }
    sodium_bin2base64(out, out_size, in, in_len,
                      sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    return (int)strlen(out);
}

int crypto_base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_size)
{
    if (in == NULL || out == NULL) {
        return -1;
    }
    size_t bin_len = 0;
    int rc = sodium_base642bin(out, out_size, in, in_len,
                               NULL, &bin_len, NULL,
                               sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    if (rc != 0) {
        return -1;
    }
    return (int)bin_len;
}

/* HKDF-SHA-256 */

esp_err_t crypto_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                              const uint8_t *salt, size_t salt_len,
                              const uint8_t *info, size_t info_len,
                              uint8_t *okm, size_t okm_len)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) {
        return ESP_FAIL;
    }
    int rc = mbedtls_hkdf(md,
                           salt, salt_len,
                           ikm, ikm_len,
                           info, info_len,
                           okm, okm_len);
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

/* HMAC-SHA-256 */

esp_err_t crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                              const uint8_t *data, size_t data_len,
                              uint8_t *mac_out)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) {
        return ESP_FAIL;
    }
    int rc = mbedtls_md_hmac(md, key, key_len, data, data_len, mac_out);
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

/* AES-256-CBC with PKCS#7 */

esp_err_t crypto_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                                     const uint8_t *in, size_t in_len,
                                     uint8_t *out, size_t out_size, size_t *out_len)
{
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    const mbedtls_cipher_info_t *ci =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
    if (ci == NULL) {
        mbedtls_cipher_free(&ctx);
        return ESP_FAIL;
    }

    int rc = mbedtls_cipher_setup(&ctx, ci);
    if (rc != 0) { mbedtls_cipher_free(&ctx); return ESP_FAIL; }

    rc = mbedtls_cipher_setkey(&ctx, key, 256, MBEDTLS_ENCRYPT);
    if (rc != 0) { mbedtls_cipher_free(&ctx); return ESP_FAIL; }

    mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7);

    rc = mbedtls_cipher_set_iv(&ctx, iv, 16);
    if (rc != 0) { mbedtls_cipher_free(&ctx); return ESP_FAIL; }

    rc = mbedtls_cipher_reset(&ctx);
    if (rc != 0) { mbedtls_cipher_free(&ctx); return ESP_FAIL; }

    size_t olen = 0;
    rc = mbedtls_cipher_update(&ctx, in, in_len, out, &olen);
    if (rc != 0) { mbedtls_cipher_free(&ctx); return ESP_FAIL; }

    size_t finish_len = 0;
    rc = mbedtls_cipher_finish(&ctx, out + olen, &finish_len);
    mbedtls_cipher_free(&ctx);
    if (rc != 0) { return ESP_FAIL; }

    *out_len = olen + finish_len;
    return ESP_OK;
}

esp_err_t crypto_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                                     const uint8_t *in, size_t in_len,
                                     uint8_t *out, size_t out_size, size_t *out_len)
{
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    const mbedtls_cipher_info_t *ci =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
    if (ci == NULL) {
        mbedtls_cipher_free(&ctx);
        return ESP_FAIL;
    }

    int rc = mbedtls_cipher_setup(&ctx, ci);
    if (rc != 0) { mbedtls_cipher_free(&ctx); return ESP_FAIL; }

    rc = mbedtls_cipher_setkey(&ctx, key, 256, MBEDTLS_DECRYPT);
    if (rc != 0) { mbedtls_cipher_free(&ctx); return ESP_FAIL; }

    mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7);

    rc = mbedtls_cipher_set_iv(&ctx, iv, 16);
    if (rc != 0) { mbedtls_cipher_free(&ctx); return ESP_FAIL; }

    rc = mbedtls_cipher_reset(&ctx);
    if (rc != 0) { mbedtls_cipher_free(&ctx); return ESP_FAIL; }

    size_t olen = 0;
    rc = mbedtls_cipher_update(&ctx, in, in_len, out, &olen);
    if (rc != 0) { mbedtls_cipher_free(&ctx); return ESP_FAIL; }

    size_t finish_len = 0;
    rc = mbedtls_cipher_finish(&ctx, out + olen, &finish_len);
    mbedtls_cipher_free(&ctx);
    if (rc != 0) { return ESP_FAIL; }

    *out_len = olen + finish_len;
    return ESP_OK;
}

/* SHA-256 */

esp_err_t crypto_sha256(const uint8_t *data, size_t data_len, uint8_t *hash_out)
{
    int rc = mbedtls_sha256(data, data_len, hash_out, 0);
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

/* Random */

void crypto_random_bytes(uint8_t *buf, size_t len)
{
    randombytes_buf(buf, len);
}

/* Secure wipe */

void crypto_wipe(void *buf, size_t len)
{
    sodium_memzero(buf, len);
}

/*
 * Ed25519 wrappers that use internal SRAM temp buffers.
 *
 * On ESP32-S3 with PSRAM, libsodium's Ed25519 implementation crashes
 * (IDFGH-7139) when the key buffers reside in PSRAM because the HW SHA
 * accelerator cannot DMA from PSRAM. We work around this by doing the
 * crypto operation in MALLOC_CAP_INTERNAL buffers and copying results out.
 */

#include "esp_heap_caps.h"

esp_err_t crypto_ed25519_keypair(uint8_t pk_out[32], uint8_t sk_out[64])
{
    /* Allocate temp buffers in internal SRAM */
    uint8_t *pk = heap_caps_malloc(32, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    uint8_t *sk = heap_caps_malloc(64, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (pk == NULL || sk == NULL) {
        free(pk); free(sk);
        return ESP_ERR_NO_MEM;
    }

    crypto_sign_ed25519_keypair(pk, sk);

    memcpy(pk_out, pk, 32);
    memcpy(sk_out, sk, 64);
    sodium_memzero(sk, 64);
    free(pk);
    free(sk);
    return ESP_OK;
}

esp_err_t crypto_ed25519_sign(const uint8_t sk[64],
                               const uint8_t *message, size_t message_len,
                               uint8_t sig_out[64])
{
    /* Copy secret key to internal SRAM */
    uint8_t *sk_int = heap_caps_malloc(64, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    uint8_t *sig_int = heap_caps_malloc(64, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (sk_int == NULL || sig_int == NULL) {
        free(sk_int); free(sig_int);
        return ESP_ERR_NO_MEM;
    }

    memcpy(sk_int, sk, 64);

    int rc = crypto_sign_ed25519_detached(sig_int, NULL, message, message_len, sk_int);

    memcpy(sig_out, sig_int, 64);
    sodium_memzero(sk_int, 64);
    free(sk_int);
    free(sig_int);
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t crypto_ed25519_verify(const uint8_t pk[32],
                                 const uint8_t *message, size_t message_len,
                                 const uint8_t sig[64])
{
    uint8_t *pk_int = heap_caps_malloc(32, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    uint8_t *sig_int = heap_caps_malloc(64, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (pk_int == NULL || sig_int == NULL) {
        free(pk_int); free(sig_int);
        return ESP_ERR_NO_MEM;
    }

    memcpy(pk_int, pk, 32);
    memcpy(sig_int, sig, 64);

    int rc = crypto_sign_ed25519_verify_detached(sig_int, message, message_len, pk_int);

    free(pk_int);
    free(sig_int);
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

/*
 * Curve25519 ECDH wrapper with internal SRAM copies.
 * Same IDFGH-7139 concern: the HW SHA engine (used internally by
 * some libsodium Curve25519 paths on ESP32-S3) cannot DMA from PSRAM.
 */

esp_err_t crypto_curve25519_scalarmult(uint8_t out[32],
                                        const uint8_t scalar[32],
                                        const uint8_t point[32])
{
    uint8_t *s = heap_caps_malloc(32, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    uint8_t *p = heap_caps_malloc(32, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    uint8_t *o = heap_caps_malloc(32, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (s == NULL || p == NULL || o == NULL) {
        free(s); free(p); free(o);
        return ESP_ERR_NO_MEM;
    }

    memcpy(s, scalar, 32);
    memcpy(p, point, 32);

    int rc = crypto_scalarmult_curve25519(o, s, p);

    if (rc == 0) {
        memcpy(out, o, 32);
    }
    sodium_memzero(s, 32);
    free(s); free(p); free(o);
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t crypto_curve25519_base(uint8_t pk_out[32], const uint8_t sk[32])
{
    uint8_t *s = heap_caps_malloc(32, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    uint8_t *p = heap_caps_malloc(32, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (s == NULL || p == NULL) {
        free(s); free(p);
        return ESP_ERR_NO_MEM;
    }

    memcpy(s, sk, 32);
    int rc = crypto_scalarmult_curve25519_base(p, s);

    if (rc == 0) {
        memcpy(pk_out, p, 32);
    }
    sodium_memzero(s, 32);
    free(s); free(p);
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}
