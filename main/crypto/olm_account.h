#ifndef OLM_ACCOUNT_H
#define OLM_ACCOUNT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define OLM_MAX_ONE_TIME_KEYS 50

typedef struct {
    uint8_t ed25519_private[64];    /* libsodium 64-byte secret key */
    uint8_t ed25519_public[32];
    uint8_t curve25519_private[32]; /* derived from ed25519 */
    uint8_t curve25519_public[32];
} olm_identity_keys_t;

typedef struct {
    uint8_t private_key[32];
    uint8_t public_key[32];
    uint32_t key_id;
    bool published;
    bool used;
} olm_one_time_key_t;

typedef struct {
    olm_identity_keys_t identity;
    olm_one_time_key_t one_time_keys[OLM_MAX_ONE_TIME_KEYS];
    uint32_t next_key_id;
    bool initialized;
} olm_account_t;

/* Create a new account with fresh Ed25519 + Curve25519 keys */
esp_err_t olm_account_create(olm_account_t *account);

/* Generate count new one-time keys */
esp_err_t olm_account_generate_one_time_keys(olm_account_t *account, int count);

/* Mark all unpublished keys as published */
void olm_account_mark_keys_as_published(olm_account_t *account);

/* Find and consume the OTK matching public_key. Returns private key. */
esp_err_t olm_account_consume_one_time_key(olm_account_t *account,
                                            const uint8_t public_key[32],
                                            uint8_t out_private[32]);

/* Count unpublished OTKs */
int olm_account_unpublished_otk_count(const olm_account_t *account);

/* Count published but unused OTKs (server-side count equivalent) */
int olm_account_available_otk_count(const olm_account_t *account);

/* Sign a message with Ed25519. sig_out must be 64 bytes. */
esp_err_t olm_account_sign(const olm_account_t *account,
                            const uint8_t *message, size_t message_len,
                            uint8_t sig_out[64]);

/* Get identity keys as base64 strings */
esp_err_t olm_account_get_identity_json(const olm_account_t *account,
                                         char *ed25519_b64, size_t ed_size,
                                         char *curve25519_b64, size_t cv_size);

/* Serialize/deserialize for NVS persistence */
size_t olm_account_serialize(const olm_account_t *account, uint8_t *buf, size_t buf_size);
esp_err_t olm_account_deserialize(olm_account_t *account, const uint8_t *buf, size_t buf_len);

#endif /* OLM_ACCOUNT_H */
