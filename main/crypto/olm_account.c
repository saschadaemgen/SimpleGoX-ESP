#include "olm_account.h"
#include "crypto_utils.h"

#include <string.h>
#include "esp_log.h"
#include "sodium.h"

static const char *TAG = "olm_account";

esp_err_t olm_account_create(olm_account_t *account)
{
    if (account == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(account, 0, sizeof(olm_account_t));

    /* Generate Ed25519 signing keypair (SRAM-safe wrapper) */
    esp_err_t err = crypto_ed25519_keypair(account->identity.ed25519_public,
                                            account->identity.ed25519_private);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Ed25519 keypair generation failed");
        return err;
    }

    /* Derive Curve25519 identity keys from Ed25519 */
    if (crypto_sign_ed25519_pk_to_curve25519(
            account->identity.curve25519_public,
            account->identity.ed25519_public) != 0) {
        ESP_LOGE(TAG, "Ed25519->Curve25519 public key conversion failed");
        return ESP_FAIL;
    }

    if (crypto_sign_ed25519_sk_to_curve25519(
            account->identity.curve25519_private,
            account->identity.ed25519_private) != 0) {
        ESP_LOGE(TAG, "Ed25519->Curve25519 secret key conversion failed");
        return ESP_FAIL;
    }

    account->next_key_id = 1;
    account->initialized = true;

    ESP_LOGI(TAG, "Olm account created");
    return ESP_OK;
}

esp_err_t olm_account_generate_one_time_keys(olm_account_t *account, int count)
{
    if (account == NULL || !account->initialized || count <= 0) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Priority for slot reuse:
     * 1. Empty slots (key_id == 0)
     * 2. Used slots (already consumed by a peer)
     * 3. Published slots (on the server, can be replaced with fresh keys) */
    int generated = 0;
    for (int i = 0; i < OLM_MAX_ONE_TIME_KEYS && generated < count; i++) {
        if (account->one_time_keys[i].key_id == 0) {
            crypto_random_bytes(account->one_time_keys[i].private_key, 32);
            crypto_curve25519_base(account->one_time_keys[i].public_key,
                                    account->one_time_keys[i].private_key);
            account->one_time_keys[i].key_id = account->next_key_id++;
            account->one_time_keys[i].published = false;
            account->one_time_keys[i].used = false;
            generated++;
        }
    }
    for (int i = 0; i < OLM_MAX_ONE_TIME_KEYS && generated < count; i++) {
        if (account->one_time_keys[i].used) {
            crypto_random_bytes(account->one_time_keys[i].private_key, 32);
            crypto_curve25519_base(account->one_time_keys[i].public_key,
                                    account->one_time_keys[i].private_key);
            account->one_time_keys[i].key_id = account->next_key_id++;
            account->one_time_keys[i].published = false;
            account->one_time_keys[i].used = false;
            generated++;
        }
    }
    /* Never overwrite published-but-not-used slots: they may still be
     * on the server waiting to be claimed. With 50 slots there is enough
     * room for ~40 published keys plus 10 fresh ones at any time. */

    ESP_LOGI(TAG, "Generated %d one-time keys", generated);
    return ESP_OK;
}

void olm_account_mark_keys_as_published(olm_account_t *account)
{
    if (account == NULL) { return; }
    for (int i = 0; i < OLM_MAX_ONE_TIME_KEYS; i++) {
        if (account->one_time_keys[i].key_id != 0 &&
            !account->one_time_keys[i].published) {
            account->one_time_keys[i].published = true;
        }
    }
}

esp_err_t olm_account_consume_one_time_key(olm_account_t *account,
                                            const uint8_t public_key[32],
                                            uint8_t out_private[32])
{
    if (account == NULL || public_key == NULL || out_private == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    for (int i = 0; i < OLM_MAX_ONE_TIME_KEYS; i++) {
        if (account->one_time_keys[i].key_id != 0 &&
            !account->one_time_keys[i].used &&
            memcmp(account->one_time_keys[i].public_key, public_key, 32) == 0) {
            memcpy(out_private, account->one_time_keys[i].private_key, 32);
            account->one_time_keys[i].used = true;
            ESP_LOGD(TAG, "Consumed OTK id=%lu",
                     (unsigned long)account->one_time_keys[i].key_id);
            return ESP_OK;
        }
    }

    ESP_LOGW(TAG, "OTK not found for consumption");
    return ESP_ERR_NOT_FOUND;
}

int olm_account_unpublished_otk_count(const olm_account_t *account)
{
    if (account == NULL) { return 0; }
    int count = 0;
    for (int i = 0; i < OLM_MAX_ONE_TIME_KEYS; i++) {
        if (account->one_time_keys[i].key_id != 0 &&
            !account->one_time_keys[i].published &&
            !account->one_time_keys[i].used) {
            count++;
        }
    }
    return count;
}

int olm_account_available_otk_count(const olm_account_t *account)
{
    if (account == NULL) { return 0; }
    int count = 0;
    for (int i = 0; i < OLM_MAX_ONE_TIME_KEYS; i++) {
        if (account->one_time_keys[i].key_id != 0 &&
            account->one_time_keys[i].published &&
            !account->one_time_keys[i].used) {
            count++;
        }
    }
    return count;
}

esp_err_t olm_account_sign(const olm_account_t *account,
                            const uint8_t *message, size_t message_len,
                            uint8_t sig_out[64])
{
    if (account == NULL || message == NULL || sig_out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    return crypto_ed25519_sign(account->identity.ed25519_private,
                               message, message_len, sig_out);
}

esp_err_t olm_account_get_identity_json(const olm_account_t *account,
                                         char *ed25519_b64, size_t ed_size,
                                         char *curve25519_b64, size_t cv_size)
{
    if (account == NULL) { return ESP_ERR_INVALID_ARG; }

    if (ed25519_b64 != NULL) {
        crypto_base64_encode(account->identity.ed25519_public, 32,
                             ed25519_b64, ed_size);
    }
    if (curve25519_b64 != NULL) {
        crypto_base64_encode(account->identity.curve25519_public, 32,
                             curve25519_b64, cv_size);
    }
    return ESP_OK;
}

/*
 * Serialization format:
 * [1B version=0x01]
 * [64B ed25519_private][32B ed25519_public]
 * [32B curve25519_private][32B curve25519_public]
 * [4B next_key_id LE]
 * [1B otk_count]
 * per OTK: [32B private][32B public][4B key_id LE][1B flags]
 *   flags: bit0=published, bit1=used
 */

#define SERIALIZE_VERSION 0x01
#define FIXED_HEADER_SIZE (1 + 64 + 32 + 32 + 32 + 4 + 1)
#define OTK_ENTRY_SIZE (32 + 32 + 4 + 1)

size_t olm_account_serialize(const olm_account_t *account, uint8_t *buf, size_t buf_size)
{
    if (account == NULL || buf == NULL) { return 0; }

    /* Count active OTKs */
    int otk_count = 0;
    for (int i = 0; i < OLM_MAX_ONE_TIME_KEYS; i++) {
        if (account->one_time_keys[i].key_id != 0) {
            otk_count++;
        }
    }

    size_t needed = FIXED_HEADER_SIZE + (size_t)otk_count * OTK_ENTRY_SIZE;
    if (buf_size < needed) { return 0; }

    size_t pos = 0;
    buf[pos++] = SERIALIZE_VERSION;

    memcpy(buf + pos, account->identity.ed25519_private, 64); pos += 64;
    memcpy(buf + pos, account->identity.ed25519_public, 32); pos += 32;
    memcpy(buf + pos, account->identity.curve25519_private, 32); pos += 32;
    memcpy(buf + pos, account->identity.curve25519_public, 32); pos += 32;

    buf[pos++] = (uint8_t)(account->next_key_id & 0xFF);
    buf[pos++] = (uint8_t)((account->next_key_id >> 8) & 0xFF);
    buf[pos++] = (uint8_t)((account->next_key_id >> 16) & 0xFF);
    buf[pos++] = (uint8_t)((account->next_key_id >> 24) & 0xFF);

    buf[pos++] = (uint8_t)otk_count;

    for (int i = 0; i < OLM_MAX_ONE_TIME_KEYS; i++) {
        if (account->one_time_keys[i].key_id != 0) {
            memcpy(buf + pos, account->one_time_keys[i].private_key, 32); pos += 32;
            memcpy(buf + pos, account->one_time_keys[i].public_key, 32); pos += 32;
            uint32_t kid = account->one_time_keys[i].key_id;
            buf[pos++] = (uint8_t)(kid & 0xFF);
            buf[pos++] = (uint8_t)((kid >> 8) & 0xFF);
            buf[pos++] = (uint8_t)((kid >> 16) & 0xFF);
            buf[pos++] = (uint8_t)((kid >> 24) & 0xFF);
            uint8_t flags = 0;
            if (account->one_time_keys[i].published) { flags |= 0x01; }
            if (account->one_time_keys[i].used) { flags |= 0x02; }
            buf[pos++] = flags;
        }
    }

    return pos;
}

esp_err_t olm_account_deserialize(olm_account_t *account, const uint8_t *buf, size_t buf_len)
{
    if (account == NULL || buf == NULL || buf_len < FIXED_HEADER_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(account, 0, sizeof(olm_account_t));

    size_t pos = 0;
    if (buf[pos++] != SERIALIZE_VERSION) {
        return ESP_FAIL;
    }

    memcpy(account->identity.ed25519_private, buf + pos, 64); pos += 64;
    memcpy(account->identity.ed25519_public, buf + pos, 32); pos += 32;
    memcpy(account->identity.curve25519_private, buf + pos, 32); pos += 32;
    memcpy(account->identity.curve25519_public, buf + pos, 32); pos += 32;

    account->next_key_id = (uint32_t)buf[pos] |
                           ((uint32_t)buf[pos + 1] << 8) |
                           ((uint32_t)buf[pos + 2] << 16) |
                           ((uint32_t)buf[pos + 3] << 24);
    pos += 4;

    int otk_count = buf[pos++];
    if (buf_len < pos + (size_t)otk_count * OTK_ENTRY_SIZE) {
        return ESP_FAIL;
    }

    for (int i = 0; i < otk_count && i < OLM_MAX_ONE_TIME_KEYS; i++) {
        memcpy(account->one_time_keys[i].private_key, buf + pos, 32); pos += 32;
        memcpy(account->one_time_keys[i].public_key, buf + pos, 32); pos += 32;
        account->one_time_keys[i].key_id =
            (uint32_t)buf[pos] |
            ((uint32_t)buf[pos + 1] << 8) |
            ((uint32_t)buf[pos + 2] << 16) |
            ((uint32_t)buf[pos + 3] << 24);
        pos += 4;
        uint8_t flags = buf[pos++];
        account->one_time_keys[i].published = (flags & 0x01) != 0;
        account->one_time_keys[i].used = (flags & 0x02) != 0;
    }

    account->initialized = true;
    ESP_LOGI(TAG, "Account deserialized, %d OTKs", otk_count);
    return ESP_OK;
}
