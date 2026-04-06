#include "megolm_session.h"
#include "megolm_message.h"
#include "crypto_utils.h"

#include <string.h>
#include "esp_log.h"
#include "sodium.h"

static const char *TAG = "megolm_session";

/*
 * Megolm 4-part hash ratchet advancement.
 *
 * The ratchet has 4 parts (R0..R3). Each part advances at different rates:
 * R3: every message        (mask 0x00000000 - always)
 * R2: every 256 messages   (mask 0x000000FF)
 * R1: every 65536 messages (mask 0x0000FFFF)
 * R0: every 2^24 messages  (mask 0x00FFFFFF)
 *
 * When part i advances: R[i] = HMAC(R[i], byte(i)), then all lower parts
 * are re-derived: R[j] = HMAC(R[i], byte(j)) for j > i.
 */

static const uint32_t RATCHET_MASKS[MEGOLM_RATCHET_PARTS] = {
    0x00FFFFFF, /* R0: advances when counter & mask == 0, i.e. every 2^24 */
    0x0000FFFF, /* R1: every 2^16 */
    0x000000FF, /* R2: every 2^8 */
    0x00000000, /* R3: every message */
};

esp_err_t megolm_ratchet_advance(megolm_ratchet_t *ratchet)
{
    if (ratchet == NULL) { return ESP_ERR_INVALID_ARG; }

    /* Find the highest-level part that should advance at this counter */
    int h = MEGOLM_RATCHET_PARTS - 1; /* default: R3 */
    for (int i = 0; i < MEGOLM_RATCHET_PARTS; i++) {
        if ((ratchet->counter & RATCHET_MASKS[i]) == 0) {
            h = i;
            break;
        }
    }

    /* Advance R[h] by self-hashing, then derive lower parts from R[h] */
    for (int j = h; j < MEGOLM_RATCHET_PARTS; j++) {
        uint8_t idx = (uint8_t)j;
        if (j == h) {
            /* Self-hash: R[h] = HMAC(R[h], byte(h)) */
            uint8_t tmp[32];
            crypto_hmac_sha256(ratchet->data[h], 32, &idx, 1, tmp);
            memcpy(ratchet->data[h], tmp, 32);
            crypto_wipe(tmp, sizeof(tmp));
        } else {
            /* Derive: R[j] = HMAC(R[h], byte(j)) */
            crypto_hmac_sha256(ratchet->data[h], 32, &idx, 1, ratchet->data[j]);
        }
    }

    ratchet->counter++;
    return ESP_OK;
}

esp_err_t megolm_ratchet_advance_to(megolm_ratchet_t *ratchet, uint32_t target)
{
    if (ratchet == NULL) { return ESP_ERR_INVALID_ARG; }

    if (target < ratchet->counter) {
        ESP_LOGE(TAG, "Cannot ratchet backward: current=%lu, target=%lu",
                 (unsigned long)ratchet->counter, (unsigned long)target);
        return ESP_FAIL;
    }

    /* Efficient advancement using the hierarchical structure */
    while (ratchet->counter < target) {
        megolm_ratchet_advance(ratchet);
    }

    return ESP_OK;
}

/* Derive AES key (32) + HMAC key (32) + IV (16) from ratchet state */
static esp_err_t megolm_derive_keys(const megolm_ratchet_t *ratchet,
                                     uint8_t aes_key[32],
                                     uint8_t hmac_key[32],
                                     uint8_t iv[16])
{
    /* IKM = R0 || R1 || R2 || R3 = 128 bytes */
    uint8_t ikm[128];
    memcpy(ikm, ratchet->data[0], 32);
    memcpy(ikm + 32, ratchet->data[1], 32);
    memcpy(ikm + 64, ratchet->data[2], 32);
    memcpy(ikm + 96, ratchet->data[3], 32);

    uint8_t expanded[80];
    esp_err_t err = crypto_hkdf_sha256(ikm, 128, NULL, 0,
                                        (const uint8_t *)"MEGOLM_KEYS", 11,
                                        expanded, 80);
    crypto_wipe(ikm, sizeof(ikm));
    if (err != ESP_OK) { return err; }

    memcpy(aes_key, expanded, 32);
    memcpy(hmac_key, expanded + 32, 32);
    memcpy(iv, expanded + 64, 16);
    crypto_wipe(expanded, sizeof(expanded));
    return ESP_OK;
}

esp_err_t megolm_outbound_create(megolm_outbound_session_t *session)
{
    if (session == NULL) { return ESP_ERR_INVALID_ARG; }

    memset(session, 0, sizeof(megolm_outbound_session_t));

    /* Initialize ratchet with 128 bytes of random data */
    crypto_random_bytes((uint8_t *)session->ratchet.data, 128);
    session->ratchet.counter = 0;

    /* Generate Ed25519 signing keypair (SRAM-safe wrapper) */
    esp_err_t err = crypto_ed25519_keypair(session->signing_public,
                                            session->signing_private);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Megolm Ed25519 keypair generation failed");
        return err;
    }

    /* Session ID = base64(signing_public) */
    crypto_base64_encode(session->signing_public, 32,
                         session->session_id_b64, sizeof(session->session_id_b64));

    session->initialized = true;
    ESP_LOGI(TAG, "Outbound Megolm session created, id=%s", session->session_id_b64);
    return ESP_OK;
}

esp_err_t megolm_outbound_encrypt(megolm_outbound_session_t *session,
                                   const uint8_t *plaintext, size_t plaintext_len,
                                   uint8_t *out, size_t out_size, size_t *out_len)
{
    if (session == NULL || !session->initialized || plaintext == NULL || out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Derive keys from current ratchet state */
    uint8_t aes_key[32], hmac_key[32], iv[16];
    esp_err_t err = megolm_derive_keys(&session->ratchet, aes_key, hmac_key, iv);
    if (err != ESP_OK) { return err; }

    /* AES-CBC output: plaintext + up to 16 bytes PKCS#7 padding */
    size_t ct_buf_size = plaintext_len + 32;
    uint8_t *ciphertext = malloc(ct_buf_size);
    if (ciphertext == NULL) {
        crypto_wipe(aes_key, sizeof(aes_key));
        crypto_wipe(hmac_key, sizeof(hmac_key));
        return ESP_ERR_NO_MEM;
    }

    size_t ct_len = 0;
    err = crypto_aes256_cbc_encrypt(aes_key, iv, plaintext, plaintext_len,
                                     ciphertext, ct_buf_size, &ct_len);
    crypto_wipe(aes_key, sizeof(aes_key));
    crypto_wipe(iv, sizeof(iv));
    if (err != ESP_OK) {
        crypto_wipe(hmac_key, sizeof(hmac_key));
        free(ciphertext);
        return err;
    }

    /* Build protobuf payload on heap:
     * version(1) + tag+varint+varint(~7) + tag+varint+ciphertext(~5+ct_len) */
    size_t payload_buf_size = ct_len + 64;
    uint8_t *payload_buf = malloc(payload_buf_size);
    if (payload_buf == NULL) {
        crypto_wipe(hmac_key, sizeof(hmac_key));
        free(ciphertext);
        return ESP_ERR_NO_MEM;
    }

    megolm_payload_t payload = {
        .message_index = session->ratchet.counter,
        .ciphertext = ciphertext,
        .ciphertext_len = ct_len,
    };

    size_t payload_len = megolm_payload_encode(&payload, payload_buf, payload_buf_size);
    free(ciphertext);
    if (payload_len == 0) {
        crypto_wipe(hmac_key, sizeof(hmac_key));
        free(payload_buf);
        return ESP_FAIL;
    }

    /* Total output: payload + 8-byte HMAC + 64-byte Ed25519 signature */
    size_t total = payload_len + 8 + 64;
    if (total > out_size) {
        crypto_wipe(hmac_key, sizeof(hmac_key));
        free(payload_buf);
        return ESP_FAIL;
    }

    /* Copy payload to output */
    memcpy(out, payload_buf, payload_len);
    free(payload_buf);

    /* Append 8-byte truncated HMAC over payload */
    uint8_t full_mac[32];
    crypto_hmac_sha256(hmac_key, 32, out, payload_len, full_mac);
    memcpy(out + payload_len, full_mac, 8);
    crypto_wipe(hmac_key, sizeof(hmac_key));
    crypto_wipe(full_mac, sizeof(full_mac));

    /* Append 64-byte Ed25519 signature over (payload + MAC) */
    uint8_t sig[64];
    err = crypto_ed25519_sign(session->signing_private,
                               out, payload_len + 8, sig);
    if (err != ESP_OK) { return err; }
    memcpy(out + payload_len + 8, sig, 64);

    *out_len = total;

    /* Advance ratchet for next message */
    megolm_ratchet_advance(&session->ratchet);

    return ESP_OK;
}

esp_err_t megolm_outbound_get_session_key(const megolm_outbound_session_t *session,
                                           uint8_t *out, size_t out_size,
                                           size_t *out_len)
{
    if (session == NULL || !session->initialized || out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (out_size < MEGOLM_SESSION_KEY_SIZE) {
        return ESP_FAIL;
    }

    esp_err_t err;
    size_t pos = 0;

    /* Version byte */
    out[pos++] = 0x02;

    /* Message index (4 bytes big-endian) */
    uint32_t idx = session->ratchet.counter;
    out[pos++] = (uint8_t)((idx >> 24) & 0xFF);
    out[pos++] = (uint8_t)((idx >> 16) & 0xFF);
    out[pos++] = (uint8_t)((idx >> 8) & 0xFF);
    out[pos++] = (uint8_t)(idx & 0xFF);

    /* Ratchet data: R0, R1, R2, R3 */
    for (int i = 0; i < MEGOLM_RATCHET_PARTS; i++) {
        memcpy(out + pos, session->ratchet.data[i], 32);
        pos += 32;
    }

    /* Ed25519 public key */
    memcpy(out + pos, session->signing_public, 32);
    pos += 32;

    /* Ed25519 signature over the preceding 165 bytes */
    uint8_t sig[64];
    err = crypto_ed25519_sign(session->signing_private, out, pos, sig);
    if (err != ESP_OK) { return err; }
    memcpy(out + pos, sig, 64);
    pos += 64;

    *out_len = pos; /* Should be 229 */
    return ESP_OK;
}

esp_err_t megolm_inbound_create(megolm_inbound_session_t *session,
                                 const uint8_t *session_key, size_t session_key_len,
                                 const char *sender_key_b64)
{
    if (session == NULL || session_key == NULL || session_key_len < MEGOLM_SESSION_EXPORT_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(session, 0, sizeof(megolm_inbound_session_t));

    size_t pos = 0;

    /* Version byte */
    if (session_key[pos++] != 0x02) {
        ESP_LOGE(TAG, "Invalid session key version");
        return ESP_FAIL;
    }

    /* Message index (4 bytes big-endian) */
    session->ratchet.counter =
        ((uint32_t)session_key[pos] << 24) |
        ((uint32_t)session_key[pos + 1] << 16) |
        ((uint32_t)session_key[pos + 2] << 8) |
        (uint32_t)session_key[pos + 3];
    pos += 4;

    /* Ratchet data */
    for (int i = 0; i < MEGOLM_RATCHET_PARTS; i++) {
        memcpy(session->ratchet.data[i], session_key + pos, 32);
        pos += 32;
    }

    /* Ed25519 public key */
    memcpy(session->signing_public, session_key + pos, 32);
    pos += 32;

    /* Session ID = base64(signing_public) */
    crypto_base64_encode(session->signing_public, 32,
                         session->session_id_b64, sizeof(session->session_id_b64));

    /* TODO: verify signature if session_key_len >= 229 */

    if (sender_key_b64 != NULL) {
        snprintf(session->sender_key_b64, sizeof(session->sender_key_b64),
                 "%s", sender_key_b64);
    }

    session->initialized = true;
    ESP_LOGI(TAG, "Inbound Megolm session created, id=%s", session->session_id_b64);
    return ESP_OK;
}

esp_err_t megolm_inbound_decrypt(megolm_inbound_session_t *session,
                                  const uint8_t *message, size_t message_len,
                                  uint8_t *plaintext, size_t plaintext_size,
                                  size_t *plaintext_len)
{
    if (session == NULL || !session->initialized || message == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Message = payload + 8-byte HMAC + 64-byte Ed25519 signature */
    if (message_len < 72 + 3) { /* minimum: version + field + HMAC + sig */
        ESP_LOGE(TAG, "Message too short: %d", (int)message_len);
        return ESP_FAIL;
    }

    size_t payload_len = message_len - 8 - 64;

    /* TODO: verify Ed25519 signature */
    /* TODO: verify HMAC */

    /* Decode payload to get message_index and ciphertext */
    megolm_payload_t payload;
    esp_err_t err = megolm_payload_decode(message, payload_len, &payload);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to decode Megolm payload");
        return err;
    }

    /* Advance ratchet to the message index */
    if (payload.message_index < session->ratchet.counter) {
        ESP_LOGE(TAG, "Message index %lu < ratchet counter %lu (replay?)",
                 (unsigned long)payload.message_index,
                 (unsigned long)session->ratchet.counter);
        return ESP_FAIL;
    }

    err = megolm_ratchet_advance_to(&session->ratchet, payload.message_index);
    if (err != ESP_OK) { return err; }

    /* Derive keys */
    uint8_t aes_key[32], hmac_key[32], iv[16];
    err = megolm_derive_keys(&session->ratchet, aes_key, hmac_key, iv);
    if (err != ESP_OK) { return err; }

    /* Decrypt */
    err = crypto_aes256_cbc_decrypt(aes_key, iv,
                                     payload.ciphertext, payload.ciphertext_len,
                                     plaintext, plaintext_size, plaintext_len);
    crypto_wipe(aes_key, sizeof(aes_key));
    crypto_wipe(hmac_key, sizeof(hmac_key));
    crypto_wipe(iv, sizeof(iv));

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Megolm AES decrypt failed");
        return err;
    }

    /* Advance ratchet past this message */
    megolm_ratchet_advance(&session->ratchet);

    return ESP_OK;
}

bool megolm_inbound_matches(const megolm_inbound_session_t *session,
                             const char *session_id_b64)
{
    if (session == NULL || session_id_b64 == NULL || !session->initialized) {
        return false;
    }
    return strcmp(session->session_id_b64, session_id_b64) == 0;
}
