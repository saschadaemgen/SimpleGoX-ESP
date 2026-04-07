#include "olm_session.h"
#include "olm_message.h"
#include "crypto_utils.h"

#include <string.h>
#include "esp_log.h"

static const char *TAG = "olm_session";

/*
 * Derive root key + chain key from DH shared secret.
 * For initial setup: salt=NULL, info="OLM_ROOT"
 * For ratchet step: salt=current_root_key, info="OLM_RATCHET"
 */
static esp_err_t derive_root_chain(const uint8_t *shared_secret, size_t shared_len,
                                    const uint8_t *salt, size_t salt_len,
                                    const char *info,
                                    uint8_t root_out[32], uint8_t chain_out[32])
{
    uint8_t derived[64];
    esp_err_t err = crypto_hkdf_sha256(shared_secret, shared_len,
                                        salt, salt_len,
                                        (const uint8_t *)info, strlen(info),
                                        derived, 64);
    if (err != ESP_OK) { return err; }
    memcpy(root_out, derived, 32);
    memcpy(chain_out, derived + 32, 32);
    crypto_wipe(derived, sizeof(derived));
    return ESP_OK;
}

/* Chain ratchet: advance chain key, produce message key */
static esp_err_t chain_ratchet(uint8_t chain_key[32], uint8_t msg_key_out[32])
{
    uint8_t one = 0x01;
    uint8_t two = 0x02;

    /* message_key = HMAC(chain_key, 0x01) */
    esp_err_t err = crypto_hmac_sha256(chain_key, 32, &one, 1, msg_key_out);
    if (err != ESP_OK) { return err; }

    /* next_chain_key = HMAC(chain_key, 0x02) */
    uint8_t next[32];
    err = crypto_hmac_sha256(chain_key, 32, &two, 1, next);
    if (err != ESP_OK) { return err; }

    memcpy(chain_key, next, 32);
    crypto_wipe(next, sizeof(next));
    return ESP_OK;
}

/* Expand message key to AES key (32) + HMAC key (32) + IV (16) = 80 bytes */
static esp_err_t expand_message_key(const uint8_t msg_key[32],
                                     uint8_t aes_key[32],
                                     uint8_t hmac_key[32],
                                     uint8_t iv[16])
{
    uint8_t expanded[80];
    esp_err_t err = crypto_hkdf_sha256(msg_key, 32,
                                        NULL, 0,
                                        (const uint8_t *)"OLM_KEYS", 8,
                                        expanded, 80);
    if (err != ESP_OK) { return err; }

    memcpy(aes_key, expanded, 32);
    memcpy(hmac_key, expanded + 32, 32);
    memcpy(iv, expanded + 64, 16);
    crypto_wipe(expanded, sizeof(expanded));
    return ESP_OK;
}

esp_err_t olm_session_create_outbound(olm_session_t *session,
                                       const uint8_t our_identity_curve_private[32],
                                       const uint8_t their_identity_curve_public[32],
                                       const uint8_t their_one_time_key_public[32],
                                       uint8_t ephemeral_public_out[32])
{
    if (session == NULL) { return ESP_ERR_INVALID_ARG; }

    memset(session, 0, sizeof(olm_session_t));

    /* Generate ephemeral keypair */
    uint8_t ephemeral_private[32];
    crypto_random_bytes(ephemeral_private, 32);
    if (crypto_curve25519_base(ephemeral_public_out, ephemeral_private) != ESP_OK) {
        ESP_LOGE(TAG, "Ephemeral keypair generation failed");
        return ESP_FAIL;
    }

    /* 3DH per Olm spec (Alice/outbound perspective):
     * S = ECDH(I_A, E_B) || ECDH(E_A, I_B) || ECDH(E_A, E_B)
     * I_A = our identity, I_B = their identity
     * E_A = our ephemeral, E_B = their one-time key */
    uint8_t dh1[32], dh2[32], dh3[32];
    if (crypto_curve25519_scalarmult(dh1, our_identity_curve_private,
                                      their_one_time_key_public) != ESP_OK) {
        ESP_LOGE(TAG, "DH1 (I_A, E_B) failed");
        return ESP_FAIL;
    }
    if (crypto_curve25519_scalarmult(dh2, ephemeral_private,
                                      their_identity_curve_public) != ESP_OK) {
        ESP_LOGE(TAG, "DH2 (E_A, I_B) failed");
        return ESP_FAIL;
    }
    if (crypto_curve25519_scalarmult(dh3, ephemeral_private,
                                      their_one_time_key_public) != ESP_OK) {
        ESP_LOGE(TAG, "DH3 (E_A, E_B) failed");
        return ESP_FAIL;
    }

    /* Concatenate: S = DH1 || DH2 || DH3 */
    uint8_t S[96];
    memcpy(S, dh1, 32);
    memcpy(S + 32, dh2, 32);
    memcpy(S + 64, dh3, 32);
    crypto_wipe(dh1, 32);
    crypto_wipe(dh2, 32);
    crypto_wipe(dh3, 32);

    /* Derive initial root key + sending chain key */
    esp_err_t err = derive_root_chain(S, 96, NULL, 0, "OLM_ROOT",
                                       session->root_key,
                                       session->sending_chain.key);
    crypto_wipe(S, sizeof(S));
    if (err != ESP_OK) { return err; }

    session->sending_chain.index = 0;

    /* Set up our ratchet key (initially same as ephemeral for outbound) */
    memcpy(session->our_ratchet_private, ephemeral_private, 32);
    memcpy(session->our_ratchet_public, ephemeral_public_out, 32);
    crypto_wipe(ephemeral_private, 32);

    memcpy(session->their_identity_key, their_identity_curve_public, 32);

    session->initialized = true;
    session->received_message = false;
    session->is_outbound = true;

    ESP_LOGI(TAG, "Outbound Olm session created");
    return ESP_OK;
}

esp_err_t olm_session_create_inbound(olm_session_t *session,
                                      const uint8_t our_identity_curve_private[32],
                                      const uint8_t our_one_time_key_private[32],
                                      const uint8_t their_identity_curve_public[32],
                                      const uint8_t their_ephemeral_public[32])
{
    if (session == NULL) { return ESP_ERR_INVALID_ARG; }

    memset(session, 0, sizeof(olm_session_t));

    /* 3DH per Olm spec (Bob/inbound perspective):
     * S = ECDH(E_B, I_A) || ECDH(I_B, E_A) || ECDH(E_B, E_A)
     * E_B = our one-time key, I_B = our identity
     * I_A = their identity, E_A = their ephemeral (base_key) */
    ESP_LOGI(TAG, "Inbound 3DH inputs:");
    ESP_LOGI(TAG, "  our_otk_priv[0..3]=%02x%02x%02x%02x",
             our_one_time_key_private[0], our_one_time_key_private[1],
             our_one_time_key_private[2], our_one_time_key_private[3]);
    ESP_LOGI(TAG, "  our_id_priv[0..3]=%02x%02x%02x%02x",
             our_identity_curve_private[0], our_identity_curve_private[1],
             our_identity_curve_private[2], our_identity_curve_private[3]);
    ESP_LOGI(TAG, "  their_id_pub[0..3]=%02x%02x%02x%02x",
             their_identity_curve_public[0], their_identity_curve_public[1],
             their_identity_curve_public[2], their_identity_curve_public[3]);
    ESP_LOGI(TAG, "  their_eph_pub[0..3]=%02x%02x%02x%02x",
             their_ephemeral_public[0], their_ephemeral_public[1],
             their_ephemeral_public[2], their_ephemeral_public[3]);

    uint8_t dh1[32], dh2[32], dh3[32];
    if (crypto_curve25519_scalarmult(dh1, our_one_time_key_private,
                                      their_identity_curve_public) != ESP_OK) {
        ESP_LOGE(TAG, "Inbound DH1 (E_B, I_A) failed"); return ESP_FAIL;
    }
    if (crypto_curve25519_scalarmult(dh2, our_identity_curve_private,
                                      their_ephemeral_public) != ESP_OK) {
        ESP_LOGE(TAG, "Inbound DH2 (I_B, E_A) failed"); return ESP_FAIL;
    }
    if (crypto_curve25519_scalarmult(dh3, our_one_time_key_private,
                                      their_ephemeral_public) != ESP_OK) {
        ESP_LOGE(TAG, "Inbound DH3 (E_B, E_A) failed"); return ESP_FAIL;
    }

    uint8_t S[96];
    memcpy(S, dh1, 32);
    memcpy(S + 32, dh2, 32);
    memcpy(S + 64, dh3, 32);

    ESP_LOGI(TAG, "Inbound 3DH: S[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x",
             S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7]);

    crypto_wipe(dh1, 32); crypto_wipe(dh2, 32); crypto_wipe(dh3, 32);

    /* For inbound: the initiator's first chain becomes our receiving chain */
    esp_err_t err = derive_root_chain(S, 96, NULL, 0, "OLM_ROOT",
                                       session->root_key,
                                       session->receiving_chain.key);
    crypto_wipe(S, sizeof(S));
    if (err != ESP_OK) { return err; }

    ESP_LOGI(TAG, "Inbound root_key[0..3]=%02x%02x%02x%02x, recv_chain[0..3]=%02x%02x%02x%02x",
             session->root_key[0], session->root_key[1],
             session->root_key[2], session->root_key[3],
             session->receiving_chain.key[0], session->receiving_chain.key[1],
             session->receiving_chain.key[2], session->receiving_chain.key[3]);

    session->receiving_chain.index = 0;

    /* Their ratchet key = their ephemeral key (base_key from pre-key message). */
    memcpy(session->their_ratchet_key, their_ephemeral_public, 32);
    memcpy(session->their_identity_key, their_identity_curve_public, 32);

    /* Generate our ratchet keypair for when we send.
     * We need this even before sending because the decrypt function uses
     * our_ratchet_private for DH ratchet steps. */
    crypto_random_bytes(session->our_ratchet_private, 32);
    crypto_curve25519_base(session->our_ratchet_public,
                            session->our_ratchet_private);

    /* Set up the sending chain via a root ratchet step.
     * IMPORTANT: We must save root_key BEFORE this step because the
     * receiving_chain was derived from the original root_key via 3DH.
     * The root ratchet overwrites root_key but receiving_chain.key stays intact. */
    uint8_t shared[32];
    crypto_curve25519_scalarmult(shared, session->our_ratchet_private,
                                 session->their_ratchet_key);
    err = derive_root_chain(shared, 32,
                            session->root_key, 32, "OLM_RATCHET",
                            session->root_key,
                            session->sending_chain.key);
    crypto_wipe(shared, 32);
    if (err != ESP_OK) { return err; }

    session->sending_chain.index = 0;
    session->initialized = true;
    session->received_message = false; /* First message not yet received */
    session->is_outbound = false;

    ESP_LOGI(TAG, "Inbound Olm session created");
    ESP_LOGI(TAG, "  recv_chain[0..3]=%02x%02x%02x%02x (from 3DH, for their first msg)",
             session->receiving_chain.key[0], session->receiving_chain.key[1],
             session->receiving_chain.key[2], session->receiving_chain.key[3]);
    ESP_LOGI(TAG, "  their_ratchet(base_key)[0..3]=%02x%02x%02x%02x",
             session->their_ratchet_key[0], session->their_ratchet_key[1],
             session->their_ratchet_key[2], session->their_ratchet_key[3]);
    return ESP_OK;
}

esp_err_t olm_session_encrypt(olm_session_t *session,
                               const uint8_t *plaintext, size_t plaintext_len,
                               uint8_t *out, size_t out_size, size_t *out_len,
                               int *msg_type_out)
{
    if (session == NULL || !session->initialized || plaintext == NULL || out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Advance sending chain */
    uint8_t msg_key[32];
    esp_err_t err = chain_ratchet(session->sending_chain.key, msg_key);
    if (err != ESP_OK) { return err; }

    /* Expand to AES key + HMAC key + IV */
    uint8_t aes_key[32], hmac_key[32], iv[16];
    err = expand_message_key(msg_key, aes_key, hmac_key, iv);
    crypto_wipe(msg_key, sizeof(msg_key));
    if (err != ESP_OK) { return err; }

    /* Encrypt with AES-256-CBC (heap buffer: plaintext + 32 for padding) */
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

    /* Build inner message with HMAC (heap buffer) */
    olm_inner_message_t inner = {
        .chain_index = session->sending_chain.index,
        .ciphertext = ciphertext,
        .ciphertext_len = ct_len,
    };
    memcpy(inner.ratchet_key, session->our_ratchet_public, 32);

    size_t inner_buf_size = ct_len + 128;
    uint8_t *inner_buf = malloc(inner_buf_size);
    if (inner_buf == NULL) {
        crypto_wipe(hmac_key, sizeof(hmac_key));
        free(ciphertext);
        return ESP_ERR_NO_MEM;
    }

    size_t inner_len = olm_inner_message_encode(&inner, hmac_key,
                                                 inner_buf, inner_buf_size);
    free(ciphertext);
    crypto_wipe(hmac_key, sizeof(hmac_key));
    if (inner_len == 0) { free(inner_buf); return ESP_FAIL; }

    session->sending_chain.index++;

    /* First message -> pre-key message (type 0), otherwise normal (type 1) */
    *msg_type_out = session->received_message ? OLM_MSG_TYPE_MESSAGE : OLM_MSG_TYPE_PRE_KEY;

    if (inner_len > out_size) {
        free(inner_buf);
        return ESP_FAIL;
    }
    memcpy(out, inner_buf, inner_len);
    *out_len = inner_len;
    free(inner_buf);

    return ESP_OK;
}

esp_err_t olm_session_decrypt(olm_session_t *session, int msg_type,
                               const uint8_t *message, size_t message_len,
                               uint8_t *plaintext, size_t plaintext_size,
                               size_t *plaintext_len)
{
    if (session == NULL || !session->initialized || message == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "olm_decrypt: msg_type=%d, msg_len=%d", msg_type, (int)message_len);

    const uint8_t *inner_msg = message;
    size_t inner_len = message_len;

    /* For pre-key messages, extract the inner message */
    if (msg_type == OLM_MSG_TYPE_PRE_KEY) {
        olm_pre_key_message_t pre_key;
        esp_err_t err = olm_pre_key_message_decode(message, message_len, &pre_key);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "olm_decrypt: pre-key decode failed");
            return err;
        }
        inner_msg = pre_key.inner_message;
        inner_len = pre_key.inner_message_len;
        ESP_LOGI(TAG, "olm_decrypt: inner message extracted, %d bytes", (int)inner_len);
    }

    /* Decode inner message */
    olm_inner_message_t inner;
    esp_err_t err = olm_inner_message_decode(inner_msg, inner_len, &inner);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "olm_decrypt: inner message decode failed, len=%d, first bytes: %02x %02x %02x",
                 (int)inner_len,
                 inner_len > 0 ? inner_msg[0] : 0,
                 inner_len > 1 ? inner_msg[1] : 0,
                 inner_len > 2 ? inner_msg[2] : 0);
        return err;
    }

    ESP_LOGI(TAG, "olm_decrypt: chain_index=%lu, ciphertext=%d bytes, ratchet_key[0..3]=%02x%02x%02x%02x",
             (unsigned long)inner.chain_index, (int)inner.ciphertext_len,
             inner.ratchet_key[0], inner.ratchet_key[1],
             inner.ratchet_key[2], inner.ratchet_key[3]);

    /* Check if we need to ratchet (new ratchet key from sender).
     * For the FIRST received message after session creation, we use the
     * receiving chain from the 3DH directly. The ratchet_key in the message
     * is the sender's current key for FUTURE DH ratchet steps, not for this
     * message. We store it for later use. */
    bool ratchet_changed = memcmp(inner.ratchet_key, session->their_ratchet_key, 32) != 0;
    bool first_inbound_msg = !session->received_message && !session->is_outbound;
    ESP_LOGI(TAG, "olm_decrypt: ratchet_changed=%d, first_inbound=%d, outbound=%d, recv_idx=%lu",
             ratchet_changed, first_inbound_msg, session->is_outbound,
             (unsigned long)session->receiving_chain.index);

    if (first_inbound_msg) {
        /* First message on an INBOUND session: use the 3DH-derived
         * receiving chain directly (sender used the 3DH sending chain).
         * Save the sender's ratchet key for future DH ratchet steps. */
        memcpy(session->their_ratchet_key, inner.ratchet_key, 32);
        session->received_message = true;
        ESP_LOGI(TAG, "olm_decrypt: first inbound msg, using 3DH recv_chain");
    } else if (ratchet_changed) {
        /* New ratchet key: advance root ratchet */
        memcpy(session->their_ratchet_key, inner.ratchet_key, 32);

        /* DH with their new ratchet key and our current ratchet private */
        uint8_t shared[32];
        if (crypto_curve25519_scalarmult(shared, session->our_ratchet_private,
                                          session->their_ratchet_key) != ESP_OK) {
            ESP_LOGE(TAG, "olm_decrypt: ratchet DH1 failed");
            return ESP_FAIL;
        }

        err = derive_root_chain(shared, 32,
                                session->root_key, 32, "OLM_RATCHET",
                                session->root_key,
                                session->receiving_chain.key);
        crypto_wipe(shared, 32);
        if (err != ESP_OK) { return err; }
        session->receiving_chain.index = 0;

        /* Generate new ratchet key for our next send */
        crypto_random_bytes(session->our_ratchet_private, 32);
        crypto_curve25519_base(session->our_ratchet_public,
                                session->our_ratchet_private);

        /* Advance root ratchet for our sending chain */
        if (crypto_curve25519_scalarmult(shared, session->our_ratchet_private,
                                          session->their_ratchet_key) != ESP_OK) {
            ESP_LOGE(TAG, "olm_decrypt: ratchet DH2 failed");
            return ESP_FAIL;
        }
        err = derive_root_chain(shared, 32,
                                session->root_key, 32, "OLM_RATCHET",
                                session->root_key,
                                session->sending_chain.key);
        crypto_wipe(shared, 32);
        if (err != ESP_OK) { return err; }
        session->sending_chain.index = 0;
    }

    /* Advance receiving chain to the message's chain index */
    /* TODO: handle out-of-order messages by caching skipped keys */
    while (session->receiving_chain.index < inner.chain_index) {
        uint8_t skip_key[32];
        err = chain_ratchet(session->receiving_chain.key, skip_key);
        if (err != ESP_OK) { return err; }
        crypto_wipe(skip_key, 32);
        session->receiving_chain.index++;
    }

    /* Get message key */
    uint8_t msg_key[32];
    err = chain_ratchet(session->receiving_chain.key, msg_key);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "olm_decrypt: chain_ratchet failed");
        return err;
    }
    session->receiving_chain.index++;

    ESP_LOGI(TAG, "olm_decrypt: msg_key[0..3]=%02x%02x%02x%02x, chain_key[0..3]=%02x%02x%02x%02x",
             msg_key[0], msg_key[1], msg_key[2], msg_key[3],
             session->receiving_chain.key[0], session->receiving_chain.key[1],
             session->receiving_chain.key[2], session->receiving_chain.key[3]);

    /* Expand message key */
    uint8_t aes_key[32], hmac_key[32], iv[16];
    err = expand_message_key(msg_key, aes_key, hmac_key, iv);
    crypto_wipe(msg_key, sizeof(msg_key));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "olm_decrypt: expand_message_key failed");
        return err;
    }

    ESP_LOGI(TAG, "olm_decrypt: aes_key[0..3]=%02x%02x%02x%02x, iv[0..3]=%02x%02x%02x%02x",
             aes_key[0], aes_key[1], aes_key[2], aes_key[3],
             iv[0], iv[1], iv[2], iv[3]);
    ESP_LOGI(TAG, "olm_decrypt: ciphertext %d bytes (mod16=%d), ct[0..3]=%02x%02x%02x%02x",
             (int)inner.ciphertext_len,
             (int)(inner.ciphertext_len % 16),
             inner.ciphertext_len > 0 ? inner.ciphertext[0] : 0,
             inner.ciphertext_len > 1 ? inner.ciphertext[1] : 0,
             inner.ciphertext_len > 2 ? inner.ciphertext[2] : 0,
             inner.ciphertext_len > 3 ? inner.ciphertext[3] : 0);

    if (inner.ciphertext_len == 0 || inner.ciphertext_len % 16 != 0) {
        ESP_LOGE(TAG, "olm_decrypt: ciphertext length %d not a multiple of 16!",
                 (int)inner.ciphertext_len);
    }

    /* TODO: verify HMAC before decrypting */

    /* Decrypt */
    err = crypto_aes256_cbc_decrypt(aes_key, iv,
                                     inner.ciphertext, inner.ciphertext_len,
                                     plaintext, plaintext_size, plaintext_len);
    crypto_wipe(aes_key, sizeof(aes_key));
    crypto_wipe(hmac_key, sizeof(hmac_key));
    crypto_wipe(iv, sizeof(iv));

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "olm_decrypt: AES-CBC decrypt failed (ct_len=%d, maybe bad padding?)",
                 (int)inner.ciphertext_len);
        return err;
    }

    ESP_LOGI(TAG, "olm_decrypt: SUCCESS, plaintext %d bytes", (int)*plaintext_len);

    session->received_message = true;
    return ESP_OK;
}
