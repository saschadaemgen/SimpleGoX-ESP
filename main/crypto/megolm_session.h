#ifndef MEGOLM_SESSION_H
#define MEGOLM_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define MEGOLM_RATCHET_PARTS 4
#define MEGOLM_SESSION_KEY_SIZE 229
#define MEGOLM_SESSION_EXPORT_SIZE 165

typedef struct {
    uint8_t data[MEGOLM_RATCHET_PARTS][32]; /* R0, R1, R2, R3 */
    uint32_t counter;
} megolm_ratchet_t;

typedef struct {
    megolm_ratchet_t ratchet;
    uint8_t signing_private[64]; /* Ed25519 */
    uint8_t signing_public[32];
    char session_id_b64[48];    /* base64 of signing_public */
    bool initialized;
} megolm_outbound_session_t;

typedef struct {
    megolm_ratchet_t ratchet;
    uint8_t signing_public[32];
    char session_id_b64[48];
    char sender_key_b64[48];
    bool initialized;
} megolm_inbound_session_t;

/* Advance the ratchet by one step */
esp_err_t megolm_ratchet_advance(megolm_ratchet_t *ratchet);

/* Advance the ratchet to a specific counter value */
esp_err_t megolm_ratchet_advance_to(megolm_ratchet_t *ratchet, uint32_t target);

/* Create a new outbound Megolm session for a room */
esp_err_t megolm_outbound_create(megolm_outbound_session_t *session);

/* Encrypt plaintext. Output includes payload + 8-byte HMAC + 64-byte Ed25519 sig. */
esp_err_t megolm_outbound_encrypt(megolm_outbound_session_t *session,
                                   const uint8_t *plaintext, size_t plaintext_len,
                                   uint8_t *out, size_t out_size, size_t *out_len);

/* Export session key for sharing (229 bytes). */
esp_err_t megolm_outbound_get_session_key(const megolm_outbound_session_t *session,
                                           uint8_t *out, size_t out_size,
                                           size_t *out_len);

/* Create inbound session from received session key (229 bytes). */
esp_err_t megolm_inbound_create(megolm_inbound_session_t *session,
                                 const uint8_t *session_key, size_t session_key_len,
                                 const char *sender_key_b64);

/* Decrypt a Megolm message. Input is the full message (payload + MAC + sig). */
esp_err_t megolm_inbound_decrypt(megolm_inbound_session_t *session,
                                  const uint8_t *message, size_t message_len,
                                  uint8_t *plaintext, size_t plaintext_size,
                                  size_t *plaintext_len);

/* Check if this session matches a given session ID */
bool megolm_inbound_matches(const megolm_inbound_session_t *session,
                             const char *session_id_b64);

#endif /* MEGOLM_SESSION_H */
