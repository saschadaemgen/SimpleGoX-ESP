#ifndef MATRIX_E2EE_H
#define MATRIX_E2EE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "matrix_client.h"
#include "olm_account.h"
#include "olm_session.h"
#include "megolm_session.h"

#define E2EE_MAX_INBOUND_SESSIONS 5
#define E2EE_MAX_OLM_SESSIONS 16
#define E2EE_MAX_ROOM_DEVICES 16

typedef struct {
    char user_id[128];
    char device_id[64];
    char curve25519_b64[48];
    char ed25519_b64[48];
    uint8_t curve25519_key[32];
} e2ee_device_info_t;

typedef struct matrix_e2ee {
    olm_account_t account;

    /* Olm sessions for to-device messaging */
    olm_session_t olm_sessions[E2EE_MAX_OLM_SESSIONS];
    e2ee_device_info_t olm_session_devices[E2EE_MAX_OLM_SESSIONS];
    int olm_session_count;

    /* Megolm sessions */
    megolm_outbound_session_t outbound_megolm;
    bool outbound_megolm_valid;
    bool outbound_megolm_shared;

    megolm_inbound_session_t inbound_megolm[E2EE_MAX_INBOUND_SESSIONS];
    int inbound_megolm_count;

    /* Known devices in the room */
    e2ee_device_info_t room_devices[E2EE_MAX_ROOM_DEVICES];
    int room_device_count;

    bool keys_uploaded;
    bool initialized;
} matrix_e2ee_t;

/* Initialize E2EE: create or load Olm account from NVS */
esp_err_t matrix_e2ee_init(matrix_e2ee_t *e2ee);

/* Save Olm account to NVS */
esp_err_t matrix_e2ee_save_account(matrix_e2ee_t *e2ee);

/* Upload device keys + one-time keys to homeserver */
esp_err_t matrix_e2ee_upload_keys(matrix_e2ee_t *e2ee, matrix_client_t *client);

/* Query device keys for a user */
esp_err_t matrix_e2ee_query_keys(matrix_e2ee_t *e2ee, matrix_client_t *client,
                                  const char *user_id);

/* Ensure outbound Megolm session exists, share with room devices */
esp_err_t matrix_e2ee_ensure_outbound_session(matrix_e2ee_t *e2ee,
                                               matrix_client_t *client,
                                               const char *room_id);

/* Send an encrypted event to a room (generic: any event type + content JSON) */
esp_err_t matrix_e2ee_send_event(matrix_e2ee_t *e2ee, matrix_client_t *client,
                                  const char *room_id,
                                  const char *event_type,
                                  const char *content_json);

/* Send an encrypted text message (convenience wrapper for m.room.message) */
esp_err_t matrix_e2ee_send_text(matrix_e2ee_t *e2ee, matrix_client_t *client,
                                 const char *room_id, const char *message);

/* Decrypt a received m.room.encrypted event (Megolm).
 * event_json: the full encrypted event JSON from sync timeline.
 * plaintext_out: receives the decrypted content JSON.
 * event_type_out: receives the decrypted event type (e.g. "m.room.message"). */
esp_err_t matrix_e2ee_decrypt_room_event(matrix_e2ee_t *e2ee,
                                          const char *event_json, int event_json_len,
                                          char *plaintext_out, size_t plaintext_out_size,
                                          char *event_type_out, size_t event_type_out_size);

/* Handle a received to_device event (Olm-encrypted session key sharing) */
esp_err_t matrix_e2ee_handle_to_device(matrix_e2ee_t *e2ee,
                                        const char *event_json, int event_json_len);

#endif /* MATRIX_E2EE_H */
