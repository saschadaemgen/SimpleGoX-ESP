#ifndef MATRIX_CLIENT_H
#define MATRIX_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "matrix_http.h"

#define MATRIX_ACCESS_TOKEN_SIZE  256
#define MATRIX_DEVICE_ID_SIZE      64
#define MATRIX_USER_ID_SIZE       128
#define MATRIX_ROOM_ID_SIZE       128
#define MATRIX_SYNC_TOKEN_SIZE    256
#define MATRIX_HOMESERVER_SIZE    256
#define MATRIX_URL_SIZE          1024
#define MATRIX_RESPONSE_BUF_SIZE (1024 * 32)

#define MATRIX_MAX_MESSAGES         10
#define MATRIX_MAX_IOT_COMMANDS      5
#define MATRIX_MAX_ENCRYPTED_EVENTS  3
#define MATRIX_MAX_TO_DEVICE_EVENTS  3

typedef struct matrix_message {
    char sender[MATRIX_USER_ID_SIZE];
    char body[256];
    char event_id[128];
} matrix_message_t;

typedef struct matrix_iot_command {
    char sender[MATRIX_USER_ID_SIZE];
    char device_id[64];
    char action[16];
    double value;
    bool has_value;
    bool bool_value;
} matrix_iot_command_t;

typedef struct matrix_encrypted_event {
    char sender[MATRIX_USER_ID_SIZE];
    char algorithm[64];
    char sender_key[48];
    char session_id[64];
    char ciphertext[4096];
    char event_id[128];
} matrix_encrypted_event_t;

typedef struct matrix_to_device_event {
    char type[64];
    char sender[MATRIX_USER_ID_SIZE];
    char *content_json;      /* heap-allocated, caller must free */
    int content_json_len;
} matrix_to_device_event_t;

typedef struct matrix_sync_response {
    char next_batch[MATRIX_SYNC_TOKEN_SIZE];
    matrix_message_t messages[MATRIX_MAX_MESSAGES];
    int message_count;
    matrix_iot_command_t iot_commands[MATRIX_MAX_IOT_COMMANDS];
    int iot_command_count;
    matrix_encrypted_event_t encrypted_events[MATRIX_MAX_ENCRYPTED_EVENTS];
    int encrypted_event_count;
    matrix_to_device_event_t to_device_events[MATRIX_MAX_TO_DEVICE_EVENTS];
    int to_device_event_count;
} matrix_sync_response_t;

typedef struct matrix_client {
    char homeserver_url[MATRIX_HOMESERVER_SIZE];
    char access_token[MATRIX_ACCESS_TOKEN_SIZE];
    char device_id[MATRIX_DEVICE_ID_SIZE];
    char user_id[MATRIX_USER_ID_SIZE];
    char sync_next_batch[MATRIX_SYNC_TOKEN_SIZE];
    char room_id[MATRIX_ROOM_ID_SIZE];
    uint32_t txn_counter;
    matrix_http_t http;
    void *e2ee;  /* pointer to matrix_e2ee_t, NULL if E2EE not enabled */
} matrix_client_t;

/* Client lifecycle */
esp_err_t matrix_client_init(matrix_client_t *client, const char *homeserver);
void matrix_client_free(matrix_client_t *client);

/* Authentication */
esp_err_t matrix_client_login(matrix_client_t *client,
                               const char *username,
                               const char *password,
                               const char *device_id);
esp_err_t matrix_client_logout(matrix_client_t *client);

/* Rooms */
esp_err_t matrix_client_join_room(matrix_client_t *client,
                                   const char *room_id_or_alias);
esp_err_t matrix_client_resolve_alias(matrix_client_t *client,
                                       const char *alias,
                                       char *room_id_out,
                                       size_t room_id_out_size);

/* Messaging */
esp_err_t matrix_client_send_text(matrix_client_t *client,
                                   const char *room_id,
                                   const char *message);

/* IoT - Custom Events */

/** Register this device in a room via state event dev.simplego.iot.device. */
esp_err_t matrix_client_register_device(matrix_client_t *client,
                                         const char *room_id,
                                         const char *device_id,
                                         const char *device_type,
                                         const char *label,
                                         const char *icon,
                                         bool online);

/** Send a status update via timeline event dev.simplego.iot.status. */
esp_err_t matrix_client_send_status(matrix_client_t *client,
                                     const char *room_id,
                                     const char *device_id,
                                     bool state,
                                     float value,
                                     const char *unit);

/* Sync */
esp_err_t matrix_client_sync(matrix_client_t *client,
                              matrix_sync_response_t *response,
                              int timeout_ms);

/* Sync token persistence */
esp_err_t matrix_client_save_sync_token(matrix_client_t *client);
esp_err_t matrix_client_load_sync_token(matrix_client_t *client);

#endif /* MATRIX_CLIENT_H */
