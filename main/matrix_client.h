#ifndef MATRIX_CLIENT_H
#define MATRIX_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define MATRIX_ACCESS_TOKEN_SIZE  256
#define MATRIX_DEVICE_ID_SIZE      64
#define MATRIX_USER_ID_SIZE       128
#define MATRIX_ROOM_ID_SIZE       128
#define MATRIX_SYNC_TOKEN_SIZE    256
#define MATRIX_HOMESERVER_SIZE    256
#define MATRIX_URL_SIZE          1024
#define MATRIX_RESPONSE_BUF_SIZE (1024 * 32)

#define MATRIX_MAX_MESSAGES        10

typedef struct matrix_message {
    char sender[MATRIX_USER_ID_SIZE];
    char body[256];
    char event_id[128];
} matrix_message_t;

typedef struct matrix_sync_response {
    char next_batch[MATRIX_SYNC_TOKEN_SIZE];
    matrix_message_t messages[MATRIX_MAX_MESSAGES];
    int message_count;
} matrix_sync_response_t;

typedef struct matrix_client {
    char homeserver_url[MATRIX_HOMESERVER_SIZE];
    char access_token[MATRIX_ACCESS_TOKEN_SIZE];
    char device_id[MATRIX_DEVICE_ID_SIZE];
    char user_id[MATRIX_USER_ID_SIZE];
    char sync_next_batch[MATRIX_SYNC_TOKEN_SIZE];
    char room_id[MATRIX_ROOM_ID_SIZE];
    uint32_t txn_counter;
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

/* Sync */
esp_err_t matrix_client_sync(matrix_client_t *client,
                              matrix_sync_response_t *response,
                              int timeout_ms);

/* Sync token persistence */
esp_err_t matrix_client_save_sync_token(matrix_client_t *client);
esp_err_t matrix_client_load_sync_token(matrix_client_t *client);

#endif /* MATRIX_CLIENT_H */
