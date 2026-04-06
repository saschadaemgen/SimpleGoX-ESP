#ifndef MATRIX_JSON_H
#define MATRIX_JSON_H

#include <stddef.h>
#include "esp_err.h"
#include "matrix_client.h"

/* Extract a string value from JSON by path (e.g. "$.access_token") */
esp_err_t matrix_json_get_string(const char *json, int json_len,
                                  const char *path,
                                  char *out, size_t out_size);

/* Build login request body. Returns bytes written or -1 on error. */
int matrix_json_build_login(char *buf, size_t buf_size,
                             const char *username,
                             const char *password,
                             const char *device_id);

/* Build m.text message body. Returns bytes written or -1 on error. */
int matrix_json_build_text_message(char *buf, size_t buf_size,
                                    const char *message);

/* Build sync filter JSON. Returns bytes written or -1 on error. */
int matrix_json_build_sync_filter(char *buf, size_t buf_size,
                                   const char *room_id);

/* Parse sync response and extract timeline messages */
esp_err_t matrix_json_parse_sync(const char *json, int json_len,
                                  matrix_sync_response_t *response);

#endif /* MATRIX_JSON_H */
