#ifndef MATRIX_HTTP_H
#define MATRIX_HTTP_H

#include <stddef.h>
#include "esp_err.h"
#include "esp_http_client.h"

typedef struct {
    esp_http_client_handle_t client;
    char *response_buf;
    int response_buf_size;
    int response_len;
} matrix_http_t;

/* Create the HTTP client once. Call before any requests. */
esp_err_t matrix_http_init(matrix_http_t *http, const char *base_url);

/* Destroy the HTTP client. Call on shutdown. */
void matrix_http_cleanup(matrix_http_t *http);

esp_err_t matrix_http_get(matrix_http_t *http,
                           const char *url,
                           const char *access_token,
                           char *response_buf,
                           size_t response_buf_size,
                           int *response_len);

esp_err_t matrix_http_post(matrix_http_t *http,
                            const char *url,
                            const char *access_token,
                            const char *json_body,
                            char *response_buf,
                            size_t response_buf_size,
                            int *response_len);

esp_err_t matrix_http_put(matrix_http_t *http,
                           const char *url,
                           const char *access_token,
                           const char *json_body,
                           char *response_buf,
                           size_t response_buf_size,
                           int *response_len);

#endif /* MATRIX_HTTP_H */
