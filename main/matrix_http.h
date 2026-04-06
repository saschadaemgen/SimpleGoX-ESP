#ifndef MATRIX_HTTP_H
#define MATRIX_HTTP_H

#include <stddef.h>
#include "esp_err.h"

esp_err_t matrix_http_get(const char *url,
                           const char *access_token,
                           char *response_buf,
                           size_t response_buf_size,
                           int *response_len);

esp_err_t matrix_http_post(const char *url,
                            const char *access_token,
                            const char *json_body,
                            char *response_buf,
                            size_t response_buf_size,
                            int *response_len);

esp_err_t matrix_http_put(const char *url,
                           const char *access_token,
                           const char *json_body,
                           char *response_buf,
                           size_t response_buf_size,
                           int *response_len);

#endif /* MATRIX_HTTP_H */
