#include "matrix_http.h"

#include <string.h>
#include <sys/param.h>
#include "esp_log.h"
#include "esp_tls.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"

static const char *TAG = "matrix_http";

typedef struct {
    char *buf;
    int buf_size;
    int data_len;
} http_response_ctx_t;

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    http_response_ctx_t *ctx = (http_response_ctx_t *)evt->user_data;
    if (ctx == NULL) {
        return ESP_OK;
    }

    switch (evt->event_id) {
    case HTTP_EVENT_ON_DATA:
        if (ctx->buf != NULL) {
            int copy_len = MIN(evt->data_len, ctx->buf_size - ctx->data_len - 1);
            if (copy_len > 0) {
                memcpy(ctx->buf + ctx->data_len, evt->data, copy_len);
                ctx->data_len += copy_len;
                ctx->buf[ctx->data_len] = '\0';
            }
        }
        break;
    case HTTP_EVENT_DISCONNECTED: {
        int mbedtls_err = 0;
        esp_err_t err = esp_tls_get_and_clear_last_error(
            (esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
        if (err != 0) {
            ESP_LOGW(TAG, "TLS error: 0x%x, mbedtls: 0x%x", err, mbedtls_err);
        }
        break;
    }
    default:
        break;
    }
    return ESP_OK;
}

static esp_err_t do_request(esp_http_client_method_t method,
                             const char *url,
                             const char *access_token,
                             const char *json_body,
                             char *response_buf,
                             size_t response_buf_size,
                             int *response_len)
{
    http_response_ctx_t ctx = {
        .buf = response_buf,
        .buf_size = (int)response_buf_size,
        .data_len = 0,
    };

    if (response_buf != NULL && response_buf_size > 0) {
        response_buf[0] = '\0';
    }

    esp_http_client_config_t config = {
        .url = url,
        .event_handler = http_event_handler,
        .user_data = &ctx,
        .disable_auto_redirect = false,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 60000,
        .buffer_size = 4096,
        .buffer_size_tx = 2048,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return ESP_FAIL;
    }

    esp_http_client_set_method(client, method);

    if (access_token != NULL && strlen(access_token) > 0) {
        char auth_header[300];
        snprintf(auth_header, sizeof(auth_header), "Bearer %s", access_token);
        esp_http_client_set_header(client, "Authorization", auth_header);
    }

    if (json_body != NULL) {
        esp_http_client_set_header(client, "Content-Type", "application/json");
        esp_http_client_set_post_field(client, json_body, strlen(json_body));
    }

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }

    int status_code = esp_http_client_get_status_code(client);
    ESP_LOGD(TAG, "%s %d, len=%d",
             method == HTTP_METHOD_GET ? "GET" :
             method == HTTP_METHOD_POST ? "POST" : "PUT",
             status_code, ctx.data_len);

    if (response_len != NULL) {
        *response_len = ctx.data_len;
    }

    esp_http_client_cleanup(client);

    if (status_code >= 400) {
        ESP_LOGE(TAG, "HTTP %d: %.*s", status_code,
                 ctx.data_len > 200 ? 200 : ctx.data_len,
                 response_buf ? response_buf : "");
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t matrix_http_get(const char *url,
                           const char *access_token,
                           char *response_buf,
                           size_t response_buf_size,
                           int *response_len)
{
    return do_request(HTTP_METHOD_GET, url, access_token, NULL,
                      response_buf, response_buf_size, response_len);
}

esp_err_t matrix_http_post(const char *url,
                            const char *access_token,
                            const char *json_body,
                            char *response_buf,
                            size_t response_buf_size,
                            int *response_len)
{
    return do_request(HTTP_METHOD_POST, url, access_token, json_body,
                      response_buf, response_buf_size, response_len);
}

esp_err_t matrix_http_put(const char *url,
                           const char *access_token,
                           const char *json_body,
                           char *response_buf,
                           size_t response_buf_size,
                           int *response_len)
{
    return do_request(HTTP_METHOD_PUT, url, access_token, json_body,
                      response_buf, response_buf_size, response_len);
}
