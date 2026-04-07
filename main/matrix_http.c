#include "matrix_http.h"

#include <string.h>
#include <sys/param.h>
#include "esp_log.h"
#include "esp_tls.h"
#include "esp_crt_bundle.h"

static const char *TAG = "matrix_http";

/*
 * Response accumulation context.
 * Passed as user_data to the esp_http_client event handler.
 * The handler copies incoming data chunks into the caller-provided buffer.
 */
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
            int remaining = ctx->buf_size - ctx->data_len - 1;
            if (remaining <= 0) {
                ESP_LOGW("matrix_http", "Response buffer full (%d bytes), data truncated!",
                         ctx->buf_size);
                break;
            }
            int copy_len = MIN(evt->data_len, remaining);
            memcpy(ctx->buf + ctx->data_len, evt->data, copy_len);
            ctx->data_len += copy_len;
            ctx->buf[ctx->data_len] = '\0';
        }
        break;
    case HTTP_EVENT_DISCONNECTED: {
        int mbedtls_err = 0;
        esp_err_t err = esp_tls_get_and_clear_last_error(
            (esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
        if (err != 0) {
            ESP_LOGW(TAG, "TLS disconnect: esp=0x%x, mbedtls=0x%x", err, mbedtls_err);
        }
        break;
    }
    default:
        break;
    }
    return ESP_OK;
}

esp_err_t matrix_http_init(matrix_http_t *http, const char *base_url)
{
    if (http == NULL || base_url == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(http, 0, sizeof(matrix_http_t));

    esp_http_client_config_t config = {
        .url = base_url,
        .event_handler = http_event_handler,
        .user_data = NULL,
        .disable_auto_redirect = false,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 15000,
        .buffer_size = 4096,
        .buffer_size_tx = 2048,
        .keep_alive_enable = true,
    };

    http->client = esp_http_client_init(&config);
    if (http->client == NULL) {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "HTTP client initialized for %s", base_url);
    return ESP_OK;
}

void matrix_http_cleanup(matrix_http_t *http)
{
    if (http == NULL) {
        return;
    }
    if (http->client != NULL) {
        esp_http_client_cleanup(http->client);
        http->client = NULL;
    }
}

static const char *method_to_str(esp_http_client_method_t method)
{
    switch (method) {
    case HTTP_METHOD_GET:  return "GET";
    case HTTP_METHOD_POST: return "POST";
    case HTTP_METHOD_PUT:  return "PUT";
    default:               return "???";
    }
}

static esp_err_t do_request(matrix_http_t *http,
                             esp_http_client_method_t method,
                             const char *url,
                             const char *access_token,
                             const char *json_body,
                             char *response_buf,
                             size_t response_buf_size,
                             int *response_len)
{
    if (http == NULL || http->client == NULL || url == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "%s %s", method_to_str(method), url);

    /* Close any lingering connection from a previous request.
     * This is critical for client reuse: esp_http_client_perform may hang
     * if the previous TCP/TLS session is still open with unread data. */
    esp_http_client_close(http->client);

    /* Set up response accumulation context on the stack */
    http_response_ctx_t ctx = {
        .buf = response_buf,
        .buf_size = (int)response_buf_size,
        .data_len = 0,
    };

    if (response_buf != NULL && response_buf_size > 0) {
        response_buf[0] = '\0';
    }

    /* Reconfigure the persistent client for this request */
    esp_http_client_set_url(http->client, url);
    esp_http_client_set_method(http->client, method);
    esp_http_client_set_user_data(http->client, &ctx);

    /* Re-apply timeout (may not persist across URL changes) */
    esp_http_client_set_timeout_ms(http->client, 15000);

    /* Authorization header */
    if (access_token != NULL && strlen(access_token) > 0) {
        char auth_header[300];
        snprintf(auth_header, sizeof(auth_header), "Bearer %s", access_token);
        esp_http_client_set_header(http->client, "Authorization", auth_header);
    } else {
        esp_http_client_delete_header(http->client, "Authorization");
    }

    /* JSON body for POST/PUT */
    if (json_body != NULL) {
        esp_http_client_set_header(http->client, "Content-Type", "application/json");
        esp_http_client_set_post_field(http->client, json_body, strlen(json_body));
    } else {
        esp_http_client_set_post_field(http->client, NULL, 0);
        esp_http_client_delete_header(http->client, "Content-Type");
    }

    ESP_LOGD(TAG, "perform starting...");
    esp_err_t err = esp_http_client_perform(http->client);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "perform failed: %s", esp_err_to_name(err));
        esp_http_client_close(http->client);
        return err;
    }

    int status_code = esp_http_client_get_status_code(http->client);
    int64_t content_length = esp_http_client_get_content_length(http->client);

    ESP_LOGI(TAG, "response: %d, content_length=%lld, received=%d",
             status_code, (long long)content_length, ctx.data_len);

    if (response_len != NULL) {
        *response_len = ctx.data_len;
    }

    if (status_code >= 400) {
        ESP_LOGE(TAG, "HTTP %d: %.*s", status_code,
                 ctx.data_len > 200 ? 200 : ctx.data_len,
                 response_buf ? response_buf : "");
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t matrix_http_get(matrix_http_t *http,
                           const char *url,
                           const char *access_token,
                           char *response_buf,
                           size_t response_buf_size,
                           int *response_len)
{
    return do_request(http, HTTP_METHOD_GET, url, access_token, NULL,
                      response_buf, response_buf_size, response_len);
}

esp_err_t matrix_http_post(matrix_http_t *http,
                            const char *url,
                            const char *access_token,
                            const char *json_body,
                            char *response_buf,
                            size_t response_buf_size,
                            int *response_len)
{
    return do_request(http, HTTP_METHOD_POST, url, access_token, json_body,
                      response_buf, response_buf_size, response_len);
}

esp_err_t matrix_http_put(matrix_http_t *http,
                           const char *url,
                           const char *access_token,
                           const char *json_body,
                           char *response_buf,
                           size_t response_buf_size,
                           int *response_len)
{
    return do_request(http, HTTP_METHOD_PUT, url, access_token, json_body,
                      response_buf, response_buf_size, response_len);
}
