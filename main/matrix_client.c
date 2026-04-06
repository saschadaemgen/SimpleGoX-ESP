#include "matrix_client.h"
#include "matrix_http.h"
#include "matrix_json.h"
#include "nvs_storage.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"

static const char *TAG = "matrix_client";

esp_err_t matrix_client_init(matrix_client_t *client, const char *homeserver)
{
    if (client == NULL || homeserver == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(client, 0, sizeof(matrix_client_t));
    snprintf(client->homeserver_url, MATRIX_HOMESERVER_SIZE, "%s", homeserver);
    client->txn_counter = 0;

    /* Create persistent HTTP client (one TLS session, reused) */
    esp_err_t err = matrix_http_init(&client->http, homeserver);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return err;
    }

    ESP_LOGI(TAG, "Client initialized for %s", homeserver);
    return ESP_OK;
}

void matrix_client_free(matrix_client_t *client)
{
    if (client == NULL) {
        return;
    }
    matrix_http_cleanup(&client->http);
    memset(client, 0, sizeof(matrix_client_t));
}

esp_err_t matrix_client_login(matrix_client_t *client,
                               const char *username,
                               const char *password,
                               const char *device_id)
{
    if (client == NULL || username == NULL || password == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    char request_buf[512];
    int req_len = matrix_json_build_login(request_buf, sizeof(request_buf),
                                           username, password, device_id);
    if (req_len < 0) {
        ESP_LOGE(TAG, "Failed to build login request");
        return ESP_FAIL;
    }

    char url[MATRIX_URL_SIZE];
    snprintf(url, sizeof(url), "%s/_matrix/client/v3/login", client->homeserver_url);

    char response_buf[2048];
    int response_len = 0;
    esp_err_t err = matrix_http_post(&client->http, url, NULL, request_buf,
                                      response_buf, sizeof(response_buf),
                                      &response_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Login HTTP request failed");
        return err;
    }

    /* Extract access_token, device_id, user_id from response */
    matrix_json_get_string(response_buf, response_len,
                            "$.access_token",
                            client->access_token, sizeof(client->access_token));
    matrix_json_get_string(response_buf, response_len,
                            "$.device_id",
                            client->device_id, sizeof(client->device_id));
    matrix_json_get_string(response_buf, response_len,
                            "$.user_id",
                            client->user_id, sizeof(client->user_id));

    if (strlen(client->access_token) == 0) {
        ESP_LOGE(TAG, "Login failed: no access token in response");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Logged in as %s (device %s)", client->user_id, client->device_id);
    return ESP_OK;
}

esp_err_t matrix_client_logout(matrix_client_t *client)
{
    if (client == NULL || strlen(client->access_token) == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    char url[MATRIX_URL_SIZE];
    snprintf(url, sizeof(url), "%s/_matrix/client/v3/logout", client->homeserver_url);

    char response_buf[512];
    int response_len = 0;
    esp_err_t err = matrix_http_post(&client->http, url, client->access_token, "{}",
                                      response_buf, sizeof(response_buf),
                                      &response_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Logout request failed");
        return err;
    }

    /* Clear credentials */
    memset(client->access_token, 0, sizeof(client->access_token));
    memset(client->device_id, 0, sizeof(client->device_id));

    ESP_LOGI(TAG, "Logged out");
    return ESP_OK;
}

esp_err_t matrix_client_join_room(matrix_client_t *client,
                                   const char *room_id_or_alias)
{
    if (client == NULL || room_id_or_alias == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* URL-encode the room ID or alias */
    char encoded[MATRIX_ROOM_ID_SIZE * 3];
    int ei = 0;
    for (int i = 0; room_id_or_alias[i] != '\0' && ei < (int)sizeof(encoded) - 4; i++) {
        char c = room_id_or_alias[i];
        if (c == '#') {
            encoded[ei++] = '%'; encoded[ei++] = '2'; encoded[ei++] = '3';
        } else if (c == ':') {
            encoded[ei++] = '%'; encoded[ei++] = '3'; encoded[ei++] = 'A';
        } else if (c == '!') {
            encoded[ei++] = '%'; encoded[ei++] = '2'; encoded[ei++] = '1';
        } else {
            encoded[ei++] = c;
        }
    }
    encoded[ei] = '\0';

    char url[MATRIX_URL_SIZE];
    snprintf(url, sizeof(url), "%s/_matrix/client/v3/join/%s",
             client->homeserver_url, encoded);

    char response_buf[1024];
    int response_len = 0;
    esp_err_t err = matrix_http_post(&client->http, url, client->access_token, "{}",
                                      response_buf, sizeof(response_buf),
                                      &response_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Join room request failed");
        return err;
    }

    /* Extract room_id from response */
    char joined_room_id[MATRIX_ROOM_ID_SIZE];
    matrix_json_get_string(response_buf, response_len,
                            "$.room_id",
                            joined_room_id, sizeof(joined_room_id));

    if (strlen(joined_room_id) > 0) {
        snprintf(client->room_id, sizeof(client->room_id), "%s", joined_room_id);
    }

    ESP_LOGI(TAG, "Joined room %s", client->room_id);
    return ESP_OK;
}

esp_err_t matrix_client_resolve_alias(matrix_client_t *client,
                                       const char *alias,
                                       char *room_id_out,
                                       size_t room_id_out_size)
{
    if (client == NULL || alias == NULL || room_id_out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* URL-encode the alias */
    char encoded[MATRIX_ROOM_ID_SIZE * 3];
    int ei = 0;
    for (int i = 0; alias[i] != '\0' && ei < (int)sizeof(encoded) - 4; i++) {
        char c = alias[i];
        if (c == '#') {
            encoded[ei++] = '%'; encoded[ei++] = '2'; encoded[ei++] = '3';
        } else if (c == ':') {
            encoded[ei++] = '%'; encoded[ei++] = '3'; encoded[ei++] = 'A';
        } else {
            encoded[ei++] = c;
        }
    }
    encoded[ei] = '\0';

    char url[MATRIX_URL_SIZE];
    snprintf(url, sizeof(url), "%s/_matrix/client/v3/directory/room/%s",
             client->homeserver_url, encoded);

    char response_buf[1024];
    int response_len = 0;
    esp_err_t err = matrix_http_get(&client->http, url, client->access_token,
                                     response_buf, sizeof(response_buf),
                                     &response_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Resolve alias request failed");
        return err;
    }

    matrix_json_get_string(response_buf, response_len,
                            "$.room_id",
                            room_id_out, room_id_out_size);

    if (strlen(room_id_out) == 0) {
        ESP_LOGE(TAG, "Failed to resolve alias %s", alias);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Resolved %s -> %s", alias, room_id_out);
    return ESP_OK;
}

esp_err_t matrix_client_send_text(matrix_client_t *client,
                                   const char *room_id,
                                   const char *message)
{
    if (client == NULL || room_id == NULL || message == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    char body[512];
    int body_len = matrix_json_build_text_message(body, sizeof(body), message);
    if (body_len < 0) {
        return ESP_FAIL;
    }

    /* URL-encode room_id for the path */
    char encoded_room[MATRIX_ROOM_ID_SIZE * 3];
    int ei = 0;
    for (int i = 0; room_id[i] != '\0' && ei < (int)sizeof(encoded_room) - 4; i++) {
        char c = room_id[i];
        if (c == '!') {
            encoded_room[ei++] = '%'; encoded_room[ei++] = '2'; encoded_room[ei++] = '1';
        } else if (c == ':') {
            encoded_room[ei++] = '%'; encoded_room[ei++] = '3'; encoded_room[ei++] = 'A';
        } else {
            encoded_room[ei++] = c;
        }
    }
    encoded_room[ei] = '\0';

    client->txn_counter++;

    char url[MATRIX_URL_SIZE];
    snprintf(url, sizeof(url),
             "%s/_matrix/client/v3/rooms/%s/send/m.room.message/%" PRIu32,
             client->homeserver_url, encoded_room, client->txn_counter);

    char response_buf[512];
    int response_len = 0;
    esp_err_t err = matrix_http_put(&client->http, url, client->access_token, body,
                                     response_buf, sizeof(response_buf),
                                     &response_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Send message failed");
        return err;
    }

    ESP_LOGD(TAG, "Message sent to %s", room_id);
    return ESP_OK;
}

/*
 * URL-encode a string into a destination buffer.
 * Encodes all characters that are not unreserved per RFC 3986.
 * Returns the number of bytes written (excluding null terminator), or -1 on overflow.
 */
static int url_encode(const char *src, char *dst, size_t dst_size)
{
    static const char hex[] = "0123456789ABCDEF";
    int pos = 0;

    for (int i = 0; src[i] != '\0'; i++) {
        unsigned char c = (unsigned char)src[i];
        /* Unreserved characters per RFC 3986 */
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            if (pos >= (int)dst_size - 1) { return -1; }
            dst[pos++] = c;
        } else {
            if (pos >= (int)dst_size - 3) { return -1; }
            dst[pos++] = '%';
            dst[pos++] = hex[c >> 4];
            dst[pos++] = hex[c & 0x0F];
        }
    }
    dst[pos] = '\0';
    return pos;
}

esp_err_t matrix_client_sync(matrix_client_t *client,
                              matrix_sync_response_t *response,
                              int timeout_ms)
{
    if (client == NULL || response == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(response, 0, sizeof(matrix_sync_response_t));

    ESP_LOGI(TAG, "Sync starting, since=%s",
             client->sync_next_batch[0] ? client->sync_next_batch : "(initial)");

    /* Build URL: start with base sync endpoint */
    char url[MATRIX_URL_SIZE * 2];
    int pos = snprintf(url, sizeof(url),
                       "%s/_matrix/client/v3/sync?timeout=%d",
                       client->homeserver_url, timeout_ms);

    /* Append since token if we have one */
    if (client->sync_next_batch[0] != '\0') {
        char encoded_token[MATRIX_SYNC_TOKEN_SIZE * 3];
        url_encode(client->sync_next_batch, encoded_token, sizeof(encoded_token));
        pos += snprintf(url + pos, sizeof(url) - pos, "&since=%s", encoded_token);
    }

    /* Append sync filter if we have a room to filter on */
    if (client->room_id[0] != '\0') {
        char filter[512];
        int filter_len = matrix_json_build_sync_filter(filter, sizeof(filter),
                                                        client->room_id);
        if (filter_len > 0) {
            char encoded_filter[1024];
            if (url_encode(filter, encoded_filter, sizeof(encoded_filter)) > 0) {
                pos += snprintf(url + pos, sizeof(url) - pos,
                                "&filter=%s", encoded_filter);
            }
        }
    }

    char *response_buf = malloc(MATRIX_RESPONSE_BUF_SIZE);
    if (response_buf == NULL) {
        ESP_LOGE(TAG, "Failed to allocate sync response buffer");
        return ESP_ERR_NO_MEM;
    }

    int response_len = 0;
    esp_err_t err = matrix_http_get(&client->http, url, client->access_token,
                                     response_buf, MATRIX_RESPONSE_BUF_SIZE,
                                     &response_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Sync request failed: %s", esp_err_to_name(err));
        free(response_buf);
        return err;
    }

    ESP_LOGI(TAG, "Sync response: %d bytes", response_len);

    /* Parse the sync response */
    err = matrix_json_parse_sync(response_buf, response_len, response);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to parse sync response");
        free(response_buf);
        return err;
    }

    /* Update the next_batch token */
    if (strlen(response->next_batch) > 0) {
        snprintf(client->sync_next_batch, sizeof(client->sync_next_batch),
                 "%s", response->next_batch);
    }

    free(response_buf);
    ESP_LOGI(TAG, "Sync ok: next_batch=%s, %d messages",
             response->next_batch, response->message_count);
    return ESP_OK;
}

esp_err_t matrix_client_save_sync_token(matrix_client_t *client)
{
    if (client == NULL || strlen(client->sync_next_batch) == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    return nvs_storage_save_string("sync_token", client->sync_next_batch);
}

esp_err_t matrix_client_load_sync_token(matrix_client_t *client)
{
    if (client == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return nvs_storage_load_string("sync_token",
                                    client->sync_next_batch,
                                    sizeof(client->sync_next_batch));
}
