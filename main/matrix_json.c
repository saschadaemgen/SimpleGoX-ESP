#include "matrix_json.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "mjson.h"

static const char *TAG = "matrix_json";

esp_err_t matrix_json_get_string(const char *json, int json_len,
                                  const char *path,
                                  char *out, size_t out_size)
{
    if (json == NULL || path == NULL || out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    int result = mjson_get_string(json, json_len, path, out, (int)out_size);
    if (result < 0) {
        out[0] = '\0';
        return ESP_ERR_NOT_FOUND;
    }
    return ESP_OK;
}

int matrix_json_build_login(char *buf, size_t buf_size,
                             const char *username,
                             const char *password,
                             const char *device_id)
{
    if (buf == NULL || username == NULL || password == NULL) {
        return -1;
    }

    const char *dev_name = (device_id != NULL && strlen(device_id) > 0)
                            ? device_id : "SimpleGoX-ESP";

    int len = mjson_snprintf(buf, (int)buf_size,
        "{"
            "\"type\":\"m.login.password\","
            "\"identifier\":{"
                "\"type\":\"m.id.user\","
                "\"user\":\"%s\""
            "},"
            "\"password\":\"%s\","
            "\"initial_device_display_name\":\"%s\""
        "}",
        username, password, dev_name);

    return len;
}

int matrix_json_build_text_message(char *buf, size_t buf_size,
                                    const char *message)
{
    if (buf == NULL || message == NULL) {
        return -1;
    }

    int len = mjson_snprintf(buf, (int)buf_size,
        "{"
            "\"msgtype\":\"m.text\","
            "\"body\":\"%s\""
        "}",
        message);

    return len;
}

int matrix_json_build_sync_filter(char *buf, size_t buf_size,
                                   const char *room_id)
{
    if (buf == NULL) {
        return -1;
    }

    /* If no room_id, return a minimal filter */
    if (room_id == NULL || strlen(room_id) == 0) {
        int len = snprintf(buf, buf_size,
            "{"
                "\"presence\":{\"types\":[]},"
                "\"account_data\":{\"types\":[]}"
            "}");
        return len;
    }

    int len = snprintf(buf, buf_size,
        "{"
            "\"room\":{"
                "\"rooms\":[\"%s\"],"
                "\"timeline\":{\"limit\":10,\"types\":[\"m.room.message\"]},"
                "\"state\":{\"types\":[]},"
                "\"ephemeral\":{\"types\":[]}"
            "},"
            "\"presence\":{\"types\":[]},"
            "\"account_data\":{\"types\":[]}"
        "}",
        room_id);

    return len;
}

esp_err_t matrix_json_parse_sync(const char *json, int json_len,
                                  matrix_sync_response_t *response)
{
    if (json == NULL || response == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(response, 0, sizeof(matrix_sync_response_t));

    /* Extract next_batch */
    mjson_get_string(json, json_len, "$.next_batch",
                     response->next_batch, sizeof(response->next_batch));

    /* Find rooms.join */
    const char *rooms_join = NULL;
    int rooms_join_len = 0;
    int res = mjson_find(json, json_len, "$.rooms.join", &rooms_join, &rooms_join_len);
    if (res == MJSON_TOK_INVALID || rooms_join == NULL) {
        return ESP_OK; /* No joined rooms in response */
    }

    /* Iterate over each joined room */
    int koff, klen, voff, vlen, vtype, off = 0;
    while ((off = mjson_next(rooms_join, rooms_join_len, off,
                              &koff, &klen, &voff, &vlen, &vtype)) != 0) {
        const char *room_data = rooms_join + voff;
        int room_data_len = vlen;

        /* Find timeline.events in this room */
        const char *events = NULL;
        int events_len = 0;
        res = mjson_find(room_data, room_data_len,
                          "$.timeline.events", &events, &events_len);
        if (res == MJSON_TOK_INVALID || events == NULL) {
            continue;
        }

        /* Iterate events */
        int ek, ekl, ev, evl, evt2, eoff = 0;
        while ((eoff = mjson_next(events, events_len, eoff,
                                   &ek, &ekl, &ev, &evl, &evt2)) != 0) {
            if (response->message_count >= MATRIX_MAX_MESSAGES) {
                break;
            }

            const char *event = events + ev;
            int event_len = evl;

            /* Check if this is m.room.message */
            char event_type[64];
            mjson_get_string(event, event_len, "$.type", event_type, sizeof(event_type));
            if (strcmp(event_type, "m.room.message") != 0) {
                continue;
            }

            matrix_message_t *msg = &response->messages[response->message_count];

            mjson_get_string(event, event_len, "$.sender",
                              msg->sender, sizeof(msg->sender));
            mjson_get_string(event, event_len, "$.content.body",
                              msg->body, sizeof(msg->body));
            mjson_get_string(event, event_len, "$.event_id",
                              msg->event_id, sizeof(msg->event_id));

            if (strlen(msg->body) > 0) {
                response->message_count++;
            }
        }
    }

    ESP_LOGD(TAG, "Parsed sync: next_batch=%s, messages=%d",
             response->next_batch, response->message_count);
    return ESP_OK;
}
