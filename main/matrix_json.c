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

    int len;
    /* If device_id looks like a Matrix device_id (not a display name),
     * send it as device_id to reuse the same device across reboots.
     * This is critical for E2EE: the Olm account keys are bound to the device_id. */
    if (device_id != NULL && strlen(device_id) > 0 &&
        strlen(device_id) < 20 && strchr(device_id, ' ') == NULL) {
        /* Looks like a device_id: send both device_id and display_name */
        len = mjson_snprintf(buf, (int)buf_size,
            "{"
                "\"type\":\"m.login.password\","
                "\"identifier\":{"
                    "\"type\":\"m.id.user\","
                    "\"user\":\"%s\""
                "},"
                "\"password\":\"%s\","
                "\"device_id\":\"%s\","
                "\"initial_device_display_name\":\"SimpleGoX-ESP\""
            "}",
            username, password, dev_name);
    } else {
        len = mjson_snprintf(buf, (int)buf_size,
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
    }

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
                "\"timeline\":{\"limit\":10,\"types\":[\"m.room.message\",\"m.room.encrypted\",\"dev.simplego.iot.command\"]},"
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
            const char *event = events + ev;
            int event_len = evl;

            /* Check event type */
            char event_type[64];
            mjson_get_string(event, event_len, "$.type", event_type, sizeof(event_type));

            if (strcmp(event_type, "m.room.message") == 0) {
                if (response->message_count >= MATRIX_MAX_MESSAGES) {
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
            } else if (strcmp(event_type, "m.room.encrypted") == 0) {
                if (response->encrypted_event_count >= MATRIX_MAX_ENCRYPTED_EVENTS) {
                    continue;
                }
                matrix_encrypted_event_t *enc = &response->encrypted_events[response->encrypted_event_count];
                memset(enc, 0, sizeof(matrix_encrypted_event_t));
                mjson_get_string(event, event_len, "$.sender",
                                  enc->sender, sizeof(enc->sender));
                mjson_get_string(event, event_len, "$.event_id",
                                  enc->event_id, sizeof(enc->event_id));
                mjson_get_string(event, event_len, "$.content.algorithm",
                                  enc->algorithm, sizeof(enc->algorithm));
                mjson_get_string(event, event_len, "$.content.sender_key",
                                  enc->sender_key, sizeof(enc->sender_key));
                mjson_get_string(event, event_len, "$.content.session_id",
                                  enc->session_id, sizeof(enc->session_id));
                mjson_get_string(event, event_len, "$.content.ciphertext",
                                  enc->ciphertext, sizeof(enc->ciphertext));
                if (strlen(enc->ciphertext) > 0) {
                    response->encrypted_event_count++;
                }
            } else if (strcmp(event_type, "dev.simplego.iot.command") == 0) {
                if (response->iot_command_count >= MATRIX_MAX_IOT_COMMANDS) {
                    continue;
                }
                matrix_iot_command_t *cmd = &response->iot_commands[response->iot_command_count];
                mjson_get_string(event, event_len, "$.sender",
                                  cmd->sender, sizeof(cmd->sender));
                mjson_get_string(event, event_len, "$.content.device_id",
                                  cmd->device_id, sizeof(cmd->device_id));
                mjson_get_string(event, event_len, "$.content.action",
                                  cmd->action, sizeof(cmd->action));

                /* Value can be bool or number */
                double dval = 0;
                int vres = mjson_get_number(event, event_len, "$.content.value", &dval);
                if (vres == 1) {
                    cmd->value = dval;
                    cmd->has_value = true;
                    cmd->bool_value = (dval != 0);
                } else {
                    /* Try as boolean: mjson returns true/false as number 1/0 via find */
                    const char *vptr = NULL;
                    int vlen2 = 0;
                    int vtype2 = mjson_find(event, event_len, "$.content.value", &vptr, &vlen2);
                    if (vtype2 == MJSON_TOK_TRUE) {
                        cmd->bool_value = true;
                        cmd->has_value = true;
                    } else if (vtype2 == MJSON_TOK_FALSE) {
                        cmd->bool_value = false;
                        cmd->has_value = true;
                    } else {
                        cmd->has_value = false;
                    }
                }

                if (strlen(cmd->device_id) > 0) {
                    response->iot_command_count++;
                }
            }
        }
    }

    /* Parse to_device events */
    const char *to_device_events = NULL;
    int to_device_events_len = 0;
    res = mjson_find(json, json_len, "$.to_device.events",
                      &to_device_events, &to_device_events_len);

    if (res != MJSON_TOK_INVALID && to_device_events != NULL) {
        int tdkoff, tdklen, tdvoff, tdvlen, tdvtype, tdoff = 0;
        while ((tdoff = mjson_next(to_device_events, to_device_events_len, tdoff,
                                    &tdkoff, &tdklen, &tdvoff, &tdvlen, &tdvtype)) != 0) {
            if (response->to_device_event_count >= MATRIX_MAX_TO_DEVICE_EVENTS) {
                break;
            }

            const char *td_event = to_device_events + tdvoff;
            int td_event_len = tdvlen;

            matrix_to_device_event_t *tde =
                &response->to_device_events[response->to_device_event_count];
            memset(tde, 0, sizeof(matrix_to_device_event_t));

            mjson_get_string(td_event, td_event_len, "$.type",
                              tde->type, sizeof(tde->type));
            mjson_get_string(td_event, td_event_len, "$.sender",
                              tde->sender, sizeof(tde->sender));

            /* Store the full event JSON on heap for E2EE processing */
            tde->content_json = malloc(td_event_len + 1);
            if (tde->content_json != NULL) {
                memcpy(tde->content_json, td_event, td_event_len);
                tde->content_json[td_event_len] = '\0';
                tde->content_json_len = td_event_len;
            }

            if (strlen(tde->type) > 0) {
                response->to_device_event_count++;
            }
        }
    }

    ESP_LOGD(TAG, "Parsed sync: messages=%d, encrypted=%d, to_device=%d",
             response->message_count, response->encrypted_event_count,
             response->to_device_event_count);
    return ESP_OK;
}
