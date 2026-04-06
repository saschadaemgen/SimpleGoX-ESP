#include <stdio.h>
#include <string.h>
#include <math.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

#include "nvs_storage.h"
#include "matrix_client.h"
#include "gpio_control.h"
#include "crypto_utils.h"
#include "matrix_e2ee.h"
#include "mjson.h"

static const char *TAG = "simplego";

static matrix_client_t g_client;
static matrix_e2ee_t g_e2ee;
static bool g_e2ee_active = false;
static int g_relay_pin = CONFIG_SIMPLEGO_RELAY_GPIO;
static bool g_current_state = false;

/* WiFi connection */

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static int s_retry_count = 0;
#define WIFI_MAX_RETRIES 10

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_count < WIFI_MAX_RETRIES) {
            esp_wifi_connect();
            s_retry_count++;
            ESP_LOGI(TAG, "Retrying WiFi connection (%d/%d)", s_retry_count, WIFI_MAX_RETRIES);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_count = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_connect(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t any_id;
    esp_event_handler_instance_t got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = { .capable = true, .required = false },
        },
    };
    snprintf((char *)wifi_config.sta.ssid, sizeof(wifi_config.sta.ssid),
             "%s", CONFIG_SIMPLEGO_WIFI_SSID);
    snprintf((char *)wifi_config.sta.password, sizeof(wifi_config.sta.password),
             "%s", CONFIG_SIMPLEGO_WIFI_PASSWORD);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to WiFi SSID: %s", CONFIG_SIMPLEGO_WIFI_SSID);

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                            pdFALSE, pdFALSE, portMAX_DELAY);

    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(
        IP_EVENT, IP_EVENT_STA_GOT_IP, got_ip));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(
        WIFI_EVENT, ESP_EVENT_ANY_ID, any_id));
    vEventGroupDelete(s_wifi_event_group);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connected");
        return ESP_OK;
    }

    ESP_LOGE(TAG, "WiFi connection failed");
    return ESP_FAIL;
}

/* Send a text message (encrypted if E2EE active, plaintext otherwise) */

static esp_err_t send_text(const char *message)
{
    if (g_e2ee_active) {
        return matrix_e2ee_send_text(&g_e2ee, &g_client,
                                      g_client.room_id, message);
    }
    return matrix_client_send_text(&g_client, g_client.room_id, message);
}

/* Set relay and send status update */

static void set_relay(bool state)
{
    g_current_state = state;
    gpio_control_set(g_relay_pin, state);
    matrix_client_send_status(&g_client, g_client.room_id,
                               CONFIG_SIMPLEGO_IOT_DEVICE_ID,
                               state, NAN, NULL);
}

/* Process IoT custom commands */

static void handle_iot_command(const matrix_iot_command_t *cmd)
{
    if (cmd == NULL || strlen(cmd->device_id) == 0) { return; }
    if (strcmp(cmd->device_id, CONFIG_SIMPLEGO_IOT_DEVICE_ID) != 0) {
        return;
    }

    ESP_LOGI(TAG, "IoT command: device=%s action=%s",
             cmd->device_id, cmd->action[0] ? cmd->action : "(none)");

    if (strcmp(cmd->action, "set") == 0 && cmd->has_value) {
        set_relay(cmd->bool_value);
    } else if (strcmp(cmd->action, "toggle") == 0) {
        set_relay(!g_current_state);
    } else if (strcmp(cmd->action, "query") == 0) {
        matrix_client_send_status(&g_client, g_client.room_id,
                                   CONFIG_SIMPLEGO_IOT_DEVICE_ID,
                                   g_current_state, NAN, NULL);
    } else {
        ESP_LOGW(TAG, "Unknown IoT action: %s", cmd->action);
    }
}

/* Process text message commands (works for both plaintext and decrypted) */

static void handle_text_command(const char *sender, const char *body)
{
    if (sender == NULL || body == NULL || body[0] == '\0') { return; }

    /* Skip messages from ourselves */
    if (strcmp(sender, g_client.user_id) == 0) {
        return;
    }

    ESP_LOGI(TAG, "Message from %s: %s", sender, body);

    if (strcasecmp(body, "on") == 0) {
        set_relay(true);
        send_text("Light is ON");
    } else if (strcasecmp(body, "off") == 0) {
        set_relay(false);
        send_text("Light is OFF");
    } else if (strcasecmp(body, "status") == 0) {
        int64_t uptime_s = esp_timer_get_time() / 1000000;
        wifi_ap_record_t ap_info;
        int rssi = 0;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            rssi = ap_info.rssi;
        }
        char status_buf[256];
        snprintf(status_buf, sizeof(status_buf),
                 "Light: %s | Uptime: %lldh %lldm | WiFi RSSI: %d dBm",
                 g_current_state ? "ON" : "OFF",
                 (long long)(uptime_s / 3600),
                 (long long)((uptime_s % 3600) / 60),
                 rssi);
        send_text(status_buf);
    } else if (strcasecmp(body, "help") == 0) {
        send_text("Commands: on, off, status, help, reboot");
    } else if (strcasecmp(body, "reboot") == 0) {
        send_text("Rebooting...");
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();
    }
}

/* Process decrypted event content JSON based on its type */

static void handle_decrypted_event(const char *sender,
                                    const char *event_type,
                                    const char *content_json,
                                    int content_json_len)
{
    if (sender == NULL || event_type == NULL || content_json == NULL) { return; }
    if (sender[0] == '\0' || event_type[0] == '\0') { return; }

    /* Skip events from ourselves */
    if (strcmp(sender, g_client.user_id) == 0) {
        return;
    }

    ESP_LOGI(TAG, "Decrypted event [%s] from %s", event_type, sender);

    if (strcmp(event_type, "m.room.message") == 0) {
        char body[256] = {0};
        mjson_get_string(content_json, content_json_len,
                          "$.body", body, sizeof(body));
        if (strlen(body) > 0) {
            handle_text_command(sender, body);
        }
    } else if (strcmp(event_type, "dev.simplego.iot.command") == 0) {
        matrix_iot_command_t cmd = {0};
        snprintf(cmd.sender, sizeof(cmd.sender), "%s", sender);
        mjson_get_string(content_json, content_json_len,
                          "$.device_id", cmd.device_id, sizeof(cmd.device_id));
        mjson_get_string(content_json, content_json_len,
                          "$.action", cmd.action, sizeof(cmd.action));

        double dval = 0;
        if (mjson_get_number(content_json, content_json_len, "$.value", &dval) == 1) {
            cmd.value = dval;
            cmd.has_value = true;
            cmd.bool_value = (dval != 0);
        } else {
            const char *vptr = NULL;
            int vlen = 0;
            int vtype = mjson_find(content_json, content_json_len,
                                    "$.value", &vptr, &vlen);
            if (vtype == MJSON_TOK_TRUE) {
                cmd.bool_value = true;
                cmd.has_value = true;
            } else if (vtype == MJSON_TOK_FALSE) {
                cmd.bool_value = false;
                cmd.has_value = true;
            }
        }

        if (strlen(cmd.device_id) > 0) {
            handle_iot_command(&cmd);
        }
    }
}

/* Sync task */

static void sync_task(void *arg)
{
    matrix_sync_response_t response;

    ESP_LOGI(TAG, "Sync task started (E2EE %s)",
             g_e2ee_active ? "active" : "inactive");
    ESP_LOGI(TAG, "Free heap in sync task: %lu, largest block: %lu",
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));

    while (1) {
        esp_err_t err = matrix_client_sync(&g_client, &response, 0);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Sync failed, retrying in 5s...");
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        /* 1. Process to_device events first (receive Megolm session keys) */
        if (g_e2ee_active) {
            if (response.to_device_event_count > 0) {
                ESP_LOGI(TAG, "Processing %d to_device events",
                         response.to_device_event_count);
            }
            for (int i = 0; i < response.to_device_event_count; i++) {
                matrix_to_device_event_t *tde = &response.to_device_events[i];
                ESP_LOGI(TAG, "to_device[%d]: type=%s sender=%s len=%d",
                         i, tde->type, tde->sender, tde->content_json_len);
                if (tde->content_json != NULL && tde->content_json_len > 0) {
                    matrix_e2ee_handle_to_device(&g_e2ee,
                                                  tde->content_json,
                                                  tde->content_json_len);
                } else {
                    ESP_LOGW(TAG, "to_device[%d]: empty content, skipped", i);
                }
            }
        }

        /* 2. Process encrypted room events */
        if (g_e2ee_active) {
            if (response.encrypted_event_count > 0) {
                ESP_LOGI(TAG, "Processing %d encrypted events",
                         response.encrypted_event_count);
            }
            for (int i = 0; i < response.encrypted_event_count; i++) {
                matrix_encrypted_event_t *enc = &response.encrypted_events[i];

                /* Skip our own messages */
                if (strcmp(enc->sender, g_client.user_id) == 0) {
                    continue;
                }

                /* Build a minimal JSON to pass to decrypt */
                char *event_json = malloc(sizeof(enc->ciphertext) + 512);
                if (event_json == NULL) { continue; }

                int ej_len = snprintf(event_json, sizeof(enc->ciphertext) + 512,
                    "{\"content\":{"
                        "\"algorithm\":\"%s\","
                        "\"sender_key\":\"%s\","
                        "\"session_id\":\"%s\","
                        "\"ciphertext\":\"%s\""
                    "}}",
                    enc->algorithm, enc->sender_key,
                    enc->session_id, enc->ciphertext);

                char *content_out = malloc(2048);
                char type_out[64] = {0};
                if (content_out == NULL) { free(event_json); continue; }
                content_out[0] = '\0';

                err = matrix_e2ee_decrypt_room_event(&g_e2ee,
                                                      event_json, ej_len,
                                                      content_out, 2048,
                                                      type_out, sizeof(type_out));
                free(event_json);

                if (err == ESP_OK && strlen(type_out) > 0) {
                    handle_decrypted_event(enc->sender, type_out,
                                            content_out, strlen(content_out));
                }
                free(content_out);
            }
        }

        /* 3. Process custom IoT commands (plaintext) */
        for (int i = 0; i < response.iot_command_count; i++) {
            matrix_iot_command_t *cmd = &response.iot_commands[i];
            if (strcmp(cmd->sender, g_client.user_id) == 0) { continue; }
            handle_iot_command(cmd);
        }

        /* 4. Process text messages (plaintext fallback) */
        for (int i = 0; i < response.message_count; i++) {
            matrix_message_t *msg = &response.messages[i];
            handle_text_command(msg->sender, msg->body);
        }

        /* Free heap-allocated to_device content buffers */
        for (int i = 0; i < response.to_device_event_count; i++) {
            free(response.to_device_events[i].content_json);
            response.to_device_events[i].content_json = NULL;
        }

        /* Persist sync token */
        matrix_client_save_sync_token(&g_client);

        /* Simple polling: wait 5 seconds before next sync */
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

/* Entry point */

void app_main(void)
{
    ESP_LOGI(TAG, "SimpleGoX ESP starting...");
    ESP_LOGI(TAG, "Device: %s (%s)", CONFIG_SIMPLEGO_IOT_DEVICE_ID,
             CONFIG_SIMPLEGO_IOT_DEVICE_LABEL);

    /* NVS init */
    ESP_ERROR_CHECK(nvs_storage_init());

    /* WiFi connect (blocking) */
    ESP_ERROR_CHECK(wifi_connect());

    /* Matrix client init */
    ESP_ERROR_CHECK(matrix_client_init(&g_client, CONFIG_SIMPLEGO_MATRIX_HOMESERVER));

    /* Try to load saved device_id from NVS (stable across reboots for E2EE) */
    char saved_device_id[MATRIX_DEVICE_ID_SIZE] = {0};
    nvs_storage_load_string("device_id", saved_device_id, sizeof(saved_device_id));

    /* Login with saved device_id if available, otherwise server assigns one */
    ESP_ERROR_CHECK(matrix_client_login(&g_client,
                                         CONFIG_SIMPLEGO_MATRIX_USERNAME,
                                         CONFIG_SIMPLEGO_MATRIX_PASSWORD,
                                         saved_device_id[0] ? saved_device_id : NULL));

    /* Save the device_id we got from the server */
    if (g_client.device_id[0] != '\0') {
        nvs_storage_save_string("device_id", g_client.device_id);
        ESP_LOGI(TAG, "Device ID: %s%s", g_client.device_id,
                 saved_device_id[0] ? " (reused)" : " (new)");
    }

    /* E2EE initialization */
    ESP_LOGI(TAG, "Initializing E2EE...");
    esp_err_t e2ee_err = crypto_utils_init();
    if (e2ee_err == ESP_OK) {
        e2ee_err = matrix_e2ee_init(&g_e2ee);
    }
    if (e2ee_err == ESP_OK) {
        e2ee_err = matrix_e2ee_upload_keys(&g_e2ee, &g_client);
    }
    if (e2ee_err == ESP_OK) {
        g_client.e2ee = &g_e2ee;
        g_e2ee_active = true;
        ESP_LOGI(TAG, "E2EE active");
    } else {
        ESP_LOGW(TAG, "E2EE init failed (%s), continuing without encryption",
                 esp_err_to_name(e2ee_err));
        g_e2ee_active = false;
    }

    /* Load sync token from NVS (ignore error on first boot) */
    matrix_client_load_sync_token(&g_client);

    /* Resolve room alias to room ID */
    const char *room_config = CONFIG_SIMPLEGO_MATRIX_ROOM;
    if (room_config[0] == '#') {
        char resolved_room_id[MATRIX_ROOM_ID_SIZE];
        esp_err_t err = matrix_client_resolve_alias(&g_client, room_config,
                                                     resolved_room_id,
                                                     sizeof(resolved_room_id));
        if (err == ESP_OK) {
            snprintf(g_client.room_id, sizeof(g_client.room_id), "%s", resolved_room_id);
        } else {
            ESP_LOGE(TAG, "Failed to resolve room alias, using as-is");
            snprintf(g_client.room_id, sizeof(g_client.room_id), "%s", room_config);
        }
    } else {
        snprintf(g_client.room_id, sizeof(g_client.room_id), "%s", room_config);
    }

    /* Join room */
    ESP_ERROR_CHECK(matrix_client_join_room(&g_client, room_config));

    /* Query room members' device keys for E2EE */
    if (g_e2ee_active) {
        /* Query keys for room members we might communicate with.
         * For now, query the admin user. In the future, get the member list. */
        matrix_e2ee_query_keys(&g_e2ee, &g_client, "@sash710:simplego.dev");
    }

    /* Register device in room via state event */
    matrix_client_register_device(&g_client, g_client.room_id,
                                   CONFIG_SIMPLEGO_IOT_DEVICE_ID,
                                   CONFIG_SIMPLEGO_IOT_DEVICE_TYPE,
                                   CONFIG_SIMPLEGO_IOT_DEVICE_LABEL,
                                   CONFIG_SIMPLEGO_IOT_DEVICE_ICON,
                                   true);

    /* GPIO init */
    ESP_ERROR_CHECK(gpio_control_init(g_relay_pin));

    /* Send initial status */
    g_current_state = gpio_control_get(g_relay_pin);
    matrix_client_send_status(&g_client, g_client.room_id,
                               CONFIG_SIMPLEGO_IOT_DEVICE_ID,
                               g_current_state, NAN, NULL);

    /* Heap diagnostics before sync task */
    ESP_LOGI(TAG, "Free heap: %lu, largest block: %lu",
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));

    /* Start sync task (24 KB stack for TLS + crypto + buffers) */
    xTaskCreate(sync_task, "sync_task", 49152, NULL, 5, NULL);

    ESP_LOGI(TAG, "Setup complete, sync task running");
}
