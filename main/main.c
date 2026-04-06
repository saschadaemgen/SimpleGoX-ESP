#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_timer.h"

#include "nvs_storage.h"
#include "matrix_client.h"
#include "gpio_control.h"

static const char *TAG = "simplego";

static matrix_client_t g_client;
static int g_relay_pin = CONFIG_SIMPLEGO_RELAY_GPIO;

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

/* Sync task */

static void sync_task(void *arg)
{
    matrix_sync_response_t response;

    ESP_LOGI(TAG, "Sync task started");

    while (1) {
        esp_err_t err = matrix_client_sync(&g_client, &response, 30000);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Sync failed, retrying in 5s...");
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        for (int i = 0; i < response.message_count; i++) {
            matrix_message_t *msg = &response.messages[i];

            /* Skip messages from ourselves */
            if (strcmp(msg->sender, g_client.user_id) == 0) {
                continue;
            }

            ESP_LOGI(TAG, "Message from %s: %s", msg->sender, msg->body);

            if (strcasecmp(msg->body, "on") == 0) {
                gpio_control_set(g_relay_pin, true);
                matrix_client_send_text(&g_client, g_client.room_id, "Light is ON");
            } else if (strcasecmp(msg->body, "off") == 0) {
                gpio_control_set(g_relay_pin, false);
                matrix_client_send_text(&g_client, g_client.room_id, "Light is OFF");
            } else if (strcasecmp(msg->body, "status") == 0) {
                bool state = gpio_control_get(g_relay_pin);
                int64_t uptime_s = esp_timer_get_time() / 1000000;
                wifi_ap_record_t ap_info;
                int rssi = 0;
                if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
                    rssi = ap_info.rssi;
                }
                char status_buf[256];
                snprintf(status_buf, sizeof(status_buf),
                         "Light: %s | Uptime: %lldh %lldm | WiFi RSSI: %d dBm",
                         state ? "ON" : "OFF",
                         (long long)(uptime_s / 3600),
                         (long long)((uptime_s % 3600) / 60),
                         rssi);
                matrix_client_send_text(&g_client, g_client.room_id, status_buf);
            } else if (strcasecmp(msg->body, "help") == 0) {
                matrix_client_send_text(&g_client, g_client.room_id,
                    "Commands: on, off, status, help, reboot");
            } else if (strcasecmp(msg->body, "reboot") == 0) {
                matrix_client_send_text(&g_client, g_client.room_id, "Rebooting...");
                vTaskDelay(pdMS_TO_TICKS(500));
                esp_restart();
            }
        }

        /* Persist sync token */
        matrix_client_save_sync_token(&g_client);
    }
}

/* Entry point */

void app_main(void)
{
    ESP_LOGI(TAG, "SimpleGoX ESP starting...");

    /* NVS init */
    ESP_ERROR_CHECK(nvs_storage_init());

    /* WiFi connect (blocking) */
    ESP_ERROR_CHECK(wifi_connect());

    /* Matrix client init */
    ESP_ERROR_CHECK(matrix_client_init(&g_client, CONFIG_SIMPLEGO_MATRIX_HOMESERVER));

    /* Login */
    ESP_ERROR_CHECK(matrix_client_login(&g_client,
                                         CONFIG_SIMPLEGO_MATRIX_USERNAME,
                                         CONFIG_SIMPLEGO_MATRIX_PASSWORD,
                                         "SimpleGoX-ESP"));

    /* Load sync token from NVS (ignore error on first boot) */
    matrix_client_load_sync_token(&g_client);

    /* Resolve room alias to room ID if it starts with '#' */
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

    /* Send online message */
    matrix_client_send_text(&g_client, g_client.room_id, "SimpleGoX ESP online!");

    /* GPIO init */
    ESP_ERROR_CHECK(gpio_control_init(g_relay_pin));

    /* Start sync task */
    xTaskCreate(sync_task, "sync_task", 8192, NULL, 5, NULL);

    ESP_LOGI(TAG, "Setup complete, sync task running");
}
