#include "nvs_storage.h"

#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"

static const char *TAG = "nvs_storage";

#define NVS_NAMESPACE "simplego"

esp_err_t nvs_storage_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition needs erase, erasing...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS init failed: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "NVS initialized");
    }

    return err;
}

esp_err_t nvs_storage_save_string(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_str(handle, key, value);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to write key '%s': %s", key, esp_err_to_name(err));
        nvs_close(handle);
        return err;
    }

    err = nvs_commit(handle);
    nvs_close(handle);

    ESP_LOGD(TAG, "Saved '%s'", key);
    return err;
}

esp_err_t nvs_storage_load_string(const char *key, char *value, size_t max_len)
{
    if (key == NULL || value == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        /* NVS namespace may not exist yet on first boot */
        value[0] = '\0';
        return err;
    }

    size_t required_size = max_len;
    err = nvs_get_str(handle, key, value, &required_size);
    if (err != ESP_OK) {
        value[0] = '\0';
        if (err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to read key '%s': %s", key, esp_err_to_name(err));
        }
    } else {
        ESP_LOGD(TAG, "Loaded '%s'", key);
    }

    nvs_close(handle);
    return err;
}
