#include "gpio_control.h"

#include "driver/gpio.h"
#include "esp_log.h"

static const char *TAG = "gpio_control";

static bool current_state = false;

esp_err_t gpio_control_init(int relay_pin)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << relay_pin),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };

    esp_err_t err = gpio_config(&io_conf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to configure GPIO %d", relay_pin);
        return err;
    }

    gpio_set_level(relay_pin, 0);
    current_state = false;

    ESP_LOGI(TAG, "GPIO %d initialized as output (relay)", relay_pin);
    return ESP_OK;
}

esp_err_t gpio_control_set(int relay_pin, bool state)
{
    esp_err_t err = gpio_set_level(relay_pin, state ? 1 : 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set GPIO %d", relay_pin);
        return err;
    }

    current_state = state;
    ESP_LOGI(TAG, "Relay %s", state ? "ON" : "OFF");
    return ESP_OK;
}

bool gpio_control_get(int relay_pin)
{
    (void)relay_pin;
    return current_state;
}
