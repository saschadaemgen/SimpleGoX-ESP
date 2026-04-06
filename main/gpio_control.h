#ifndef GPIO_CONTROL_H
#define GPIO_CONTROL_H

#include <stdbool.h>
#include "esp_err.h"

esp_err_t gpio_control_init(int relay_pin);
esp_err_t gpio_control_set(int relay_pin, bool state);
bool gpio_control_get(int relay_pin);

#endif /* GPIO_CONTROL_H */
