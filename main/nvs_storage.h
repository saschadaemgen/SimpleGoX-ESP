#ifndef NVS_STORAGE_H
#define NVS_STORAGE_H

#include <stddef.h>
#include "esp_err.h"

esp_err_t nvs_storage_init(void);
esp_err_t nvs_storage_save_string(const char *key, const char *value);
esp_err_t nvs_storage_load_string(const char *key, char *value, size_t max_len);

#endif /* NVS_STORAGE_H */
