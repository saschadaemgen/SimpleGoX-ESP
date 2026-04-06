# SimpleGoX ESP - Cloudcoat Instructions

## Project
SimpleGoX ESP - Matrix IoT devices on ESP32-S3 (T-Deck Plus)

## Language & Framework
- C with ESP-IDF 5.5.x
- No Arduino, no C++

## Build
- `idf.py set-target esp32s3`
- `idf.py menuconfig` (set WiFi + Matrix credentials)
- `idf.py build`
- `idf.py flash monitor`

## Rules
- Conventional Commits: feat(scope): description
- Valid scopes: iot, matrix, wifi, gpio, gadget, docs, ci
- NO em dashes
- NO version number changes without permission
- NO placeholder/demo data - use menuconfig for all credentials
- NO git push/commit to remote
- English code, German conversation
- Apache-2.0 license
- C11 standard, ESP-IDF coding style (4 spaces, snake_case)
- Handle all errors explicitly - check every return value
- Use ESP_LOGI/ESP_LOGW/ESP_LOGE for logging
- NEVER log access tokens or passwords

## Reference
- MatrixClientLibrary analysis: docs/ANALYSIS.md
- Matrix CS API spec: https://spec.matrix.org/v1.13/client-server-api/
- ESP-IDF docs: https://docs.espressif.com/projects/esp-idf/en/v5.5/

## Matrix Endpoints We Use
- POST /_matrix/client/v3/login
- POST /_matrix/client/v3/join/{roomIdOrAlias}
- GET /_matrix/client/v3/directory/room/{roomAlias}
- PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}
- GET /_matrix/client/v3/sync?filter={filter}&timeout={timeout}&since={since}
- POST /_matrix/client/v3/logout

## No E2E Encryption
We use unencrypted rooms only. No Olm, no Megolm.

## Homeserver
- URL: https://matrix.simplego.dev
- Software: Tuwunel
- User: @iot-light:simplego.dev (needs to be created)
- Room: #iot:simplego.dev (needs to be created, unencrypted)
- Admin: @sash710:simplego.dev

## Architecture
- FreeRTOS tasks for concurrent operations (sync loop in its own task)
- Filtered /sync to minimize RAM usage
- Store since-token in NVS for restart recovery
- GPIO abstraction layer for easy gadget porting
- All credentials via Kconfig menuconfig
