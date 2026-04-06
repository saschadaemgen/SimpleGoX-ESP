# MatrixClientLibrary Analysis

Analysis of `C:\Projects\MatrixClientLibrary\` for the SimpleGoX ESP project.

## 1. MatrixClient Struct

Defined in `src/matrix.h`:

```c
typedef struct MatrixClient {
    MatrixOlmAccount olmAccount;                            // Olm account for E2EE (not needed for us)

    MatrixMegolmInSession megolmInSessions[2];              // Inbound Megolm sessions (E2EE, skip)
    int numMegolmInSessions;
    MatrixMegolmOutSession megolmOutSessions[2];            // Outbound Megolm sessions (E2EE, skip)
    int numMegolmOutSessions;
    MatrixOlmSession olmSessions[2];                        // Olm sessions (E2EE, skip)
    int numOlmSessions;

    MatrixDevice devices[10];                               // Cached device info (E2EE, skip)
    int numDevices;

    char userId[64];                                        // Full Matrix user ID (@user:server)
    char accessToken[40];                                   // Bearer token from login
    char deviceId[20];                                      // Device ID from login
    char expireMs[20];                                      // Token expiry (ms)
    char refreshToken[20];                                  // Refresh token
    char masterKey[44];                                     // Cross-signing master key (E2EE, skip)

    bool verified;                                          // Verification status (E2EE, skip)

    MatrixHttpConnection * hc;                              // HTTP connection handle
} MatrixClient;
```

### Key size constants

| Constant            | Value | Purpose                        |
|---------------------|-------|--------------------------------|
| USER_ID_SIZE        | 64    | Max user ID length             |
| ROOM_ID_SIZE        | 128   | Max room ID length             |
| ACCESS_TOKEN_SIZE   | 40    | Max access token length        |
| DEVICE_ID_SIZE      | 20    | Max device ID length           |
| MAX_URL_LEN         | 1024  | Max URL buffer size            |

**Note for SimpleGoX:** ACCESS_TOKEN_SIZE of 40 is very small. Modern homeservers
(including Tuwunel) may return longer tokens. We should use at least 256 bytes.

## 2. Function Catalog

### Client Lifecycle

| Function | Signature | Matrix Endpoint | Description |
|----------|-----------|-----------------|-------------|
| `MatrixClientInit` | `bool (MatrixClient *)` | None | Zeroes struct, initializes OlmAccount |
| `MatrixClientSetAccessToken` | `bool (MatrixClient *, const char *)` | None | Copies token to client (char-by-char, 40 byte limit) |
| `MatrixClientSetDeviceId` | `bool (MatrixClient *, const char *)` | None | Copies device ID (char-by-char, 20 byte limit) |
| `MatrixClientSetUserId` | `bool (MatrixClient *, const char *)` | None | Copies user ID (char-by-char, 64 byte limit) |

### Authentication

| Function | Signature | Matrix Endpoint | Description |
|----------|-----------|-----------------|-------------|
| `MatrixClientLoginPassword` | `bool (MatrixClient *, username, password, displayName)` | `POST /_matrix/client/v3/login` | Sends m.login.password, stores access_token, device_id, expires_in_ms, refresh_token |
| `MatrixClientDeleteDevice` | `bool (MatrixClient *)` | `POST /_matrix/client/v3/delete_devices` | Deletes the current device on the server |

### Messaging

| Function | Signature | Matrix Endpoint | Description |
|----------|-----------|-----------------|-------------|
| `MatrixClientSendEvent` | `bool (MatrixClient *, roomId, msgType, msgBody)` | `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}` | Sends a room event. txnId = time(NULL). msgBody is raw JSON. |
| `MatrixClientSendEventEncrypted` | `bool (MatrixClient *, roomId, msgType, msgBody)` | Same as above (wraps in m.room.encrypted) | Encrypts with Megolm then sends |

### Sync

| Function | Signature | Matrix Endpoint | Description |
|----------|-----------|-----------------|-------------|
| `MatrixClientSync` | `bool (MatrixClient *, outSyncBuffer, outSyncCap, nextBatch, nextBatchCap)` | `GET /_matrix/client/v3/sync?timeout=5000&since={nextBatch}` | Long-polls for events. Passes response to HandleSync. |
| `MatrixClientGetRoomEvent` | `bool (MatrixClient *, roomId, eventId, outEvent, outEventCap)` | `GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}` | Fetches a single event |

### E2EE (Not needed for SimpleGoX)

- `MatrixClientGenerateOnetimeKeys` - Generates Olm one-time keys
- `MatrixClientUploadOnetimeKeys` - `POST /_matrix/client/v3/keys/upload`
- `MatrixClientUploadDeviceKeys` - `POST /_matrix/client/v3/keys/upload`
- `MatrixClientClaimOnetimeKey` - `POST /_matrix/client/v3/keys/claim`
- `MatrixClientRequestDeviceKeys` - `POST /_matrix/client/v3/keys/query`
- `MatrixClientShareMegolmOutSession` - Sends m.room_key via to-device
- `MatrixClientSendToDevice` - `PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}`
- `MatrixClientSendToDeviceEncrypted` - Encrypts then sends to-device
- Various Megolm/Olm session management functions

### HTTP Layer

| Function | Signature | Description |
|----------|-----------|-------------|
| `MatrixHttpInit` | `bool (MatrixHttpConnection **, const char * host)` | Allocates connection, stores host, calls connect |
| `MatrixHttpDeinit` | `bool (MatrixHttpConnection **)` | Cleans up and frees |
| `MatrixHttpSetAccessToken` | `bool (MatrixHttpConnection *, const char *)` | Stores token pointer |
| `MatrixHttpGet` | `bool (hc, url, outBuf, outCap, authenticated)` | GET with optional Bearer auth |
| `MatrixHttpPost` | `bool (hc, url, reqBuf, outBuf, outCap, authenticated)` | POST with JSON body |
| `MatrixHttpPut` | `bool (hc, url, reqBuf, outBuf, outCap, authenticated)` | PUT with JSON body |

## 3. HTTP Layer (matrix_http_esp32.c)

### MatrixHttpConnection struct (ESP32)

```c
struct MatrixHttpConnection {
    esp_http_client_handle_t client;  // ESP-IDF HTTP client handle
    const char * host;                // Base URL (e.g. "https://matrix.org")
    const char * accessToken;         // Bearer token pointer
    char * data;                      // Response buffer (caller-provided)
    int dataCap;                      // Response buffer capacity
    int dataLen;                      // Bytes received so far
};
```

### How it works

1. **Init**: Allocates `MatrixHttpConnection` on heap via `calloc`. Calls `MatrixHttpConnect`
   which creates an `esp_http_client` with:
   - URL set to the host
   - Event handler for chunked response accumulation
   - `crt_bundle_attach` for TLS certificate validation
   - 20-second timeout

2. **Request flow** (same for GET/POST/PUT):
   - Builds full URL: `snprintf(hostAndUrl, MAX_URL_LEN, "%s%s", host, url)`
   - Sets Authorization header if authenticated: `"Bearer %s"`
   - For POST/PUT: sets `Content-Type: application/json` and post field
   - Calls `esp_http_client_perform` (blocking)
   - Response data accumulated in event handler via `HTTP_EVENT_ON_DATA`

3. **Event handler** (`_http_event_handler`):
   - Calls `vTaskDelay(10/portTICK_PERIOD_MS)` on every event (yields to scheduler)
   - On `HTTP_EVENT_ON_DATA`: copies data to `hc->data + hc->dataLen`, null-terminates
   - Handles both chunked and non-chunked responses
   - On disconnect: logs TLS errors

4. **Key design choices**:
   - Single persistent `esp_http_client` handle reused across requests
   - Caller provides response buffer (no internal allocation for responses)
   - Static `authorizationHeader` and `hostAndUrl` buffers (not thread-safe)
   - Always returns true even on HTTP errors (only logs them)

### Comparison: Mongoose transport (desktop)

The desktop transport (`matrix_http_mongoose.c`) uses the Mongoose networking library
with raw HTTP/1.0 or HTTP/1.1 requests built via `mg_printf`. It polls `mg_mgr_poll`
in a blocking loop waiting for responses. The API is identical; only the transport differs.

## 4. JSON Patterns (mjson usage)

### Building JSON

Uses `mjson_snprintf` for JSON string construction with proper escaping:

```c
mjson_snprintf(requestBuffer, LOGIN_REQUEST_SIZE,
    "{"
        "\"type\":\"m.login.password\","
        "\"identifier\":{\"type\":\"m.id.user\",\"user\":\"%s\"},"
        "\"password\":\"%s\","
        "\"initial_device_display_name\":\"%s\""
    "}",
    username, password, displayName);
```

Also uses raw `snprintf` for simpler JSON where escaping is not a concern.

### Parsing JSON

- **`mjson_get_string(json, len, "$.path", out, outCap)`** - Extracts string value by JSON path
- **`mjson_find(json, len, "$.path", &ptr, &len)`** - Finds a JSON value, returns pointer+length (no copy)
- **`mjson_next(json, len, off, &koff, &klen, &voff, &vlen, &vtype)`** - Iterates object key/value pairs

### Iteration pattern

Arrays/objects are iterated with `mjson_next` in a for loop:
```c
int koff, klen, voff, vlen, vtype, off = 0;
for (off = 0; (off = mjson_next(s, slen, off, &koff, &klen, &voff, &vlen, &vtype)) != 0; ) {
    const char * val = s + voff;
    // process val with length vlen
}
```

### Merging JSON

Uses `mjson_merge` with `mjson_print_fixed_buf` for combining JSON objects (used in
canonicalization and signing).

### Pretty printing

Uses `mjson_pretty` for debug output.

## 5. Sync Mechanism

### How /sync is called

```c
// URL construction
snprintf(url, MAX_URL_LEN,
    "/_matrix/client/v3/sync?timeout=%d%s%s",
    SYNC_TIMEOUT,           // 5000ms
    "",                     // no filter applied
    strlen(nextBatch) > 0 ? "&since=" : "");

// URL-encode nextBatch (only ~ is encoded as %7E)
for (size_t i = 0; i < strlen(nextBatch); i++) {
    if (nextBatch[i] == '~') { url[index++] = '%'; url[index++] = '7'; url[index++] = 'E'; }
    else { url[index++] = nextBatch[i]; }
}
```

### How sync responses are parsed (MatrixClientHandleSync)

1. Extract `next_batch`: `mjson_get_string(s, slen, "$.next_batch", nextBatch, nextBatchCap)`
2. Process `to_device.events`: iterate with `mjson_next`, pass each to `HandleEvent`
3. Process `rooms.join`: iterate rooms, then for each room iterate `timeline.events`,
   pass each to `HandleRoomEvent`

### HandleRoomEvent flow

1. Check event type via `mjson_get_string(event, "$.type", ...)`
2. For `m.room.encrypted`: decrypt with Megolm, then handle decrypted content
3. For other events: pass to `HandleEvent`

### Observations

- No sync filter is applied (receives everything including presence, account_data)
- Sync timeout is only 5 seconds (we should use 30 seconds for IoT)
- No error handling on sync failure (no retry logic)
- The sync buffer in examples is 50KB (`1024*50`)
- `nextBatch` is stored in a caller-provided buffer (no persistence across reboots)

## 6. Buffer Strategy

### Static buffers (STATIC macro)

The library uses `#define STATIC static` to allocate many buffers as static variables.
This avoids heap allocation but means:
- Buffers persist for the lifetime of the program
- Functions are NOT reentrant or thread-safe
- Memory usage is constant but always consumed

### Key buffer sizes

| Buffer | Size | Purpose |
|--------|------|---------|
| `LOGIN_REQUEST_SIZE` | 1024 | Login request JSON |
| `LOGIN_RESPONSE_SIZE` | 1024 | Login response JSON |
| `ENCRYPTED_REQUEST_SIZE` | 5120 | Encrypted event request |
| `ENCRYPTED_EVENT_SIZE` | 10240 | Encrypted event buffer |
| `ROOM_SEND_REQUEST_SIZE` | 256 | Room send request |
| `ROOM_SEND_RESPONSE_SIZE` | 1024 | Room send response |
| `KEYS_QUERY_RESPONSE_SIZE` | 5120 | Keys query response |
| `KEYS_UPLOAD_REQUEST_SIZE` | 4096 | Keys upload request |
| `AUTHORIZATION_HEADER_LEN` | 64 | Auth header |
| `HTTP_CONNECTION_DATA_SIZE` | 65536 | HTTP response accumulation (unused, heap now) |
| `MAX_URL_LEN` | 1024 | URL construction |
| `JSON_QUERY_SIZE` | 128 | JSON path queries |

### Allocation pattern

- **HTTP connection**: heap-allocated via `calloc(1, sizeof(MatrixHttpConnection))`
- **MatrixClient**: allocated by caller (stack in examples, heap in ESP32 example)
- **Response buffers**: caller-provided (stack or static in examples)
- **Internal work buffers**: static globals (`g_EncryptedRequestBuffer`, etc.)

## 7. ESP-IDF Integration

### Project structure

```
esp32/esp_project/
  CMakeLists.txt                    # Standard ESP-IDF project boilerplate
  main/
    CMakeLists.txt                  # Registers wifi.c + SendEncrypted.c
    SendEncrypted.c                 # Main app (app_main + main)
    wifi.c                          # WiFi STA initialization
    wifi.h                          # void wifi_init(ssid, pass)
  components/
    matrix/CMakeLists.txt           # Matrix lib as ESP-IDF component
    olm/CMakeLists.txt              # Olm lib as ESP-IDF component
```

### Root CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp_project)
```

### Component registration (matrix)

```cmake
idf_component_register(SRCS
    "../../../../src/matrix.c"
    "../../../../src/matrix_http_esp32.c"
    "../../../../ext/mjson/src/mjson.c"
  INCLUDE_DIRS
    "../../../../ext/olm/include"
    "../../../../ext/olm/lib"
    "../../../../ext/mjson/src"
    "../../../../src"
  REQUIRES
    esp-tls esp_http_client esp_netif nvs_flash)
```

Uses relative paths back to the source tree rather than copying files.
Required ESP-IDF components: `esp-tls`, `esp_http_client`, `esp_netif`, `nvs_flash`.

### WiFi initialization pattern

1. Initialize NVS flash
2. Create event group for synchronization
3. Init TCP/IP stack and event loop
4. Create default WiFi STA interface
5. Register event handlers for WiFi + IP events
6. Configure WiFi with SSID/password, WPA2-PSK
7. Start WiFi and block on `xEventGroupWaitBits` until connected or failed
8. Retry up to 3 times on disconnect
9. Unregister handlers and delete event group after connection

### FreeRTOS task structure

The ESP32 example does NOT use separate FreeRTOS tasks. Everything runs in the default
`app_main` task. `app_main` calls `wifi_init` (blocking), then calls `main()` which
runs the Matrix operations sequentially.

### Credential handling

Credentials are **hardcoded as #defines** in the source file:
```c
#define SERVER        "https://matrix.org"
#define USERNAME      ""
#define PASSWORD      ""
#define WIFI_SSID     ""
#define WIFI_PASSWORD ""
```

No menuconfig, no NVS, no runtime configuration.

## 8. Gaps for Our Use Case

The library is missing several features we need:

1. **Room join** - No `MatrixClientJoinRoom` function. The library assumes the user is
   already in the room.

2. **Room alias resolution** - No function to resolve `#alias:server` to `!roomid:server`.

3. **Plaintext message sending** - `MatrixClientSendEvent` exists and works for plaintext,
   but the body must be raw JSON. No helper to build `m.text` messages.

4. **Sync filtering** - No sync filter is applied. On a constrained device, we need to
   filter to only the room we care about and only `m.room.message` events.

5. **Sync token persistence** - No NVS storage for the `next_batch` token. On reboot,
   the device would re-sync from scratch.

6. **Logout** - No `MatrixClientLogout` function. Only `DeleteDevice` exists.

7. **Error handling** - HTTP functions always return true. No status code checking.
   No retry logic.

8. **Thread safety** - Static buffers and static local variables make the HTTP layer
   and several client functions non-reentrant.

9. **Token size** - ACCESS_TOKEN_SIZE of 40 is too small for modern homeservers.

10. **Configurable credentials** - Everything is hardcoded. Needs menuconfig/Kconfig.

## 9. Reusable Patterns

### Adopt from MatrixClientLibrary:

1. **HTTP wrapper pattern** - The approach of wrapping `esp_http_client` with a simpler
   API (GET/POST/PUT with auth flag) is clean and we should follow it.

2. **Event handler for response accumulation** - The `_http_event_handler` pattern of
   accumulating chunked data into a caller-provided buffer works well.

3. **mjson usage** - The `mjson_snprintf` for building JSON and `mjson_get_string` /
   `mjson_find` / `mjson_next` for parsing is exactly what we need.

4. **WiFi init pattern** - The event group based blocking WiFi initialization is
   standard ESP-IDF practice and works well.

5. **URL construction** - Building URLs with `snprintf` and the path-only approach
   (host + path concatenation) is straightforward.

6. **Login flow** - The login request/response pattern with field extraction is directly
   reusable.

7. **Sync response parsing** - The nested `mjson_next` iteration pattern for extracting
   timeline events from sync responses is the right approach.

8. **Certificate bundle** - Using `esp_crt_bundle_attach` for TLS validation is the
   correct ESP-IDF approach.

## 10. Pitfalls

### What we should do differently:

1. **Larger token buffers** - Use 256+ bytes for access tokens instead of 40.

2. **Error handling** - Check HTTP status codes, return meaningful errors, implement
   retry with backoff for sync failures.

3. **Thread safety** - Avoid static buffers in functions. Use stack or heap allocation
   for request/response buffers within each function call.

4. **Sync filter** - Always use a filter to minimize data transfer. Filter to our room,
   only `m.room.message` events, no presence, no account_data.

5. **Longer sync timeout** - Use 30 seconds instead of 5 seconds to reduce unnecessary
   round-trips.

6. **NVS persistence** - Store the sync token in NVS so we do not re-process old
   messages after reboot.

7. **Separate FreeRTOS task for sync** - Run the sync loop in its own task so the main
   task can handle other duties (GPIO, watchdog, etc.).

8. **Kconfig for credentials** - Use `menuconfig` for WiFi and Matrix credentials
   instead of hardcoding.

9. **URL encoding** - The library only encodes `~`. We need proper URL encoding for
   room aliases (at minimum `#` -> `%23`, `:` -> `%3A`).

10. **Transaction IDs** - The library uses `time(NULL)` as txnId. This can collide if
    two messages are sent in the same second. Use an incrementing counter or combine
    timestamp with a counter.

11. **Reconnection** - No handling of WiFi or HTTP disconnection/reconnection. We need
    automatic recovery.

12. **Buffer overflow** - The `vTaskDelay` in the event handler and the `MIN` clamping
    protect against overflow, but we should also check `copy_len` is not negative
    (when buffer is full).
