<p align="center">
  <img src=".github/assets/simplegox_esp_banner.png" alt="SimpleGoX ESP" width="1500" height="230">
</p>

<h1 align="center">SimpleGoX ESP</h1>

<p align="center">
  <strong>The world's first IoT devices that speak Matrix natively on ESP32.</strong><br>
  Control lights, read sensors, send alerts - all through Matrix rooms.<br>
  No cloud, no bridge, no MQTT. Just pure Matrix Client-Server API on a $10 microcontroller.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License"></a>
  <a href="#status"><img src="https://img.shields.io/badge/version-0.1.0--alpha-orange.svg" alt="Version"></a>
  <a href="#getting-started"><img src="https://img.shields.io/badge/platform-ESP32--S3-lightgrey.svg" alt="Platform"></a>
  <a href="#getting-started"><img src="https://img.shields.io/badge/framework-ESP--IDF%205.5-blue.svg" alt="Framework"></a>
  <a href="https://matrix.org"><img src="https://img.shields.io/badge/protocol-Matrix-black.svg" alt="Matrix"></a>
  <a href="#"><img src="https://img.shields.io/badge/language-C-yellow.svg" alt="Language"></a>
</p>

---

SimpleGoX ESP puts the Matrix protocol onto microcontrollers. The [Matrix specification](https://spec.matrix.org/latest/) explicitly names IoT devices as intended clients, but until now nobody has built one. This project changes that.

A $10 ESP32 connects to WiFi, logs into your Matrix homeserver, joins a room, and starts listening for commands. Send "on" in the room and a relay switches. Send "status" and it reports back. All communication flows through standard Matrix rooms that you can access from Element, FluffyChat, or any other Matrix client.

No proprietary cloud service. No separate IoT protocol. No MQTT bridge to maintain. The device is a Matrix client, just like your phone or laptop.

Part of the [SimpleGoX ecosystem](https://github.com/saschadaemgen) - bringing the Matrix protocol to dedicated hardware.

---

## How It Works

```
 Your Phone (Element)                    ESP32 + Relay
 +------------------+                   +------------------+
 |                  |                   |                  |
 |  Send: "on"      |                   |  GPIO --> Relay  |
 |                  |     Matrix        |       |          |
 |  #iot:server     +---Homeserver------+  Light Switch    |
 |                  |                   |                  |
 |  < "Light is ON" |                   |  Send: response  |
 |                  |                   |                  |
 +------------------+                   +------------------+
```

1. The ESP32 connects to WiFi and logs into your Matrix homeserver
2. It joins a designated room and starts long-polling for new messages
3. When you send a command ("on", "off", "status"), it parses the message
4. It executes the hardware action (switch relay, read sensor)
5. It sends a response back to the same room
6. The sync token is persisted to flash, so it survives reboots without replaying old messages

---

## Gadgets

Each gadget is a specific hardware configuration running the same firmware core. Start with the Light Switch. Add sensors and buttons as you go.

| # | Gadget | What it does | Hardware | Cost |
|:--|:-------|:-------------|:---------|:-----|
| 1 | **Light Switch** | Control a lamp via Matrix | ESP32 + Relay module | ~$12 |
| 2 | **Temperature Bot** | Posts temperature and humidity to a room | ESP32 + DHT22 sensor | ~$13 |
| 3 | **Panic Button** | One press sends an alert to your contacts | ESP32 + Big red button | ~$11 |
| 4 | **Matrix Display** | Shows the latest message from a room | ESP32 + OLED/E-Paper | ~$18 |
| 5 | **Doorbell** | Ring the bell, get a Matrix notification | ESP32 + Button + Buzzer | ~$13 |
| 6 | **T-Deck Chat** | Retro handheld Matrix messenger | LilyGo T-Deck Plus | ~$60 |

---

## Commands

Send these as plain text messages in the IoT room. Commands are case-insensitive.

| Command | Response | Action |
|:--------|:---------|:-------|
| `on` | "Light is ON" | Switches the relay to HIGH |
| `off` | "Light is OFF" | Switches the relay to LOW |
| `status` | "Light is OFF, Uptime: 2h 15m, WiFi: -42 dBm" | Reports device state, uptime, and signal strength |
| `help` | Lists all available commands | No hardware action |
| `reboot` | "Rebooting..." | Restarts the ESP32 |

The device ignores its own messages to prevent echo loops.

---

## Architecture

```
+---------------------------------------------------------------+
|                      APPLICATION LAYER                        |
|           Light Switch  /  Sensors  /  Alerts                 |
+---------------------------------------------------------------+
|                     MATRIX CLIENT LAYER                       |
|      Login  /  Join  /  Sync  /  Send  /  NVS Persistence    |
+---------------------------------------------------------------+
|                      TRANSPORT LAYER                          |
|        esp_http_client  /  TLS 1.3  /  WiFi STA              |
+---------------------------------------------------------------+
|                     HARDWARE LAYER                            |
|          GPIO  /  Relay  /  Sensors  /  FreeRTOS              |
+---------------+---------------+---------------+---------------+
|  T-Deck Plus  |  ESP32-S3     |  ESP32-C3     |   Any ESP32   |
|  (Grove)      |  DevKitC      |  RISC-V       |   Board       |
+---------------+---------------+---------------+---------------+
```

### Matrix Endpoints

The firmware implements a minimal but complete Matrix client using six endpoints from the [Client-Server API](https://spec.matrix.org/v1.13/client-server-api/):

| Endpoint | Method | Purpose |
|:---------|:-------|:--------|
| `/_matrix/client/v3/login` | POST | Password authentication, returns access token |
| `/_matrix/client/v3/directory/room/{alias}` | GET | Resolves room alias to room ID |
| `/_matrix/client/v3/join/{roomIdOrAlias}` | POST | Joins a room |
| `/_matrix/client/v3/rooms/{id}/send/{type}/{txn}` | PUT | Sends a message to a room |
| `/_matrix/client/v3/sync` | GET | Long-polls for new events (30s timeout, filtered) |
| `/_matrix/client/v3/logout` | POST | Invalidates the access token |

### Sync Strategy

Full `/sync` responses are too large for a microcontroller. The firmware applies aggressive filtering:

- Only the designated IoT room (by room ID)
- Only `m.room.message` events
- No presence, no typing indicators, no account data, no room state
- Timeline limited to 10 events per sync
- 30-second long-poll timeout (server holds connection open)
- `since` token persisted to NVS flash across reboots

This keeps sync responses under 32 KB, well within ESP32 memory constraints.

---

## Project Structure

```
SimpleGoX-ESP/
+-- main/
|   +-- main.c                  # Entry point, WiFi, FreeRTOS sync task
|   +-- matrix_client.h/.c      # Matrix client: login, join, sync, send
|   +-- matrix_http.h/.c        # esp_http_client wrapper with TLS
|   +-- matrix_json.h/.c        # mjson-based JSON building and parsing
|   +-- gpio_control.h/.c       # Relay and LED control
|   +-- nvs_storage.h/.c        # Sync token persistence
|   +-- Kconfig.projbuild       # menuconfig entries
+-- components/
|   +-- mjson/                  # Lightweight JSON parser (Cesanta)
+-- gadgets/
|   +-- light-switch/           # Wiring diagrams and instructions
+-- docs/
|   +-- ANALYSIS.md             # Reference library analysis
|   +-- WIRING.md               # GPIO assignments and wiring
|   +-- FLASHING.md             # Build and flash guide
|   +-- HOMESERVER-SETUP.md     # Matrix server preparation
|   +-- FIRST-FLASH.md          # Step-by-step first test
+-- LICENSE                     # Apache-2.0
+-- README.md
```

---

## Getting Started

### What You Need

| Item | Details |
|:-----|:--------|
| **ESP32 board** | Any ESP32, ESP32-S3, or ESP32-C3 board. Tested on LilyGo T-Deck Plus. |
| **Relay module** | 5V single-channel relay module (~$2) |
| **Jumper wires** | Dupont cables for connecting relay to GPIO |
| **USB-C cable** | For flashing and serial monitoring |
| **ESP-IDF 5.5.x** | Espressif IoT Development Framework ([download](https://docs.espressif.com/projects/esp-idf/en/v5.5.2/esp32s3/get-started/)) |
| **Matrix homeserver** | Any homeserver you control. Tested with [Tuwunel](https://gitlab.com/tuwunel/tuwunel). |

### Homeserver Preparation

Before flashing the ESP32, set up your Matrix homeserver:

1. **Create an IoT user** (e.g. `@iot-light:yourserver.dev`)
2. **Create a public, unencrypted room** (e.g. `#iot:yourserver.dev`)
3. **Verify with curl** that login and messaging work

Detailed instructions with curl commands in [docs/HOMESERVER-SETUP.md](docs/HOMESERVER-SETUP.md).

### Installation

**1. Clone the repository**

```bash
git clone https://github.com/saschadaemgen/SimpleGoX-ESP.git
cd SimpleGoX-ESP
```

**2. Get the mjson dependency**

```bash
git clone https://github.com/cesanta/mjson.git /tmp/mjson
cp /tmp/mjson/src/mjson.h components/mjson/
cp /tmp/mjson/src/mjson.c components/mjson/
```

**3. Set the target**

```bash
idf.py set-target esp32s3
```

For other chips, use `esp32`, `esp32c3`, etc.

**4. Configure**

```bash
idf.py menuconfig
```

Navigate to **SimpleGoX Configuration** and set:

| Setting | Example |
|:--------|:--------|
| WiFi SSID | `YourNetwork` |
| WiFi Password | `YourPassword` |
| Matrix Homeserver URL | `https://matrix.yourserver.dev` |
| Matrix Username | `iot-light` |
| Matrix Password | `YourMatrixPassword` |
| Matrix Room | `#iot:yourserver.dev` |
| Relay GPIO Pin | `43` (T-Deck Plus Grove) or `2` (generic boards) |

**5. Build and flash**

```bash
idf.py build
idf.py flash monitor -p /dev/ttyACM0
```

Replace `/dev/ttyACM0` with your serial port (`COMx` on Windows).

**6. Test**

Open the IoT room in Element or any Matrix client. You should see:

> **iot-light:** SimpleGoX ESP online!

Send `on`. The relay clicks. The device responds:

> **iot-light:** Light is ON

---

## Wiring

### Generic ESP32 Board

```
ESP32                Relay Module
+-------+           +--------+
| 3.3V  +-----------+ VCC    |
| GND   +-----------+ GND    |
| GPIO2 +-----------+ IN     |
+-------+           |    NO  +----> Lamp (+)
                     |    COM +----> Power
                     +--------+
```

### T-Deck Plus (Grove Connector)

The T-Deck Plus has a Grove connector on GPIO 43 (TX) and GPIO 44 (RX). Use GPIO 43 for relay control.

See [docs/WIRING.md](docs/WIRING.md) for detailed GPIO assignments and safety notes.

> **Warning:** Relay modules switching mains voltage (110/230V) can be lethal. If you are not experienced with mains wiring, use a low-voltage LED for testing instead.

---

## Memory Budget

The ESP32-S3 has 512 KB internal SRAM. Here is how the firmware uses it:

| Component | RAM Usage | Notes |
|:----------|:----------|:------|
| WiFi + TLS stack | ~80 KB | ESP-IDF managed |
| Sync response buffer | 32 KB | Largest single allocation |
| HTTP response buffer | 16 KB | For non-sync requests |
| Matrix client state | ~2 KB | Tokens, URLs, room ID |
| JSON build buffers | ~4 KB | Login, message, filter |
| FreeRTOS sync task | 8 KB | Task stack |
| NVS | ~4 KB | Sync token storage |
| **Total** | **~146 KB** | **~28% of available SRAM** |

Binary size: 960 KB (51% of 1.9 MB app partition free).

---

## Technical Decisions

| Decision | Rationale |
|:---------|:----------|
| **No E2E encryption** | Olm/Megolm requires significant RAM and complexity. IoT commands ("on"/"off") are not confidential. Can be added later. |
| **No Arduino** | ESP-IDF gives direct control over FreeRTOS, memory allocation, and the HTTP stack. Arduino abstractions waste resources on a constrained device. |
| **mjson for JSON** | Tiny footprint (~2 KB code), zero-allocation parsing, perfect for embedded. Used by the reference MatrixClientLibrary. |
| **Filtered sync** | Full sync responses can exceed 1 MB. Our filter keeps them under 32 KB by requesting only our room and only message events. |
| **NVS for sync token** | Survives reboots. The device picks up where it left off without replaying old messages. |
| **Counter-based txnId** | The reference library uses `time(NULL)` which collides if two messages are sent in the same second. We use an incrementing counter. |
| **Public unencrypted room** | Simplest setup. The ESP32 can join without invitation. No key exchange needed. |

---

## Why Matrix for IoT?

The [Matrix specification v1.13](https://spec.matrix.org/v1.13/) explicitly envisions IoT devices as clients:

> *"Lightweight clients which store no state"*

Matrix provides everything an IoT device needs out of the box:

| Feature | How Matrix provides it |
|:--------|:-----------------------|
| **Device authentication** | Standard login with access tokens |
| **Message routing** | Rooms act as named channels |
| **Access control** | Room membership and power levels |
| **Message history** | Server stores events, device syncs only what it needs |
| **Multiple users** | Anyone in the room can send commands |
| **Notifications** | Standard Matrix push notifications |
| **Federation** | Devices on different homeservers can share rooms |
| **Existing clients** | Control your IoT devices from Element, FluffyChat, or any Matrix client |

No proprietary protocol to learn. No vendor lock-in. No cloud subscription fees.

---

## Status

Alpha software under active development. Targeting live hardware demo at the **Matrix Community Summit Berlin, 22 May 2026**.

| Component | Status |
|:----------|:-------|
| Matrix login (password auth) | Working |
| Room alias resolution | Working |
| Room join | Working |
| Send text message | Working |
| Filtered sync (long-poll) | Working |
| Command parsing (on/off/status/help/reboot) | Working |
| GPIO relay control | Working |
| NVS sync token persistence | Working |
| WiFi connection with retry | Working |
| Kconfig credential management | Working |
| Temperature sensor gadget | Planned |
| Panic button gadget | Planned |
| Matrix display gadget | Planned |
| Doorbell gadget | Planned |
| Web-based WiFi provisioning | Planned |
| OTA firmware updates via Matrix | Planned |

---

## Background

This project was born from a simple observation: the Matrix specification names IoT as a target use case, but nobody has ever built a native Matrix IoT device. Not a bridge. Not a gateway. An actual microcontroller that speaks the Matrix Client-Server API directly.

SimpleGoX ESP is part of the broader [SimpleGoX ecosystem](https://github.com/saschadaemgen), which brings the Matrix protocol to dedicated hardware - from [full desktop clients in Rust](https://github.com/saschadaemgen/SimpleGoX) to [browser-based chat](https://github.com/saschadaemgen/GoChatX) to this: IoT devices on $10 microcontrollers.

The analysis of Patrick Scho's [MatrixClientLibrary](https://github.com/patrick-scho/MatrixClientLibrary) - the only other known C implementation of Matrix on ESP32 - informed our design decisions. We built our own client from scratch, taking the good patterns (mjson, HTTP event handler, certificate bundle) and fixing the issues (undersized buffers, missing error handling, no sync filtering, hardcoded credentials).

---

## Related Projects

| Project | Description |
|:--------|:------------|
| [SimpleGo](https://github.com/saschadaemgen/SimpleGo) | Encrypted hardware messenger on ESP32-S3 (SimpleX protocol) |
| [SimpleGoX](https://github.com/saschadaemgen/SimpleGoX) | Native Matrix desktop client in Rust |
| [GoChatX](https://github.com/saschadaemgen/GoChatX) | Browser-based Matrix client with Go backend |
| [MatrixClientLibrary](https://github.com/patrick-scho/MatrixClientLibrary) | Reference C Matrix library (Patrick Scho's master thesis) |

---

## License

Apache-2.0

---

<p align="center">
  <i>SimpleGoX ESP is an independent open-source project by IT and More Systems, Recklinghausen, Germany.</i><br>
  <i>Matrix is an open standard maintained by the <a href="https://matrix.org/foundation/">Matrix.org Foundation</a>.</i><br>
  <i>This project is not affiliated with or endorsed by the Matrix.org Foundation.</i>
</p>

<p align="center">
  <strong>SimpleGoX ESP - The world's first Matrix IoT devices.</strong>
</p>
