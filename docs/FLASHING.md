# Build and Flash Instructions

## Prerequisites

1. Install ESP-IDF 5.5.x following the official guide:
   https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32s3/get-started/

2. Copy mjson source files into `components/mjson/`:
   - Download `mjson.h` and `mjson.c` from https://github.com/cesanta/mjson
   - Place them in `components/mjson/`

## Set Target

```bash
idf.py set-target esp32s3
```

## Configure

```bash
idf.py menuconfig
```

Navigate to "SimpleGoX ESP Configuration" and set:
- WiFi SSID and password
- Matrix homeserver URL (default: https://matrix.simplego.dev)
- Matrix username and password
- Matrix room alias (default: #iot:simplego.dev)
- Relay GPIO pin (default: 2)

## Build

```bash
idf.py build
```

## Flash

Connect the ESP32-S3 via USB and run:

```bash
idf.py flash
```

## Monitor

```bash
idf.py monitor
```

Or combine flash and monitor:

```bash
idf.py flash monitor
```

Press `Ctrl+]` to exit the monitor.

## Troubleshooting

### WiFi connection fails
- Check SSID and password in menuconfig
- Ensure the WiFi network is 2.4 GHz (ESP32 does not support 5 GHz)

### Matrix login fails
- Verify the homeserver URL is correct and reachable
- Check username and password
- Ensure the user account exists on the homeserver

### No messages received
- Verify the room exists and is unencrypted
- Check that the bot user has joined the room
- Look at the serial monitor for error messages
