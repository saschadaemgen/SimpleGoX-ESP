# SimpleGoX ESP - Matrix IoT on ESP32

The world's first IoT devices that speak Matrix.

Control lights, read sensors, ring doorbells - all through Matrix rooms.
Built on $10 hardware. Open source. No cloud required.

## Status

Work in progress - targeting Matrix Community Summit Berlin, May 2026.

## Hardware

- LilyGo T-Deck Plus (ESP32-S3) or any ESP32 board
- 5V Relay module (1-channel)
- LED for testing

## Building

Requires ESP-IDF 5.5.x.

1. `idf.py set-target esp32s3`
2. `idf.py menuconfig` - Set WiFi credentials and Matrix server details
3. `idf.py build`
4. `idf.py flash monitor`

## How It Works

The ESP32 connects to WiFi, logs into your Matrix homeserver, joins a room,
and listens for commands:

- Send `on` in the room - the light turns on
- Send `off` in the room - the light turns off
- Send `status` in the room - it reports the current state

## License

Apache-2.0
