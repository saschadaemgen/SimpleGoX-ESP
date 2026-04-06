# First Flash Guide

Step-by-step instructions for the very first test on hardware.

## Prerequisites

- ESP-IDF 5.5.x installed
- T-Deck Plus (or any ESP32-S3 board) connected via USB
- Homeserver setup completed (see HOMESERVER-SETUP.md)
- WiFi network available (2.4 GHz)

## 1. Connect Hardware

1. Connect the T-Deck Plus to your computer via USB-C
2. Identify the COM port:
   - **Windows PowerShell:** `Get-WmiObject Win32_SerialPort | Select-Object DeviceID, Description`
   - **Windows Device Manager:** Look under "Ports (COM & LPT)"
   - **Linux:** `ls /dev/ttyACM* /dev/ttyUSB*`
3. Note the COM port (e.g. `COM6` or `/dev/ttyACM0`)

## 2. Set Target

```bash
idf.py set-target esp32s3
```

## 3. Configure

```bash
idf.py menuconfig
```

Navigate to **"SimpleGoX ESP Configuration"** and set:

| Setting                | Value                              |
|------------------------|------------------------------------|
| WiFi SSID              | Your 2.4 GHz WiFi network name     |
| WiFi Password          | Your WiFi password                  |
| Matrix Homeserver URL  | `https://matrix.simplego.dev`       |
| Matrix Username        | `iot-light`                         |
| Matrix Password        | The password you set for iot-light  |
| Matrix Room            | `#iot:simplego.dev`                 |
| Relay GPIO Pin         | `2` (or your chosen pin)            |

Save and exit (S, then Q in menuconfig).

## 4. Build

```bash
idf.py build
```

Expected: Build completes with "Project build complete."

## 5. Flash

```bash
idf.py -p COM6 flash
```

Replace `COM6` with your actual COM port.

## 6. Monitor

```bash
idf.py -p COM6 monitor
```

Or combine flash and monitor:

```bash
idf.py -p COM6 flash monitor
```

Press `Ctrl+]` to exit the monitor.

## 7. Expected Serial Output

On successful startup, you should see output like this:

```
I (xxx) simplego: SimpleGoX ESP starting...
I (xxx) nvs_storage: NVS initialized
I (xxx) simplego: Connecting to WiFi SSID: YourNetwork
I (xxx) simplego: Got IP: 192.168.1.42
I (xxx) simplego: WiFi connected
I (xxx) matrix_client: Client initialized for https://matrix.simplego.dev
I (xxx) matrix_client: Logged in as @iot-light:simplego.dev (device ABCDEFGHIJ)
I (xxx) matrix_client: Resolved #iot:simplego.dev -> !roomid:simplego.dev
I (xxx) matrix_client: Joined room !roomid:simplego.dev
I (xxx) gpio_control: GPIO 2 initialized as output (relay)
I (xxx) simplego: Setup complete, sync task running
I (xxx) simplego: Sync task started
```

## 8. Test from Matrix Client

1. Open your Matrix client (Element, etc.)
2. Go to the room `#iot:simplego.dev`
3. You should see the message "SimpleGoX ESP online!"
4. Test the commands:

| Send       | Expected response                              |
|------------|------------------------------------------------|
| `status`   | Light: OFF \| Uptime: 0h 0m \| WiFi RSSI: -45 dBm |
| `on`       | Light is ON                                     |
| `status`   | Light: ON \| Uptime: 0h 1m \| WiFi RSSI: -45 dBm  |
| `off`      | Light is OFF                                    |
| `help`     | Commands: on, off, status, help, reboot         |
| `reboot`   | Rebooting...                                    |

## 9. Troubleshooting

### WiFi connection fails

- Check that the SSID and password are correct in menuconfig
- Ensure the WiFi network is 2.4 GHz (ESP32 does not support 5 GHz)
- Check signal strength (move closer to the router)
- Monitor output will show retry attempts

### Matrix login fails

- Verify the homeserver URL is correct (include `https://`)
- Check username and password
- Ensure the user account exists (see HOMESERVER-SETUP.md)
- Check serial output for HTTP error codes

### No "online" message in room

- Verify the room exists and the alias resolves
- Check that the room is unencrypted
- Look at serial output for join/send errors

### No response to commands

- Messages from the device's own user are ignored (no echo)
- Send commands from a different Matrix account
- Check serial output for sync errors
- Verify the sync task is running ("Sync task started" in log)

### Device reboots repeatedly

- Check that the main task stack size is 16384 (menuconfig)
- Check for panic messages in serial output
- Reduce MATRIX_RESPONSE_BUF_SIZE if running out of heap

### Flash fails

- Try holding the BOOT button while pressing RESET
- Check USB cable (some cables are charge-only)
- Try a different USB port
- On T-Deck Plus: the USB-C port is used for both power and programming
