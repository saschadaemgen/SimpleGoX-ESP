# Wiring Guide

## T-Deck Plus GPIO Usage

The LilyGo T-Deck Plus has many GPIOs allocated to built-in peripherals.
Below is a summary of known assignments (may vary by hardware revision).
Based on the official `utilities.h` from Xinyuan-LilyGO/T-Deck repository.

### GPIOs used by T-Deck Plus peripherals

| GPIO | Function                          |
|------|-----------------------------------|
| 0    | Trackball click / boot strapping  |
| 1    | Trackball LEFT                    |
| 2    | Trackball RIGHT                   |
| 3    | Trackball UP                      |
| 4    | Microphone / Battery ADC          |
| 5    | I2S WS (speaker)                  |
| 6    | I2S BCK (speaker)                 |
| 7    | I2S data out (speaker)            |
| 8    | I2C SCL (keyboard, touch)         |
| 9    | SPI DC (display)                  |
| 10   | Display CS                        |
| 11   | SPI SCLK (display, LoRa, SD)     |
| 12   | SPI MOSI (display, LoRa, SD)     |
| 13   | LoRa CS                           |
| 14   | LoRa DIO1 (interrupt)             |
| 15   | Trackball DOWN                    |
| 16   | Peripheral power enable           |
| 17   | LoRa BUSY                         |
| 18   | I2C SDA (keyboard, touch)         |
| 19   | USB D-                            |
| 20   | USB D+                            |
| 39   | SD MISO                           |
| 40   | SD CS                             |
| 42   | Display backlight                 |
| 45   | LoRa RST                          |
| 46   | Keyboard interrupt                |

### GPIOs available for external use

On the T-Deck Plus, most GPIOs are consumed by peripherals. The Grove
connector exposes GPIO 43 (TX0) and GPIO 44 (RX0), which are the most
physically accessible pins for external wiring.

| GPIO | Notes                                          |
|------|------------------------------------------------|
| 43   | Grove TX - best choice, loses serial TX output |
| 44   | Grove RX - second choice, loses serial input   |
| 21   | May be free (verify on your board revision)    |
| 47   | May be free (verify on your board revision)    |
| 48   | May be free (verify on your board revision)    |

**Important:** Always verify against your specific T-Deck Plus hardware
revision. Pin assignments may differ between v1.0, v2.0, and Plus.
Check the schematic PDF from LilyGo's GitHub repository.

### Recommended GPIO for relay

**Default: GPIO 43** (Grove connector TX pin)

This is exposed on the Grove connector, making it physically accessible
without soldering. The trade-off is losing UART0 TX debug output via
serial monitor. For production deployments this is acceptable.

**Avoid GPIO 2** - it is used by the trackball (RIGHT direction) on
the T-Deck Plus and will cause conflicts.

For generic ESP32-S3 boards (not T-Deck Plus), GPIO 2 is typically fine.

The GPIO pin is configurable via `idf.py menuconfig` under
"SimpleGoX ESP Configuration" -> "Relay GPIO Pin".

## Light Switch Wiring

### Components

- LilyGo T-Deck Plus (ESP32-S3) or any ESP32-S3 board
- 1-channel 5V relay module
- Jumper wires

### Connections (T-Deck Plus via Grove)

| T-Deck Plus Pin   | Relay Module Pin | Description            |
|--------------------|------------------|------------------------|
| GPIO 43 (Grove TX) | IN               | Control signal         |
| 5V (Grove VCC)     | VCC              | Power for relay coil   |
| GND (Grove GND)    | GND              | Common ground          |

### Connections (generic ESP32-S3 board)

| ESP32 Pin         | Relay Module Pin | Description            |
|-------------------|------------------|------------------------|
| GPIO 2 (or other) | IN               | Control signal         |
| 5V                | VCC              | Power for relay coil   |
| GND               | GND              | Common ground          |

### Relay Output

Connect the load (light bulb, LED strip, etc.) to the relay's
NO (Normally Open) and COM (Common) terminals.

- When GPIO is HIGH: relay closes, load is powered
- When GPIO is LOW: relay opens, load is off

### LED Testing (No Relay)

For testing without a relay, connect an LED with a 220 ohm resistor
between the configured GPIO pin and GND. This is the recommended
first test to verify the firmware works before connecting a relay.

### Safety

When switching mains voltage (110V/230V AC):
- Use a relay rated for the voltage and current of your load
- Use proper isolation between low-voltage and high-voltage sides
- Never work on live mains wiring
- Consider using a solid-state relay (SSR) for safer mains switching
- Ensure proper enclosure for any mains-connected components
