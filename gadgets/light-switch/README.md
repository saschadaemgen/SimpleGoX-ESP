# Light Switch Gadget

The first SimpleGoX gadget: a relay-controlled light switch operated
via Matrix room messages.

## Behavior

- Send `on` in the Matrix room to turn the light on
- Send `off` to turn it off
- Send `status` to query the current state

The device responds with a confirmation message in the room.

## Wiring

See [../../docs/WIRING.md](../../docs/WIRING.md) for connection details.

## Parts List

- 1x ESP32-S3 board
- 1x 5V single-channel relay module
- 3x Jumper wires (GPIO, VCC, GND)
- 1x USB cable for power and programming
