# Homeserver Setup

Instructions for setting up the Matrix homeserver for SimpleGoX ESP.

## Prerequisites

- Matrix homeserver running at https://matrix.simplego.dev (Tuwunel)
- Admin access to the homeserver
- A Matrix client (Element, etc.) for room creation

## 1. Create the IoT User

The ESP device needs its own Matrix account: `@iot-light:simplego.dev`

### Option A: Via Synapse-compatible Admin API

If Tuwunel supports the Synapse admin API:

```bash
curl -X PUT "https://matrix.simplego.dev/_synapse/admin/v2/users/@iot-light:simplego.dev" \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "<CHOOSE_A_PASSWORD>",
    "displayname": "IoT Light Switch",
    "admin": false
  }'
```

### Option B: Via Client Registration

If registration is enabled on the server:

```bash
curl -X POST "https://matrix.simplego.dev/_matrix/client/v3/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "iot-light",
    "password": "<CHOOSE_A_PASSWORD>",
    "auth": {"type": "m.login.dummy"}
  }'
```

Note: Tuwunel may have different admin APIs than Synapse. Check the
Tuwunel documentation for the correct approach.

## 2. Create the IoT Room

### Using Element (recommended)

1. Open Element and log in as `@sash710:simplego.dev`
2. Create a new room:
   - Name: "IoT"
   - Topic: "SimpleGoX ESP device control"
   - **IMPORTANT: Disable encryption** (toggle off "Enable end-to-end encryption")
   - Visibility: Private (or Public if you prefer)
3. Set the room alias:
   - Room Settings -> General -> Local Addresses
   - Add alias: `#iot:simplego.dev`
4. Invite `@iot-light:simplego.dev` to the room

### Using curl (alternative)

```bash
# Create room (must be logged in as admin)
curl -X POST "https://matrix.simplego.dev/_matrix/client/v3/createRoom" \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "IoT",
    "topic": "SimpleGoX ESP device control",
    "room_alias_name": "iot",
    "visibility": "private",
    "preset": "private_chat",
    "creation_content": {
      "m.federate": false
    },
    "initial_state": []
  }'
```

**Important:** Do NOT include `"m.room.encryption"` in `initial_state`.
The room must remain unencrypted for the ESP device to participate.

### Invite the IoT user

```bash
curl -X POST "https://matrix.simplego.dev/_matrix/client/v3/rooms/<ROOM_ID>/invite" \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "@iot-light:simplego.dev"}'
```

## 3. Verification

Before flashing the ESP, verify everything works with curl.

### Test login

```bash
curl -s -X POST "https://matrix.simplego.dev/_matrix/client/v3/login" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "m.login.password",
    "identifier": {"type": "m.id.user", "user": "iot-light"},
    "password": "<PASSWORD>",
    "initial_device_display_name": "curl-test"
  }'
```

Expected: JSON with `access_token`, `user_id`, `device_id`.
Save the `access_token` for the next steps.

### Test room alias resolution

```bash
curl -s "https://matrix.simplego.dev/_matrix/client/v3/directory/room/%23iot%3Asimplego.dev"
```

Expected: JSON with `room_id` (e.g. `!abc123:simplego.dev`).

### Test joining the room

```bash
curl -s -X POST "https://matrix.simplego.dev/_matrix/client/v3/join/%23iot%3Asimplego.dev" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Expected: JSON with `room_id`.

### Test sending a message

```bash
curl -s -X PUT \
  "https://matrix.simplego.dev/_matrix/client/v3/rooms/<ROOM_ID>/send/m.room.message/test1" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"msgtype": "m.text", "body": "Hello from curl!"}'
```

Expected: JSON with `event_id`.

### Test sync

```bash
curl -s "https://matrix.simplego.dev/_matrix/client/v3/sync?timeout=1000" \
  -H "Authorization: Bearer <TOKEN>" | python -m json.tool | head -20
```

Expected: JSON with `next_batch` and room data.

### Clean up test device

```bash
curl -s -X POST "https://matrix.simplego.dev/_matrix/client/v3/logout" \
  -H "Authorization: Bearer <TOKEN>"
```

## 4. Checklist

- [ ] User `@iot-light:simplego.dev` exists and can log in
- [ ] Room `#iot:simplego.dev` exists
- [ ] Room encryption is DISABLED
- [ ] IoT user is invited to (or has joined) the room
- [ ] Login via curl returns an access token
- [ ] Room alias resolves to a room ID
- [ ] Messages can be sent to the room
- [ ] Sync returns room data
