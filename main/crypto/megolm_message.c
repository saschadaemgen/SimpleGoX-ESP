#include "megolm_message.h"
#include "olm_message.h" /* reuse varint encode/decode */
#include <string.h>

#define WIRE_VARINT 0
#define WIRE_LENGTH 2
#define TAG(field, wire) (((field) << 3) | (wire))

size_t megolm_payload_encode(const megolm_payload_t *msg, uint8_t *out, size_t out_size)
{
    if (msg == NULL || out == NULL || out_size < 16) {
        return 0;
    }

    size_t pos = 0;

    /* Version byte */
    out[pos++] = MEGOLM_PROTOCOL_VERSION;

    /* Field 1: message_index (tag 0x08 = field 1, varint) */
    if (pos + 6 > out_size) { return 0; }
    out[pos++] = TAG(1, WIRE_VARINT);
    pos += olm_varint_encode(msg->message_index, out + pos);

    /* Field 2: ciphertext (tag 0x12 = field 2, length-delimited) */
    if (pos + 1 + 5 + msg->ciphertext_len > out_size) { return 0; }
    out[pos++] = TAG(2, WIRE_LENGTH);
    pos += olm_varint_encode((uint32_t)msg->ciphertext_len, out + pos);
    memcpy(out + pos, msg->ciphertext, msg->ciphertext_len);
    pos += msg->ciphertext_len;

    return pos;
}

esp_err_t megolm_payload_decode(const uint8_t *buf, size_t buf_len, megolm_payload_t *msg)
{
    if (buf == NULL || msg == NULL || buf_len < 3) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(msg, 0, sizeof(megolm_payload_t));

    size_t pos = 0;
    if (buf[pos] != MEGOLM_PROTOCOL_VERSION) {
        return ESP_FAIL;
    }
    pos++;

    while (pos < buf_len) {
        if (pos >= buf_len) { break; }
        uint8_t tag = buf[pos++];
        uint8_t field_num = tag >> 3;
        uint8_t wire_type = tag & 0x07;

        if (wire_type == WIRE_VARINT) {
            uint32_t val;
            size_t consumed = olm_varint_decode(buf + pos, buf_len - pos, &val);
            if (consumed == 0) { return ESP_FAIL; }
            pos += consumed;
            if (field_num == 1) { msg->message_index = val; }
        } else if (wire_type == WIRE_LENGTH) {
            uint32_t len;
            size_t consumed = olm_varint_decode(buf + pos, buf_len - pos, &len);
            if (consumed == 0) { return ESP_FAIL; }
            pos += consumed;
            if (pos + len > buf_len) { return ESP_FAIL; }
            if (field_num == 2) {
                msg->ciphertext = buf + pos;
                msg->ciphertext_len = len;
            }
            pos += len;
        } else {
            return ESP_FAIL;
        }
    }

    return ESP_OK;
}
