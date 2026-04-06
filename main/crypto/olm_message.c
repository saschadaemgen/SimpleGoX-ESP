#include "olm_message.h"
#include "crypto_utils.h"
#include <string.h>

/* Protobuf wire types */
#define WIRE_VARINT 0
#define WIRE_LENGTH 2

/* Tag = (field_number << 3) | wire_type */
#define TAG(field, wire) (((field) << 3) | (wire))

size_t olm_varint_encode(uint32_t value, uint8_t *out)
{
    size_t pos = 0;
    while (value >= 0x80) {
        out[pos++] = (uint8_t)(value | 0x80);
        value >>= 7;
    }
    out[pos++] = (uint8_t)value;
    return pos;
}

size_t olm_varint_decode(const uint8_t *buf, size_t buf_len, uint32_t *value)
{
    *value = 0;
    size_t pos = 0;
    int shift = 0;
    while (pos < buf_len) {
        uint8_t b = buf[pos];
        *value |= (uint32_t)(b & 0x7F) << shift;
        pos++;
        if ((b & 0x80) == 0) {
            return pos;
        }
        shift += 7;
        if (shift > 28) {
            return 0; /* overflow */
        }
    }
    return 0; /* incomplete */
}

/* Write a length-delimited field: tag + varint(len) + data */
static size_t write_bytes_field(uint8_t *out, size_t pos, size_t out_size,
                                 uint8_t tag, const uint8_t *data, size_t data_len)
{
    if (pos + 1 + 5 + data_len > out_size) { return 0; }
    out[pos++] = tag;
    pos += olm_varint_encode((uint32_t)data_len, out + pos);
    memcpy(out + pos, data, data_len);
    return pos + data_len;
}

/* Write a varint field: tag + varint(value) */
static size_t write_varint_field(uint8_t *out, size_t pos, size_t out_size,
                                  uint8_t tag, uint32_t value)
{
    if (pos + 1 + 5 > out_size) { return 0; }
    out[pos++] = tag;
    pos += olm_varint_encode(value, out + pos);
    return pos;
}

size_t olm_inner_message_encode(const olm_inner_message_t *msg,
                                 const uint8_t hmac_key[32],
                                 uint8_t *out, size_t out_size)
{
    if (msg == NULL || out == NULL || out_size < 64) {
        return 0;
    }

    size_t pos = 0;

    /* Version byte */
    out[pos++] = OLM_PROTOCOL_VERSION;

    /* Field 1: ratchet_key (tag 0x0A = field 1, length-delimited) */
    pos = write_bytes_field(out, pos, out_size, TAG(1, WIRE_LENGTH),
                            msg->ratchet_key, 32);
    if (pos == 0) { return 0; }

    /* Field 2: chain_index (tag 0x10 = field 2, varint) */
    pos = write_varint_field(out, pos, out_size, TAG(2, WIRE_VARINT),
                             msg->chain_index);
    if (pos == 0) { return 0; }

    /* Field 4: ciphertext (tag 0x22 = field 4, length-delimited) */
    pos = write_bytes_field(out, pos, out_size, TAG(4, WIRE_LENGTH),
                            msg->ciphertext, msg->ciphertext_len);
    if (pos == 0) { return 0; }

    /* HMAC-SHA-256, truncated to 8 bytes */
    if (hmac_key != NULL && pos + 8 <= out_size) {
        uint8_t full_mac[32];
        crypto_hmac_sha256(hmac_key, 32, out, pos, full_mac);
        memcpy(out + pos, full_mac, 8);
        pos += 8;
        crypto_wipe(full_mac, sizeof(full_mac));
    }

    return pos;
}

esp_err_t olm_inner_message_decode(const uint8_t *buf, size_t buf_len,
                                    olm_inner_message_t *msg)
{
    if (buf == NULL || msg == NULL || buf_len < 10) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(msg, 0, sizeof(olm_inner_message_t));

    /* Strip 8-byte MAC from end for payload parsing */
    if (buf_len < 9) { return ESP_FAIL; }
    size_t payload_len = buf_len - 8;

    size_t pos = 0;
    if (buf[pos] != OLM_PROTOCOL_VERSION) {
        return ESP_FAIL;
    }
    pos++;

    while (pos < payload_len) {
        uint8_t tag = buf[pos++];
        uint8_t field_num = tag >> 3;
        uint8_t wire_type = tag & 0x07;

        if (wire_type == WIRE_VARINT) {
            uint32_t val;
            size_t consumed = olm_varint_decode(buf + pos, payload_len - pos, &val);
            if (consumed == 0) { return ESP_FAIL; }
            pos += consumed;
            if (field_num == 2) { msg->chain_index = val; }
        } else if (wire_type == WIRE_LENGTH) {
            uint32_t len;
            size_t consumed = olm_varint_decode(buf + pos, payload_len - pos, &len);
            if (consumed == 0) { return ESP_FAIL; }
            pos += consumed;
            if (pos + len > payload_len) { return ESP_FAIL; }
            if (field_num == 1 && len == 32) {
                memcpy(msg->ratchet_key, buf + pos, 32);
            } else if (field_num == 4) {
                msg->ciphertext = buf + pos;
                msg->ciphertext_len = len;
            }
            pos += len;
        } else {
            return ESP_FAIL; /* unknown wire type */
        }
    }

    return ESP_OK;
}

size_t olm_pre_key_message_encode(const olm_pre_key_message_t *msg,
                                   uint8_t *out, size_t out_size)
{
    if (msg == NULL || out == NULL || out_size < 128) {
        return 0;
    }

    size_t pos = 0;

    /* Version byte */
    out[pos++] = OLM_PROTOCOL_VERSION;

    /* Field 1: one_time_key */
    pos = write_bytes_field(out, pos, out_size, TAG(1, WIRE_LENGTH),
                            msg->one_time_key, 32);
    if (pos == 0) { return 0; }

    /* Field 2: base_key (ephemeral) */
    pos = write_bytes_field(out, pos, out_size, TAG(2, WIRE_LENGTH),
                            msg->base_key, 32);
    if (pos == 0) { return 0; }

    /* Field 3: identity_key */
    pos = write_bytes_field(out, pos, out_size, TAG(3, WIRE_LENGTH),
                            msg->identity_key, 32);
    if (pos == 0) { return 0; }

    /* Field 4: inner_message */
    pos = write_bytes_field(out, pos, out_size, TAG(4, WIRE_LENGTH),
                            msg->inner_message, msg->inner_message_len);
    if (pos == 0) { return 0; }

    return pos;
}

esp_err_t olm_pre_key_message_decode(const uint8_t *buf, size_t buf_len,
                                      olm_pre_key_message_t *msg)
{
    if (buf == NULL || msg == NULL || buf_len < 10) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(msg, 0, sizeof(olm_pre_key_message_t));

    size_t pos = 0;
    if (buf[pos] != OLM_PROTOCOL_VERSION) {
        return ESP_FAIL;
    }
    pos++;

    while (pos < buf_len) {
        uint8_t tag = buf[pos++];
        uint8_t field_num = tag >> 3;
        uint8_t wire_type = tag & 0x07;

        if (wire_type == WIRE_LENGTH) {
            uint32_t len;
            size_t consumed = olm_varint_decode(buf + pos, buf_len - pos, &len);
            if (consumed == 0) { return ESP_FAIL; }
            pos += consumed;
            if (pos + len > buf_len) { return ESP_FAIL; }
            if (field_num == 1 && len == 32) {
                memcpy(msg->one_time_key, buf + pos, 32);
            } else if (field_num == 2 && len == 32) {
                memcpy(msg->base_key, buf + pos, 32);
            } else if (field_num == 3 && len == 32) {
                memcpy(msg->identity_key, buf + pos, 32);
            } else if (field_num == 4) {
                msg->inner_message = buf + pos;
                msg->inner_message_len = len;
            }
            pos += len;
        } else if (wire_type == WIRE_VARINT) {
            uint32_t val;
            size_t consumed = olm_varint_decode(buf + pos, buf_len - pos, &val);
            if (consumed == 0) { return ESP_FAIL; }
            pos += consumed;
        } else {
            return ESP_FAIL;
        }
    }

    return ESP_OK;
}
