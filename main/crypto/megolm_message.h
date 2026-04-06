#ifndef MEGOLM_MESSAGE_H
#define MEGOLM_MESSAGE_H

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define MEGOLM_PROTOCOL_VERSION 0x03

typedef struct {
    uint32_t message_index;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
} megolm_payload_t;

/* Encode payload protobuf (without MAC or signature). Returns bytes written. */
size_t megolm_payload_encode(const megolm_payload_t *msg, uint8_t *out, size_t out_size);

/* Decode payload protobuf. ciphertext points into input buffer. */
esp_err_t megolm_payload_decode(const uint8_t *buf, size_t buf_len, megolm_payload_t *msg);

#endif /* MEGOLM_MESSAGE_H */
