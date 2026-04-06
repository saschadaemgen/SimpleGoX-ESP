#ifndef OLM_MESSAGE_H
#define OLM_MESSAGE_H

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define OLM_PROTOCOL_VERSION 0x03
#define OLM_MSG_TYPE_PRE_KEY 0
#define OLM_MSG_TYPE_MESSAGE 1

typedef struct {
    uint8_t ratchet_key[32];
    uint32_t chain_index;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
} olm_inner_message_t;

typedef struct {
    uint8_t one_time_key[32];
    uint8_t base_key[32];
    uint8_t identity_key[32];
    const uint8_t *inner_message;
    size_t inner_message_len;
} olm_pre_key_message_t;

/* Varint encode/decode */
size_t olm_varint_encode(uint32_t value, uint8_t *out);
size_t olm_varint_decode(const uint8_t *buf, size_t buf_len, uint32_t *value);

/* Inner message (type 1): encode returns bytes written, 0 on error.
 * mac_key is used to compute 8-byte truncated HMAC appended to output. */
size_t olm_inner_message_encode(const olm_inner_message_t *msg,
                                 const uint8_t hmac_key[32],
                                 uint8_t *out, size_t out_size);
esp_err_t olm_inner_message_decode(const uint8_t *buf, size_t buf_len,
                                    olm_inner_message_t *msg);

/* Pre-key message (type 0): wraps an already-encoded inner message */
size_t olm_pre_key_message_encode(const olm_pre_key_message_t *msg,
                                   uint8_t *out, size_t out_size);
esp_err_t olm_pre_key_message_decode(const uint8_t *buf, size_t buf_len,
                                      olm_pre_key_message_t *msg);

#endif /* OLM_MESSAGE_H */
