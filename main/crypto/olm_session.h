#ifndef OLM_SESSION_H
#define OLM_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

typedef struct {
    uint8_t key[32];
    uint32_t index;
} olm_chain_t;

typedef struct {
    uint8_t root_key[32];
    uint8_t our_ratchet_private[32];
    uint8_t our_ratchet_public[32];
    uint8_t their_ratchet_key[32];
    olm_chain_t sending_chain;
    olm_chain_t receiving_chain;
    uint8_t their_identity_key[32];
    bool initialized;
    bool received_message;
} olm_session_t;

/*
 * Create outbound session (Alice -> Bob).
 * our_identity_curve_private: our Curve25519 identity private key
 * their_identity_curve_public: Bob's Curve25519 identity public key
 * their_one_time_key_public: Bob's claimed one-time key
 * ephemeral_public_out: filled with our ephemeral public key (for pre-key msg)
 */
esp_err_t olm_session_create_outbound(olm_session_t *session,
                                       const uint8_t our_identity_curve_private[32],
                                       const uint8_t their_identity_curve_public[32],
                                       const uint8_t their_one_time_key_public[32],
                                       uint8_t ephemeral_public_out[32]);

/*
 * Create inbound session (Bob receives pre-key from Alice).
 * our_identity_curve_private: our Curve25519 identity private key
 * our_one_time_key_private: our consumed OTK private key
 * their_identity_curve_public: Alice's Curve25519 identity public key
 * their_ephemeral_public: Alice's ephemeral public key (from pre-key msg)
 */
esp_err_t olm_session_create_inbound(olm_session_t *session,
                                      const uint8_t our_identity_curve_private[32],
                                      const uint8_t our_one_time_key_private[32],
                                      const uint8_t their_identity_curve_public[32],
                                      const uint8_t their_ephemeral_public[32]);

/*
 * Encrypt plaintext. Output is the full Olm message (inner or pre-key).
 * msg_type_out: 0 for pre-key (first message), 1 for normal.
 */
esp_err_t olm_session_encrypt(olm_session_t *session,
                               const uint8_t *plaintext, size_t plaintext_len,
                               uint8_t *out, size_t out_size, size_t *out_len,
                               int *msg_type_out);

/*
 * Decrypt an Olm message.
 * msg_type: 0 for pre-key, 1 for normal (from the JSON ciphertext object).
 */
esp_err_t olm_session_decrypt(olm_session_t *session, int msg_type,
                               const uint8_t *message, size_t message_len,
                               uint8_t *plaintext, size_t plaintext_size,
                               size_t *plaintext_len);

#endif /* OLM_SESSION_H */
