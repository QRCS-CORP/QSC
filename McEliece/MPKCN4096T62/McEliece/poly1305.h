/**
* \file poly1305.h
* \brief <b>Poly1305 header definition</b> \n
* Contains the public api and documentation for the Poly1305 implementation.
*
* \author John Underhill
* \date April 7, 2018
* \remarks For usage examples, see poly1305_kat.h
*
* <b>Poly1305 Examples</b> \n
* \code
*
* uint8_t key[POLY1305_KEY_SIZE];
* uint8_t mac[POLY1305_MAC_SIZE];
* uint8_t msg[34];
*
* // simplified
* poly1305_compute(mac, msg, 34, key);
*
* // long-form
* size_t i;
* poly1305_state state;
*
* poly1305_initialize(&state, key);
*
* for (i = 0; i < 32; i += POLY1305_BLOCK_SIZE)
* {
*	poly1305_blockupdate(&state, msg + i);
* }
*
* poly1305_update(&state, msg + i, 2);
* poly1305_finalize(&state, mac);
*
* \endcode
*/

#ifndef POLY1305_H
#define POLY1305_H

#include "common.h"

/*!
\def POLY1305_BLOCK_SIZE
* The natural block size of the message input
*/
#define POLY1305_BLOCK_SIZE 16

/*!
\def POLY1305_KEY_SIZE
* The Poly1305 key size
*/
#define POLY1305_KEY_SIZE 32

/*!
\def POLY1305_MAC_SIZE
* The Poly1305 MAC code size
*/
#define POLY1305_MAC_SIZE 16

/*! \struct poly1305_state
* Internal: contains the Poly1305 state
*/
typedef struct poly1305_state
{
	uint32_t h[5];
	uint32_t k[4];
	uint32_t r[5];
	uint32_t s[4];
	uint8_t buf[POLY1305_BLOCK_SIZE];
	size_t fnl;
	size_t rmd;
} poly1305_state;


/**
* \brief Update the poly1305 generator with a single block of message input.
* Absorbs block sized lengths of input message into the state.
*
* \warning Message length must be a single 16 byte message block. \n
*
* \param state The function state; must be initialized
* \param message The input message byte array
*/
void poly1305_blockupdate(poly1305_state* state, const uint8_t* message);

/**
* \brief Compute the MAC code and return the result in the mac byte array.
*
* \warning The output array must be at least 16 bytes in length.
*
* \param mac The output byte array; receives the MAC code
* \param message The message input byte array
* \param msglen The number of message bytes to process
* \param key The 32 byte key array
*/
void poly1305_compute(uint8_t mac[POLY1305_MAC_SIZE], const uint8_t* message, size_t msglen, const uint8_t key[POLY1305_KEY_SIZE]);

/**
* \brief Finalize the message state and returns the MAC code.
* Absorb the last block of message and create the MAC array. \n
*
* \param state The function state; must be initialized
* \param mac The MAC byte array; receives the MAC code
*/
void poly1305_finalize(poly1305_state* state, uint8_t mac[POLY1305_MAC_SIZE]);

/**
* \brief Initialize the state with the secret key.
*
* \param state The function state
* \param key The secret key byte array
*/
void poly1305_initialize(poly1305_state* state, const uint8_t key[POLY1305_KEY_SIZE]);

/**
* \brief Reset the state values to zero.
*
* \param state The function state
*/
void poly1305_reset(poly1305_state* state);

/**
* \brief Update the poly1305 generator with a length of message input.
* Absorbs the input message into the state.
*
* \param state The function state; must be initialized
* \param message The input message byte array
* \param msglen The number of input message bytes to process
*/
void poly1305_update(poly1305_state* state, const uint8_t* message, size_t msglen);

/**
* \brief Verify a MAC code.
* Tests the code against the message and returns MQC_STATUS_SUCCESS or MQC_STATUS_FAILURE.
*
* \param mac The MAC code byte array to test
* \param message The input message byte array
* \param msglen The number of input message bytes to process
* \param key The secret key byte array
*/
mqc_status poly1305_verify(const uint8_t mac[POLY1305_MAC_SIZE], const uint8_t* message, size_t msglen, const uint8_t key[POLY1305_KEY_SIZE]);

#endif
