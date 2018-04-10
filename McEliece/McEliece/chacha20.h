/**
* \file chacha20.h
* \brief <b>ChaCha20 header definition</b> \n
* Contains the public api and documentation for the ChaCha20 implementation.
*
* \author John Underhill
* \date April 7, 2018
* \remarks For usage examples, see chacha_kat.h
*
* <b>Poly1305 Examples</b> \n
* \code
*
* uint8_t key[32];
* uint8_t nonce[CHACHA_NONCE_SIZE];
* uint8_t msg[133];
* uint8_t out[133];
*
* chacha_state ctx;
* chacha_initialize(&ctx, key, 32, nonce);
* chacha_transform(&ctx, out, msg, 133);
*
* \endcode
*/

#ifndef CHACHA20_H
#define CHACHA20_H

#include "common.h"

/*!
\def CHACHA_BLOCK_SIZE
* The natural block size of the message input
*/
#define CHACHA_BLOCK_SIZE 64

/*!
\def CHACHA_STATE_SIZE
* The uint32 size of the states internal array
*/
#define CHACHA_STATE_SIZE 16

#if defined(__AVX__)
/*!
\def CHACHA_AVXBLOCK_SIZE
* The minimum block size used to trigger AVX processing
*/
#define CHACHA_AVXBLOCK_SIZE (4 * CHACHA_BLOCK_SIZE)
#endif

#if defined(__AVX2__)
/*!
\def CHACHA_AVX2BLOCK_SIZE
* The minimum block size used to trigger AVX2 processing
*/
#define CHACHA_AVX2BLOCK_SIZE (8 * CHACHA_BLOCK_SIZE)
#endif

#if defined(__AVX512__)
/*!
\def CHACHA_AVX512BLOCK_SIZE
* The minimum block size used to trigger AVX512 processing
*/
#define CHACHA_AVX512BLOCK_SIZE (16 * CHACHA_BLOCK_SIZE)
#endif

/*!
\def CHACHA_NONCE_SIZE
* The size of the secret nonce array
*/
#define CHACHA_NONCE_SIZE 8

/*! \struct chacha_state
* Internal: contains the chacha_state state
*/
typedef struct chacha_state
{
	uint32_t state[16];
} chacha_state;

/**
* \brief Initialize the state with the secret key and nonce.
*
* \warning The key array must be either 16 or 32 bytes in length.
*
* \param state The function state
* \param key The secret key byte array
* \param keylen The length of the key array
* \param key The 16 byte secret nonce byte array
*/
void chacha_initialize(chacha_state* state, const uint8_t* key, size_t keylen, const uint8_t nonce[CHACHA_NONCE_SIZE]);

/**
* \brief Transform a length of input text.
*
* \param state The function state
* \param output The output byte array
* \param input The input byte array
* \param length The number of bytes to process
*/
void chacha_transform(chacha_state* state, uint8_t* output, const uint8_t* input, size_t length);

#endif