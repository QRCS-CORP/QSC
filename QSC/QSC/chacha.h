/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
*/

#ifndef QSC_CHACHA20_H
#define QSC_CHACHA20_H

#include "common.h"

/**
* \file chacha.h
* \brief Contains the public api and documentation for the ChaChaPoly20 implementation
* Key sizes are 128- and 256-bit (16 and 32 byte).
* The nonce must be 64-bits in length (8 bytes).
*
* \author John Underhill
* \date April 7, 2018
*
* ChaCha encryption example \n
* \code
*
* size_t const MSG_LEN = 1024;
* uint8_t key[32] = {...};
* uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = {...};
* uint8_t msg[MSG_LEN] = {...};
* uint8_t out[MSG_LEN] = { 0 };
*
* qsc_chacha_state ctx;
* qsc_chacha_initialize(&ctx, key, 32, nonce);
* qsc_chacha_transform(&ctx, out, msg, MSG_LEN);
*
* \endcode
* An implementation of the ChaChaPoly20 stream cipher by Daniel J. Bernstein.
* Implementation contains AVX, AVX2, and AVX512 intrinsics support.
* \remarks For usage examples, see chacha_test.h
*/

/*!
* \def QSC_CHACHA_BLOCK_SIZE
* \brief The internal block size
*/
#define QSC_CHACHA_BLOCK_SIZE 64

/*!
* \def QSC_CHACHA_KEY128_SIZE
* \brief The size of the 128-bit secret key array in bytes
*/
#define QSC_CHACHA_KEY128_SIZE 16

/*!
* \def QSC_CHACHA_KEY256_SIZE
* \brief The size of the 256-bit secret key array in bytes
*/
#define QSC_CHACHA_KEY256_SIZE 32

/*!
* \def QSC_CHACHA_NONCE_SIZE
* \brief The size of the nonce array in bytes
*/
#define QSC_CHACHA_NONCE_SIZE 8

/*!
* \def QSC_CHACHA_ROUND_COUNT
* \brief The number of mixing rounds used by ChaCha
*/
#define QSC_CHACHA_ROUND_COUNT 20

/*!
* \struct qsc_chacha_state
* \brief Internal: contains the qsc_chacha_state state
*/
QSC_EXPORT_API typedef struct
{
	uint32_t state[16];	/*!< The internal state array */
} qsc_chacha_state;

/*! 
* \struct qsc_chacha_keyparams
* \brief The key parameters structure containing key, and nonce arrays and lengths.
* Use this structure to load an input cipher-key and nonce using the qsc_chacha_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The key must be QSC_CHACHA_KEY128_SIZE or QSC_CHACHA_KEY256_SIZE in length.
* The nonce is always QSC_CHACHA_NONCE_SIZE in length.
*/
QSC_EXPORT_API typedef struct
{
	const uint8_t* key;	/*!< The input cipher key */
	size_t keylen;		/*!< The length in bytes of the cipher key */
	uint8_t* nonce;		/*!< The nonce or initialization vector */
} qsc_chacha_keyparams;

/**
* \brief Dispose of the ChaCha cipher state.
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys internal arrays and data
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_chacha_dispose(qsc_chacha_state* ctx);

/**
* \brief Initialize the state with the secret key and nonce.
*
* \warning The key array must be either 16 or 32 bytes in length
* \warning The nonce array must be 8 bytes bytes in length
*
* \param ctx: [struct] The cipher state structure
* \param keyparams: [const][struct] The secret key and nonce structure
*/
QSC_EXPORT_API void qsc_chacha_initialize(qsc_chacha_state* ctx, const qsc_chacha_keyparams* keyparams);

/**
* \brief Transform a length of input text.
*
* \param ctx: [struct] The cipher state structure
* \param output: A pointer to the output byte array
* \param input: [const] A pointer to the input byte array
* \param length: The number of bytes to process
*/
QSC_EXPORT_API void qsc_chacha_transform(qsc_chacha_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

#endif
