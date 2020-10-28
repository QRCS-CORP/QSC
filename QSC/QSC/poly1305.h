/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2020 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* An implementation of the Rijndael Hash-based eXtension (RHX/RSX=eAES) symmetric block cipher.
* Written by John G. Underhill
* Updated on January 20, 2020
* Contact: develop@vtdev.com */

/**
* \file poly1305.h
* \brief <b>Poly1305 function definitions</b> \n
* Contains the public api and documentation for the Poly1305 implementation.
*
* \author John Underhill
* \date April 7, 2018
*
* <b>Poly1305 Examples</b> \n
* \code
*
* uint8_t key[QSC_POLY1305_KEY_SIZE];
* uint8_t mac[QSC_POLY1305_MAC_SIZE];
* uint8_t msg[34];
*
* // simplified
* qsc_poly1305_compute(mac, msg, 34, key);
*
* // long-form
* size_t i;
* qsc_poly1305_state ctx;
*
* qsc_poly1305_initialize(&ctx, key);
*
* for (i = 0; i < 32; i += QSC_POLY1305_BLOCK_SIZE)
* {
*	qsc_poly1305_blockupdate(&ctx, msg + i);
* }
*
* qsc_poly1305_update(&ctx, msg + i, 2);
* qsc_poly1305_finalize(&ctx, mac);
*
* \endcode
* \remarks
* For usage examples, see poly1305_test.h
*/

#ifndef QSC_POLY1305_H
#define QSC_POLY1305_H

#include "common.h"

/*!
* \def QSC_POLY1305_BLOCK_SIZE
* \brief The natural block size of the message input in bytes
*/
#define QSC_POLY1305_BLOCK_SIZE 16

/*!
* \def QSC_POLY1305_KEY_SIZE
* \brief The Poly1305 key size in bytes
*/
#define QSC_POLY1305_KEY_SIZE 32

/*!
* \def QSC_POLY1305_MAC_SIZE
* \brief The Poly1305 MAC code size in bytes
*/
#define QSC_POLY1305_MAC_SIZE 16

/*! 
* \struct qsc_poly1305_state
* \brief Internal: contains the Poly1305 state
*/
QSC_EXPORT_API typedef struct qsc_poly1305_state
{
	uint32_t h[5];
	uint32_t k[4];
	uint32_t r[5];
	uint32_t s[4];
	uint8_t buf[QSC_POLY1305_BLOCK_SIZE];
	size_t fnl;
	size_t rmd;
} qsc_poly1305_state;


/**
* \brief Update the poly1305 generator with a single block of message input.
* Absorbs block sized lengths of input message into the state.
*
* \warning Message length must be a single 16 byte message block. \n
*
* \param ctx: [struct] The function state; must be initialized
* \param message: [const] The input message byte array
*/
QSC_EXPORT_API void qsc_poly1305_blockupdate(qsc_poly1305_state* ctx, const uint8_t* message);

/**
* \brief Compute the MAC code and return the result in the mac byte array.
*
* \warning The output array must be at least 16 bytes in length.
*
* \param output: The output byte array; receives the MAC code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The 32 byte key array
*/
QSC_EXPORT_API void qsc_poly1305_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key);

/**
* \brief Finalize the message state and returns the MAC code.
* Absorb the last block of message and create the MAC array. \n
*
* \param ctx: [struct] The function state; must be initialized
* \param mac: The MAC byte array; receives the MAC code
*/
QSC_EXPORT_API void qsc_poly1305_finalize(qsc_poly1305_state* ctx, uint8_t* mac);

/**
* \brief Initialize the state with the secret key.
*
* \param ctx: [struct] The function state
* \param key: [const] The secret key byte array
*/
QSC_EXPORT_API void qsc_poly1305_initialize(qsc_poly1305_state* ctx, const uint8_t* key);

/**
* \brief Reset the state values to zero.
*
* \param ctx The function state
*/
QSC_EXPORT_API void qsc_poly1305_reset(qsc_poly1305_state* ctx);

/**
* \brief Update the poly1305 generator with a length of message input.
* Absorbs the input message into the state.
*
* \param ctx: [struct] The function state; must be initialized
* \param message: [const] The input message byte array
* \param msglen: The number of input message bytes to process
*/
QSC_EXPORT_API void qsc_poly1305_update(qsc_poly1305_state* ctx, const uint8_t* message, size_t msglen);

/**
* \brief Verify a MAC code.
* Tests the code against the message and returns MQC_STATUS_SUCCESS or MQC_STATUS_FAILURE.
*
* \param output: The output MAC code byte array to test
* \param message: [const] The input message byte array
* \param msglen: The number of input message bytes to process
* \param key: [const] The secret key byte array
*/
QSC_EXPORT_API int qsc_poly1305_verify(const uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key);

#endif
