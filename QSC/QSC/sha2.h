/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef QSC_SHA2_H
#define QSC_SHA2_H

#include "common.h"

/**
* \file sha2.h
* \author John Underhill
* \date May 23, 2019
* \updated September 12, 2020
*
* \brief SHA2 header definition \n
* Contains the public api and documentation for SHA2 digests, HMAC and HKDF implementations.
*
* SHA2-512 hash computation using long-form api \n
* \code
* #define MSGLEN 200
* uint8_t msg[MSGLEN] = { ... };
* uint8_t otp[QSC_SHA2_512_HASH_SIZE] = { 0 };
* qsc_sha512_state ctx;
*
* qsc_sha512_initialize(&ctx);
* qsc_sha512_update(&ctx, msg, MSGLEN);
* qsc_sha512_finalize(&ctx, otp);
* \endcode
*
* \remarks For usage examples, see sha3_test.h. \n
*
* \ section Links
* NIST: The SHA-2 Standard http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf \n
* Analysis of SIMD Applicability to SHA Algorithms https://software.intel.com/sites/default/files/m/b/9/b/aciicmez.pdf \n
*
* \remarks
* \par
* The SHA2 and HMAC implementations use two different forms of api: short-form and long-form. \n
* The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call,
* for example; qsc_sha512_compute(uint8_t* output, const uint8_t* message, size_t msglen),
* the entire message array is processed and the hash code is written to the output array. \n
* The long-form api uses an initialization call to prepare the state, a update call to process the message,
* and the finalize call, which finalizes the state and generates a hash or mac-code. \n
* The HKDF key derivation functions HKDF(HMAC(SHA2-256/512)), use only the short-form api, single-call functions, to generate pseudo-random to an output array. \n
* Each of the function families (SHA2, HMAC, HKDF), have a corresponding set of reference constants associated with that member, example;
* QSC_HKDF_256_KEY_SIZE is the minimum expected HKDF-256 key size in bytes, QSC_HMAC_512_MAC_SIZE is the minimum size of the HMAC-512 output mac-code output array.
*
* For additional usage examples, see sha2_test.h
*/

/*!
* \def QSC_SHA2_SHANI_ENABLED
* \brief Enables the SHA2 permutation intrinsics.
* For testing only; add this flag to your preprocessor definitions to enable SHA-NI intrinsics.
*/
#if !defined(QSC_SHA2_SHANI_ENABLED)
//#	define QSC_SHA2_SHANI_ENABLED
#endif

/*!
* \def QSC_HKDF_256_KEY_SIZE
* \brief The HKDF-256 key size in bytes
*/
#define QSC_HKDF_256_KEY_SIZE 32

/*!
* \def QSC_HKDF_512_KEY_SIZE
* \brief The HKDF-512 key size in bytes
*/
#define QSC_HKDF_512_KEY_SIZE 64

/*!
* \def QSC_HMAC_256_KEY_SIZE
* \brief The recommended HMAC(SHA2-256) key size, minimum is 32 bytes
*/
#define QSC_HMAC_256_KEY_SIZE 32

/*!
* \def QSC_HMAC_512_KEY_SIZE
* \brief The recommended HMAC(SHA2-512) key size minimum is 64 bytes
*/
#define QSC_HMAC_512_KEY_SIZE 64

/*!
* \def QSC_HMAC_256_MAC_SIZE
* \brief The HMAC-256 mac-code size in bytes
*/
#define QSC_HMAC_256_MAC_SIZE 32

/*!
* \def QSC_HMAC_512_MAC_SIZE
* \brief The HMAC-512 mac-code size in bytes
*/
#define QSC_HMAC_512_MAC_SIZE 64

/*!
* \def QSC_HMAC_256_RATE
* \brief The HMAC-256 input rate size in bytes
*/
#define QSC_HMAC_256_RATE 64

/*!
* \def QSC_HMAC_512_RATE
* \brief The HMAC-512 input rate size in bytes
*/
#define QSC_HMAC_512_RATE 128

/*!
* \def QSC_SHA2_256_HASH_SIZE
* \brief The SHA2-256 hash size in bytes
*/
#define QSC_SHA2_256_HASH_SIZE 32

/*!
* \def QSC_SHA2_384_HASH_SIZE
* \brief The SHA2-384 hash size in bytes
*/
#define QSC_SHA2_384_HASH_SIZE 48

/*!
* \def QSC_SHA2_512_HASH_SIZE
* \brief The SHA2-512 hash size in bytes
*/
#define QSC_SHA2_512_HASH_SIZE 64

/*!
* \def QSC_SHA2_256_RATE
* \brief The SHA-256 byte absorption rate
*/
#define QSC_SHA2_256_RATE 64

/*!
* \def QSC_SHA2_384_RATE
* \brief The SHA-384 byte absorption rate
*/
#define QSC_SHA2_384_RATE 128

/*!
* \def QSC_SHA2_512_RATE
* \brief The SHA2-512 byte absorption rate
*/
#define QSC_SHA2_512_RATE 128

/*!
* \def QSC_SHA2_STATE_SIZE
* \brief The SHA2-256 state array size
*/
#define QSC_SHA2_STATE_SIZE 8

/* SHA2-256 */

/*!
* \struct qsc_sha256_state
* \brief The SHA2-256 digest state array
*/
QSC_EXPORT_API typedef struct
{
	uint32_t state[QSC_SHA2_STATE_SIZE];	/*!< The SHA2-256 state  */
	uint8_t buffer[QSC_SHA2_256_RATE];		/*!< The message buffer  */
	uint64_t t;								/*!< The message length  */
	size_t position;						/*!< The cache position  */
} qsc_sha256_state;

/**
* \brief Process a message with SHA2-256 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_sha256_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Dispose of the SHA2-256 state.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_sha256_dispose(qsc_sha256_state* ctx);

/**
* \brief Finalize the message state and returns the hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 32-byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
QSC_EXPORT_API void qsc_sha256_finalize(qsc_sha256_state* ctx, uint8_t* output);

/**
* \brief Initializes a SHA2-256 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
*/
QSC_EXPORT_API void qsc_sha256_initialize(qsc_sha256_state* ctx);

/**
* \brief The SHA2-256 permutation function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Absorbs a message and permutes the state array.
*
* \param output: The function output; must be initialized
* \param input: [const] The input message byte array
*/
QSC_EXPORT_API void qsc_sha256_permute(uint32_t* output, const uint8_t* input);

/**
* \brief Update SHA2-256 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a length of message input into the hash function.
*
* \warning State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_sha256_update(qsc_sha256_state* ctx, const uint8_t* message, size_t msglen);

/* SHA2-384 */

/*!
* \struct qsc_sha384_state
* \brief The SHA2-384 digest state array
*/
QSC_EXPORT_API typedef struct
{
	uint64_t state[QSC_SHA2_STATE_SIZE];	/*!< The SHA2-384 state  */
	uint64_t t[2];							/*!< The message size  */
	uint8_t buffer[QSC_SHA2_384_RATE];		/*!< The message buffer  */
	size_t position;						/*!< The message position  */
} qsc_sha384_state;

/**
* \brief Process a message with SHA2-384 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 48 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
QSC_EXPORT_API void qsc_sha384_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Dispose of the SHA2-384 state.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_sha384_dispose(qsc_sha384_state* ctx);

/**
* \brief Finalize the message state and returns the SHA2-384 hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 48 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
QSC_EXPORT_API void qsc_sha384_finalize(qsc_sha384_state* ctx, uint8_t* output);

/**
* \brief Initializes a SHA2-384 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
*/
QSC_EXPORT_API void qsc_sha384_initialize(qsc_sha384_state* ctx);

/**
* \brief Update SHA2-384 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a length of input into the hash function.
*
* \warning State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_sha384_update(qsc_sha384_state* ctx, const uint8_t* message, size_t msglen);

/* SHA2-512 */

/*!
* \struct qsc_sha512_state
* \brief The SHA2-512 digest state array
*/
QSC_EXPORT_API typedef struct
{
	uint64_t state[QSC_SHA2_STATE_SIZE];	/*!< The SHA2-512 state  */
	uint64_t t[2];							/*!< The message length  */
	uint8_t buffer[QSC_SHA2_512_RATE];		/*!< The message buffer  */
	size_t position;						/*!< The cache position  */
} qsc_sha512_state;

/**
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
QSC_EXPORT_API void qsc_sha512_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Dispose of the SHA2-512 state.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_sha512_dispose(qsc_sha512_state* ctx);

/**
* \brief Finalize the message state and returns the SHA2-512 hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
QSC_EXPORT_API void qsc_sha512_finalize(qsc_sha512_state* ctx, uint8_t* output);

/**
* \brief Initializes a SHA2-512 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
*/
QSC_EXPORT_API void qsc_sha512_initialize(qsc_sha512_state* ctx);

/**
* \brief The SHA2-512 permutation function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Absorbs a message and permutes the state array.
*
* \param output: The function output; must be initialized
* \param input: [const] The input message byte array
*/
QSC_EXPORT_API void qsc_sha512_permute(uint64_t* output, const uint8_t* input);

/**
* \brief Update SHA2-512 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a length of input into the hash function.
*
* \warning State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_sha512_update(qsc_sha512_state* ctx, const uint8_t* message, size_t msglen);

/* HMAC-256 */

/*!
* \struct qsc_hmac256_state
* \brief The HMAC(SHA2-256) state array
*/
QSC_EXPORT_API typedef struct
{
	qsc_sha256_state pstate;			/*!< The SHA2-256 state  */
	uint8_t ipad[QSC_SHA2_256_RATE];	/*!< The input pad array  */
	uint8_t opad[QSC_SHA2_256_RATE];	/*!< The output pad array  */
} qsc_hmac256_state;

/**
* \brief Process a message with HMAC(SHA2-256) and returns the hash code in the output byte array.
* Short form api: processes the key and complete message, and generates the MAC code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
QSC_EXPORT_API void qsc_hmac256_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/**
* \brief Dispose of the HMAC-256 state.
* This function destroys the internal state of the MAC.
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_hmac256_dispose(qsc_hmac256_state* ctx);

/**
* \brief Finalize the HMAC-256 message state and return the hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 32 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
QSC_EXPORT_API void qsc_hmac256_finalize(qsc_hmac256_state* ctx, uint8_t* output);

/**
* \brief Initializes an HMAC-256 state structure with a key, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
QSC_EXPORT_API void qsc_hmac256_initialize(qsc_hmac256_state* ctx, const uint8_t* key, size_t keylen);

/**
* \brief Update HMAC-256 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_hmac256_update(qsc_hmac256_state* ctx, const uint8_t* message, size_t msglen);

/* HMAC-512 */

/*!
* \struct qsc_hmac512_state
* \brief The HMAC(SHA2-512) state array
*/
QSC_EXPORT_API typedef struct
{
	qsc_sha512_state pstate;			/*!< The SHA2-512 state  */
	uint8_t ipad[QSC_SHA2_512_RATE];	/*!< The input pad array  */
	uint8_t opad[QSC_SHA2_512_RATE];	/*!< The output pad array  */
} qsc_hmac512_state;

/**
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
* Short form api: processes the key and complete message, and generates the MAC code with a single call.
*
* \warning The output array must be at least 128 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
QSC_EXPORT_API void qsc_hmac512_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/**
* \brief Dispose of the HMAC-512 state.
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_hmac512_dispose(qsc_hmac512_state* ctx);

/**
* \brief Finalize the HMAC-512 message state and return the hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
QSC_EXPORT_API void qsc_hmac512_finalize(qsc_hmac512_state* ctx, uint8_t* output);

/**
* \brief Initializes an HMAC-512 state structure with a key, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
QSC_EXPORT_API void qsc_hmac512_initialize(qsc_hmac512_state* ctx, const uint8_t* key, size_t keylen);

/**
* \brief Update HMAC-512 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_hmac512_update(qsc_hmac512_state* ctx, const uint8_t* message, size_t msglen);

/* HKDF */

/**
* \brief Initialize an instance of HKDF(HMAC(SHA2-256)), and output an array of pseudo-random.
* Short form api: initializes with the key and user info, and generates the output pseudo-random with a single call.
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
QSC_EXPORT_API void qsc_hkdf256_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen);

/**
* \brief Extract a key from a combined key and salt input using HMAC(SHA2-256).
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param salt: [const] The salt array
* \param saltlen: The salt array length
*/
QSC_EXPORT_API void qsc_hkdf256_extract(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen);

/**
* \brief Initialize an instance of HKDF(HMAC(SHA2-512)), and output an array of pseudo-random.
* Short form api: initializes with the key and user info, and generates the output pseudo-random with a single call.
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
QSC_EXPORT_API void qsc_hkdf512_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen);

/**
* \brief Extract a key from a combined key and salt input using HMAC(SHA2-512).
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param salt: [const] The salt array
* \param saltlen: The salt array length
*/
QSC_EXPORT_API void qsc_hkdf512_extract(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen);

#endif
