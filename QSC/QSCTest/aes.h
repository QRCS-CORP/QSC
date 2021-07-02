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
*/

/**
* \file aes.h
* \brief <b>AES header definition</b> \n
* An implementation of the AES symmetric cipher.
*
* \author John Underhill
* \date January 20, 2020
* \updated June 30, 2021
*
* <b>AES-256 CTR short-form api example</b> \n
* \code
* // external message, key and custom-info arrays
* const size_t MSG_LEN = 200;
* const size_t CST_LEN = 20;
* uint8_t msg[MSG_LEN] = {...};
* uint8_t key[QSC_AES256_KEY_SIZE] = {...};
* uint8_t nonce[QSC_AES_BLOCK_SIZE] = {...};
* uint8_t cust[CST_LEN] = {...};
* ...
* uint8_t output[MSG_LEN] = { 0 };
* qsc_hba_state state;
* qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE, nonce, cust, CST_LEN };
* 
* // initialize the state
* qsc_aes_initialize(&state, &kp, true, AES256);
* // encrypt the message
* qsc_aes_ctr_transform(&state, output, msg, MSG_LEN)
* \endcode
*/

#ifndef QSC_AES_H
#define QSC_AES_H

#include "../QSC/common.h"

/*! \enum qsc_aes_cipher_mode
* The pre-defined cipher mode implementations
*/
typedef enum
{
	AES128 = 1,	/*!< The AES-128 block cipher */
	AES256 = 2,	/*!< The AES-256 block cipher */
} qsc_aes_cipher_type;

/*! \enum qsc_aes_cipher_mode
* The pre-defined cipher mode implementations
*/
typedef enum
{
	CBC = 1,	/*!< Cipher Block Chaining */
	CTR = 2,	/*!< segmented integer counter */
	ECB = 3,	/*!< Electronic CodeBook mode (insecure) */
} qsc_aes_cipher_mode;

/***********************************
*    USER CONFIGURABLE SETTINGS    *
***********************************/

/*!
\def QSC_SYSTEM_AESNI_ENABLED
* Enable the use of intrinsics and the AES-NI implementation.
* Just for testing, add the QSC_SYSTEM_AESNI_ENABLED preprocessor definition and enable SIMD and AES-NI.
*/
#if !defined(QSC_SYSTEM_AESNI_ENABLED)
#	if defined(QSC_SYSTEM_AVX_INTRINSICS)
#		define QSC_SYSTEM_AESNI_ENABLED
#	endif
#endif 

#if defined(QSC_SYSTEM_AESNI_ENABLED)
#	if defined(QSC_SYSTEM_COMPILER_MSC)
#		include <intrin.h>
#		include <immintrin.h>
#	elif defined(QSC_SYSTEM_COMPILER_GCC)
#		include <x86intrin.h>
#	endif
#endif

/***********************************
*     AES CONSTANTS AND SIZES      *
***********************************/

/*!
\def QSC_AES_BLOCK_SIZE
* The internal block size in bytes, required by the encryption and decryption functions.
*/
#define QSC_AES_BLOCK_SIZE 16

/*!
\def QSC_AES128_KEY_SIZE
* The size in bytes of the AES-128 input cipher-key.
*/
#define QSC_AES128_KEY_SIZE 16

/*!
\def QSC_AES256_KEY_SIZE
* The size in bytes of the AES-256 input cipher-key.
*/
#define QSC_AES256_KEY_SIZE 32

/*! \struct qsc_aes_keyparams
* The key parameters structure containing key and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the qsc_aes_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
*/
typedef struct
{
	const uint8_t* key;				/*!< The input cipher key */
	size_t keylen;					/*!< The length in bytes of the cipher key */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
} qsc_aes_keyparams;

/*! \struct qsc_aes_state
* The internal state structure containing the round-key array.
*/
typedef struct
{
#if defined(QSC_SYSTEM_AESNI_ENABLED)
	__m128i roundkeys[31];		/*!< The 128-bit intel integer round-key array */
#	if defined(QSC_SYSTEM_HAS_AVX512)
		__m512i roundkeysw[31];
#	endif
#else
	uint32_t roundkeys[124];		/*!< The round-keys 32-bit subkey array */
#endif
	size_t roundkeylen;				/*!< The round-key array length */
	size_t rounds;					/*!< The number of transformation rounds */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
} qsc_aes_state;

/* common functions */

/**
* \brief Erase the round-key array and size
*/
void qsc_aes_dispose(qsc_aes_state* state);

/**
* \brief Initialize the state with the input cipher-key and optional info tweak. 
* The qsc_aes_state round-key array must be initialized and size set before passing the state to this function.
*
* \param state: [struct] The qsc_aes_state structure
* \param keyparams: The input cipher-key, expanded to the state round-key array
* \param encryption: Initialize the cipher for encryption, false for decryption mode
*
* \warning When using a CTR mode, the cipher is always initialized for encryption.
*/
void qsc_aes_initialize(qsc_aes_state* state, const qsc_aes_keyparams* keyparams, bool encryption, qsc_aes_cipher_type ctype);

/* cbc mode */

/**
* \brief Decrypt a length of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text bytes
* \param inputlen: The number of input cipher-text bytes to decrypt
*/
void qsc_aes_cbc_decrypt(qsc_aes_state* state, uint8_t* output, size_t *outputlen, const uint8_t* input, size_t inputlen);

/**
* \brief Encrypt a length of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the encrypted plain-text
* \param input: [const] The input plain-text bytes
* \param inputlen: The number of input plain-text bytes to encrypt
*/
void qsc_aes_cbc_encrypt(qsc_aes_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

/**
* \brief Decrypt one 16-byte block of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
void qsc_aes_cbc_decrypt_block(qsc_aes_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Encrypt one 16-byte block of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
void qsc_aes_cbc_encrypt_block(qsc_aes_state* state, uint8_t* output, const uint8_t* input);

/* pkcs7 */

/**
* \brief Add padding to a plaintext block pad before encryption.
*
* \param input: The block of input plaintext
* \param offset: The first byte in the block to pad
* \param length: The length of the plaintext block
*/
void qsc_pkcs7_add_padding(uint8_t* input, size_t length);

/**
* \brief Get the number of padded bytes in a block of decrypted cipher-text.
*
* \param input: [const] The block of input plaintext
* \param offset: The first byte in the block to pad
* \param length: The length of the plaintext block
* 
* \return: The length of the block padding
*/
size_t qsc_pkcs7_padding_length(const uint8_t* input);

/* ctr mode */

/**
* \brief Transform a length of data using a Big Endian block cipher Counter mode. \n
* The CTR mode will encrypt plain-text, and decrypt cipher-text.
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the transformed text
* \param input: [const] The input data byte array
* \param inputlen: The number of input bytes to transform
*/
void qsc_aes_ctrbe_transform(qsc_aes_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

/**
* \brief Transform a length of data using a Little Endian block cipher Counter mode. \n
* The CTR mode will encrypt plain-text, and decrypt cipher-text.
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the transformed text
* \param input: [const] The input data byte array
* \param inputlen: The number of input bytes to transform
*/
void qsc_aes_ctrle_transform(qsc_aes_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

/* ecb mode */

/**
* \brief Decrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
void qsc_aes_ecb_decrypt_block(qsc_aes_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Encrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
* 
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
void qsc_aes_ecb_encrypt_block(qsc_aes_state* state, uint8_t* output, const uint8_t* input);

#endif
