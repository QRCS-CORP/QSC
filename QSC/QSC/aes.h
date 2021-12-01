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

#ifndef QSC_AES_H
#define QSC_AES_H

#include "common.h"
#include "intrinsics.h"

/**
* \file aes.h
* \brief An implementation of the AES symmetric cipher
*
* AES-256 CTR short-form api example \n
* \code
* const size_t MSG_LEN = 200;
* const size_t CST_LEN = 20;
* uint8_t msg[MSG_LEN] = {...};
* uint8_t key[QSC_AES256_KEY_SIZE] = {...};
* uint8_t nonce[QSC_AES_BLOCK_SIZE] = {...};
* uint8_t cust[CST_LEN] = {...};
*
* uint8_t output[MSG_LEN] = { 0 };
* qsc_hba_state state;
* qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE, nonce, cust, CST_LEN };
*
* qsc_aes_initialize(&state, &kp, true, AES256);
* qsc_aes_ctr_transform(&state, output, msg, MSG_LEN)
* \endcode
*/

/*!
\def QSC_HBA_KMAC_EXTENSION
* Enables the cSHAKE extensions for the HBA cipher mode
*///
#define QSC_HBA_KMAC_EXTENSION

///*!
//\def QSC_HBA_HKDF_EXTENSION
//* Enables the HKDF extensions for the HBA cipher-mode; alternative to HBA(cSHAKE)
//*/
#define QSC_HBA_HKDF_EXTENSION

#if defined(QSC_HBA_KMAC_EXTENSION)
#	include "sha3.h"
#else
#	include "sha2.h"
#endif

/*! \enum qsc_aes_cipher_mode
* The pre-defined cipher mode implementations
*/
typedef enum qsc_aes_cipher_type
{
	AES128 = 1,	/*!< The AES-128 block cipher */
	AES256 = 2,	/*!< The AES-256 block cipher */
} qsc_aes_cipher_type;

/*! \enum qsc_aes_cipher_mode
* The pre-defined cipher mode implementations
*/
typedef enum qsc_aes_cipher_mode
{
	CBC = 1,	/*!< Cipher Block Chaining */
	CTR = 2,	/*!< segmented integer counter */
	ECB = 3,	/*!< Electronic CodeBook mode (insecure) */
} qsc_aes_cipher_mode;

/***********************************
*     AES CONSTANTS AND SIZES      *
***********************************/

/*!
\def QSC_AES_BLOCK_SIZE
* The internal block size in bytes, required by the encryption and decryption functions.
*/
#define QSC_AES_BLOCK_SIZE 16

/*!
\def QSC_AES_IV_SIZE
* The initialization vector size in bytes.
*/
#define QSC_AES_IV_SIZE 16

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

/*!
\def QSC_HBA256_MAC_LENGTH
* The HBA-256 MAC code array length in bytes.
*/
#define QSC_HBA256_MAC_LENGTH 32

/*!
\def QSC_HBA_MAXAAD_SIZE
* The maximum allowed AAD size.
*/
#define QSC_HBA_MAXAAD_SIZE 256

/*!
\def QSC_HBA_MAXINFO_SIZE
* The maximum allowed key info size.
*/
#define QSC_HBA_MAXINFO_SIZE 256

/*!
\def HBA_NAME_LENGTH
* The HBA implementation specific name array length.
*/
#if defined(QSC_HBA_KMAC_EXTENSION)
#	define HBA_NAME_LENGTH 29
#else
#	define HBA_NAME_LENGTH 33
#endif

/*!
\def QSC_HBA_KMAC_AUTH
* Use KMAC to authenticate HBA; removing this macro is enabled when running in SHAKE extension mode.
* If the QSC_HBA_KMAC_EXTENSION is disabled, HMAC(SHA2) is the default authentication mode in HBA.
*/
#if defined(QSC_HBA_KMAC_EXTENSION)
#	define QSC_HBA_KMAC_AUTH
#endif

/*! \struct qsc_aes_keyparams
* The key parameters structure containing key and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the qsc_aes_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
*/
QSC_EXPORT_API typedef struct
{
	const uint8_t* key;				/*!< [const] The input cipher key */
	size_t keylen;					/*!< The length in bytes of the cipher key */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
	const uint8_t* info;			/*!< [const] The information tweak */
	size_t infolen;					/*!< The length in bytes of the HBA information tweak */
} qsc_aes_keyparams;

/*! \struct qsc_aes_state
* The internal state structure containing the round-key array.
*/
QSC_EXPORT_API typedef struct
{
#if defined(QSC_SYSTEM_AESNI_ENABLED)
	__m128i roundkeys[31];		/*!< The 128-bit Intel integer round-key array */
#	if defined(QSC_SYSTEM_HAS_AVX512)
		__m512i roundkeysw[31];
#	endif
#else
	uint32_t roundkeys[124];		/*!< The round-keys 32-bit sub-key array */
#endif
	size_t roundkeylen;				/*!< The round-key array length */
	size_t rounds;					/*!< The number of transformation rounds */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
} qsc_aes_state;

/* common functions */

/**
* \brief Erase the round-key array and size
*/
QSC_EXPORT_API void qsc_aes_dispose(qsc_aes_state* state);

/**
* \brief Initialize the state with the input cipher-key and optional info tweak.
* The qsc_aes_state round-key array must be initialized and size set before passing the state to this function.
*
* \param state: [struct] The qsc_aes_state structure
* \param keyparams: [const] The input cipher-key, expanded to the state round-key array
* \param encryption: Initialize the cipher for encryption, false for decryption mode
*
* \warning When using a CTR mode, the cipher is always initialized for encryption.
*/
QSC_EXPORT_API void qsc_aes_initialize(qsc_aes_state* state, const qsc_aes_keyparams* keyparams, bool encryption, qsc_aes_cipher_type ctype);

/* cbc mode */

/**
* \brief Decrypt a length of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text bytes
* \param length: The number of input cipher-text bytes to decrypt
*/
QSC_EXPORT_API void qsc_aes_cbc_decrypt(qsc_aes_state* state, uint8_t* output, size_t* outputlen, const uint8_t* input, size_t length);

/**
* \brief Encrypt a length of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the encrypted plain-text
* \param input: [const] The input plain-text bytes
* \param length: The number of input plain-text bytes to encrypt
*/
QSC_EXPORT_API void qsc_aes_cbc_encrypt(qsc_aes_state* state, uint8_t* output, const uint8_t* input, size_t length);

/**
* \brief Decrypt one 16-byte block of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
QSC_EXPORT_API void qsc_aes_cbc_decrypt_block(qsc_aes_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Encrypt one 16-byte block of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
QSC_EXPORT_API void qsc_aes_cbc_encrypt_block(qsc_aes_state* state, uint8_t* output, const uint8_t* input);

/* pkcs7 */

/**
* \brief Add padding to a plain-text block pad before encryption.
*
* \param input: The block of input plain-text
* \param offset: The first byte in the block to pad
* \param length: The length of the plain-text block
*/
QSC_EXPORT_API void qsc_pkcs7_add_padding(uint8_t* input, size_t length);

/**
* \brief Get the number of padded bytes in a block of decrypted cipher-text.
*
* \param input: [const] The block of input plain-text
* \param offset: The first byte in the block to pad
* \param length: The length of the plain-text block
*
* \return: The length of the block padding
*/
QSC_EXPORT_API size_t qsc_pkcs7_padding_length(const uint8_t* input);

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
* \param length: The number of input bytes to transform
*/
QSC_EXPORT_API void qsc_aes_ctrbe_transform(qsc_aes_state* state, uint8_t* output, const uint8_t* input, size_t length);

/**
* \brief Transform a length of data using a Little Endian block cipher Counter mode. \n
* The CTR mode will encrypt plain-text, and decrypt cipher-text.
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the transformed text
* \param input: [const] The input data byte array
* \param length: The number of input bytes to transform
*/
QSC_EXPORT_API void qsc_aes_ctrle_transform(qsc_aes_state* state, uint8_t* output, const uint8_t* input, size_t length);

/* ecb mode */

/**
* \brief Decrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
QSC_EXPORT_API void qsc_aes_ecb_decrypt_block(const qsc_aes_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Encrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
QSC_EXPORT_API void qsc_aes_ecb_encrypt_block(const qsc_aes_state* state, uint8_t* output, const uint8_t* input);

/* HBA-256 */

/*! \struct qsc_aes_hba256_state
* The HBA-256 state array; pointers for the cipher state, mac-key and length, transformation mode, and the state counter.
* Used by the long-form of the HBA api, and initialized by the hba_initialize function.
*/
QSC_EXPORT_API typedef struct
{
#if defined(QSC_HBA_KMAC_EXTENSION)
	qsc_keccak_state kstate;	/*!< the mac state */
#else
	qsc_hmac256_state kstate;
#endif
	qsc_aes_state cstate;				/*!< the underlying block-ciphers state structure */
	uint64_t counter;					/*!< the processed bytes counter */
	uint8_t mkey[32];					/*!< the mac generators key array */
	uint8_t cust[QSC_HBA_MAXINFO_SIZE];	/*!< the ciphers custom key */
	size_t custlen;						/*!< the custom key array length */
	bool encrypt;						/*!< the transformation mode; true for encryption */
} qsc_aes_hba256_state;

/**
* \brief Dispose of the HBA-256 cipher state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys internal arrays allocated on the heap,
* and must be called before the state goes out of scope.
*
* \param state: [struct] The HBA state structure; contains internal state information
*/
QSC_EXPORT_API void qsc_aes_hba256_dispose(qsc_aes_hba256_state* state);

/**
* \brief Initialize the cipher and load the keying material.
* Initializes the cipher state to an AES-256 instance.
*
* \warning The initialize function must be called before either the associated data or transform functions are called.
*
* \param state: [struct] The HBA state structure; contains internal state information
* \param keyparams: [const][struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param encrypt: The cipher encryption mode; true for encryption, false for decryption
*/
QSC_EXPORT_API void qsc_aes_hba256_initialize(qsc_aes_hba256_state* state, const qsc_aes_keyparams* keyparams, bool encrypt);

/**
* \brief Set the associated data string used in authenticating the message.
* The associated data may be packet header information, domain specific data, or a secret shared by a group.
* The associated data must be set after initialization, and before each transformation call.
* The data is erased after each call to the transform.
*
* \param state: [struct] The HBA-256 state structure; contains internal state information
* \param data: [const] The associated data array
* \param datalen: The associated data array length
*/
QSC_EXPORT_API void qsc_aes_hba256_set_associated(qsc_aes_hba256_state* state, const uint8_t* data, size_t datalen);

/**
* \brief Transform an array of bytes using an instance of AES-256.
* In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the cipher-text.
* In decryption mode, the input cipher-text is authenticated internally and compared to the mac code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param state: [struct] The HBA state structure; contains internal state information
* \param output: The output byte array
* \param input: [const] The input byte array
* \param length: The number of bytes to transform
*
* \return: Returns true if the cipher has been initialized successfully, false on failure
*/
QSC_EXPORT_API bool qsc_aes_hba256_transform(qsc_aes_hba256_state* state, uint8_t* output, const uint8_t* input, size_t length);

#endif
