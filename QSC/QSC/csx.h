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

#ifndef QSC_CSX_H
#define QSC_CSX_H

#include "common.h"
#include "sha3.h"

/**
* \file csx.h
* \brief ChaCha-based authenticated Stream cipher eXtension
*
* \author		John G. Underhill
* \version		1.0.0.0b
* \date			May 2, 2020
* \updated		October 13, 2021
* \contact:		support@digitalfreedomdefence.com
* \copyright	GPL version 3 license (GPLv3)
*
*
* CSX-512 encryption example \n
* \code
* // external message, key, nonce, and custom-info arrays
* #define CSTLEN 20
* #define MSGLEN 200
* uint8_t cust[CSTLEN] = {...};
* uint8_t key[QSC_CSX_KEY_SIZE] = {...};
* uint8_t msg[MSGLEN] = {...};
* uint8_t nonce[QSC_CSX_NONCE_SIZE] = {...};
* ...
* uint8_t cpt[MSGLEN + QSC_CSX_MAC_SIZE] = { 0 };
* qsc_csx_state state;
* qsc_csx_keyparams kp = { key, QSC_CSX_KEY_SIZE, nonce, cust, CSTLEN };
*
* // initialize the state
* qsc_csx_initialize(&state, &kp, true);
* // encrypt the message
* qsc_csx_transform(&state, cpt, msg, MSGLEN)
* \endcode
*
* CSX-512 decryption example \n
* \code
* // external cipher-text, key and custom-info arrays,
* // and cipher-text containing the encrypted plain-text and the mac-code
* uint8_t cpt[CPT_LEN] = { qsc_csx_transform(k,p) }
* uint8_t key[QSC_CSX_KEY_SIZE] = {...};
* uint8_t nonce[QSC_CSX_NONCE_SIZE] = {...};
* uint8_t cust[CSTLEN] = {...};
* ...
* // subtract the mac-code length from the overall cipher-text length for the message size
* const size_t MSGLEN = CPT_LEN - QSC_CSX_MAC_SIZE;
* uint8_t msg[MSGLEN] = { 0 };
* qsc_csx_keyparams kp = { key, QSC_CSX_KEY_SIZE, nonce, cust, CSTLEN };
*
* // initialize the cipher state for decryption
* qsc_csx_initialize(&state, &kp, false);
*
* // authenticate and decrypt the cipher-text
* if (qsc_csx_transform(&state, msg, cpt, MSGLEN) == false)
* {
*	// authentication has failed, do something..
* }
* \endcode
*
* \remarks
* \par
* An [EXPERIMENTAL] vectorized, 64-bit, 40-round stream cipher [CSX512] implementation based on ChaCha.
* This cipher uses KMAC-512 to authenticate the cipher-text stream in an encrypt-then-mac authentication configuration.
* The CSX (authenticated Cipher Stream, ChaCha eXtended) cipher, is a hybrid of the ChaCha stream cipher, 
* using 64-bit integers, a 1024-bit block and a 512-bit key. \n
* 
* \par
* The pseudo-random bytes generator used by this cipher is the Keccak cSHAKE extended output function (XOF).
* The cSHAKE XOF is implemented in the 512-bit form of that function, and used to expand the input cipher-key into the cipher and MAC keys.
* CSX-512 uses a 512-bit input key, an a 16 byte nonce, and an optional tweak; the info parameter, up to 48 bytes in length.
*
* \par
* This is a 'tweakable cipher', the initialization parameters; qsc_csx_keyparams, include an info parameter that can be used as a secondary user input.
* Internally, the info parameter is used to customize the cSHAKE output, using the cSHAKE 'custom' parameter to pre-initialize the SHAKE state.
* The info parameter can be tweaked, with a user defined string 'info' in an qsc_csx_keyparams structure passed to the csx_intitialize(state,keyparams,encrypt).
* This tweak can be used as a 'domain key', or to differentiate cipher-text output from other implementations, or as a secondary secret-key input.
*
* \par
* CSX is an authenticated encryption with associated data (AEAD) stream cipher.
* The cSHAKE key-expansion function generates a key for the keyed hash-based MAC function; KMAC, used to generate the authentication code,
* which is appended to the cipher-text output of an encryption call.
* In decryption mode, before decryption is performed, an internal mac code is calculated, and compared to the code embedded in the cipher-text.
* If authentication fails, the cipher-text is not decrypted, and the qsc_csx_transform(state,out,in,inlen) function returns a boolean false value.
* The qsc_csx_set_associated(state,in,inlen) function can be used to add additional data to the MAC generators input, like packet-header data, or a custom code or counter.
*
* \par
* For authentication CSX can use either the standard form of KMAC, which uses 24 rounds, or the default authentication setting;
* a reduced-rounds version of KMAC that uses half the number of permutation rounds KMAC-R12.
* To enable the standard from of KMAC, pass the QSC_RCS_AUTH_KMAC as a compiler definition, or unrem the definition in this header file.
* To run CSX without authentication, remove the QSC_RCS_AUTHENTICATED in this header file.
*
* \par
* The CSX-512, known answer vectors are taken from the CEX++ cryptographic library <a href="https://github.com/Steppenwolfe65/CEX">The CEX++ Cryptographic Library</a>. \n
* See the documentation and the csx_test.h tests for usage examples.
*/

/*!
\def QSC_CSX_AUTHENTICATED
* \brief Enables KMAC authentication mode
*/
#if !defined(QSC_CSX_AUTHENTICATED)
#	define QSC_CSX_AUTHENTICATED
#endif

#if defined(QSC_CSX_AUTHENTICATED)
/*!
* \def QSC_CSX_AUTH_KMAC
* \brief Sets the authentication mode to standard KMAC-R24.
* Remove this definition to enable the reduced rounds version using KMAC-R12.
*/
//#	define QSC_CSX_AUTH_KMAC
#endif

/*!
\def QSC_CSX_KMAC_R12
* \brief Enables the reduced rounds KMAC-R12 implementation.
* Unrem this flag to enable the reduced rounds KMAC implementation.
*/
#if	defined(QSC_CSX_AUTHENTICATED)
#	if !defined(QSC_CSX_AUTH_KMAC) && !defined(QSC_CSX_AUTH_KMACR12)
#		define QSC_CSX_AUTH_KMACR12
#	endif
#endif

/*!
\def QSC_CSX_BLOCK_SIZE
* \brief The internal block size in bytes, required by the encryption and decryption functions
*/
#define QSC_CSX_BLOCK_SIZE 128

/*!
\def QSC_CSX_INFO_SIZE
* \brief The maximum byte length of the info string
*/
#define QSC_CSX_INFO_SIZE 48

/*!
\def QSC_CSX_KEY_SIZE
* \brief The size in bytes of the CSX-512 input cipher-key
*/
#define QSC_CSX_KEY_SIZE 64

/*!
\def QSC_CSX_MAC_SIZE
* \brief The CSX-512 MAC code array length in bytes
*/
#define QSC_CSX_MAC_SIZE 64

/*!
\def QSC_CSX_NONCE_SIZE
* \brief The byte size of the nonce array
*/
#define QSC_CSX_NONCE_SIZE 16

/*!
\def QSC_CSX_STATE_SIZE
* \brief The uint64 size of the internal state array
*/
#define QSC_CSX_STATE_SIZE 16

/*! 
* \struct qsc_csx_keyparams
* \brief The key parameters structure containing key, nonce, and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the qsc_csx_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
* The nonce is always QSC_CSX_BLOCK_SIZE in length.
*/
QSC_EXPORT_API typedef struct
{
	const uint8_t* key;		/*!< The input cipher key */
	size_t keylen;			/*!< The length in bytes of the cipher key */
	uint8_t* nonce;			/*!< The nonce or initialization vector */
	const uint8_t* info;	/*!< The information tweak */
	size_t infolen;			/*!< The length in bytes of the information tweak */
} qsc_csx_keyparams;

/*! 
* \struct qsc_csx_state
* \brief The internal state structure containing the round-key array.
*/
QSC_EXPORT_API typedef struct
{
	uint64_t state[QSC_CSX_STATE_SIZE];		/*!< the primary state array */
#if defined(QSC_CSX_KPA_AUTHENTICATION)
	qsc_kpa_state kstate;					/*!< the KPA state structure */
#else
	qsc_keccak_state kstate;				/*!< the KMAC state structure */
#endif
	uint64_t counter;						/*!< the processed bytes counter */
	bool encrypt;							/*!< the transformation mode; true for encryption */
} qsc_csx_state;

/* public functions */

/**
* \brief Dispose of the CSX cipher state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_csx_dispose(qsc_csx_state* ctx);

/**
* \brief Initialize the state with the input cipher-key and optional info tweak.
*
* \param ctx: [struct] The cipher state structure
* \param keyparams: [const][struct] The secret input cipher-key and nonce structure
* \param encryption: Initialize the cipher for encryption, or false for decryption mode
*/
QSC_EXPORT_API void qsc_csx_initialize(qsc_csx_state* ctx, const qsc_csx_keyparams* keyparams, bool encryption);

/**
* \brief Set the associated data string used in authenticating the message.
* The associated data may be packet header information, domain specific data, or a secret shared by a group.
* The associated data must be set after initialization, and before each transformation call.
* The data is erased after each call to the transform.
*
* \warning The cipher must be initialized before this function can be called
*
* \param ctx: [struct] The cipher state structure
* \param data: [const] The associated data array
* \param length: The associated data array length
*/
QSC_EXPORT_API void qsc_csx_set_associated(qsc_csx_state* ctx, const uint8_t* data, size_t length);

/**
* \brief Transform an array of bytes.
* In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the cipher-text.
* In decryption mode, the input cipher-text is authenticated internally and compared to the MAC code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param ctx: [struct] The cipher state structure
* \param output: A pointer to the output array
* \param input: [const] A pointer to the input array
* \param length: The number of bytes to transform
*
* \return: Returns true if the cipher has been transformed the data successfully, false on failure
*/
QSC_EXPORT_API bool qsc_csx_transform(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

#endif
