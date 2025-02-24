/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_CSX_H
#define QSC_CSX_H

#include "common.h"
#include "sha3.h"

/*!
 * \file csx.h
 * \brief ChaCha-based authenticated Stream cipher eXtension
 *
 * \details
 * This header defines the public API for the CSX-512 cipher, a wide-block ChaCha-based authenticated
 * stream cipher extension. CSX-512 is a vectorized, 64-bit, 40-round stream cipher that uses a 
 * 512-bit input key, a 16-byte nonce, and an optional tweak (info) parameter. The cipher employs
 * the Keccak cSHAKE-512 extended output function (XOF) to expand the input cipher-key into both
 * the cipher key and the MAC key. It integrates a post-quantum secure MAC function (QMAC or KMAC) for message authentication, 
 * operating in an encrypt-then-MAC configuration to provide authenticated encryption with associated data (AEAD).
 * In decryption mode, the MAC code embedded in the ciphertext is verified prior to decryption, ensuring data integrity and authenticity.
 *
 * \par Example Usage:
 * \code
 * // External message, key, nonce, and custom-info arrays
 * #define CSTLEN 20
 * #define MSGLEN 200
 * uint8_t cust[CSTLEN] = { ... };
 * uint8_t key[QSC_CSX_KEY_SIZE] = { ... };
 * uint8_t msg[MSGLEN] = { ... };
 * uint8_t nonce[QSC_CSX_NONCE_SIZE] = { ... };
 * uint8_t cpt[MSGLEN + QSC_CSX_MAC_SIZE] = { 0 };
 * qsc_csx_state state;
 * qsc_csx_keyparams kp = { key, QSC_CSX_KEY_SIZE, nonce, cust, CSTLEN };
 *
 * // Initialize the state for encryption
 * qsc_csx_initialize(&state, &kp, true);
 * // Encrypt the message
 * qsc_csx_transform(&state, cpt, msg, MSGLEN);
 * \endcode
 *
 * \section csx_links Reference Links:
 * - <a href="https://cr.yp.to/chacha/chacha-20080120.pdf">Official ChaCha20 Specification</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">NIST FIPS 202 (SHA-3) Standard</a>
 * - <a href="https://www.math.ubc.ca/~cass/grad/2009-2010/Notes/FiniteFields.pdf">Galois Field Theory Reference</a>
 */

/*!
\def QSC_CSX_AUTHENTICATED
* \brief Enables KMAC authentication mode
*/
#if !defined(QSC_CSX_AUTHENTICATED)
#	define QSC_CSX_AUTHENTICATED
#endif

/* Enable one of the authentication options: 
   a 24 round KMAC, a reduced rounds KMAC, or the QMAC post quantum GMAC function */
#if defined(QSC_CSX_AUTHENTICATED)
///*!
//* \def QSC_CSX_AUTH_KMAC24
//* \brief Sets the authentication mode to standard KMAC-R24.
//*/
//#	define QSC_CSX_AUTH_KMAC24

///*!
//\def QSC_CSX_AUTH_KMACR12
//* \brief Enables the reduced rounds KMAC-R12 implementation.
//*/
//#	define QSC_CSX_AUTH_KMACR12

/*!
\def QSC_CSX_AUTH_QMAC
* \brief Enables the reduced rounds QMAC implementation.
*/
#	define QSC_CSX_AUTH_QMAC
#endif

/*!
\def QSC_CSX_KMAC_R12
* \brief Enables the reduced rounds KMAC-R12 implementation.
* Unrem this flag to enable the reduced rounds KMAC implementation.
*/
#if	defined(QSC_CSX_AUTHENTICATED)
#	if !defined(QSC_CSX_AUTH_KMAC24) && !defined(QSC_CSX_AUTH_KMACR12) && !defined(QSC_CSX_AUTH_QMAC)
#		define QSC_CSX_AUTH_KMAC24
#	endif
#endif

#if defined(QSC_CSX_AUTH_QMAC)
#	include "qmac.h"
#endif

/*!
\def QSC_CSX_BLOCK_SIZE
* \brief The internal block size in bytes, required by the encryption and decryption functions
*/
#define QSC_CSX_BLOCK_SIZE 128ULL

/*!
\def QSC_CSX_INFO_SIZE
* \brief The maximum byte length of the info string
*/
#define QSC_CSX_INFO_SIZE 48ULL

/*!
\def QSC_CSX_KEY_SIZE
* \brief The size in bytes of the CSX-512 input cipher-key
*/
#define QSC_CSX_KEY_SIZE 64ULL

#if defined(QSC_CSX_AUTH_QMAC)
/*!
* \def QSC_CSX_MAC_SIZE
* \brief The CSX MAC code array length in bytes.
*/
#define QSC_CSX_MAC_SIZE 32ULL
#else
/*!
\def QSC_CSX_MAC_SIZE
* \brief The CSX-512 MAC code array length in bytes
*/
#define QSC_CSX_MAC_SIZE 64ULL
#endif

/*!
\def QSC_CSX_NONCE_SIZE
* \brief The byte size of the nonce array
*/
#define QSC_CSX_NONCE_SIZE 16ULL

/*!
\def QSC_CSX_STATE_SIZE
* \brief The uint64 size of the internal state array
*/
#define QSC_CSX_STATE_SIZE 16ULL

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
	uint64_t state[QSC_CSX_STATE_SIZE];	/*!< the primary state array */
#if defined(QSC_CSX_AUTH_QMAC)
	qsc_qmac_state kstate;				/*!< the QMAC state structure */
#else
	qsc_keccak_state kstate;			/*!< the KMAC state structure */
#endif
	uint64_t counter;					/*!< the processed bytes counter */
	bool encrypt;						/*!< the transformation mode; true for encryption */
} qsc_csx_state;

/* public functions */

/**
* \brief Dispose of the CSX cipher state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx:			[struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_csx_dispose(qsc_csx_state* ctx);

/**
* \brief Initialize the state with the input cipher-key and optional info tweak.
*
* \param ctx:			[struct] The cipher state structure
* \param keyparams:		[const][struct] The secret input cipher-key and nonce structure
* \param encryption:	[bool] Initialize the cipher for encryption, or false for decryption mode
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
* \param ctx:			[struct] The cipher state structure
* \param data:			[const] The associated data array
* \param length:		[size_t] The associated data array length
*/
QSC_EXPORT_API void qsc_csx_set_associated(qsc_csx_state* ctx, const uint8_t* data, size_t length);

/**
* \brief Retrieves the current nonce from the state
*
* \warning If reusing a nonce/key, the nonce must be retrieved after the last finalized transform call.
*
* \param ctx:			[struct] The cipher state structure
* \param nonce:			[uint8_t*] The output nonce array
*/
QSC_EXPORT_API void qsc_csx_store_nonce(const qsc_csx_state* ctx, uint8_t nonce[QSC_CSX_NONCE_SIZE]);

/**
* \brief Transform an array of bytes.
* In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the cipher-text.
* In decryption mode, the input cipher-text is authenticated internally and compared to the MAC code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param ctx:			[struct] The cipher state structure
* \param output:		[uint8_t*] A pointer to the output array
* \param input:			[const] A pointer to the input array
* \param length:		[size_t] The number of bytes to transform
*
* \return:				[bool] Returns true if the cipher has been transformed the data successfully, false on failure
*/
QSC_EXPORT_API bool qsc_csx_transform(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/**
* \brief A multi-call transform for a large array of bytes, such as required by file encryption.
* This call can be used to transform and authenticate a very large array of bytes (+1GB).
* On the last call in the sequence, set the finalize parameter to true to complete authentication,
* and write the MAC code to the end of the output array in encryption mode, 
* or compare to the embedded MAC code and authenticate in decryption mode.
* In encryption mode, the input plain-text is encrypted, then authenticated, and the MAC code is appended to the cipher-text.
* In decryption mode, the input cipher-text is authenticated internally and compared to the MAC code appended to the cipher-text,
* if the codes do not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param ctx:			[struct] The cipher state structure
* \param output:		[uint8_t*] A pointer to the output array
* \param input:			[const] A pointer to the input array
* \param length:		[size_t] The number of bytes to transform
* \param finalize:		[bool] Complete authentication on a stream if set to true
*
* \return:				[bool] Returns true if the cipher has been transformed the data successfully, false on failure
*/
QSC_EXPORT_API bool qsc_csx_extended_transform(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length, bool finalize);

#endif
