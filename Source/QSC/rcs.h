/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_RCS_H
#define QSC_RCS_H

#include "qsccommon.h"
#include "sha3.h"
#if defined(QSC_SYSTEM_AESNI_ENABLED)
#	include "intrinsics.h"
#	include <immintrin.h>
#endif

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file rcs.h
 * \brief Rijndael-256 authenticated Cipher Stream.
 *
 * \details
 * This header defines the API for the RCS (Rijndael-256 authenticated Cipher Stream) encryption functions.
 * RCS is a hybrid cipher that combines a wide-block Rijndael-256 rounds function with a cryptographically strong
 * pseudo-random generator (cSHAKE) to expand the round-key array (key-schedule). The cryptographic XOF (cSHAKE)
 * generates the round key array used by the modified Rijndael rounds function, enabling a higher number of mixing rounds:
 *  - RCS-256 uses 22 rounds (compared to 14 in standard AES-256).
 *  - RCS-512 employs 30 rounds with a 512-bit key configuration.
 *
 * The cipher supports authenticated encryption with associated data (AEAD) by integrating a keyed MAC function (KMAC or QMAC)
 * that appends an authentication code to the ciphertext. It also supports a tweakable configuration by allowing a
 * user-specified info parameter to customize the cSHAKE output, which can be used as a secondary key or domain separator.
 *
 * \code
 * // RCS-256 encryption example:
 * #define CSTLEN 20
 * #define MSGLEN 200
 * uint8_t cust[CSTLEN] = { ... };
 * uint8_t key[QSC_RCS256_KEY_SIZE] = { ... };
 * uint8_t msg[MSGLEN] = { ... };
 * uint8_t nonce[QSC_RCS_BLOCK_SIZE] = { ... };
 * uint8_t cpt[MSGLEN + QSC_RCS256_MAC_SIZE] = { 0U };
 * qsc_rcs_state state;
 * qsc_rcs_keyparams kp = { key, QSC_RCS256_KEY_SIZE, nonce, cust, CSTLEN };
 *
 * qsc_rcs_initialize(&state, &kp, true);
 * qsc_rcs_transform(&state, cpt, msg, MSGLEN);
 *
 * // RCS-256 decryption example:
 * uint8_t cpt[CPTLEN] = { qsc_rcs_transform(state, in) };
 * uint8_t key[QSC_RCS256_KEY_SIZE] = { ... };
 * uint8_t nonce[QSC_RCS_BLOCK_SIZE] = { ... };
 * uint8_t cust[CSTLEN] = { ... };
 * const size_t MSGLEN = CPTLEN - QSC_RCS256_MAC_SIZE;
 * uint8_t msg[MSGLEN] = { 0U };
 * qsc_rcs_keyparams kp = { key, QSC_RCS256_KEY_SIZE, nonce, cust, CSTLEN };
 *
 * qsc_rcs_initialize(&state, &kp, false);
 * if (qsc_rcs_transform(&state, msg, cpt, MSGLEN) == false)
 * {
 *     // Authentication has failed, handle error...
 * }
 * \endcode
 *
 * \section rcs_links Reference Links:
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf">Rijndael Specification (NIST FIPS 197)</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA3 Specification (FIPS 202)</a>
 */

/***********************************
*    USER CONFIGURABLE SETTINGS    *
***********************************/

/*!
 * \def QSC_RCS_AUTHENTICATED
 * \brief Enables the AEAD cipher authentication mode.
 * Disable this macro to run without authentication.
 */
#if !defined(QSC_RCS_AUTHENTICATED)
#	define QSC_RCS_AUTHENTICATED
#endif

/*!
 * \def QSC_RCS_REDUCED_ROUNDS
 * \brief Sets the internal transformation round counts to: RCS256=14, RCS512=21,
 * and the KMAC rounds from 24 to 12.
 * Remove this definition to enable the standard rounds versions of RCS.
 */
//#define QSC_RCS_REDUCED_ROUNDS

/***********************************
*     RCS CONSTANTS AND SIZES      *
***********************************/

/*!
 * \def QSC_RCS_BLOCK_SIZE
 * \brief The internal block size in bytes, required by the encryption and decryption functions.
 */
#define QSC_RCS_BLOCK_SIZE 32U

/*!
 * \def QSC_RCS256_KEY_SIZE
 * \brief The size in bytes of the RCS-256 input cipher-key.
 */
#define QSC_RCS256_KEY_SIZE 32U

/*!
 * \def QSC_RCS256_MAC_SIZE
 * \brief The RCS-256 MAC code array length in bytes.
 */
#define QSC_RCS256_MAC_SIZE 32U

/*!
 * \def QSC_RCS512_KEY_SIZE
 * \brief The size in bytes of the RCS-512 input cipher-key.
 */
#define QSC_RCS512_KEY_SIZE 64U

/*!
 * \def QSC_RCS512_MAC_SIZE
 * \brief The RCS-512 MAC code array length in bytes.
 */
#define QSC_RCS512_MAC_SIZE 64U

/*!
 * \def QSC_RCS_NONCE_SIZE
 * \brief The nonce size in bytes.
 */
#define QSC_RCS_NONCE_SIZE 32U

/*! \enum rcs_cipher_type
 * \brief The pre-defined cipher mode implementations.
 */
typedef enum
{
	RCS256 = 0x01,			/*!< The RCS-256 cipher */
	RCS512 = 0x02,			/*!< The RCS-512 cipher */
} rcs_cipher_type;

/*! \struct qsc_rcs_keyparams
 * \brief The key parameters structure containing key, nonce, and info arrays and lengths.
 *
 * Use this structure to load an input cipher-key and optional info tweak using the 
 * qsc_rcs_initialize function. Keys must be random and secret, and align to the corresponding
 * key size of the cipher implemented. The info parameter is optional and can be a salt or 
 * secondary key. The nonce is always QSC_RCS_BLOCK_SIZE in length.
 */
QSC_EXPORT_API typedef struct
{
	const uint8_t* key;		/*!< [const] The input cipher key. */
	size_t keylen;			/*!< The length in bytes of the cipher key. */
	uint8_t* nonce;			/*!< The nonce or initialization vector. */
	const uint8_t* info;	/*!< [const] The information tweak. */
	size_t infolen;			/*!< The length in bytes of the information tweak. */
} qsc_rcs_keyparams;

/*! \struct qsc_rcs_state
 * \brief The internal state structure containing the round-key array.
 */
QSC_EXPORT_API typedef struct
{
	rcs_cipher_type ctype;				/*!< The cipher type; RCS-256 or RCS-512. */
#if defined(QSC_SYSTEM_AESNI_ENABLED)
	__m128i roundkeys[62U];				/*!< The 128-bit integer round-key array. */
#	if defined(QSC_SYSTEM_HAS_AVX512)
		__m512i roundkeysw[31U];			/*!< The 512-bit integer round-key array. */
#	endif
#else
	uint32_t roundkeys[248U];			/*!< The round-keys 32-bit sub-key array. */
#endif
	size_t roundkeylen;					/*!< The round-key array length. */
	size_t rounds;						/*!< The number of transformation rounds. */
	qsc_keccak_state kstate;			/*!< The Keccak state structure. */
	uint8_t nonce[QSC_RCS_NONCE_SIZE];	/*!< The nonce or initialization vector. */
	uint64_t counter;					/*!< The processed bytes counter. */
	bool encrypt;						/*!< The transformation mode; true for encryption. */
} qsc_rcs_state;

/**
 * \brief Dispose of the RCS cipher state.
 *
 * \warning The dispose function must be called when disposing of the cipher.
 * This function destroys the internal state of the cipher.
 *
 * \param ctx: [qsc_rcs_state*] A pointer to the cipher state structure.
 */
QSC_EXPORT_API void qsc_rcs_dispose(qsc_rcs_state* ctx);

/**
 * \brief Initialize the state with the input cipher-key and optional info tweak.
 *
 * \warning When using a CTR based construction the nonce must be unique for a given key.
 * Re-using a nonce-key pair on a different plaintext input represents a catastrophic loss of security.
 *
 * \param ctx: [qsc_rcs_state*] A pointer to the cipher state structure.
 * \param keyparams: [const qsc_rcs_state*] A pointer to the secret input cipher-key and nonce structure.
 * \param encryption: [bool] A flag that specifies true for encryption, false for decryption.
 */
QSC_EXPORT_API void qsc_rcs_initialize(qsc_rcs_state* ctx, const qsc_rcs_keyparams* keyparams, bool encryption);

/**
 * \brief Set the associated data string used in authenticating the message.
 *
 * The associated data may be packet header information, domain specific data, or a secret shared by a group.
 * The associated data must be set after initialization and before each transformation call.
 * The data is erased after each call to the transform.
 *
 * \param ctx: [qsc_rcs_state*] A pointer to the cipher state structure.
 * \param data: [const uint8_t*] A pointer to the associated data array.
 * \param length: [size_t] The associated data array length.
 */
QSC_EXPORT_API void qsc_rcs_set_associated(qsc_rcs_state* ctx, const uint8_t* data, size_t length);

/**
* \brief Retrieves the current nonce from the state
*
* \warning If reusing a nonce/key, the nonce must be retrieved after the last finalized transform call.
*
* \param ctx: [struct] The cipher state structure
* \param nonce: [uint8_t*] The output nonce array
*/
QSC_EXPORT_API void qsc_rcs_store_nonce(const qsc_rcs_state* ctx, uint8_t nonce[QSC_RCS_NONCE_SIZE]);

/**
 * \brief Transform an array of bytes.
 *
 * In encryption mode, the input plain-text is encrypted and an authentication MAC code is appended 
 * to the cipher-text. In decryption mode, the input cipher-text is authenticated and compared to the MAC code.
 * If the codes do not match, the cipher-text is not decrypted and the call fails.
 *
 * \param ctx: [qsc_rcs_state*] A pointer to the cipher state structure.
 * \param output: [uint8_t*] A pointer to the output array.
 * \param input: [const uint8_t*] A pointer to the input array.
 * \param length: [size_t] The number of bytes to transform (not including the tag length).
 *
 * \return [bool] Returns true if the data was transformed successfully, false on failure.
 */
QSC_EXPORT_API bool qsc_rcs_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/**
 * \brief A multi-call transform for a large array of bytes.
 *
 * This function can be used to transform and authenticate a very large array of bytes (e.g., >1GB).
 * On the last call in the sequence, set the finalize parameter to true to complete authentication.
 * In encryption mode, the plain-text is encrypted and the MAC code is appended.
 * In decryption mode, the cipher-text is authenticated; if the MAC codes do not match, the call fails.
 *
 * \param ctx: [qsc_rcs_state*] A pointer to the cipher state structure.
 * \param output: [uint8_t*] A pointer to the output array.
 * \param input: [const uint8_t*] A pointer to the input array.
 * \param length: [size_t] The number of bytes to transform.
 * \param finalize: [bool] A flag to indicate if this is the final call.
 *
 * \return [bool] Returns true if the data was transformed successfully, false on failure.
 */
QSC_EXPORT_API bool qsc_rcs_extended_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length, bool finalize);

QSC_CPLUSPLUS_ENABLED_END

#endif
