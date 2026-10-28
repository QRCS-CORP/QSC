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

#ifndef QSC_CSX_H
#define QSC_CSX_H

#include "qsccommon.h"
#include "sha3.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file csx.h
 * \brief ChaCha-based authenticated Stream cipher eXtension
 *
 * \details
 * This header defines the public API for the CSX-512 cipher, a wide-block ChaCha-based authenticated
 * stream cipher extension. CSX-512 is a vectorized, 64-bit, 20-round stream cipher by default (40 rounds when extended) that uses a 
 * 512-bit input key, a 16-byte nonce, and an optional tweak (info) parameter. The cipher employs
 * the Keccak cSHAKE-512 extended output function (XOF) to expand the input cipher-key into both
 * the cipher key and the MAC key. It integrates the QSC KMAC-512 extension for message authentication, 
 * operating in an encrypt-then-MAC configuration to provide authenticated encryption with associated data (AEAD).
 * The single-call transform verifies the embedded tag before releasing plaintext.
 * CSX and its cSHAKE-512/KMAC-512 configuration are QSC constructions, not NIST-standardized algorithms.
 * The 20-round default and optional 40-round profile retain their existing wire formats.
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
 * uint8_t cpt[MSGLEN + QSC_CSX_MAC_SIZE] = { 0U };
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

/**
 * \def QSC_CSX_EXTENDED_ROUND_COUNTS
 * \brief Select the optional 40-round CSX cipher instead of the default 20-round cipher.
 * \details This macro controls only CSX mixing rounds. Both modes always use
 * standard 24-round Keccak/KMAC for authentication and key derivation.
 * Define QSC_CSX_EXTENDED_ROUND_COUNTS consistently in all translation units
 * participating in the same CSX protocol. Ciphertext and tags produced with
 * the two profiles are not interchangeable.
 */
/* #define QSC_CSX_EXTENDED_ROUND_COUNTS */

/*!
\def QSC_CSX_BLOCK_SIZE
* \brief The internal block size in bytes, required by the encryption and decryption functions
*/
#define QSC_CSX_BLOCK_SIZE 128U

/*!
\def QSC_CSX_INFO_SIZE
* \brief The size of the raw cipher information string.
* \details Authenticated CSX uses only the first 14 info bytes as a zero-padded
* cSHAKE function name; additional bytes are ignored for compatibility.
*/
#define QSC_CSX_INFO_SIZE 48U

/*!
\def QSC_CSX_KEY_SIZE
* \brief The size in bytes of the CSX-512 input cipher-key
*/
#define QSC_CSX_KEY_SIZE 64U

/*!
\def QSC_CSX_MAC_SIZE
* \brief The CSX-512 MAC code array length in bytes
*/
#define QSC_CSX_MAC_SIZE 64U

/*!
\def QSC_CSX_NONCE_SIZE
* \brief The byte size of the nonce array
*/
#define QSC_CSX_NONCE_SIZE 16U

/*!
\def QSC_CSX_STATE_SIZE
* \brief The uint64 size of the internal state array
*/
#define QSC_CSX_STATE_SIZE 16U

/*! 
* \struct qsc_csx_keyparams
* \brief The key parameters structure containing key, nonce, and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the qsc_csx_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
* The nonce is always QSC_CSX_NONCE_SIZE in length.
*/
QSC_EXPORT_API typedef struct
{
	const uint8_t* key;					/*!< The input cipher key */
	size_t keylen;						/*!< The length in bytes of the cipher key */
	uint8_t* nonce;						/*!< The nonce or initialization vector */
	const uint8_t* info;				/*!< The information tweak */
	size_t infolen;						/*!< The length in bytes of the information tweak */
} qsc_csx_keyparams;

/*! 
* \struct qsc_csx_state
* \brief The internal state structure containing the round-key array.
*/
QSC_EXPORT_API typedef struct
{
	uint64_t state[QSC_CSX_STATE_SIZE];	/*!< the primary state array */
	qsc_keccak_state kstate;			/*!< the KMAC state structure */
	uint64_t counter;					/*!< Processed bytes; UINT64_MAX marks a disposed or invalid state. */
	bool encrypt;						/*!< the transformation mode; true for encryption */
} qsc_csx_state;

/* public functions */

/**
* \brief Dispose of the CSX cipher state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys secret state and marks the context invalid until reinitialized.
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_csx_dispose(qsc_csx_state* ctx);

/**
 * \brief Initialize the state with the input cipher-key and optional info tweak.
 *
 * \warning When using a CTR based construction the nonce must be unique for a given key.
 * Re-using a nonce-key pair on a different plaintext input represents a catastrophic loss of security.
 * The complete ranges of consumed 128-bit counters must be disjoint for a fixed key and info.
 * Distinct starting nonces alone are insufficient when their counter ranges overlap.
 * The key must contain exactly QSC_CSX_KEY_SIZE bytes and nonce must contain QSC_CSX_NONCE_SIZE bytes.
 * A nonzero infolen requires a non-NULL info pointer. Invalid parameters invalidate the context.
 * Authenticated mode retains the first 14 info bytes, zero-padded when shorter; zero length selects the default name.
 * 
 * \param ctx: [struct] The cipher state structure
 * \param keyparams: [const struct] The secret input cipher-key and nonce structure
 * \param encryption: [bool] Initialize the cipher for encryption, or false for decryption mode
 */
QSC_EXPORT_API void qsc_csx_initialize(qsc_csx_state* ctx, const qsc_csx_keyparams* keyparams, bool encryption);

/**
 * \brief Set the associated data string used in authenticating the message.
 * The associated data may be packet header information, domain specific data, or a secret shared by a group.
 * The associated data must be set after initialization, and before each transformation call.
 * Associated data is absorbed into the chained authentication state. A successful
 * finalized transform clears buffered bytes but retains the authentication history.
 * Length must not exceed UINT32_MAX; zero length is a no-op. Invalid nonempty data invalidates the context.
 *
 * \warning The cipher must be initialized before this function can be called
 *
 * \param ctx: [struct] The cipher state structure
 * \param data: [const] The associated data array
 * \param length: [size_t] The associated data array length
 */
QSC_EXPORT_API void qsc_csx_set_associated(qsc_csx_state* ctx, const uint8_t* data, size_t length);

/**
 * \brief Retrieves the current nonce from the state
 *
 * \warning Retrieve the next nonce only after a successful finalized transform and before disposal.
 * Reinitializing with the stored nonce starts a new authentication chain; both peers must reinitialize.
 *
 * \param ctx: [struct] The cipher state structure
 * \param nonce: [uint8_t*] The output nonce array
 */
QSC_EXPORT_API void qsc_csx_store_nonce(const qsc_csx_state* ctx, uint8_t nonce[QSC_CSX_NONCE_SIZE]);

/**
 * \brief Transform an array of bytes.
 * In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the cipher-text.
 * In decryption mode, the input cipher-text is authenticated internally and compared to the MAC code appended to the cipher-text,
 * If the tags do not match, output is unchanged, the state is invalidated, and the call fails.
 * Exact in-place transformation is supported; other overlapping input/output ranges are unsupported.
 * Encryption output and decryption input require length + QSC_CSX_MAC_SIZE bytes.
 * Zero-length payloads are rejected. Byte-count exhaustion and 128-bit nonce wrap are rejected
 * before processing. A context can process at most UINT64_MAX - 1 payload bytes.
 * Successful calls retain the state for chained records; failed authentication requires reinitialization.
 *
 * \warning The cipher must be initialized before this function can be called
 *
 * \param ctx: [struct] The cipher state structure.
 * \param output: [uint8_t*] A pointer to the output array.
 * \param input: [const] A pointer to the input array.
 * \param length: [size_t] The number of bytes to transform (not including the tag length).
 *
 * \return: [bool] Returns true if the cipher has been transformed the data successfully, false on failure
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
 * If the final tag does not match, the current output is unchanged and the state is invalidated.
 * Earlier calls with finalize=false release UNAUTHENTICATED plaintext. The caller must
 * quarantine all such output until the final call succeeds, and discard it on failure.
 * Both peers must use identical nonzero chunk lengths and associated-data call sequences.
 * Each call consumes whole keystream blocks and authenticates its starting nonce;
 * changing chunk boundaries is not equivalent to a single transform.
 * The same overlap and counter limits as qsc_csx_transform apply. A tag-sized extension
 * is required on encryption output or decryption input only when finalize=true.
 *
 * \warning The cipher must be initialized before this function can be called
 *
 * \param ctx: [struct] The cipher state structure
 * \param output: [uint8_t*] A pointer to the output array
 * \param input: [const] A pointer to the input array
 * \param length: [size_t] The number of bytes to transform
 * \param finalize: [bool] Complete authentication on a stream if set to true
 *
 * \return: [bool] Returns true if the cipher has been transformed the data successfully, false on failure
*/
QSC_EXPORT_API bool qsc_csx_extended_transform(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length, bool finalize);

QSC_CPLUSPLUS_ENABLED_END

#endif
