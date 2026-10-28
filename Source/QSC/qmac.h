/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
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
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_QMAC_H
#define QSC_QMAC_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file QMAC.h
 * \brief QMAC function definitions
 *
 * \details
 * This header defines the public API for QMAC (Quantum-Safe Message Authentication Code).
 * A cSHAKE256 expansion derives a 256-bit polynomial hash key and a 256-bit
 * finalization mask from the secret key, nonce, and information string.
 * Message blocks are authenticated using carryless multiplication in GF(2^256).
 *
 * \warning NONCE UNIQUENESS IS MANDATORY FOR SECURE MAC GENERATION.
 * For every NEW tag generated under the same secret key, the caller MUST provide
 * a nonce that has never been used to generate another tag with that key.
 * This requirement applies even if the message or information string changes,
 * and across processes, devices, restarts, and independent instances sharing
 * the secret key. Reusing a nonce repeats the derived hash key and finalization
 * mask and can permit authentication forgeries.
 *
 * \par Nonce management and verification
 * Supply a nonce of QSC_QMAC_NONCE_SIZE bytes for new authenticated messages.
 * The caller/protocol owns nonce generation and uniqueness tracking; the QMAC
 * implementation neither generates nonces nor detects reuse. The nonce need
 * not be secret, but must accompany the authenticated message so that a verifier
 * can recompute its tag with the same key, nonce, and information string.
 * Such verification is not a new tag-generation event and necessarily uses
 * the supplied nonce. Replay rejection, if required, is a protocol responsibility.
 * The legacy API accepts a null/empty nonce, but such usage does not satisfy
 * the unique-nonce security requirement for repeated tag generation.
 *
 * Additionally, this module provides documentation and references for:
 * - GMAC (Galois Message Authentication Code): a variant of GCM used for authentication.
 * - Carryless multiplication: an efficient method for performing multiplication in binary fields, as utilized by GMAC.
 * - Galois fields: the underlying mathematical structure used in GMAC and other cryptographic primitives.
 * - SHA3: the cryptographic hash standard specified in FIPS 202. 
 *
 * \section qmac_links Reference Links:
 * - <a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">GMAC (NIST SP 800-38D)</a>
 * - <a href="https://software.intel.com/sites/default/files/managed/7b/7b/319433-Intel_64_and_IA-32_Architectures_Optimization_Reference_Manual.pdf ">Carryless Multiplication (Intel Optimization Reference Manual)</a>
 * - <a href="https://www.mathworks.com/help/symbolic/galois-field.html">Galois Fields (MathWorks Documentation)</a> 
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA3 FIPS 202</a>
 */

/*! 
 * \def QSC_QMAC_BLOCK_SIZE
 * \brief The natural block size of the message input in bytes.
 */
#define QSC_QMAC_BLOCK_SIZE 32ULL

/*! 
 * \def QSC_QMAC_KEY_SIZE
 * \brief The QMAC key size in bytes.
 */
#define QSC_QMAC_KEY_SIZE 32ULL

/*! 
 * \def QSC_QMAC_MAC_SIZE
 * \brief The QMAC MAC code size in bytes.
 */
#define QSC_QMAC_MAC_SIZE 32ULL

/*! 
 * \def QSC_QMAC_NONCE_SIZE
 * \brief The recommended QMAC nonce size in bytes (32).
 * \warning Each nonce MUST be unique for every new tag generated with a given
 * secret key. The API does not enforce nonce length or uniqueness.
 */
#define QSC_QMAC_NONCE_SIZE 32ULL

/*! 
 * \def QSC_QMAC_STATE_SIZE
 * \brief The QMAC state size.
 */
#define QSC_QMAC_STATE_SIZE (QSC_QMAC_BLOCK_SIZE / sizeof(uint64_t))

/*! 
 * \struct qsc_qmac_state
 * \brief The QMAC state.
 *
 * This structure holds the internal state of the QMAC algorithm including the
 * finalization subkey, hash subkey, hash state, partial message block, message
 * length, and status flags.
 */
QSC_EXPORT_API typedef struct
{
	uint64_t F[QSC_QMAC_STATE_SIZE];	/*!< The finalization subkey */
	uint64_t H[QSC_QMAC_STATE_SIZE];	/*!< The hash subkey */
	uint64_t Y[QSC_QMAC_STATE_SIZE];	/*!< The hash state */
	uint8_t buffer[QSC_QMAC_BLOCK_SIZE];	/*!< The partial message block */
	uint64_t msglen;				/*!< The processed message length in bytes */
	size_t position;				/*!< The partial block position */
	bool initialized;					/*!< The initialized status */
} qsc_qmac_state;

/*! 
 * \struct qsc_qmac_keyparams
 * \brief The key parameters structure containing key and info arrays and lengths.
 *
 * This structure holds caller-owned key material and derivation parameters.
 * The nonce must be fresh for every new tag generated with a given secret key;
 * changing the message or information string does not authorize nonce reuse.
 * The implementation does not retain these pointers after initialization.
 * A null key, or a null nonce/info pointer paired with a nonzero length,
 * causes initialization to leave the state disabled.
 */
QSC_EXPORT_API typedef struct
{
	const uint8_t* key;					/*!< [const] The input MAC key */
	uint8_t* nonce;						/*!< Caller-owned nonce; MUST be unique per new tag under this key */
	const uint8_t* info;				/*!< [const] The information tweak */
	size_t keylen;						/*!< The length in bytes of the MAC key */
	size_t noncelen;					/*!< Nonce length in bytes; use QSC_QMAC_NONCE_SIZE for new tags */
	size_t infolen;						/*!< The length in bytes of the information tweak */
} qsc_qmac_keyparams;

/**
 * \brief Compute the MAC code.
 *
 * \details Computes the QMAC code for the provided nonempty message using
 * the supplied key and derivation parameters. Writes QSC_QMAC_MAC_SIZE bytes.
 * If initialization rejects malformed parameters, no tag is written. Because
 * the legacy one-shot API has no error return, callers must validate the
 * key parameters before calling this function.
 *
 * \warning Each new tag generated under a key MUST use a nonce not used
 * for any previous tag under that key. Repeated calls with unchanged keyparams
 * and nonce violate this requirement. No runtime reuse detection is performed.
 *
 * \param output: [uint8_t*] Writable array of at least QSC_QMAC_MAC_SIZE bytes.
 * \param keyparams: [qsc_qmac_keyparams*] Pointer to the QMAC key parameters structure.
 * \param message: [const uint8_t*] Pointer to the message input byte array.
 * \param msglen: [size_t] The number of message bytes to process.
 */
QSC_EXPORT_API void qsc_qmac_compute(uint8_t* output, qsc_qmac_keyparams* keyparams, const uint8_t* message, size_t msglen);

/**
 * \brief Dispose of the state.
 *
 * \details Erases all variables and resets the state.
 *
 * \param ctx: [qsc_qmac_state*] Pointer to the QMAC state structure; must be initialized.
 */
QSC_EXPORT_API void qsc_qmac_dispose(qsc_qmac_state* ctx);

/**
 * \brief Finalize the message state and return the MAC code.
 *
 * \details Absorbs the last block of the message, creates the tag,
 * and disposes of the QMAC state.
 *
 * \warning The state must have been initialized with a nonce unique to
 * this new tag under its master key. Finalize does not check nonce uniqueness.
 *
 * \param ctx: [qsc_qmac_state*] Pointer to the QMAC state structure; must be initialized.
 * \param output: [uint8_t*] Pointer to the MAC output byte array.
 */
QSC_EXPORT_API void qsc_qmac_finalize(qsc_qmac_state* ctx, uint8_t* output);

/**
 * \brief Initialize the state with the secret key.
 *
 * \details Initializes the QMAC state by deriving per-nonce hash and
 * finalization subkeys from the supplied key and cSHAKE parameters.
 * One initialized state may process a message in any number of updates, but
 * must be finalized before authenticating a different message.
 *
 * \warning Every initialization used to generate a NEW message tag MUST
 * use a nonce unique to the master key. Reinitializing with the same key and
 * nonce to generate another tag is insecure. This function does not enforce
 * nonce presence, length, or uniqueness; these are caller responsibilities.
 * Invalid key pointers, inconsistent nonce/info pointer-length pairs, or
 * nonrepresentable cSHAKE length encodings leave ctx->initialized false and
 * clear its secret-bearing state. Callers may inspect this flag before update.
 *
 * \param ctx: [qsc_qmac_state*] Pointer to the QMAC state structure.
 * \param keyparams: [qsc_qmac_keyparams*] Pointer to the QMAC key parameters structure.
 */
QSC_EXPORT_API void qsc_qmac_initialize(qsc_qmac_state* ctx, qsc_qmac_keyparams* keyparams);

/**
 * \brief Absorb the next nonempty segment of a message.
 *
 * \details Processes an arbitrary positive number of bytes as part of the
 * message associated with the nonce supplied at initialization. Fragmenting
 * one message across update calls does not constitute nonce reuse.
 *
 * \param ctx: [qsc_qmac_state*] Pointer to an initialized QMAC state.
 * \param message: [const uint8_t*] Pointer to msglen readable bytes.
 * \param msglen: [size_t] Number of bytes to process; must be nonzero.
 */
QSC_EXPORT_API void qsc_qmac_update(qsc_qmac_state* ctx, const uint8_t* message, size_t msglen);

QSC_CPLUSPLUS_ENABLED_END

#endif
