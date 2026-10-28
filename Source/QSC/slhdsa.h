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

#ifndef QSC_SLHDSA_H
#define QSC_SLHDSA_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START


/** \brief Approved prehash functions implemented by the QSC HashSLH-DSA facade.
 * \note SHAKE-128 produces 32 bytes; SHAKE-256 produces 64 bytes, as in FIPS 205.
 */
typedef enum qsc_slhdsa_prehash_algorithm
{
	qsc_slhdsa_prehash_sha256 = 1,   /*!< FIPS 180 SHA-256, 32-byte digest. */
	qsc_slhdsa_prehash_sha512 = 2,   /*!< FIPS 180 SHA-512, 64-byte digest. */
	qsc_slhdsa_prehash_shake128 = 3, /*!< FIPS 202 SHAKE-128, 32-byte digest. */
	qsc_slhdsa_prehash_shake256 = 4  /*!< FIPS 202 SHAKE-256, 64-byte digest. */
} qsc_slhdsa_prehash_algorithm;

/** \file slhdsa.h
 * \brief Independent SHAKE-based FIPS 205 SLH-DSA algorithms.
 * \details All six standardized variants coexist in one library; these interfaces
 * are deliberately distinct from QSC's legacy SPHINCS+ and extended configurations.
 * Seeded key generation requires 3*n bytes. The deterministic signer uses PK.seed
 * as opt_rand, while the hedged signer requires fresh n-byte randomizer input from RNG.
 * Output buffers must be at least the documented fixed sizes. Not thread-shared state.
 */

/** \def QSC_SLHDSA_SHAKE128S_PUBLICKEY_SIZE
 * \brief Public key size, bytes for SLH-DSA-SHAKE-128s.
 */
#define QSC_SLHDSA_SHAKE128S_PUBLICKEY_SIZE 32U

/** \def QSC_SLHDSA_SHAKE128S_PRIVATEKEY_SIZE
 * \brief Private key size, bytes for SLH-DSA-SHAKE-128s.
 */
#define QSC_SLHDSA_SHAKE128S_PRIVATEKEY_SIZE 64U

/** \def QSC_SLHDSA_SHAKE128S_SIGNATURE_SIZE
 * \brief Detached signature size, bytes for SLH-DSA-SHAKE-128s.
 */
#define QSC_SLHDSA_SHAKE128S_SIGNATURE_SIZE 7856U

/** \def QSC_SLHDSA_SHAKE128S_KEYGEN_SEED_SIZE
 * \brief Deterministic key-generation seed size, bytes for SLH-DSA-SHAKE-128s.
 */
#define QSC_SLHDSA_SHAKE128S_KEYGEN_SEED_SIZE 48U

/** \def QSC_SLHDSA_SHAKE128S_SIGN_RANDOM_SIZE
 * \brief Hedged signing randomizer size, bytes for SLH-DSA-SHAKE-128s.
 */
#define QSC_SLHDSA_SHAKE128S_SIGN_RANDOM_SIZE 16U

/** \brief Generates the SLH-DSA-SHAKE-128s key pair with a random generator.
 * \param publickey Output buffer, at least 32 bytes.
 * \param privatekey Output buffer, at least 64 bytes; contains secret material.
 * \param rng_generate Cryptographically secure generator, return true on success.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128s_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Generates a repeatable SLH-DSA-SHAKE-128s key pair from 3*n bytes.
 * \param publickey Output buffer, at least 32 bytes.
 * \param privatekey Output buffer, at least 64 bytes.
 * \param seed Exactly 48 bytes, caller-owned and not modified.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128s_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t seed[QSC_SLHDSA_SHAKE128S_KEYGEN_SEED_SIZE]);

/** \brief Creates a FIPS 205 pure hedged detached signature with RNG-supplied randomizer.
 * \param signature Output buffer, at least 7856 bytes.
 * \param siglen Receives 7856 on success, zero on failure.
 * \param message Message pointer; NULL allowed only if msglen is zero.
 * \param msglen Message length in bytes.
 * \param context Optional context, at most 255 bytes; NULL iff ctxlen is zero.
 * \param ctxlen Context length in bytes.
 * \param privatekey Input 64-byte secret key.
 * \param rng_generate Secure randomizer generator, must return true.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128s_sign(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Creates a FIPS 205 pure deterministic detached signature using PK.seed as randomizer.
 * \param signature Output buffer, at least 7856 bytes.
 * \param siglen Receives 7856 on success, zero on failure.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Context pointer; NULL permitted only when ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param privatekey Input 64-byte secret key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128s_sign_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey);

/** \brief HashSLH-DSA-SHAKE-128s hedged signing with FIPS 205 prehash domain.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned plaintext, NULL only for zero length.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only if ctxlen zero.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \param rng_generate Secure n-byte randomizer generator.
 * \return True only when signing succeeds.
 * \note Reentrant; internal prehash/digest and randomizer securely erased.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128s_sign_prehash(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief HashSLH-DSA-SHAKE-128s deterministic prehash signing.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned input, NULL only when msglen zero.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only for empty context.
 * \param ctxlen Context length, at most 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \return True on success, false on invalid inputs or signing failure.
 * \note Reentrant; deterministic signing uses private key's PK.seed.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128s_sign_prehash_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey);

/** \brief Verify a FIPS 205 HashSLH-DSA-SHAKE-128s signature.
 * \param signature Fixed-size caller-owned detached signature.
 * \param siglen Signature length; must match the selected parameter set.
 * \param message Caller-owned message; NULL only for empty message.
 * \param msglen Input message length.
 * \param context Caller-owned context; NULL only for empty context.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Hash function used by signer to construct digest and OID.
 * \param publickey Caller-owned public key.
 * \return True only if the prehash-mode signature verifies.
 * \note Reentrant; pure-mode signatures are never accepted as prehash signatures.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128s_verify_prehash(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* publickey);


/** \brief Verifies an exactly 7856-byte pure detached SLH-DSA-SHAKE-128s signature.
 * \param signature Exactly 7856 bytes, caller-owned.
 * \param siglen Must equal 7856.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Optional context; NULL iff ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param publickey Input 32-byte public key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128s_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* publickey);

/** \def QSC_SLHDSA_SHAKE128F_PUBLICKEY_SIZE
 * \brief Public key size, bytes for SLH-DSA-SHAKE-128f.
 */
#define QSC_SLHDSA_SHAKE128F_PUBLICKEY_SIZE 32U
/** \def QSC_SLHDSA_SHAKE128F_PRIVATEKEY_SIZE
 * \brief Private key size, bytes for SLH-DSA-SHAKE-128f.
 */
#define QSC_SLHDSA_SHAKE128F_PRIVATEKEY_SIZE 64U
/** \def QSC_SLHDSA_SHAKE128F_SIGNATURE_SIZE
 * \brief Detached signature size, bytes for SLH-DSA-SHAKE-128f.
 */
#define QSC_SLHDSA_SHAKE128F_SIGNATURE_SIZE 17088U
/** \def QSC_SLHDSA_SHAKE128F_KEYGEN_SEED_SIZE
 * \brief Deterministic key-generation seed size, bytes for SLH-DSA-SHAKE-128f.
 */
#define QSC_SLHDSA_SHAKE128F_KEYGEN_SEED_SIZE 48U
/** \def QSC_SLHDSA_SHAKE128F_SIGN_RANDOM_SIZE
 * \brief Hedged signing randomizer size, bytes for SLH-DSA-SHAKE-128f.
 */
#define QSC_SLHDSA_SHAKE128F_SIGN_RANDOM_SIZE 16U

/** \brief Generates the SLH-DSA-SHAKE-128f key pair with a random generator.
 * \param publickey Output buffer, at least 32 bytes.
 * \param privatekey Output buffer, at least 64 bytes; contains secret material.
 * \param rng_generate Cryptographically secure generator, return true on success.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128f_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Generates a repeatable SLH-DSA-SHAKE-128f key pair from 3*n bytes.
 * \param publickey Output buffer, at least 32 bytes.
 * \param privatekey Output buffer, at least 64 bytes.
 * \param seed Exactly 48 bytes, caller-owned and not modified.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128f_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t seed[QSC_SLHDSA_SHAKE128F_KEYGEN_SEED_SIZE]);

/** \brief Creates a FIPS 205 pure hedged detached signature with RNG-supplied randomizer.
 * \param signature Output buffer, at least 17088 bytes.
 * \param siglen Receives 17088 on success, zero on failure.
 * \param message Message pointer; NULL allowed only if msglen is zero.
 * \param msglen Message length in bytes.
 * \param context Optional context, at most 255 bytes; NULL iff ctxlen is zero.
 * \param ctxlen Context length in bytes.
 * \param privatekey Input 64-byte secret key.
 * \param rng_generate Secure randomizer generator, must return true.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128f_sign(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Creates a FIPS 205 pure deterministic detached signature using PK.seed as randomizer.
 * \param signature Output buffer, at least 17088 bytes.
 * \param siglen Receives 17088 on success, zero on failure.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Context pointer; NULL permitted only when ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param privatekey Input 64-byte secret key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128f_sign_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey);

/** \brief HashSLH-DSA-SHAKE-128f hedged signing with FIPS 205 prehash domain.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned plaintext, NULL only for zero length.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only if ctxlen zero.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \param rng_generate Secure n-byte randomizer generator.
 * \return True only when signing succeeds.
 * \note Reentrant; internal prehash/digest and randomizer securely erased.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128f_sign_prehash(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief HashSLH-DSA-SHAKE-128f deterministic prehash signing.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned input, NULL only when msglen zero.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only for empty context.
 * \param ctxlen Context length, at most 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \return True on success, false on invalid inputs or signing failure.
 * \note Reentrant; deterministic signing uses private key's PK.seed.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128f_sign_prehash_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey);

/** \brief Verify a FIPS 205 HashSLH-DSA-SHAKE-128f signature.
 * \param signature Fixed-size caller-owned detached signature.
 * \param siglen Signature length; must match the selected parameter set.
 * \param message Caller-owned message; NULL only for empty message.
 * \param msglen Input message length.
 * \param context Caller-owned context; NULL only for empty context.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Hash function used by signer to construct digest and OID.
 * \param publickey Caller-owned public key.
 * \return True only if the prehash-mode signature verifies.
 * \note Reentrant; pure-mode signatures are never accepted as prehash signatures.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128f_verify_prehash(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* publickey);


/** \brief Verifies an exactly 17088-byte pure detached SLH-DSA-SHAKE-128f signature.
 * \param signature Exactly 17088 bytes, caller-owned.
 * \param siglen Must equal 17088.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Optional context; NULL iff ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param publickey Input 32-byte public key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake128f_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* publickey);

/** \def QSC_SLHDSA_SHAKE192S_PUBLICKEY_SIZE
 * \brief Public key size, bytes for SLH-DSA-SHAKE-192s.
 */
#define QSC_SLHDSA_SHAKE192S_PUBLICKEY_SIZE 48U
/** \def QSC_SLHDSA_SHAKE192S_PRIVATEKEY_SIZE
 * \brief Private key size, bytes for SLH-DSA-SHAKE-192s.
 */
#define QSC_SLHDSA_SHAKE192S_PRIVATEKEY_SIZE 96U
/** \def QSC_SLHDSA_SHAKE192S_SIGNATURE_SIZE
 * \brief Detached signature size, bytes for SLH-DSA-SHAKE-192s.
 */
#define QSC_SLHDSA_SHAKE192S_SIGNATURE_SIZE 16224U
/** \def QSC_SLHDSA_SHAKE192S_KEYGEN_SEED_SIZE
 * \brief Deterministic key-generation seed size, bytes for SLH-DSA-SHAKE-192s.
 */
#define QSC_SLHDSA_SHAKE192S_KEYGEN_SEED_SIZE 72U
/** \def QSC_SLHDSA_SHAKE192S_SIGN_RANDOM_SIZE
 * \brief Hedged signing randomizer size, bytes for SLH-DSA-SHAKE-192s.
 */
#define QSC_SLHDSA_SHAKE192S_SIGN_RANDOM_SIZE 24U

/** \brief Generates the SLH-DSA-SHAKE-192s key pair with a random generator.
 * \param publickey Output buffer, at least 48 bytes.
 * \param privatekey Output buffer, at least 96 bytes; contains secret material.
 * \param rng_generate Cryptographically secure generator, return true on success.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192s_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Generates a repeatable SLH-DSA-SHAKE-192s key pair from 3*n bytes.
 * \param publickey Output buffer, at least 48 bytes.
 * \param privatekey Output buffer, at least 96 bytes.
 * \param seed Exactly 72 bytes, caller-owned and not modified.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192s_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t seed[QSC_SLHDSA_SHAKE192S_KEYGEN_SEED_SIZE]);

/** \brief Creates a FIPS 205 pure hedged detached signature with RNG-supplied randomizer.
 * \param signature Output buffer, at least 16224 bytes.
 * \param siglen Receives 16224 on success, zero on failure.
 * \param message Message pointer; NULL allowed only if msglen is zero.
 * \param msglen Message length in bytes.
 * \param context Optional context, at most 255 bytes; NULL iff ctxlen is zero.
 * \param ctxlen Context length in bytes.
 * \param privatekey Input 96-byte secret key.
 * \param rng_generate Secure randomizer generator, must return true.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192s_sign(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Creates a FIPS 205 pure deterministic detached signature using PK.seed as randomizer.
 * \param signature Output buffer, at least 16224 bytes.
 * \param siglen Receives 16224 on success, zero on failure.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Context pointer; NULL permitted only when ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param privatekey Input 96-byte secret key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192s_sign_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey);

/** \brief HashSLH-DSA-SHAKE-192s hedged signing with FIPS 205 prehash domain.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned plaintext, NULL only for zero length.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only if ctxlen zero.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \param rng_generate Secure n-byte randomizer generator.
 * \return True only when signing succeeds.
 * \note Reentrant; internal prehash/digest and randomizer securely erased.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192s_sign_prehash(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief HashSLH-DSA-SHAKE-192s deterministic prehash signing.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned input, NULL only when msglen zero.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only for empty context.
 * \param ctxlen Context length, at most 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \return True on success, false on invalid inputs or signing failure.
 * \note Reentrant; deterministic signing uses private key's PK.seed.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192s_sign_prehash_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey);

/** \brief Verify a FIPS 205 HashSLH-DSA-SHAKE-192s signature.
 * \param signature Fixed-size caller-owned detached signature.
 * \param siglen Signature length; must match the selected parameter set.
 * \param message Caller-owned message; NULL only for empty message.
 * \param msglen Input message length.
 * \param context Caller-owned context; NULL only for empty context.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Hash function used by signer to construct digest and OID.
 * \param publickey Caller-owned public key.
 * \return True only if the prehash-mode signature verifies.
 * \note Reentrant; pure-mode signatures are never accepted as prehash signatures.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192s_verify_prehash(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* publickey);


/** \brief Verifies an exactly 16224-byte pure detached SLH-DSA-SHAKE-192s signature.
 * \param signature Exactly 16224 bytes, caller-owned.
 * \param siglen Must equal 16224.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Optional context; NULL iff ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param publickey Input 48-byte public key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192s_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* publickey);

/** \def QSC_SLHDSA_SHAKE192F_PUBLICKEY_SIZE
 * \brief Public key size, bytes for SLH-DSA-SHAKE-192f.
 */
#define QSC_SLHDSA_SHAKE192F_PUBLICKEY_SIZE 48U
/** \def QSC_SLHDSA_SHAKE192F_PRIVATEKEY_SIZE
 * \brief Private key size, bytes for SLH-DSA-SHAKE-192f.
 */
#define QSC_SLHDSA_SHAKE192F_PRIVATEKEY_SIZE 96U
/** \def QSC_SLHDSA_SHAKE192F_SIGNATURE_SIZE
 * \brief Detached signature size, bytes for SLH-DSA-SHAKE-192f.
 */
#define QSC_SLHDSA_SHAKE192F_SIGNATURE_SIZE 35664U
/** \def QSC_SLHDSA_SHAKE192F_KEYGEN_SEED_SIZE
 * \brief Deterministic key-generation seed size, bytes for SLH-DSA-SHAKE-192f.
 */
#define QSC_SLHDSA_SHAKE192F_KEYGEN_SEED_SIZE 72U
/** \def QSC_SLHDSA_SHAKE192F_SIGN_RANDOM_SIZE
 * \brief Hedged signing randomizer size, bytes for SLH-DSA-SHAKE-192f.
 */
#define QSC_SLHDSA_SHAKE192F_SIGN_RANDOM_SIZE 24U

/** \brief Generates the SLH-DSA-SHAKE-192f key pair with a random generator.
 * \param publickey Output buffer, at least 48 bytes.
 * \param privatekey Output buffer, at least 96 bytes; contains secret material.
 * \param rng_generate Cryptographically secure generator, return true on success.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192f_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Generates a repeatable SLH-DSA-SHAKE-192f key pair from 3*n bytes.
 * \param publickey Output buffer, at least 48 bytes.
 * \param privatekey Output buffer, at least 96 bytes.
 * \param seed Exactly 72 bytes, caller-owned and not modified.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192f_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t seed[QSC_SLHDSA_SHAKE192F_KEYGEN_SEED_SIZE]);

/** \brief Creates a FIPS 205 pure hedged detached signature with RNG-supplied randomizer.
 * \param signature Output buffer, at least 35664 bytes.
 * \param siglen Receives 35664 on success, zero on failure.
 * \param message Message pointer; NULL allowed only if msglen is zero.
 * \param msglen Message length in bytes.
 * \param context Optional context, at most 255 bytes; NULL iff ctxlen is zero.
 * \param ctxlen Context length in bytes.
 * \param privatekey Input 96-byte secret key.
 * \param rng_generate Secure randomizer generator, must return true.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192f_sign(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Creates a FIPS 205 pure deterministic detached signature using PK.seed as randomizer.
 * \param signature Output buffer, at least 35664 bytes.
 * \param siglen Receives 35664 on success, zero on failure.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Context pointer; NULL permitted only when ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param privatekey Input 96-byte secret key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192f_sign_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey);

/** \brief HashSLH-DSA-SHAKE-192f hedged signing with FIPS 205 prehash domain.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned plaintext, NULL only for zero length.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only if ctxlen zero.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \param rng_generate Secure n-byte randomizer generator.
 * \return True only when signing succeeds.
 * \note Reentrant; internal prehash/digest and randomizer securely erased.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192f_sign_prehash(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief HashSLH-DSA-SHAKE-192f deterministic prehash signing.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned input, NULL only when msglen zero.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only for empty context.
 * \param ctxlen Context length, at most 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \return True on success, false on invalid inputs or signing failure.
 * \note Reentrant; deterministic signing uses private key's PK.seed.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192f_sign_prehash_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey);

/** \brief Verify a FIPS 205 HashSLH-DSA-SHAKE-192f signature.
 * \param signature Fixed-size caller-owned detached signature.
 * \param siglen Signature length; must match the selected parameter set.
 * \param message Caller-owned message; NULL only for empty message.
 * \param msglen Input message length.
 * \param context Caller-owned context; NULL only for empty context.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Hash function used by signer to construct digest and OID.
 * \param publickey Caller-owned public key.
 * \return True only if the prehash-mode signature verifies.
 * \note Reentrant; pure-mode signatures are never accepted as prehash signatures.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192f_verify_prehash(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* publickey);


/** \brief Verifies an exactly 35664-byte pure detached SLH-DSA-SHAKE-192f signature.
 * \param signature Exactly 35664 bytes, caller-owned.
 * \param siglen Must equal 35664.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Optional context; NULL iff ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param publickey Input 48-byte public key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake192f_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* publickey);

/** \def QSC_SLHDSA_SHAKE256S_PUBLICKEY_SIZE
 * \brief Public key size, bytes for SLH-DSA-SHAKE-256s.
 */
#define QSC_SLHDSA_SHAKE256S_PUBLICKEY_SIZE 64U
/** \def QSC_SLHDSA_SHAKE256S_PRIVATEKEY_SIZE
 * \brief Private key size, bytes for SLH-DSA-SHAKE-256s.
 */
#define QSC_SLHDSA_SHAKE256S_PRIVATEKEY_SIZE 128U
/** \def QSC_SLHDSA_SHAKE256S_SIGNATURE_SIZE
 * \brief Detached signature size, bytes for SLH-DSA-SHAKE-256s.
 */
#define QSC_SLHDSA_SHAKE256S_SIGNATURE_SIZE 29792U
/** \def QSC_SLHDSA_SHAKE256S_KEYGEN_SEED_SIZE
 * \brief Deterministic key-generation seed size, bytes for SLH-DSA-SHAKE-256s.
 */
#define QSC_SLHDSA_SHAKE256S_KEYGEN_SEED_SIZE 96U
/** \def QSC_SLHDSA_SHAKE256S_SIGN_RANDOM_SIZE
 * \brief Hedged signing randomizer size, bytes for SLH-DSA-SHAKE-256s.
 */
#define QSC_SLHDSA_SHAKE256S_SIGN_RANDOM_SIZE 32U

/** \brief Generates the SLH-DSA-SHAKE-256s key pair with a random generator.
 * \param publickey Output buffer, at least 64 bytes.
 * \param privatekey Output buffer, at least 128 bytes; contains secret material.
 * \param rng_generate Cryptographically secure generator, return true on success.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256s_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Generates a repeatable SLH-DSA-SHAKE-256s key pair from 3*n bytes.
 * \param publickey Output buffer, at least 64 bytes.
 * \param privatekey Output buffer, at least 128 bytes.
 * \param seed Exactly 96 bytes, caller-owned and not modified.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256s_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t seed[QSC_SLHDSA_SHAKE256S_KEYGEN_SEED_SIZE]);

/** \brief Creates a FIPS 205 pure hedged detached signature with RNG-supplied randomizer.
 * \param signature Output buffer, at least 29792 bytes.
 * \param siglen Receives 29792 on success, zero on failure.
 * \param message Message pointer; NULL allowed only if msglen is zero.
 * \param msglen Message length in bytes.
 * \param context Optional context, at most 255 bytes; NULL iff ctxlen is zero.
 * \param ctxlen Context length in bytes.
 * \param privatekey Input 128-byte secret key.
 * \param rng_generate Secure randomizer generator, must return true.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256s_sign(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Creates a FIPS 205 pure deterministic detached signature using PK.seed as randomizer.
 * \param signature Output buffer, at least 29792 bytes.
 * \param siglen Receives 29792 on success, zero on failure.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Context pointer; NULL permitted only when ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param privatekey Input 128-byte secret key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256s_sign_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey);

/** \brief HashSLH-DSA-SHAKE-256s hedged signing with FIPS 205 prehash domain.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned plaintext, NULL only for zero length.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only if ctxlen zero.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \param rng_generate Secure n-byte randomizer generator.
 * \return True only when signing succeeds.
 * \note Reentrant; internal prehash/digest and randomizer securely erased.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256s_sign_prehash(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief HashSLH-DSA-SHAKE-256s deterministic prehash signing.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned input, NULL only when msglen zero.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only for empty context.
 * \param ctxlen Context length, at most 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \return True on success, false on invalid inputs or signing failure.
 * \note Reentrant; deterministic signing uses private key's PK.seed.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256s_sign_prehash_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey);

/** \brief Verify a FIPS 205 HashSLH-DSA-SHAKE-256s signature.
 * \param signature Fixed-size caller-owned detached signature.
 * \param siglen Signature length; must match the selected parameter set.
 * \param message Caller-owned message; NULL only for empty message.
 * \param msglen Input message length.
 * \param context Caller-owned context; NULL only for empty context.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Hash function used by signer to construct digest and OID.
 * \param publickey Caller-owned public key.
 * \return True only if the prehash-mode signature verifies.
 * \note Reentrant; pure-mode signatures are never accepted as prehash signatures.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256s_verify_prehash(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* publickey);


/** \brief Verifies an exactly 29792-byte pure detached SLH-DSA-SHAKE-256s signature.
 * \param signature Exactly 29792 bytes, caller-owned.
 * \param siglen Must equal 29792.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Optional context; NULL iff ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param publickey Input 64-byte public key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256s_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* publickey);

/** \def QSC_SLHDSA_SHAKE256F_PUBLICKEY_SIZE
 * \brief Public key size, bytes for SLH-DSA-SHAKE-256f.
 */
#define QSC_SLHDSA_SHAKE256F_PUBLICKEY_SIZE 64U
/** \def QSC_SLHDSA_SHAKE256F_PRIVATEKEY_SIZE
 * \brief Private key size, bytes for SLH-DSA-SHAKE-256f.
 */
#define QSC_SLHDSA_SHAKE256F_PRIVATEKEY_SIZE 128U
/** \def QSC_SLHDSA_SHAKE256F_SIGNATURE_SIZE
 * \brief Detached signature size, bytes for SLH-DSA-SHAKE-256f.
 */
#define QSC_SLHDSA_SHAKE256F_SIGNATURE_SIZE 49856U
/** \def QSC_SLHDSA_SHAKE256F_KEYGEN_SEED_SIZE
 * \brief Deterministic key-generation seed size, bytes for SLH-DSA-SHAKE-256f.
 */
#define QSC_SLHDSA_SHAKE256F_KEYGEN_SEED_SIZE 96U
/** \def QSC_SLHDSA_SHAKE256F_SIGN_RANDOM_SIZE
 * \brief Hedged signing randomizer size, bytes for SLH-DSA-SHAKE-256f.
 */
#define QSC_SLHDSA_SHAKE256F_SIGN_RANDOM_SIZE 32U

/** \brief Generates the SLH-DSA-SHAKE-256f key pair with a random generator.
 * \param publickey Output buffer, at least 64 bytes.
 * \param privatekey Output buffer, at least 128 bytes; contains secret material.
 * \param rng_generate Cryptographically secure generator, return true on success.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256f_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Generates a repeatable SLH-DSA-SHAKE-256f key pair from 3*n bytes.
 * \param publickey Output buffer, at least 64 bytes.
 * \param privatekey Output buffer, at least 128 bytes.
 * \param seed Exactly 96 bytes, caller-owned and not modified.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256f_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t seed[QSC_SLHDSA_SHAKE256F_KEYGEN_SEED_SIZE]);

/** \brief Creates a FIPS 205 pure hedged detached signature with RNG-supplied randomizer.
 * \param signature Output buffer, at least 49856 bytes.
 * \param siglen Receives 49856 on success, zero on failure.
 * \param message Message pointer; NULL allowed only if msglen is zero.
 * \param msglen Message length in bytes.
 * \param context Optional context, at most 255 bytes; NULL iff ctxlen is zero.
 * \param ctxlen Context length in bytes.
 * \param privatekey Input 128-byte secret key.
 * \param rng_generate Secure randomizer generator, must return true.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256f_sign(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Creates a FIPS 205 pure deterministic detached signature using PK.seed as randomizer.
 * \param signature Output buffer, at least 49856 bytes.
 * \param siglen Receives 49856 on success, zero on failure.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Context pointer; NULL permitted only when ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param privatekey Input 128-byte secret key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. Signing reads secret material; never share writable buffers across calls.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256f_sign_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey);

/** \brief HashSLH-DSA-SHAKE-256f hedged signing with FIPS 205 prehash domain.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned plaintext, NULL only for zero length.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only if ctxlen zero.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \param rng_generate Secure n-byte randomizer generator.
 * \return True only when signing succeeds.
 * \note Reentrant; internal prehash/digest and randomizer securely erased.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256f_sign_prehash(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief HashSLH-DSA-SHAKE-256f deterministic prehash signing.
 * \param signature Output buffer of the set's signature size.
 * \param siglen Output signature length or zero on error.
 * \param message Caller-owned input, NULL only when msglen zero.
 * \param msglen Input message length.
 * \param context Caller-owned context, NULL only for empty context.
 * \param ctxlen Context length, at most 255 bytes.
 * \param algorithm Supported prehash function.
 * \param privatekey Caller-owned private key.
 * \return True on success, false on invalid inputs or signing failure.
 * \note Reentrant; deterministic signing uses private key's PK.seed.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256f_sign_prehash_deterministic(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey);

/** \brief Verify a FIPS 205 HashSLH-DSA-SHAKE-256f signature.
 * \param signature Fixed-size caller-owned detached signature.
 * \param siglen Signature length; must match the selected parameter set.
 * \param message Caller-owned message; NULL only for empty message.
 * \param msglen Input message length.
 * \param context Caller-owned context; NULL only for empty context.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param algorithm Hash function used by signer to construct digest and OID.
 * \param publickey Caller-owned public key.
 * \return True only if the prehash-mode signature verifies.
 * \note Reentrant; pure-mode signatures are never accepted as prehash signatures.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256f_verify_prehash(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* publickey);


/** \brief Verifies an exactly 49856-byte pure detached SLH-DSA-SHAKE-256f signature.
 * \param signature Exactly 49856 bytes, caller-owned.
 * \param siglen Must equal 49856.
 * \param message Message pointer; NULL permitted only when msglen is zero.
 * \param msglen Message length.
 * \param context Optional context; NULL iff ctxlen is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param publickey Input 64-byte public key.
 * \return True on success, false on invalid input or cryptographic failure.
 * \note Reentrant. All buffers are caller-owned. No shared mutable state.
 */
QSC_EXPORT_API bool qsc_slhdsa_shake256f_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
