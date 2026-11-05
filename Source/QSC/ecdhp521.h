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

 /* Implementation acknowledgements:
 *
 * This QRCS implementation was developed with reference to the
 * Botan cryptographic library, established cryptographic research,
 * applicable NIST and IETF standards, and published algorithms.
 *
 * The implementation has been adapted and optimized for the QSC
 * architecture, including its arithmetic engines, memory management,
 * platform-specific acceleration, and security requirements.
 *
 * Reference: Botan Cryptographic Library
 * https://botan.randombit.net/
 *
 * Copyright and licensing of third-party derived material remain
 * subject to the applicable original license terms.
 */

#ifndef QSC_ECDHP521_H

#define QSC_ECDHP521_H

#include "qsccommon.h"

 /* \cond NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/*! \file ecdhp521.h
 * \brief NIST P-521 ECDH key generation and raw agreement.
 * \details Keys retain the established raw encoding: 66-byte big-endian private
 * scalar in [1,n), 132-byte public X||Y, and 66-byte shared X coordinate.
 * Seed processing is unchanged. Fresh QSC CSP entropy is required independently
 * for scalar and coordinate blinding, including deterministic seeded generation.
 * Failure clears each supplied output. Inputs/outputs must not overlap; callers
 * provide the full fixed-size buffers. All storage remains caller-owned.
 * No heap allocation or mutable global state; independent calls are thread-safe.
 * Raw ECDH output must be processed by an appropriate protocol KDF. This module
 * does not authenticate the peer or define a key-confirmation protocol.
 */

/*! \def QSC_ECDHP521_PUBLICKEY_SIZE
 * \brief P-521 publickey length in bytes.
 */
#define QSC_ECDHP521_PUBLICKEY_SIZE 132U

/*! \def QSC_ECDHP521_PRIVATEKEY_SIZE
 * \brief P-521 privatekey length in bytes.
 */
#define QSC_ECDHP521_PRIVATEKEY_SIZE 66U

/*! \def QSC_ECDHP521_SHAREDSECRET_SIZE
 * \brief P-521 sharedsecret length in bytes.
 */
#define QSC_ECDHP521_SHAREDSECRET_SIZE 66U

/*! \def QSC_ECDHP521_SEED_SIZE
 * \brief P-521 seed length in bytes.
 */
#define QSC_ECDHP521_SEED_SIZE 66U

/*! \brief Derive the public point of a raw private scalar.
 * \param publickey Caller-owned 132-byte X||Y output, cleared on failure.
 * \param privatekey Read-only 66-byte big-endian scalar in [1,n).
 * \return Zero on success; -1 for null input, -2 for zero scalar, -3 for an
 * out-of-range scalar, -9 for unavailable blinding entropy; other negatives fail.
 */
QSC_EXPORT_API int32_t qsc_ecdhp521_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey);

/*! \brief Multiply a validated peer point by a raw private scalar.
 * \param secret Caller-owned 66-byte X-coordinate output, cleared on failure.
 * \param privatekey Read-only 66-byte big-endian scalar in [1,n).
 * \param publickey Read-only 132-byte canonical peer X||Y point.
 * \return Zero on success; -1 for null input, -2 for zero scalar, -3 for scalar
 * range, -4 for coordinate range, -5 for an off-curve point, -9 for entropy failure.
 * Other negative values indicate arithmetic failure. The low-level result may be
 * all zero; use key_exchange for the established all-zero rejection policy.
 */
QSC_EXPORT_API int32_t qsc_ecdhp521_scalar_multiply(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey);

/*! \brief Generate a key pair from a caller-supplied seed.
 * \param publickey Caller-owned 132-byte X||Y output, cleared on failure.
 * \param privatekey Caller-owned 66-byte raw scalar output, erased on failure.
 * \param seed Read-only 66-byte seed; must not overlap either output.
 * \return True on success; false on null inputs, zero derived scalar or CSP failure.
 */
QSC_EXPORT_API bool qsc_ecdhp521_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/*! \brief Generate a key pair from a fresh callback-supplied seed.
 * \param publickey Caller-owned 132-byte X||Y output, cleared on failure.
 * \param privatekey Caller-owned 66-byte raw scalar output, erased on failure.
 * \param rng_generate Callback writing exactly its requested byte count and returning
 * true only when all bytes are cryptographically random. Invoked once for 66 bytes;
 * borrowed buffers must not be retained. Callback state must be thread-safe when
 * shared. Blinding separately uses the QSC CSP and may independently fail.
 * \return True on success; false on null inputs, callback failure or derivation failure.
 */
QSC_EXPORT_API bool qsc_ecdhp521_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/*! \brief Validate the peer and derive a nonzero raw ECDH agreement value.
 * \param secret Caller-owned 66-byte shared output, cleared on failure.
 * \param publickey Read-only 132-byte peer X||Y.
 * \param privatekey Read-only 66-byte canonical scalar.
 * \return True on success; false on invalid inputs, CSP failure or all-zero output.
 * \warning This curve API takes the public key before the private key, unlike qsc_ecdh_key_exchange.
 */
QSC_EXPORT_API bool qsc_ecdhp521_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

/*! \brief Compatibility entry point for qsc_ecdhp521_publickey_from_privatekey.
 * \param publickey Caller-owned 132-byte X||Y output, cleared on failure.
 * \param privatekey Read-only 66-byte big-endian scalar in [1,n).
 * \details No return status. Use the canonical API to distinguish validation and
 * entropy failures. The same nonoverlap and thread-safety contracts apply.
 */
QSC_EXPORT_API void qsc_p521_public_from_private(uint8_t* publickey, const uint8_t* privatekey);

/*! \brief Compatibility entry point for qsc_ecdhp521_generate_seeded_keypair.
 * \param publickey Caller-owned 132-byte X||Y output, cleared on failure.
 * \param privatekey Caller-owned 66-byte scalar output, erased on failure.
 * \param seed Read-only 66-byte seed; must not overlap either output.
 * \details No return status. Use the canonical API to detect failure. Fresh CSP
 * entropy is required for blinding; independent calls are thread-safe.
 */
QSC_EXPORT_API void qsc_p521_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/*! \brief Compatibility entry point for qsc_ecdhp521_generate_keypair.
 * \param publickey Caller-owned 132-byte X||Y output, cleared on failure.
 * \param privatekey Caller-owned 66-byte scalar output, erased on failure.
 * \param rng_generate Borrowed callback with the same ownership, randomness and
 * thread-safety contract as qsc_ecdhp521_generate_keypair.
 * \details No return status. Use the canonical API to detect callback or CSP
 * failure. Inputs and outputs must not overlap.
 */
QSC_EXPORT_API void qsc_p521_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/*! \brief Compatibility entry point for qsc_ecdhp521_key_exchange.
 * \copydetails qsc_ecdhp521_key_exchange
 */
QSC_EXPORT_API bool qsc_p521_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

QSC_CPLUSPLUS_ENABLED_END

/* \endcond NO_DOCUMENT */

#endif
