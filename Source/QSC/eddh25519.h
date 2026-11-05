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

#ifndef QSC_EDDH25519_H
#define QSC_EDDH25519_H

#include "qsccommon.h"

 /* \cond NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/*! \file eddh25519.h
 * \brief RFC 7748 X25519 key generation and Diffie-Hellman agreement.
 * \details Encodings and public signatures are unchanged. All buffers are caller-owned;
 * sizes below are mandatory. Public APIs assert non-null preconditions in debug builds
 * and fail safely for null pointers in release builds. No heap allocation or mutable
 * global state. Overlap is supported only where explicitly documented.
 */

/*! \def QSC_X25519_PUBLICKEY_SIZE
 * \brief Public u-coordinate length in bytes.
 */
#define QSC_X25519_PUBLICKEY_SIZE 32U

/*! \def QSC_X25519_PRIVATEKEY_SIZE
 * \brief Unclamped private scalar length in bytes.
 */
#define QSC_X25519_PRIVATEKEY_SIZE 32U

/*! \def QSC_X25519_SECRET_SIZE
 * \brief Raw agreement output length in bytes.
 */
#define QSC_X25519_SECRET_SIZE 32U

/*! \def QSC_X25519_SEED_SIZE
 * \brief Deterministic seed length in bytes.
 */
#define QSC_X25519_SEED_SIZE 32U

/*! \brief Compute an RFC 7748 X25519 agreement value.
 * \param q: Caller-owned 32-byte output; may alias either input.
 * \param n: Read-only 32-byte private scalar; clamped internally.
 * \param p: Read-only 32-byte little-endian peer u-coordinate.
 * \return Zero on success; -1 for null inputs, rejected low-order input or all-zero output.
 * \details A supplied output is cleared for null input. Noncanonical coordinates are accepted
 * and the top input bit is ignored. No heap allocation or shared mutable state.
 */
QSC_EXPORT_API int32_t qsc_crypto_scalarmult_curve25519(uint8_t* q, const uint8_t* n, const uint8_t* p);

/*! \brief Compatibility entry point for variable-base multiplication.
 * \param q: Caller-owned 32-byte output; may alias either input.
 * \param n: Read-only 32-byte raw scalar; clamped internally.
 * \param p: Read-only 32-byte little-endian peer u-coordinate.
 * \return Zero when the established low-order input check accepts the peer; -1 otherwise.
 * \details The result is computed even when the peer is rejected; null inputs fail and clear
 * a supplied output. Use qsc_x25519_key_exchange for the complete output check.
 */
QSC_EXPORT_API int32_t qsc_crypto_scalarmult_curve25519_ref10(uint8_t* q, const uint8_t* n, const uint8_t* p);

/*! \brief Compatibility entry point for base-point multiplication.
 * \param q: Caller-owned 32-byte public output; may alias n.
 * \param n: Read-only 32-byte raw scalar; clamped internally.
 * \return Zero on success; -1 for null input.
 * \details A supplied output is cleared for null input. The historical symbol is retained
 * for ABI compatibility; it does not select a separate ref10 implementation.
 */
QSC_EXPORT_API int32_t qsc_crypto_scalarmult_curve25519_ref10_base(uint8_t* q, const uint8_t* n);

/*! \brief Generate an X25519 key pair using a random callback.
 * \param publickey: Caller-owned 32-byte public output; distinct from privatekey.
 * \param privatekey: Caller-owned 32-byte raw private output; clamping does not modify it.
 * \param rng_generate: Borrowed callback, invoked once for 32 bytes. Return true only after filling
 * every requested byte with cryptographically secure randomness. Do not retain the buffer;
 * synchronize callback state when shared between threads.
 * \details Null input or callback failure clears each supplied output and securely erases
 * the private output. The API returns void; no key pair is produced on failure.
 */
QSC_EXPORT_API void qsc_x25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/*! \brief Generate the established deterministic X25519 key pair from a seed.
 * \param publickey: Caller-owned 32-byte public output; must not overlap the other buffers.
 * \param privatekey: Caller-owned 32-byte raw private output; receives the unmodified seed.
 * \param seed: Read-only 32-byte seed. May equal privatekey; other overlap is unsupported.
 * \details No status return; null input clears each supplied output. Clamping applies
 * only to an internal copy. Independent calls share no mutable state.
 */
QSC_EXPORT_API void qsc_x25519_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/*! \brief Compute an X25519 agreement value and reject all-zero output.
 * \param secret: Caller-owned 32-byte shared output; may alias an input.
 * \param publickey: Read-only 32-byte peer u-coordinate.
 * \param privatekey: Read-only 32-byte raw private scalar; clamped internally.
 * \return True for an accepted nonzero result; false for null inputs or a rejected result.
 * \details Null inputs clear a supplied output. Rejected low-order peers produce zero.
 * The entire output is checked without early exit. Apply a protocol KDF before use as a key;
 * this function does not authenticate the peer. Independent calls are thread-safe.
 */
QSC_EXPORT_API bool qsc_x25519_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

/*! \brief Derive an X25519 public key from a raw private scalar.
 * \param publickey: Caller-owned 32-byte public output; may alias privatekey.
 * \param privatekey: Read-only 32-byte scalar; clamping uses an internal erased copy.
 * \details No status return; null inputs clear a supplied output. No allocation or mutable
 * global state; calls with independent output buffers are thread-safe.
 */
QSC_EXPORT_API void qsc_x25519_public_from_private(uint8_t* publickey, const uint8_t* privatekey);

QSC_CPLUSPLUS_ENABLED_END

/* \endcond NO_DOCUMENT */

#endif
