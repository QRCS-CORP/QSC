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

#ifndef QSC_ECDHP256BASE_H
#define QSC_ECDHP256BASE_H

#include "qsccommon.h"

/* \cond NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file ecdhp256base.h
 * \brief Internal NIST P-256 ECDH key-exchange functions.
 *
 * \details
 * This file provides a low-level Elliptic Curve Diffie-Hellman implementation for
 * NIST P-256 (secp256r1). The implementation uses constant-time scalar multiplication
 * over the short Weierstrass curve defined in FIPS 186-5 and SEC 1, with public-key
 * validation prior to shared-secret derivation. Public keys are encoded as the raw
 * affine form Qx || Qy using 32-byte big-endian coordinates. The shared secret is the
 * 32-byte big-endian affine X coordinate of dQ.
 *
 * The private key format used by this module is a raw 32-byte big-endian scalar in the
 * range [1, n - 1]. Seeded key generation derives that scalar from SHA-256(seed) reduced
 * modulo the group order n, rejecting the zero result.
 */

/*! \def QSC_ECDHP256_PUBLICKEY_SIZE
 *  \brief The ECDH P-256 public-key size in bytes (Qx || Qy).
 */
#define QSC_ECDHP256_PUBLICKEY_SIZE 64U

/*! \def QSC_ECDHP256_PRIVATEKEY_SIZE
 *  \brief The ECDH P-256 private-key size in bytes.
 */
#define QSC_ECDHP256_PRIVATEKEY_SIZE 32U

/*! \def QSC_ECDHP256_SHAREDSECRET_SIZE
 *  \brief The ECDH P-256 shared-secret size in bytes.
 */
#define QSC_ECDHP256_SHAREDSECRET_SIZE 32U

/*! \def QSC_ECDHP256_SEED_SIZE
 *  \brief The ECDH P-256 seed size in bytes.
 */
#define QSC_ECDHP256_SEED_SIZE 32U

/**
 * \brief Multiply the P-256 base point by a private scalar.
 *
 * \details
 * Computes Q = dG where d is a 32-byte big-endian scalar in the range [1, n - 1],
 * and serializes the affine public point as Qx || Qy.
 *
 * \param publickey:  [uint8_t*] Output 64-byte public key.
 * \param privatekey: [const uint8_t*] Input 32-byte private scalar.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
int32_t qsc_crypto_scalarmult_secp256r1_base(uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Multiply an arbitrary P-256 public point by a private scalar.
 *
 * \details
 * Computes S = dQ where d is a 32-byte big-endian scalar in the range [1, n - 1]
 * and Q is a 64-byte affine public point encoded as Qx || Qy. On success the affine
 * X coordinate of S is returned as the 32-byte big-endian shared secret.
 *
 * \param secret:     [uint8_t*] Output 32-byte shared secret.
 * \param privatekey: [const uint8_t*] Input 32-byte private scalar.
 * \param publickey:  [const uint8_t*] Input 64-byte peer public key.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
int32_t qsc_crypto_scalarmult_secp256r1(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey);

/**
 * \brief Derive an ECDH P-256 public key from an existing private key.
 *
 * \param publickey:  [uint8_t*] Output 64-byte public key.
 * \param privatekey: [const uint8_t*] Input 32-byte private scalar.
 */
void qsc_p256_public_from_private(uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Generate an ECDH P-256 key pair using a random generator callback.
 *
 * \details
 * The RNG fills a 32-byte seed which is reduced into a non-zero private scalar, then
 * the corresponding public key is derived by scalar multiplication of the base point.
 *
 * \param publickey:    [uint8_t*] Output 64-byte public key.
 * \param privatekey:   [uint8_t*] Output 32-byte private scalar.
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Random generator callback.
 */
void qsc_p256_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generate an ECDH P-256 key pair from a seed.
 *
 * \param publickey:  [uint8_t*] Output 64-byte public key.
 * \param privatekey: [uint8_t*] Output 32-byte private scalar.
 * \param seed:       [const uint8_t*] Input 32-byte seed.
 */
void qsc_p256_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Perform an ECDH P-256 key exchange.
 *
 * \details
 * Validates the peer public point and computes the affine X coordinate of dQ. The
 * function returns false on invalid inputs, invalid peer points, or an all-zero shared
 * secret.
 *
 * \param secret:     [uint8_t*] Output 32-byte shared secret.
 * \param publickey:  [const uint8_t*] Input 64-byte peer public key.
 * \param privatekey: [const uint8_t*] Input 32-byte private scalar.
 *
 * \return [bool] Returns true on success.
 */
bool qsc_p256_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

QSC_CPLUSPLUS_ENABLED_END

/* \endcond NO_DOCUMENT */

#endif
