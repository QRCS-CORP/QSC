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

#ifndef QSC_EDDH448_H
#define QSC_EDDH448_H

#include "qsccommon.h"


QSC_CPLUSPLUS_ENABLED_START

/**
 * \file eddh448.h
 * \brief Public X448 key exchange API (RFC 7748).
 *
 * \details
 * This header exposes the independent X448 Diffie-Hellman scalar multiplication
 * functions over the RFC 7748 Montgomery Curve448 curve. The functions
 * remain available regardless of the default EDDH facade selection.
 */

/*!
 * \def QSC_X448_PUBLICKEY_SIZE
 * \brief X448 public key size in bytes (u-coordinate).
 */
#define QSC_X448_PUBLICKEY_SIZE 56U

/*!
 * \def QSC_X448_PRIVATEKEY_SIZE
 * \brief X448 private key size in bytes (clamped scalar).
 */
#define QSC_X448_PRIVATEKEY_SIZE 56U

/*!
 * \def QSC_X448_SECRET_SIZE
 * \brief X448 shared secret size in bytes.
 */
#define QSC_X448_SECRET_SIZE 56U

/**
 * \def QSC_X448_SEED_SIZE
 * \brief Size of the X448 key-generation seed in bytes.
 */
#define QSC_X448_SEED_SIZE 56U

/**
 * \brief Multiply the X448 base point by a scalar (scalar * G).
 *
 * Performs the fixed-base scalar multiplication u = a * G on the
 * Montgomery curve Curve448, returning the u-coordinate as the
 * 56-byte public key.
 *
 * \param q: [uint8_t*] Output 56-byte u-coordinate.
 * \param n: [const uint8_t*] Input 56-byte clamped scalar.
 */
QSC_EXPORT_API void qsc_crypto_scalarmult_curve448_ref10_base(uint8_t* q, const uint8_t* n);

/**
 * \brief Multiply an arbitrary X448 point by a scalar.
 *
 * Performs variable-base scalar multiplication u = n * q on
 * Curve448, returning the 56-byte u-coordinate.
 *
 * \param r: [uint8_t*] Output 56-byte u-coordinate.
 * \param n: [const uint8_t*] Input 56-byte clamped scalar.
 * \param q: [const uint8_t*] Input 56-byte u-coordinate of the base.
 */
QSC_EXPORT_API void qsc_crypto_scalarmult_curve448_ref10(uint8_t* r, const uint8_t* n, const uint8_t* q);

/**
 * \brief Clamp a secret scalar for X448/Ed448.
 *
 * Clears the two low-order bits and sets the high bit of byte 55, per RFC 7748 / RFC 8032.
 *
 * \param k: [uint8_t*] Pointer to the 56-byte scalar to be clamped.
 */
QSC_EXPORT_API void qsc_crypto_sc448_clamp(uint8_t* k);

/**
 * \brief Perform an X448 Diffie-Hellman scalar multiplication.
 *
 * Wrapper around qsc_crypto_scalarmult_curve448_ref10 that applies
 * RFC 7748 clamping before the multiplication.
 *
 * \param q: [uint8_t*] Output 56-byte shared secret.
 * \param n: [const uint8_t*] Input 56-byte private scalar (unclamped).
 * \param p: [const uint8_t*] Input 56-byte peer public key.
 */
QSC_EXPORT_API void qsc_crypto_scalarmult_curve448(uint8_t* q, const uint8_t* n, const uint8_t* p);

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism using a random function pointer.
 *
 * \warning Arrays must be sized to QSC_X448_PUBLICKEY_SIZE and QSC_X448_PRIVATEKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param rng_generate: [bool (uint8_t*, size_t)] Pointer to the random generator function.
 */
QSC_EXPORT_API void qsc_x448_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism using a seed.
 *
 * \warning Arrays must be sized to QSC_X448_PUBLICKEY_SIZE and QSC_X448_PRIVATEKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param seed: [const uint8_t*] Pointer to the random seed.
 */
QSC_EXPORT_API void qsc_x448_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Perform an X448 key exchange.
 *
 * Computes the 56-byte shared secret from the local private key and
 * the remote public key.
 *
 * \param secret: [uint8_t*] Output 56-byte shared secret.
 * \param publickey: [const uint8_t*] Remote 56-byte public key.
 * \param privatekey: [const uint8_t*] Local 56-byte private key.
 * 
 * \return [bool] Returns true if the exchange succeeded; false if the peer public key is the all-zero point (invalid).
 */
QSC_EXPORT_API bool qsc_x448_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Derive an X448 public key from a raw private scalar.
 * \param publickey: [uint8_t*] Caller-owned output of QSC_X448_PUBLICKEY_SIZE bytes.
 * \param privatekey: [const uint8_t*] Caller-owned input of QSC_X448_PRIVATEKEY_SIZE bytes.
 * \details The private scalar is clamped internally per RFC 7748 without modifying the input.
 * Buffers must not overlap. No shared mutable state is accessed and concurrent calls are safe.
 * The function returns void; callers must supply valid buffers.
 */
QSC_EXPORT_API void qsc_x448_public_from_private(uint8_t* publickey, const uint8_t* privatekey);

QSC_CPLUSPLUS_ENABLED_END


#endif
