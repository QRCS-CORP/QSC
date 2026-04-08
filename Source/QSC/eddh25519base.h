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

#ifndef QSC_ECDH25519BASE_H
#define QSC_ECDH25519BASE_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file ecdhbase.h
 * \brief Contains the internal API for Ed25519 key exchange operations.
 *
 * \details
 * This header defines functions for combining an external public key with an internal
 * private key to produce a shared secret, as well as for generating key pairs for the
 * Elliptic Curve Diffie-Hellman (ECDH) key encapsulation mechanism using the Ed25519 curve.
 */

/**
 * \brief Computes an X25519 scalar multiplication on Curve25519.
 *
 * This function is a Curve25519 scalar multiplication interface intended for use by higher-level
 * ECDH and key encapsulation mechanisms. It computes the scalar multiplication of a point \p p
 * by a scalar \p n and writes the resulting u-coordinate to \p q, encoded as 32 bytes in
 * little-endian form.
 *
 * The scalar \p n is treated as a 32-byte X25519 private key and is clamped internally in
 * accordance with RFC 7748.
 *
 * The input point \p p is interpreted as a Curve25519 u-coordinate encoded as 32 bytes in
 * little-endian form.
 *
 * \warning The output buffer \p q must be at least 32 bytes in length.
 * \warning The input buffers \p n and \p p must be at least 32 bytes in length.
 *
 * \param q: [uint8_t*] Pointer to the output u-coordinate array (32 bytes).
 * \param n: [const uint8_t*] Pointer to the input scalar/private-key array (32 bytes).
 * \param p: [const uint8_t*] Pointer to the input u-coordinate array (32 bytes).
 *
 * \return   [int32_t] Returns 0 on success; a non-zero value indicates failure.
 */
int32_t qsc_crypto_scalarmult_curve25519(uint8_t* q, const uint8_t* n, const uint8_t* p);

/**
 * \brief Computes an X25519 scalar multiplication on Curve25519.
 *
 * This function computes the scalar multiplication of a Curve25519 point \p p by a scalar \p n
 * and writes the resulting u-coordinate to \p q, encoded as 32 bytes in little-endian form.
 *
 * The scalar \p n is treated as a 32-byte X25519 private key and is clamped internally in
 * accordance with RFC 7748.
 *
 * The input point \p p is interpreted as a Curve25519 u-coordinate encoded as 32 bytes in
 * little-endian form.
 *
 * For interoperability and side-channel safety, implementations commonly reject the all-zero
 * shared secret. If this function performs that check, it returns a non-zero value on failure.
 *
 * \warning The output buffer \p q must be at least 32 bytes in length.
 * \warning The input buffers \p n and \p p must be at least 32 bytes in length.
 *
 * \param q: [uint8_t*] Pointer to the output u-coordinate array (32 bytes).
 * \param n: [const uint8_t*] Pointer to the input scalar/private-key array (32 bytes).
 * \param p: [const uint8_t*] Pointer to the input u-coordinate array (32 bytes).
 *
 * \return   [int32_t] Returns 0 on success; a non-zero value indicates failure.
 */
int32_t qsc_crypto_scalarmult_curve25519_ref10(uint8_t* q, const uint8_t* n, const uint8_t* p);

/**
 * \brief Computes an X25519 public key by performing a Curve25519 basepoint scalar multiplication.
 *
 * This function multiplies the Curve25519 standard basepoint by the scalar \p n and writes the
 * resulting u-coordinate to \p q, encoded as 32 bytes in little-endian form.
 *
 * The scalar \p n is treated as a 32-byte X25519 private key and is clamped internally in
 * accordance with RFC 7748.
 *
 * \warning The output buffer \p q must be at least 32 bytes in length.
 * \warning The input buffer \p n must be at least 32 bytes in length.
 *
 * \param q: [uint8_t*] Pointer to the output public-key array (32 bytes).
 * \param n: [const uint8_t*] Pointer to the input scalar/private-key array (32 bytes).
 *
 * \return   [int32_t] Returns 0 on success; a non-zero value indicates failure.
 */
int32_t qsc_crypto_scalarmult_curve25519_ref10_base(uint8_t* q, const uint8_t* n);

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism using a random function pointer.
 *
 * \warning Arrays must be sized to QSC_EDDH_PUBLICKEY_SIZE and QSC_EDDH_SECRETKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param rng_generate: [bool (uint8_t*, size_t)] Pointer to the random generator function.
 */
void qsc_x25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism using a seed.
 *
 * \warning Arrays must be sized to QSC_EDDH_PUBLICKEY_SIZE and QSC_EDDH_SECRETKEY_SIZE using a seed.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param seed: [const uint8_t*] Pointer to the random seed.
 */
void qsc_x25519_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Combine an external public key with an internal private key to produce a shared secret.
 *
 * \warning Arrays must be sized to QSC_EDDH_PUBLICKEY_SIZE and QSC_EDDH_SECRETKEY_SIZE.
 *
 * \param secret: [uint8_t*] Pointer to the shared secret.
 * \param publickey: [const uint8_t*] Pointer to the public-key array.
 * \param privatekey: [const uint8_t*] Pointer to the private-key array.
 *
 * \return Returns true on success.
 */
bool qsc_x25519_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

QSC_CPLUSPLUS_ENABLED_END

#endif
