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

#ifndef QSC_ECNISTP384BASE_H
#define QSC_ECNISTP384BASE_H

#include "qsccommon.h"
/** cond */
QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file ecdsap384base.h
 * \brief Internal API for NIST P-384 (secp384r1) ECDSA operations.
 *
 * \details
 * This header defines the internal functions for NIST P-384 (secp384r1) ECDSA operations,
 * including key pair generation from a seed, deterministic message signing using RFC 6979,
 * and signature verification. The implementation uses Jacobian projective coordinates for
 * elliptic curve point arithmetic and generic reduction for both the prime field and group
 * order arithmetic.
 *
 * Key and signature encoding is big-endian and compatible with X9.62/SEC 1 conventions:
 * - Public key: 96 bytes (48-byte X || 48-byte Y, uncompressed, no 0x04 prefix)
 * - Private key: 48-byte seed || 96-byte public key = 144 bytes
 * - Signature: 48-byte r || 48-byte s
 */

/*! 
* \def EC_NISTP384_SEED_SIZE
* \brief Seed and derived scalar byte length 
*/
#define EC_NISTP384_SEED_SIZE 48U

/*!
* \def EC_NISTP384_PUBLICKEY_SIZE
* \brief Public key byte length (X || Y, each 48 bytes big-endian) 
*/
#define EC_NISTP384_PUBLICKEY_SIZE  96U

/*! 
* \def EC_NISTP384_PRIVATEKEY_SIZE
* \brief Private key byte length (seed[48] || pubkey[96]) 
*/
#define EC_NISTP384_PRIVATEKEY_SIZE 144U

/*!
* \def EC_NISTP384_SIGNATURE_SIZE
* \brief Signature byte length (r[48] || s[48], big-endian) 
*/
#define EC_NISTP384_SIGNATURE_SIZE  96U

/**
 * \brief Derive a P-384 public key from a raw private scalar.
 *
 * \details
 * This function derives the affine public point Q = dG from a 48-byte
 * big-endian private scalar and serializes the result as the raw public-key
 * form Qx || Qy.
 *
 * The private scalar must be in the range [1, n - 1], where n is the order
 * of the P-384 base point.
 *
 * \param publickey: [uint8_t*] Output buffer receiving the 96-byte public key.
 * \param privatekey: [const uint8_t*] Input 48-byte private scalar.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
int32_t qsc_p384_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Generate a P-384 public/private key pair from a 48-byte seed.
 *
 * \details
 * Derives a private scalar from the seed via SHA-384, reduces it into [1, n-1], computes
 * Q = d*G using the P-384 base point, and stores both keys. The private key layout is
 * seed[48] || Qx[48] || Qy[48].
 *
 * \param publickey: [uint8_t*] Output public key (96 bytes: Qx || Qy, big-endian).
 * \param privatekey: [uint8_t*] Output private key (144 bytes: seed || Qx || Qy).
 * \param seed: [const uint8_t*] 48-byte random seed.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
int32_t qsc_p384_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Sign a message using a P-384 private key.
 *
 * \details
 * Produces a 96-byte signature (r || s) prepended to the message in the signedmsg buffer.
 * The nonce k is derived deterministically from the private key and message hash per RFC 6979
 * using HMAC-SHA384, eliminating the need for a random number generator at signing time.
 *
 * \param signedmsg: [uint8_t*] Output signed-message buffer (msglen + 96 bytes).
 * \param smsglen: [size_t*]  Set to msglen + EC_NISTP384_SIGNATURE_SIZE on success, 0 on failure.
 * \param message: [const uint8_t*] Message to sign.
 * \param msglen: [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] 144-byte private key (seed || pubkey).
 * 
 * \return [int32_t] 0 on success, -1 on failure.
 */
int32_t qsc_p384_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Sign a message using a P-384 private key scalar.
 *
 * \details
 * Produces a 96-byte signature (r || s) prepended to the message in the signedmsg buffer.
 * The nonce k is derived deterministically from the private key scalar and message hash per
 * RFC 6979 using HMAC-SHA384.
 *
 * \param signedmsg: [uint8_t*] Output signed-message buffer (msglen + 96 bytes).
 * \param smsglen: [size_t*]  Set to msglen + EC_NISTP384_SIGNATURE_SIZE on success, 0 on failure.
 * \param message: [const uint8_t*] Message to sign.
 * \param msglen: [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] 48-byte private scalar.
 * 
 * \return [int32_t] 0 on success, -1 on failure.
 */
int32_t qsc_p384_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Verify a P-384 signed message and recover the message bytes.
 *
 * \details
 * Verifies the 96-byte (r || s) signature prepended to signedmsg against the 96-byte
 * public key. On success the message bytes are copied into message and msglen is set.
 * On failure message is zeroed and msglen is set to 0.
 *
 * \param message: [uint8_t*]  Output message buffer (at least smsglen - 96 bytes).
 * \param msglen: [size_t*]  Set to the recovered message length on success.
 * \param signedmsg: [const uint8_t*] Signed-message buffer (signature || message).
 * \param smsglen: [size_t] Total signed-message length.
 * \param publickey: [const uint8_t*] 96-byte public key (Qx || Qy, big-endian).
 * 
 * \return [bool] Returns true on success, false on failure.
 */
bool qsc_p384_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
