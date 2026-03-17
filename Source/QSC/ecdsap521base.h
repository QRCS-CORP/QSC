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

#ifndef QSC_ECNISTP521BASE_H
#define QSC_ECNISTP521BASE_H

#include "qsccommon.h"
/** cond */
QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file ecnistp521base.h
 * \brief Internal API for NIST P-521 (secp521r1) ECDSA operations.
 *
 * \details
 * This header defines the internal functions for NIST P-521 ECDSA operations,
 * including public-key derivation from a raw private scalar, seed-based key-pair
 * generation, deterministic signing using RFC 6979, and signature verification.
 *
 * Key and signature encoding is big-endian and compatible with X9.62 / SEC 1:
 * - Public key: 132 bytes (Qx[66] || Qy[66], uncompressed, no 0x04 prefix)
 * - Private key: 198 bytes (seed[66] || publickey[132])
 * - Signature: 132 bytes (r[66] || s[66])
 */

/*! \brief Seed and scalar byte length for P-521 */
#define EC_NISTP521_SEED_SIZE 66U

/*! \brief Public key byte length (Qx || Qy) */
#define EC_NISTP521_PUBLICKEY_SIZE 132U

/*! \brief Private key byte length (seed[66] || pubkey[132]) */
#define EC_NISTP521_PRIVATEKEY_SIZE 198U

/*! \brief Signature byte length (r[66] || s[66]) */
#define EC_NISTP521_SIGNATURE_SIZE 132U

/**
 * \brief Derive a P-521 public key from a raw private scalar.
 *
 * \details
 * This function derives the affine public point Q = dG from a 66-byte
 * big-endian private scalar and serializes the result as Qx || Qy.
 *
 * \param publickey:  [uint8_t*] Output buffer receiving the 132-byte public key.
 * \param privatekey: [const uint8_t*] Input 66-byte private scalar.
 *
 * \return            [int32_t] Returns 0 on success, or a negative error code on failure.
 */
int32_t qsc_p521_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Generate a P-521 public/private key pair from a 66-byte seed.
 *
 * \details
 * The seed is hashed with SHA-512 and reduced modulo the P-521 subgroup order to
 * derive the signing scalar. The public key is then computed as Q = dG. The output
 * private key layout is seed[66] || Qx[66] || Qy[66].
 *
 * \param publickey:  [uint8_t*] Output public key (132 bytes).
 * \param privatekey: [uint8_t*] Output private key (198 bytes).
 * \param seed:       [const uint8_t*] Input 66-byte seed.
 *
 * \return            [int32_t] Returns 0 on success, or a negative error code on failure.
 */
int32_t qsc_p521_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Sign a message using a P-521 private key.
 *
 * \details
 * The message is hashed with SHA-512. The deterministic nonce is generated using
 * RFC 6979 with HMAC-SHA512. The output signed-message buffer contains the
 * 132-byte signature prepended to the message.
 *
 * \param signedmsg:  [uint8_t*] Output signed-message buffer.
 * \param smsglen:    [size_t*] Set to msglen + EC_NISTP521_SIGNATURE_SIZE on success.
 * \param message:    [const uint8_t*] Message to sign.
 * \param msglen:     [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] 198-byte private key (seed || pubkey).
 *
 * \return            [int32_t] Returns 0 on success, or a negative error code on failure.
 */
int32_t qsc_p521_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Sign a message using a raw P-521 private scalar.
 *
 * \details
 * The input private key is the 66-byte big-endian signing scalar d. This function
 * exists so the implementation can be tested directly against RFC 6979 known-answer
 * vectors, which specify the scalar explicitly.
 *
 * \param signedmsg:  [uint8_t*] Output signed-message buffer.
 * \param smsglen:    [size_t*] Set to msglen + EC_NISTP521_SIGNATURE_SIZE on success.
 * \param message:    [const uint8_t*] Message to sign.
 * \param msglen:     [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] 66-byte private scalar.
 *
 * \return            [int32_t] Returns 0 on success, or a negative error code on failure.
 */
int32_t qsc_p521_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Verify a P-521 signed message and recover the message bytes.
 *
 * \param message:   [uint8_t*] Output message buffer.
 * \param msglen:    [size_t*] Set to the recovered message length on success.
 * \param signedmsg: [const uint8_t*] Signed-message buffer (signature || message).
 * \param smsglen:   [size_t] Total signed-message length.
 * \param publickey: [const uint8_t*] 132-byte raw public key (Qx || Qy).
 *
 * \return           [bool] Returns true on success, false on failure.
 */
bool qsc_p521_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
