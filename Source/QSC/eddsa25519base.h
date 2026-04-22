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

#ifndef QSC_ECDSA25519BASE_H
#define QSC_ECDSA25519BASE_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file ecdsabase.h
 * \brief Contains the internal API for Ed25519 key exchange operations.
 *
 * \details
 * This header defines internal functions for Ed25519 key exchange operations, including 
 * generating key pairs, signing messages, and verifying signature-message pairs.
 */

/**
 * \brief Generates public and private keys for the ECDSA key encapsulation mechanism using a random function pointer.
 *
 * \warning Arrays must be sized to QSC_EDDH_PUBLICKEY_SIZE and QSC_EDDH_SECRETKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param rng_generate: [bool (uint8_t*, size_t)] Pointer to the random generator function.
 */
void qsc_ed25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Combine an external public key with an internal private key to produce a shared secret using a seed.
 *
 * \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param seed: [const uint8_t*] Pointer to the random seed.
 */
void qsc_ed25519_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Takes the message as input and returns an array containing the signature followed by the message.
 *
 * \param signedmsg: [uint8_t*] Pointer to the signed message.
 * \param smsglen: [size_t*] Pointer to the signed message length.
 * \param message: [const uint8_t*] Pointer to the message to be signed.
 * \param msglen: [size_t] The message length.
 * \param privatekey: [const uint8_t*] Pointer to the private signature key.
 * 
 * \return [bool] Returns true for success.
 */
bool qsc_ed25519_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Verifies a signature-message pair with the public key.
 *
 * \param message: [uint8_t*] Pointer to the message to be verified.
 * \param msglen: [size_t*] Pointer to the message length.
 * \param signedmsg: [const uint8_t*] Pointer to the signed message.
 * \param smsglen: [size_t] The signed message length.
 * \param publickey: [const uint8_t*] Pointer to the public verification key.
 * 
 * \return [bool] Returns true for success.
 */
bool qsc_ed25519_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
