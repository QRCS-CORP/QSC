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
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_ECDSABASE_H
#define QSC_ECDSABASE_H

#include "common.h"

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
 * \brief Combine an external public key with an internal private key to produce a shared secret.
 *
 * \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
 *
 * \param publickey:	[uint8_t*] Pointer to the output public-key array.
 * \param privatekey:	[uint8_t*] Pointer to the output private-key array.
 * \param seed:			[const uint8_t*] Pointer to the random seed.
 */
void qsc_ed25519_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Takes the message as input and returns an array containing the signature followed by the message.
 *
 * \param signedmsg:	[uint8_t*] Pointer to the signed message.
 * \param smsglen:		[size_t*] Pointer to the signed message length.
 * \param message:		[const uint8_t*] Pointer to the message to be signed.
 * \param msglen:		[size_t] The message length.
 * \param privatekey:	[const uint8_t*] Pointer to the private signature key.
 * \return				[int32_t] Returns 0 for success.
 */
int32_t qsc_ed25519_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Verifies a signature-message pair with the public key.
 *
 * \param message:		[uint8_t*] Pointer to the message to be verified.
 * \param msglen:		[size_t*] Pointer to the message length.
 * \param signedmsg:	[const uint8_t*] Pointer to the signed message.
 * \param smsglen:		[size_t] The signed message length.
 * \param publickey:	[const uint8_t*] Pointer to the public verification key.
 * \return				[int32_t]Returns 0 for success.
 */
int32_t qsc_ed25519_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
