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

#ifndef QSC_ECDHBASE_H
#define QSC_ECDHBASE_H

#include "common.h"

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
 * \brief Combine an external public key with an internal private key to produce a shared secret.
 *
 * \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
 *
 * \param secret:	  [uint8_t*] Pointer to the shared secret.
 * \param publickey:  [const uint8_t*] Pointer to the public-key array.
 * \param privatekey: [const uint8_t*] Pointer to the private-key array.
 *
 * \return Returns true on success.
 */
bool qsc_ed25519_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism.
 *
 * \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
 *
 * \param publickey:  [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param seed:		  [const uint8_t*] Pointer to the random seed.
 */
void qsc_ed25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

QSC_CPLUSPLUS_ENABLED_END

#endif
