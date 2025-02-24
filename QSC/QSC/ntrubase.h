/* 2025 Quantum Resistant Cryptographic Solutions Corporation
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


#ifndef QSC_NTRUBASE_H
#define QSC_NTRUBASE_H

 /* \cond */

#include "common.h"

/* kem.h */

/**
* \brief Generates shared secret for given cipher text and private key
*
* \param ss:	[uint8_t*] Pointer to output shared secret (an already allocated array of NTRU_SECRET_BYTES bytes)
* \param ct:	[const uint8_t*] Pointer to input cipher text (an already allocated array of NTRU_CIPHERTEXT_SIZE bytes)
* \param sk:	[const uint8_t*] Pointer to input private key (an already allocated array of NTRU_SECRETKEY_SIZE bytes)
* \return		[bool] Returns true for success
*/
bool qsc_ntru_ref_decapsulate(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

/**
* \brief Generates cipher text and shared secret for given public key
*
* \param ct:	[uint8_t*] Pointer to output cipher text (an already allocated array of NTRU_CIPHERTEXT_SIZE bytes)
* \param ss:	[const uint8_t*] Pointer to output shared secret (an already allocated array of NTRU_BYTES bytes)
* \param pk:	[const uint8_t*] Pointer to input public key (an already allocated array of NTRU_PUBLICKEY_SIZE bytes)
* \param rng_generate: [uint8_t*, size_t] Pointer to the random generator function
*/
void qsc_ntru_ref_encapsulate(uint8_t* ct, uint8_t* ss, const uint8_t* pk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism
*
* \param pk:	[uint8_t*] Pointer to output public key (an already allocated array of NTRU_PUBLICKEY_SIZE bytes)
* \param sk:	[const uint8_t*] Pointer to output private key (an already allocated array of NTRU_SECRETKEY_SIZE bytes)
* \param rng_generate: [uint8_t*, size_t] Pointer to the random generator function
*/
void qsc_ntru_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/* \endcond */

#endif
