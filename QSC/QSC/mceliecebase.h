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


#ifndef QSC_MCELIECEBASE_H
#define QSC_MCELIECEBASE_H

#include "common.h"

/* \cond */

/* operations.h */

/**
* \brief Decapsulates the shared secret for a given cipher-text using a private-key
*
* \param key:	[uint8_t*] Pointer to a shared secret key, an array of QSC_MCELIECE_SHAREDSECRET_SIZE constant size
* \param c:		[const uint8_t*] Pointer to the cipher-text array of QSC_MCELIECE_CIPHERTEXT_SIZE constant size
* \param sk:	[const uint8_t*] Pointer to the secret-key array of QSC_MCELIECE_PRIVATEKEY_SIZE constant size
* \return		[int32_t] Returns 0 for success
*/
int32_t qsc_mceliece_ref_decapsulate(uint8_t* key, const uint8_t* c, const uint8_t* sk);

/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
*
* \param c:		[uint8_t*] Pointer to the cipher-text array
* \param key:	[uint8_t*] Pointer to a shared secret, a uint8_t array of QSC_MCELIECE_SHAREDSECRET_SIZE
* \param pk:	[const uint8_t*] Pointer to the public-key array
* \param rng_generate: [uint8_t*, size_t] Pointer to the random generator
* \return		[int32_t] Returns 0 for success
*/
int32_t qsc_mceliece_ref_encapsulate(uint8_t* c, uint8_t* key, const uint8_t* pk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the McEliece key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_QSC_MCELIECE_PUBLICKEY_SIZE and QSC_QSC_MCELIECE_SECRETKEY_SIZE.
*
* \param pk:	[uint8_t*] Pointer to the output public-key array of QSC_MCELIECE_PUBLICKEY_SIZE constant size
* \param sk:	[uint8_t*] Pointer to output private-key array of QSC_MCELIECE_PRIVATEKEY_SIZE constant size
* \param rng_generate: [uint8_t*, size_t] Pointer to the random generator function
* \return		[int32_t] Returns 0 for success
*/
int32_t qsc_mceliece_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/* \endcond */

#endif
