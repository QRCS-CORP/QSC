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


#ifndef QSCTEST_KATPARSER_H
#define QSCTEST_KATPARSER_H

#include "common.h"

/* \cond DOXYGEN_IGNORE */

/**
* \file katparser.h
* \brief KAT file support functions
*/

/**
* \brief Extract a set of values from a NIST PQC asymmetric signature scheme KAT file
*
* \param path: The KAT file relative path
* \param seed: The RNG seed
* \param seedlen: The RNG seed length
* \param msg: The message
* \param msglen: The message length
* \param pk: The public key
* \param pklen: The public key length
* \param sk: The secret key
* \param sklen: The secret key length
* \param sm: The signature and message
* \param smlen: The signature and message length
* \param setnum: The KAT set number to extract (0-99)
*/
void parse_nist_signature_kat(const char* path, uint8_t* seed, size_t* seedlen, uint8_t* msg, size_t* msglen,
	uint8_t* pk, size_t* pklen, uint8_t* sk, size_t* sklen, uint8_t* sm, size_t* smlen, uint32_t setnum);

/**
* \brief Extract a set of values from a NIST PQC asymmetric cipher KAT file
*
* \param path: The KAT file relative path
* \param seed: The RNG seed
* \param seedlen: The RNG seed length
* \param pk: The public key
* \param pklen: The public key length
* \param sk: The secret key
* \param sklen: The secret key length
* \param ct: The cipher-text
* \param ctlen: The cipher-text length
* \param ss: The shared secret
* \param sslen: The shared secret length
* \param setnum: The KAT set number to extract (0-99)
*/
void parse_nist_cipher_kat(const char* path, uint8_t* seed, size_t* seedlen, uint8_t* pk, size_t* pklen,
	uint8_t* sk, size_t* sklen, uint8_t* ct, size_t* ctlen, uint8_t* ss, size_t* sslen, uint32_t setnum);

/* \endcond DOXYGEN_IGNORE */

#endif
