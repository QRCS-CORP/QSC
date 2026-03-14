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

#ifndef QSCTEST_KATPARSER_H
#define QSCTEST_KATPARSER_H

#include "qsctestcommon.h"

 /* \cond NO_DOCUMENT */

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

/* \endcond NO_DOCUMENT */

#endif
