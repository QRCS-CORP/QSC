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

#ifndef QSCTEST_FALCON_TEST_H
#define QSCTEST_FALCON_TEST_H

#include "qsccommon.h"

/**
* \file falcon_test.c
* \brief Falcon test functions \n
* Contains the Falcon implementation KAT and wellness test functions.
*
* \author John Underhill
* \date June 13, 2019
* \updated July 1, 2021
*/

#define QSCTEST_FALCON_MLEN 33

/**
* \brief Test the public and private keys, cipher-text and shared key
* for correctness against the NIST PQC Round 3 vectors.
* tests the second vector in the NIST PQC Round 3, KAT file.
* \return Returns true for test success
*/
bool qsctest_falcon_operations_test(void);

/**
* \brief Test the validity of a mutated secret key
* \return Returns true for test success
*/
bool qsctest_falcon_privatekey_integrity(void);

/**
* \brief Test the validity of a mutated public key
* \return Returns true for test success
*/
bool qsctest_falcon_publickey_integrity(void);

/**
* \brief Test the validity of a mutated signature
* \return Returns true for test success
*/
bool qsctest_falcon_signature_integrity(void);

/**
* \brief Stress test the key generation, encryption, and decryption functions in a looping test.
* \return Returns true for test success
*/
bool qsctest_falcon_stress_test(void);

bool qsctest_falcon_stress_test2(void);

/**
* \brief Run the Falcon implementation stress and correctness tests tests
*/
void qsctest_falcon_run(void);

#endif
