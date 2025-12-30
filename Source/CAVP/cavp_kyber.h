/* 2026 Quantum Resistant Cryptographic Solutions Corporation
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

#ifndef CAVP_KYBER_H
#define CAVP_KYBER_H

/**
 * \file cavp_kyber.h
 * \brief Kyber Test Functions.
 *
 * \details
 * This file contains tests for the NIST ML-KEM key encapsulation mechanism (KEM) implementation
 * as specified in the NIST FIPS 203 specification. The test suite includes:
 *
 * - A Known Answer Test (KAT) that verifies the generated public and private keys from the NIST ACVP vector set.
 * - A Known Answer Test (KAT) that verifies the encapsulation function from the NIST ACVP vector set.
 * Tests are run against the supported parameter set selected in the qsccommon.h file of the QSC library.
 *
 * \section kyber_test_links Reference Links
 * - <a href="https://csrc.nist.gov/pubs/fips/203/final">NIST Kyber FIPS 203 Main page</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf">NIST Kyber FIPS 203 Specification</a>
 * - <a href="https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203">The NIST ML-KEM encasulation KAT vector set</a>
 * - <a href="https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203">The NIST ML-KEM key generation KAT vector set</a>
 */

static const char* CAVP_MLKEM_ENCAP_512_KAT = "KAT/MLKEM/MLKEMEncap512.rsp";
static const char* CAVP_MLKEM_ENCAP_768_KAT = "KAT/MLKEM/MLKEMEncap768.rsp";
static const char* CAVP_MLKEM_ENCAP_1024_KAT = "KAT/MLKEM/MLKEMEncap1024.rsp";
static const char* CAVP_MLKEM_KEYGEN_512_KAT = "KAT/MLKEM/MLKEMKeyGen512.rsp";
static const char* CAVP_MLKEM_KEYGEN_768_KAT = "KAT/MLKEM/MLKEMKeyGen768.rsp";
static const char* CAVP_MLKEM_KEYGEN_1024_KAT = "KAT/MLKEM/MLKEMKeyGen1024.rsp";

/**
 * \brief Runs the ML-KEM (Kyber) ACVP test suite.
 *
 * \details
 * This function sequentially executes all supported ML-KEM ACVP tests, including:
 * - Public and private key generation Known Answer Tests (KATs)
 * - Thhe encapsulation function Known Answer Tests (KATs)
 *
 * The function prints the result of each test to the console.
 */
void cavp_kyber_run(void);

#endif