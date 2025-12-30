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

#ifndef CAVP_DILITHIUM_H
#define CAVP_DILITHIUM_H

/**
 * \file dilithium_test.h
 * \brief Dilithium Test Suite for the Digital Signature Scheme.
 *
 * \details
 * This header defines a set of tests for the ML-DSA (Dilithium) digital signature scheme implementation.
 * The test suite is designed to verify the correct operation of the ML-DSA scheme by performing the following:
 *
 * - **Known Answer Test (KAT)**:  
 *   Validates key pair generation, signing, and signature verification using expected test vectors from the
 *   NIST ACVP Dilithium FIPS 204 specification. It confirms that the generated public key, secret key, signature, and recovered
 *   message exactly match the expected values.
 *
 * The known answer test uses one of the NIST FIPS 204 ACVP test vector files, selected based on the active parameter set.
 *
 * \section dilithium_test_links Reference Links
 * - <a href="https://csrc.nist.gov/pubs/fips/204/final">NIST Dilithium FIPS 204 Main page</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf">NIST Dilithium FIPS 204 Specification</a>
 * - <a href="https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json">The ACVP key generation known answer tests</a>
 * - <a href="https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigGen-FIPS204/expectedResults.json">The ACVP signature generation known answer tests</a>
 */

static const char* CAVP_MLDSA_KEYGEN_44_KAT = "KAT/MLDSA/MLDSA44KeyGen.rsp";
static const char* CAVP_MLDSA_KEYGEN_65_KAT = "KAT/MLDSA/MLDSA65KeyGen.rsp";
static const char* CAVP_MLDSA_KEYGEN_87_KAT = "KAT/MLDSA/MLDSA87KeyGen.rsp";
static const char* CAVP_MLDSA_SIGGEN_44_KAT = "KAT/MLDSA/MLDSA44SigGen.rsp";
static const char* CAVP_MLDSA_SIGGEN_65_KAT = "KAT/MLDSA/MLDSA65SigGen.rsp";
static const char* CAVP_MLDSA_SIGGEN_87_KAT = "KAT/MLDSA/MLDSA87SigGen.rsp";

/**
 * \brief Runs the ML-DSA (Dilithium) ACVP test suite.
 *
 * \details
 * -Tests the ACVP KAT against the key-pair generation
 * -Tests the ACVP KAT against the signature generation
 *
 * The function prints the result of each test to the console.
 */
void cavp_dilithium_run(void);

#endif