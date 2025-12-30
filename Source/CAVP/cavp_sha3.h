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

#ifndef CAVP_SHA3_H
#define CAVP_SHA3_H

/**
 * \file sha3_test.h
 * \brief SHA3, SHAKE, and cSHAKE Known Answer Tests.
 *
 * \details
 * This header file defines the test functions for validating the implementation of the SHA3 family,
 * its extendable-output functions (SHAKE), the customizable SHAKE (cSHAKE). 
 * The test vectors used in these functions are taken from official sources such as NIST FIPS 202, NIST SP800-185, and additional reference implementations (e.g., the CEX cryptographic library).
 *
 * The test suite includes:
 *
 * - **SHA3 Message Digest Tests**:  
 *   The functions \c qsctest_sha3_128_kat() and \c qsctest_sha3_256_kat() compute the 128-bit and 256-bit versions
 *   of the SHA3 hash function for various input messages. The results are compared against known answer test vectors
 *   from the official CAVP Secure Hashing test vector set.
 *
 * - **SHAKE XOF Tests**:  
 *   The functions \c qsctest_shake_128_kat(), \c qsctest_shake_256_kat(), and verify the
 *   extendable-output functions SHAKE-128 and SHAKE-256 by comparing their outputs to the expected
 *   values provided in the official CAVP Secure Hashing test vector set.
 *
 * - **cSHAKE Tests**:  
 *   The functions \c qsctest_cshake_128_kat() and \c qsctest_cshake_256_kat() test the customizable SHAKE (cSHAKE)
 *   functions. The results are compared against known answer test vectors from the official ACVP Secure Hashing test vector set.
 *
 * - **SIMD Equality Tests (Optional)**:  
 *   When compiling with AVX2 or AVX512 support, additional functions (such as \c qsctest_kmac128x4_equality(),
 *   \c qsctest_shake256x4_equality(), \c qsctest_kmac128x8_equality(), etc.) are provided to ensure that the
 *   SIMD-accelerated implementations produce the same output as the sequential versions.
 *
 * The function \c qsctest_sha3_run() serves as the main entry point to run all the tests in this suite,
 * printing detailed results to the console.
 * 
 * \section sha3_test_links Reference Links:
 * - <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">NIST: SHA3 FIPS-202</a>
 * - <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">NIST: SP800-185</a>
 * - <a href="https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing">CAVP Testing: Secure Hashing</a>
 * - <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip">CAVP SHA3 Byte oriented test vector set</a>
 * - <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/xofbytetestvectors.zip">CAVP SHAKE Byte oriented test vector set</a>
 * - <a href="https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/sha3/cSHAKE-128">ACVP cSHAKE-128 Byte oriented test vector set</a>
 * - <a href="https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/sha3/cSHAKE-256">ACVP cSHAKE-256 Byte oriented test vector set</a>
 */

#include "cavp_common.h"

static const char* CAVP_SHA3_256_LONGMSG = "KAT/SHA3/SHA3_256LongMsg.rsp";
static const char* CAVP_SHA3_256_MCT = "KAT/SHA3/SHA3_256Monte.rsp";
static const char* CAVP_SHA3_256_SHORTMSG = "KAT/SHA3/SHA3_256ShortMsg.rsp";
static const char* CAVP_SHA3_512_LONGMSG = "KAT/SHA3/SHA3_512LongMsg.rsp";
static const char* CAVP_SHA3_512_MCT = "KAT/SHA3/SHA3_512Monte.rsp";
static const char* CAVP_SHA3_512_SHORTMSG = "KAT/SHA3/SHA3_512ShortMsg.rsp";
static const char* CAVP_SHAKE_128_LONGMSG = "KAT/SHA3/SHAKE128LongMsg.rsp";
static const char* CAVP_SHAKE_128_MCT = "KAT/SHA3/SHAKE128Monte.rsp";
static const char* CAVP_SHAKE_128_SHORTMSG = "KAT/SHA3/SHAKE128ShortMsg.rsp";
static const char* CAVP_SHAKE_128_VAROUT = "KAT/SHA3/SHAKE128VariableOut.rsp";
static const char* CAVP_SHAKE_256_LONGMSG = "KAT/SHA3/SHAKE256LongMsg.rsp";
static const char* CAVP_SHAKE_256_MCT = "KAT/SHA3/SHAKE256Monte.rsp";
static const char* CAVP_SHAKE_256_SHORTMSG = "KAT/SHA3/SHAKE256ShortMsg.rsp";
static const char* CAVP_SHAKE_256_VAROUT = "KAT/SHA3/SHAKE256VariableOut.rsp";

/**
 * \brief Runs the complete SHA2 CAVP test suite.
 *
 * \details
 * This function sequentially executes all supported SHA3 CAVP tests, including:
 * - SHA3-256 Short Message Known Answer Tests (KATs)
 * - SHA3-512 Short Message Known Answer Tests (KATs)
 * - SHA3-256 Long Message Known Answer Tests (KATs)
 * - SHA3-512 Long Message Known Answer Tests (KATs)
 * - SHA3-256 Monte Carlo Tests (MCTs)
 * - SHA3-512 Monte Carlo Tests (MCTs)
 * - KMAC-128 KAT Tests
 * - KMAC-256 KAT Tests
 * - SHAKE-128 KAT Tests
 * - SHAKE-256 KAT Tests
 * - cSHAKE-128 KAT Tests
 * - cSHAKE-256 KAT Tests
 *
 * The function prints the result of each test to the console.
 */
void cavp_sha3_run(void);

#endif