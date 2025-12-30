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

#ifndef CAVP_SHA2_H
#define CAVP_SHA2_H

/**
 * \file sha2_test.h
 * \brief SHA2, HKDF, and HMAC Known Answer Tests.
 *
 * \details
 * This header file declares a comprehensive test suite for verifying the correct operation
 * of the SHA2 family of message digests, the HKDF (HMAC-based Extract-and-Expand Key Derivation Function),
 * and the HMAC implementations. The tests use official test vectors (known answer tests or KATs)
 * drawn from NIST CAVP project to ensure that:
 *
 * - **HKDF-Expand (HMAC-SHA2) Tests**:  
 *   The functions \c qsctest_hkdf_256_kat() and \c qsctest_hkdf_512_kat() compute the expanded keys using
 *   HMAC-SHA2-256 and HMAC-SHA2-512, respectively. These outputs are compared against expected values specified
 *   in RFC 5869.
 *
 * - **HMAC-SHA2 Tests**:  
 *   The functions \c qsctest_hmac_256_kat() and \c qsctest_hmac_512_kat() generate message authentication codes
 *   using SHA2-256 and SHA2-512. The resulting MAC values are compared with those provided in the official test vectors
 *   (e.g. RFC 4231).
 *
 * - **SHA2 Digest Tests**:  
 *   The functions \c qsctest_sha2_256_kat(), \c qsctest_sha2_384_kat(), and \c qsctest_sha2_512_kat() compute the
 *   256-bit, 384-bit, and 512-bit SHA2 digests for various messages. The computed hashes are verified against
 *   known answer values from the NIST CAVP SHA2 test suite.
 *
 * The overall test suite is executed by the function \c qsctest_sha2_run(), which sequentially runs each
 * test and prints the results to the console.
 * \section sha2_test_links Reference Links
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">The SHA2 Standard FIPS 180-4</a>
 * - <a href="https://www.rfc-editor.org/rfc/rfc5869">RFC 5869 -HMAC-based Extract-and-Expand Key Derivation Function (HKDF)</a>
 * - <a href="https://www.rfc-editor.org/rfc/rfc4231">RFC 4231 - Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512</a>
 * - <a href="http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf">The SHA Validation System document</a>
 * - <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip ">SHA Test Vectors for Hashing Byte-Oriented Messages</a>
 * - <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/HMACVS.pdf">The Keyed-Hash Message Authentication Code Validation System (HMACVS)</a>
 * - <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip">HAMAC SHA2 Test vecor set</a>
 */

#include "cavp_common.h"

static const char* CAVP_HMAC_SHA256 = "KAT/SHA2/HMACSHA256.rsp";
static const char* CAVP_HMAC_SHA512 = "KAT/SHA2/HMACSHA512.rsp";
static const char* CAVP_SHA256_LONGMSG = "KAT/SHA2/SHA256LongMsg.rsp";
static const char* CAVP_SHA256_MCT = "KAT/SHA2/SHA256Monte.rsp";
static const char* CAVP_SHA256_SHORTMSG = "KAT/SHA2/SHA256ShortMsg.rsp";
static const char* CAVP_SHA384_LONGMSG = "KAT/SHA2/SHA384LongMsg.rsp";
static const char* CAVP_SHA384_MCT = "KAT/SHA2/SHA384Monte.rsp";
static const char* CAVP_SHA384_SHORTMSG = "KAT/SHA2/SHA384ShortMsg.rsp";
static const char* CAVP_SHA512_LONGMSG = "KAT/SHA2/SHA512LongMsg.rsp";
static const char* CAVP_SHA512_MCT = "KAT/SHA2/SHA512Monte.rsp";
static const char* CAVP_SHA512_SHORTMSG = "KAT/SHA2/SHA512ShortMsg.rsp";

/**
 * \brief Runs the complete SHA2 CAVP test suite.
 *
 * \details
 * This function sequentially executes all supported SHA2 CAVP tests, including:
 * - SHA256 Short Message Known Answer Tests (KATs)
 * - SHA384 Short Message Known Answer Tests (KATs)
 * - SHA512 Short Message Known Answer Tests (KATs)
 * - SHA256 Long Message Known Answer Tests (KATs)
 * - SHA384 Long Message Known Answer Tests (KATs)
 * - SHA512 Long Message Known Answer Tests (KATs)
 * - SHA256 Monte Carlo Tests (MCTs)
 * - SHA384 Monte Carlo Tests (MCTs)
 * - SHA512 Monte Carlo Tests (MCTs)
 * - HMAC-SHA256 KAT Tests
 * - HMAC-SHA512 KAT Tests
 *
 * The function prints the result of each test to the console.
 */
void cavp_sha2_run(void);

#endif