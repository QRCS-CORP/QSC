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

#ifndef CAVP_AES_H
#define CAVP_AES_H

/**
 * \file aes_test.h
 * \brief AES CAVP Test Suite.
 *
 * \details
 * This header defines functions to perform Known Answer Tests (KATs) for the AES cipher using test vectors 
 * from the NIST AES Cryptographic Algorithm Validation Program (CAVP). The tests cover the following:
 *
 * There are four distinct KAT variants:
 *	- GFSbox: Exercises the substitution box (S-box) with fixed inputs to ensure correct non-linear substitution.
 *	- KeySbox: Combines key schedule and S-box operations to validate branching between key expansion and substitution.
 *	- Variable Key: Uses a fixed plaintext but varies the key each test to check key-dependent behavior.
 *	- Variable Text: Uses a fixed key but varies the plaintext to check plaintext-dependent behavior.
 * 
 * Each KAT “REQUEST” file supplies (key, IV if applicable, plaintext or ciphertext) and the corresponding “RESPONSE” file adds the computed ciphertext or plaintext.
 * 
 * - **AES CBC KAT Tests**:
 *   Validates the AES CBC mode implementation for both 128-bit and 256-bit keys using variable key and variable text test vectors.
 *   The function `aes_cbc_kat()` reads response files (.rsp) containing the test vectors and verifies that the computed ciphertext,
 *   as well as the recovered plaintext after decryption, match the expected values.
 *
 * - **AES ECB KAT Tests**:  
 *   Validates the AES ECB mode implementation for both 128-bit and 256-bit keys using variable key and variable text test vectors.
 *   The function `aes_ecb_kat()` processes the test vectors and compares the outputs of both encryption and decryption operations
 *   with the expected results.
 *
 * - **AES CBC Monte Carlo Tests (MCTs)**:  
 *   Repeatedly encrypts (or decrypts) AES blocks in CBC mode (for both 128-bit and 256-bit keys) for 1000 iterations.
 *   The function `aes_cbc_mct()` reads the corresponding test files and verifies that the final output produced after
 *   the repeated processing matches the expected result.
 *
 * - **AES ECB Monte Carlo Tests (MCTs)**:  
 *   Repeatedly encrypts (or decrypts) a single AES block in ECB mode for 1000 iterations using CAVP test vectors.
 *   The function `aes_ecb_mct()` confirms that the iterative process produces the expected final output.
 *
 * - **AES CBC Multi-Message Tests (MMTs)**:  
 *   Validates the AES CBC mode over multi-block messages by processing messages longer than a single block.
 *   The function `aes_cbc_mmt()` compares the computed output against the expected result provided in the test vectors.
 *
 * - **AES ECB Multi-Message Tests (MMTs)**:  
 *   Validates the AES ECB mode on multi-block messages by encrypting (or decrypting) the entire message and comparing
 *   the final output with the expected result.
 *   This is performed by the function `aes_ecb_mmt()`.
 *
 * The test vectors are read from response (.rsp) files using file utility routines provided by the QSC library. All operations,
 * including file opening, line reading, and file closing, are handled internally by the test functions.
 *
 * \section aes_test_links Reference Links
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf">AES Specification NIST FIPS 197</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">CBC and CTR Mode (NIST SP 800-38A)</a>
 * - <a href="https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program">Cryptographic Algorithm Validation Program</a>
 * - <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip ">CBC and ECB vector sets</a>
 * - <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip">GCM vector sets</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf">NIST SP800-38A CTR vector sets</a>
 */

#include "cavp_common.h"

static const char* CAVP_CBC128_GFSBOX = "KAT/AES/CBCGFSbox128.rsp";
static const char* CAVP_CBC256_GFSBOX = "KAT/AES/CBCGFSbox256.rsp";
static const char* CAVP_CBC128_KEYSBOX = "KAT/AES/CBCKeySbox128.rsp";
static const char* CAVP_CBC256_KEYSBOX = "KAT/AES/CBCKeySbox256.rsp";
static const char* CAVP_CBC128_VARKEY = "KAT/AES/CBCVarKey128.rsp";
static const char* CAVP_CBC256_VARKEY = "KAT/AES/CBCVarKey256.rsp";
static const char* CAVP_CBC128_VARTEXT = "KAT/AES/CBCVarTxt128.rsp";
static const char* CAVP_CBC128_MCT = "KAT/AES/CBCMCT128.rsp";
static const char* CAVP_CBC256_MCT = "KAT/AES/CBCMCT256.rsp";
static const char* CAVP_CBC128_MMT = "KAT/AES/CBCMMT128.rsp";
static const char* CAVP_CBC256_MMT = "KAT/AES/CBCMMT256.rsp";
static const char* CAVP_CBC256_VARTEXT = "KAT/AES/CBCVarTxt256.rsp";
static const char* CAVP_CTR128_VARKEY = "KAT/AES/CTRVarKey128.rsp";
static const char* CAVP_CTR256_VARKEY = "KAT/AES/CTRVarKey256.rsp";
static const char* CAVP_ECB128_GFSBOX = "KAT/AES/ECBGFSbox128.rsp";
static const char* CAVP_ECB256_GFSBOX = "KAT/AES/ECBGFSbox256.rsp";
static const char* CAVP_ECB128_KEYSBOX = "KAT/AES/ECBKeySbox128.rsp";
static const char* CAVP_ECB256_KEYSBOX = "KAT/AES/ECBKeySbox256.rsp";
static const char* CAVP_ECB128_VARKEY = "KAT/AES/ECBKeySbox128.rsp";
static const char* CAVP_ECB256_VARKEY = "KAT/AES/ECBKeySbox256.rsp";
static const char* CAVP_ECB128_VARTEXT = "KAT/AES/ECBVarTxt128.rsp";
static const char* CAVP_ECB256_VARTEXT = "KAT/AES/ECBVarTxt256.rsp";
static const char* CAVP_ECB128_MCT = "KAT/AES/ECBMCT128.rsp";
static const char* CAVP_ECB256_MCT = "KAT/AES/ECBMCT256.rsp";
static const char* CAVP_ECB128_MMT = "KAT/AES/ECBMMT128.rsp";
static const char* CAVP_ECB256_MMT = "KAT/AES/ECBMMT256.rsp";
static const char* CAVP_GCM128_VARKEY = "KAT/AES/GCMVarKey128.rsp";
static const char* CAVP_GCM256_VARKEY = "KAT/AES/GCMVarKey256.rsp";

/**
 * \brief Runs the complete AES CAVP test suite.
 *
 * \details
 * This function sequentially executes all supported AES CAVP tests, including:
 * - CBC Known Answer Tests (KATs)
 * - ECB Known Answer Tests (KATs)
 * - CBC Monte Carlo Tests (MCTs)
 * - ECB Monte Carlo Tests (MCTs)
 * - CBC Multi-Message Tests (MMTs)
 * - ECB Multi-Message Tests (MMTs)
 * - CTR Known Answer Tests (KATs)
 * - GCM Known Answer Tests (KATs)
 *
 * The function prints the result of each test to the console.
 */
void cavp_aes_run(void);

#endif