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

#ifndef QSCTEST_AESAVS_TEST_H
#define QSCTEST_AESAVS_TEST_H

#include "common.h"

/**
 * \file aesavs_test.h
 * \brief AES AVS Test Suite.
 *
 * \details
 * This header defines functions to perform Known Answer Tests (KATs), Monte Carlo Tests (MCTs), and Multi-Message Tests (MMTs)
 * for the AES cipher using test vectors from the NIST AES Algorithm Validation Suite (AESAVS). The tests cover the following:
 *
 * - **AES CBC KAT Tests**:  
 *   Validates the AES CBC mode implementation for both 128-bit and 256-bit keys using variable key and variable text test vectors.
 *   The function `aesavs_cbc_kat()` reads response files (.rsp) containing the test vectors and verifies that the computed ciphertext,
 *   as well as the recovered plaintext after decryption, match the expected values.
 *
 * - **AES ECB KAT Tests**:  
 *   Validates the AES ECB mode implementation for both 128-bit and 256-bit keys using variable key and variable text test vectors.
 *   The function `aesavs_ecb_kat()` processes the test vectors and compares the outputs of both encryption and decryption operations
 *   with the expected results.
 *
 * - **AES CBC Monte Carlo Tests (MCTs)**:  
 *   Repeatedly encrypts (or decrypts) AES blocks in CBC mode (for both 128-bit and 256-bit keys) for 1000 iterations.
 *   The function `aesavs_cbc_mct()` reads the corresponding test files and verifies that the final output produced after
 *   the repeated processing matches the expected result.
 *
 * - **AES ECB Monte Carlo Tests (MCTs)**:  
 *   Repeatedly encrypts (or decrypts) a single AES block in ECB mode for 1000 iterations using AESAVS test vectors.
 *   The function `aesavs_ecb_mct()` confirms that the iterative process produces the expected final output.
 *
 * - **AES CBC Multi-Message Tests (MMTs)**:  
 *   Validates the AES CBC mode over multi-block messages by processing messages longer than a single block.
 *   The function `aesavs_cbc_mmt()` compares the computed output against the expected result provided in the test vectors.
 *
 * - **AES ECB Multi-Message Tests (MMTs)**:  
 *   Validates the AES ECB mode on multi-block messages by encrypting (or decrypting) the entire message and comparing
 *   the final output with the expected result.
 *   This is performed by the function `aesavs_ecb_mmt()`.
 *
 * The test vectors are read from response (.rsp) files using file utility routines provided by the QSC library. All operations,
 * including file opening, line reading, and file closing, are handled internally by the test functions.
 *
 * \section aesavs_test_links Reference Links
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf">AES Specification NIST FIPS 197</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">CBC and CTR Mode (NIST SP 800-38A)</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA3 Implementation NIST FIPS 202</a>
 */

/**
 * \brief Performs the AES CBC Known Answer Tests (KATs) for both 128-bit and 256-bit keys using AESAVS vectors.
 *
 * \return Returns true if all CBC KAT tests pass; false otherwise.
 *
 * \remarks
 * This function reads response files containing test vectors for variable key and variable text cases and verifies that:
 * - The AES CBC mode encryption produces the expected ciphertext.
 * - The AES CBC mode decryption correctly recovers the original plaintext.
 *
 * Test Reference:
 * NIST AESAVS KAT for qsc_aes_mode_cbc (Section 6.2).
 */
bool aesavs_cbc_kat(void);

/**
 * \brief Performs the AES ECB Known Answer Tests (KATs) for both 128-bit and 256-bit keys using AESAVS vectors.
 *
 * \return Returns true if all ECB KAT tests pass; false otherwise.
 *
 * \remarks
 * This function processes response files containing AESAVS test vectors for ECB mode and validates that:
 * - The encryption operation produces the expected ciphertext.
 * - The decryption operation correctly restores the original plaintext.
 *
 * Test Reference:
 * NIST AESAVS KAT for qsc_aes_mode_ecb (Section 6.2).
 */
bool aesavs_ecb_kat(void);

/**
 * \brief Executes the AES CBC Monte Carlo Tests (MCTs) using AESAVS test vectors.
 *
 * \return Returns true if the Monte Carlo tests for CBC mode pass; false otherwise.
 *
 * \remarks
 * This function performs 1000 iterations of AES CBC encryption (or decryption) for both 128-bit and 256-bit keys,
 * comparing the final computed output with the expected value provided in the test vector file.
 *
 * Test Reference:
 * NIST AESAVS MCT for qsc_aes_mode_cbc (Section 6.4.2).
 */
bool aesavs_cbc_mct(void);

/**
 * \brief Executes the AES ECB Monte Carlo Tests (MCTs) using AESAVS test vectors.
 *
 * \return Returns true if the Monte Carlo tests for ECB mode pass; false otherwise.
 *
 * \remarks
 * This function performs 1000 iterations of AES ECB encryption (or decryption) on a single block,
 * verifying that the iterative process produces the expected final output.
 *
 * Test Reference:
 * NIST AESAVS MCT for qsc_aes_mode_ecb (Section 6.4.1).
 */
bool aesavs_ecb_mct(void);

/**
 * \brief Performs the AES CBC Multi-Message Tests (MMTs) using AESAVS test vectors.
 *
 * \return Returns true if all multi-block message tests for CBC mode pass; false otherwise.
 *
 * \remarks
 * This function validates the AES CBC mode implementation over messages spanning multiple blocks.
 * It compares the computed output for the entire message with the expected result from the test vector file.
 *
 * Test Reference:
 * NIST AESAVS MMT for qsc_aes_mode_cbc (Section 6.3).
 */
bool aesavs_cbc_mmt(void);

/**
 * \brief Performs the AES ECB Multi-Message Tests (MMTs) using AESAVS test vectors.
 *
 * \return Returns true if all multi-block message tests for ECB mode pass; false otherwise.
 *
 * \remarks
 * This function processes multi-block messages in AES ECB mode and verifies that the final output
 * matches the expected result provided in the test vector file.
 *
 * Test Reference:
 * NIST AESAVS MMT for qsc_aes_mode_ecb (Section 6.3).
 */
bool aesavs_ecb_mmt(void);

/**
 * \brief Runs the complete AES AVS test suite.
 *
 * \details
 * This function sequentially executes all AES AVS tests, including:
 * - CBC Known Answer Tests (KATs)
 * - ECB Known Answer Tests (KATs)
 * - CBC Monte Carlo Tests (MCTs)
 * - ECB Monte Carlo Tests (MCTs)
 * - CBC Multi-Message Tests (MMTs)
 * - ECB Multi-Message Tests (MMTs)
 *
 * The function prints the result of each test to the console.
 */
void qsctest_aesavs_run(void);

#endif
