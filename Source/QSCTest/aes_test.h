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

#ifndef QSCTEST_AES_TEST_H
#define QSCTEST_AES_TEST_H

#include "common.h"
#include "../QSC/aes.h"

/**
 * \file aes_test.h
 * \brief AES Known Answer and Stress Tests.
 *
 * \details
 * This header file defines functions for testing the correctness and robustness of the AES algorithm
 * implementation. The tests cover the standard block cipher modes of operation (CBC, CTR, and ECB)
 * for both 128-bit and 256-bit keys, in addition to specialized tests for the Hash Based Authentication (HBA-RHX)
 * AEAD mode and the PKCS7 padding routines.
 *
 * The test suite includes the following:
 *
 * - **AES CBC Mode KAT Tests**: These tests validate AES encryption and decryption in CBC mode using known
 *   answer test (KAT) vectors derived from NIST SP800-38A.
 *   - `qsctest_fips_aes128_cbc()` tests AES-128 CBC mode (using test vector F2.1).
 *   - `qsctest_fips_aes256_cbc()` tests AES-256 CBC mode (using test vector F2.5).
 *
 * - **AES CTR Mode KAT Tests**: These tests verify the counter (CTR) mode operation of AES with 128-bit and
 *   256-bit keys using known test vectors from NIST SP800-38A.
 *   - `qsctest_fips_aes128_ctr()` tests AES-128 CTR mode (using test vector F5.1).
 *   - `qsctest_fips_aes256_ctr()` tests AES-256 CTR mode (using test vector F5.5).
 *
 * - **AES ECB Mode KAT Tests**: These tests evaluate the correctness of AES in ECB mode by comparing
 *   computed ciphertext with expected values.
 *   - `qsctest_fips_aes128_ecb()` tests AES-128 ECB mode (using test vector F1.1).
 *   - `qsctest_fips_aes256_ecb()` tests AES-256 ECB mode (using test vector F1.5).
 *
 * - **HBA-RHX AEAD Mode KAT Test**: This test verifies the Hash Based Authentication (HBA-RHX) AEAD mode
 *   using a 256-bit key. It employs multiple test vectors—with various associated data and message lengths—to
 *   ensure that both the encryption (which produces a ciphertext concatenated with a MAC) and the decryption processes
 *   function as expected.
 *   - `qsctest_aes256_hba_kat()` covers these known answer tests.
 *
 * - **HBA-RHX AEAD Mode Stress Test**: This test subjects the HBA-RHX256 AEAD mode to extended use by repeatedly
 *   encrypting and decrypting randomly generated messages of varying lengths (ranging from 1 to 65535 bytes),
 *   ensuring robustness under stress.
 *   - `qsctest_aes256_hba_stress()` implements this stress testing.
 *
 * - **PKCS7 Padding Test**: This test validates the AES padding routines by applying and then verifying PKCS7
 *   padding on data blocks. It checks that the correct padding length is detected, even in cases where coincidental
 *   byte values might mimic padding.
 *   - `qsctest_aes256_padding_test()` performs these checks.
 *
 * - **Comprehensive Test Runner**: Finally, the function `qsctest_aes_run()` executes all of the above tests sequentially,
 *   printing the outcome of each to the console.
 *
 * Additionally, if the system supports AES-NI and AVX512 (i.e. when both the macros `QSC_SYSTEM_AESNI_ENABLED` and
 * `QSC_SYSTEM_HAS_AVX512` are defined), the macro `RHX_WIDE_BLOCK_TESTS` is defined to enable extended wide block tests.
 *
 * \section aes_test_links Reference Links
 * - FIPS 197: <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">The Advanced Encryption Standard</a>
 * - SP800-38A: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operation</a>
 */

#if defined(QSC_SYSTEM_AESNI_ENABLED) 
#	if defined(QSC_SYSTEM_HAS_AVX512)
#		define RHX_WIDE_BLOCK_TESTS
#	endif
#endif

/**
 * \brief Executes the FIPS 197 AES-128 CBC Known Answer Test.
 *
 * \details
 * This function performs a Known Answer Test (KAT) for the AES cipher operating in CBC mode using a 128-bit key.
 * It uses test vectors derived from NIST SP800-38A (test vector F2.1) to verify that:
 *  - The encryption function produces the expected ciphertext for each 16-byte block.
 *  - The decryption function correctly recovers the original plaintext.
 *
 * The test processes four blocks of data and compares the computed outputs with predetermined expected results.
 *
 * \return Returns true if both encryption and decryption produce the expected results; otherwise, false.
 */
bool qsctest_fips_aes128_cbc(void);

/**
 * \brief Executes the FIPS 197 AES-256 CBC Known Answer Test.
 *
 * \details
 * This function performs a Known Answer Test (KAT) for the AES cipher in CBC mode using a 256-bit key.
 * Utilizing test vectors from NIST SP800-38A (test vector F2.5), it validates that:
 *  - The AES encryption function outputs the correct ciphertext for each block.
 *  - The AES decryption function accurately recovers the original plaintext.
 *
 * Four blocks of data are processed, and the results are compared against predetermined values.
 *
 * \return Returns true if the encryption and decryption operations are correct; otherwise, false.
 */
bool qsctest_fips_aes256_cbc(void);

/**
 * \brief Executes the FIPS 197 AES-128 CTR Known Answer Test.
 *
 * \details
 * This function performs a Known Answer Test (KAT) for the AES cipher in CTR mode with a 128-bit key.
 * It uses test vectors from NIST SP800-38A (test vector F5.1) to confirm that:
 *  - The counter mode transformation produces the expected ciphertext.
 *  - The inverse transformation recovers the original plaintext.
 *
 * The test processes four blocks of data in a counter-based encryption/decryption sequence.
 *
 * \return Returns true if both encryption and decryption yield correct results; otherwise, false.
 */
bool qsctest_fips_aes128_ctr(void);

/**
 * \brief Executes the FIPS 197 AES-256 CTR Known Answer Test.
 *
 * \details
 * This function performs a Known Answer Test (KAT) for the AES cipher in CTR mode using a 256-bit key.
 * With test vectors from NIST SP800-38A (test vector F5.5), it verifies that:
 *  - The counter mode encryption produces the expected ciphertext.
 *  - The decryption process correctly restores the original plaintext.
 *
 * Four data blocks are processed using a counter-based mechanism.
 *
 * \return Returns true if the test passes; otherwise, false.
 */
bool qsctest_fips_aes256_ctr(void);

/**
 * \brief Executes the FIPS 197 AES-128 ECB Known Answer Test.
 *
 * \details
 * This function conducts a Known Answer Test (KAT) for the AES cipher operating in ECB mode with a 128-bit key.
 * Using test vector F1.1 from NIST SP800-38A, it verifies that:
 *  - The ECB encryption function produces the correct ciphertext for each block.
 *  - The ECB decryption function accurately recovers the original plaintext.
 *
 * Four 16-byte blocks are individually processed and validated.
 *
 * \return Returns true if the ECB mode encryption and decryption are correct; otherwise, false.
 */
bool qsctest_fips_aes128_ecb(void);

/**
 * \brief Executes the FIPS 197 AES-256 ECB Known Answer Test.
 *
 * \details
 * This function performs a Known Answer Test (KAT) for the AES cipher in ECB mode using a 256-bit key.
 * Utilizing test vector F1.5, it verifies that:
 *  - The AES ECB encryption outputs the expected ciphertext for each block.
 *  - The AES ECB decryption function properly recovers the original plaintext.
 *
 * The test compares the outputs of four individual data blocks with the expected test vectors.
 *
 * \return Returns true if both encryption and decryption pass the test; otherwise, false.
 */
bool qsctest_fips_aes256_ecb(void);

/**
 * \brief Executes the Known Answer Test for the HBA-RHX AEAD mode with a 256-bit key.
 *
 * \details
 * This function tests the Hash Based Authentication (HBA-RHX) AEAD mode using a 256-bit key.
 * It performs multiple test cases with varying associated data and message lengths, including:
 *  - Encrypting messages of one, two, and four AES blocks.
 *  - Verifying that the produced ciphertext (which includes a MAC) matches the expected test vectors.
 *  - Decrypting the ciphertext and confirming that the original plaintext is correctly recovered.
 *
 * The test vectors are derived from the authoritative CEX cryptographic library.
 *
 * \return Returns true if all known answer tests for the HBA-RHX AEAD mode are successful; otherwise, false.
 */
bool qsctest_aes256_hba_kat(void);

/**
 * \brief Performs a stress test on the HBA-RHX256 AEAD mode.
 *
 * \details
 * This function conducts a comprehensive stress test on the HBA-RHX256 AEAD mode by repeatedly:
 *  - Generating messages of random lengths (between 1 and 65535 bytes).
 *  - Encrypting these messages using dynamically allocated buffers.
 *  - Decrypting the ciphertext and verifying that the original plaintext is recovered.
 *
 * The test runs for a fixed number of iterations (defined by HBA_TEST_CYCLES) to evaluate the robustness
 * and error-handling capabilities of the AEAD implementation.
 *
 * \return Returns true if all stress test iterations pass; otherwise, false.
 */
bool qsctest_aes256_hba_stress(void);

/**
 * \brief Tests the correctness of the AES PKCS7 padding functions.
 *
 * \details
 * This function verifies the proper operation of the AES padding routines by:
 *  - Generating random message lengths less than the AES block size.
 *  - Applying PKCS7 padding and checking that the reported padding length matches the expected value.
 *  - Testing scenarios where coincidental byte values in unpadded blocks could mimic valid padding.
 *
 * The test is executed over a number of cycles (AES_TEST_CYCLES) to ensure consistent padding behavior.
 *
 * \return Returns true if the padding routines correctly add and detect padding; otherwise, false.
 */
bool qsctest_aes256_padding_test(void);

/**
 * \brief Runs the complete suite of AES tests.
 *
 * \details
 * This function serves as the main test runner that sequentially executes all individual AES tests defined in
 * this module. It calls each test function and prints the outcome to the console, including:
 *  - AES-128 CBC Known Answer Test.
 *  - AES-256 CBC Known Answer Test.
 *  - AES-128 CTR Known Answer Test.
 *  - AES-256 CTR Known Answer Test.
 *  - AES-128 ECB Known Answer Test.
 *  - AES-256 ECB Known Answer Test.
 *  - HBA-RHX AEAD Mode Known Answer Test.
 *  - HBA-RHX AEAD Mode Stress Test.
 *  - PKCS7 Padding Test.
 *
 * This comprehensive test runner validates both the correctness and the resilience of the AES and AEAD implementations.
 */
void qsctest_aes_run(void);

#endif
