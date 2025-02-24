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

#ifndef QSCTEST_SCB_TEST_H
#define QSCTEST_SCB_TEST_H

#include "../QSC/common.h"

/**
 * \file scb_test.h
 * \brief SCB Known Answer Tests.
 *
 * \details
 * This header defines functions for testing the SCB (SHAKE Cost-Based KDF) implementation against known
 * answer test (KAT) vectors. The SCB tests verify that the key derivation function produces the expected
 * output when provided with fixed seed and input parameters. The test vectors are derived from the
 * authoritative CEX cryptographic library.
 *
 * The test suite includes:
 * - A KAT test for the SCB-256 variant that computes a 256-bit hash and compares it to the expected output.
 * - A KAT test for the SCB-512 variant that computes a 512-bit hash and compares it to the expected output.
 * - A macro defining the number of test cycles for any stress testing routines.
 */

/**
 * \def QSCTEST_SCB_TEST_CYCLES
 * \brief Number of test cycles to execute in SCB tests.
 *
 * This macro defines the number of iterations (100) for SCB-related stress tests.
 */
#define QSCTEST_SCB_TEST_CYCLES 100

/**
 * \brief Tests the SCB-256 Known Answer Test (KAT) vectors.
 *
 * \details
 * This function computes a 256-bit hash using the SCB implementation with a predetermined seed and input.
 * It then compares the computed hash against the expected known answer vector.
 *
 * \return Returns true if the computed hash matches the expected output; otherwise, false.
 */
bool qsctest_scb_256_kat(void);

/**
 * \brief Tests the SCB-512 Known Answer Test (KAT) vectors.
 *
 * \details
 * This function computes a 512-bit hash using the SCB implementation with a fixed seed and input.
 * The result is compared with the expected known answer vector to verify correctness.
 *
 * \return Returns true if the computed hash matches the expected output; otherwise, false.
 */
bool qsctest_scb_512_kat(void);

/**
 * \brief Runs all SCB tests.
 *
 * \details
 * This function executes the complete set of SCB tests, including both the SCB-256 and SCB-512 known
 * answer tests. It prints the results of each test to the console.
 */
void qsctest_scb_run(void);


#endif
