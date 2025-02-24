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

#ifndef QSCTEST_QMAC_TEST_H
#define QSCTEST_QMAC_TEST_H

#include "../QSC/common.h"

/**
 * \file qmac_test.h
 * \brief QMAC Known Answer Tests.
 *
 * \details
 * This header defines functions for testing the QMAC implementation.
 * The QMAC tests verify that the MAC generator produces outputs that match the expected known
 * answer test vectors.
 *
 * The test suite includes:
 * - A compact API test that computes the MAC for various messages and keys, comparing the output
 *   against expected values.
 * - A long-form API test that uses incremental update and finalization calls to compute the MAC,
 *   verifying that the stateful interface yields the correct output.
 * - Tests that incorporate a nonce into the MAC computation to ensure proper handling of additional
 *   parameters.
 */

/**
 * \brief Tests the QMAC implementation against known answer test vectors.
 *
 * \details
 * This function computes the MAC for several test messages using different key and nonce values,
 * then compares the computed MACs to the expected known answer values.
 *
 * \return Returns true if all computed MACs match the expected outputs; otherwise, false.
 */
bool qsctest_qmac_kat(void);

/**
 * \brief Runs all QMAC tests.
 *
 * \details
 * This function executes the complete QMAC test suite, including both the compact API tests
 * and the long-form API tests. It prints the results of the tests to the console.
 */
void qsctest_qmac_run(void);

#endif
