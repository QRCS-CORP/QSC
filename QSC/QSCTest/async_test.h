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

#ifndef QSCTEST_ASYNC_TEST_H
#define QSCTEST_ASYNC_TEST_H

#include "../QSC/common.h"

/**
 * \file async_test.h
 * \brief Tests the asynchronous functions.
 *
 * \details
 * This file contains tests for the asynchronous execution functions provided by the library.
 * The tests validate two main aspects of asynchronous operations:
 *
 * 1. Single-thread test:
 *    - Launches a single asynchronous thread using qsc_async_launch_thread.
 *    - Executes a simple function that multiplies two integers.
 *    - Verifies that the result of the multiplication matches the expected value.
 *
 * 2. Multi-thread test:
 *    - Launches multiple asynchronous threads in parallel using qsc_async_launch_parallel_threads.
 *    - Executes the same multiplication function on different sets of input data.
 *    - Verifies that each thread correctly computes the product of its respective inputs.
 *
 * Both tests print messages indicating success or failure based on whether the computed results
 * match the expected values.
 */

/**
 * \brief Runs the asynchronous function tests.
 *
 * This function executes both the single-thread and multi-thread tests for asynchronous operations.
 * It prints the outcome of each test to the console.
 */
void qsctest_async_run(void);

#endif
