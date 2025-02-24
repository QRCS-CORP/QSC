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

#ifndef QSCTEST_SECRAND_TEST_H
#define QSCTEST_SECRAND_TEST_H

#include "common.h"

/**
 * \file secrand_test.h
 * \brief Entropy Provider Tests.
 *
 * \details
 * This header defines functions for testing the secure random (entropy) providers and key derivation functions.
 * It includes both stress tests and statistical evaluations (wellness tests) for various random generators,
 * such as ACP, CSP, CSG, HCG, RDP, and SCB. The tests compute statistical measures including mean value,
 * chi-square, ordered runs, and successive zeroes on a random sample to assess the quality of the random data.
 *
 * \def QSCTEST_SECRAND_SAMPLE_SIZE
 * \brief Size of the random sample used in the tests.
 *
 * The random sample size for evaluating the entropy providers is defined as 65536 bytes.
 */
#define QSCTEST_SECRAND_SAMPLE_SIZE 65536

/**
 * \brief Evaluates the output of a random provider.
 *
 * \details
 * This function computes statistical measures on a provided random sample, including:
 * - Mean value (optimal is 127.5 for uniformly distributed 8-bit data)
 * - Chi-square statistic, expressed as a percentage likelihood
 * - Ordered runs test, to detect unusually long sequences of identical values
 * - Successive zeroes test, to detect runs of zeros.
 *
 * The function prints the computed values and indicates whether the sample passes, warns, or fails the tests.
 *
 * \param name The name of the random provider.
 * \param sample Pointer to the random sample data.
 * \param length Length of the random sample in bytes.
 */
void qsctest_secrand_evaluate(const char* name, const uint8_t* sample, size_t length);

/**
 * \brief Evaluates the output of the ACP random provider.
 *
 * \details
 * This function generates a random sample using the ACP entropy provider and then evaluates its statistical
 * properties by calling \c qsctest_secrand_evaluate().
 */
void qsctest_secrand_acp_evaluate(void);

/**
 * \brief Evaluates the output of the CSG deterministic random bit generator (DRBG).
 *
 * \details
 * This function generates a random sample using the CSG DRBG and performs statistical evaluations on the sample.
 */
void qsctest_secrand_csg_evaluate(void);

/**
 * \brief Evaluates the output of the CSP random provider.
 *
 * \details
 * This function collects a random sample using the CSP provider and then assesses its statistical properties.
 */
void qsctest_secrand_csp_evaluate(void);

/**
 * \brief Evaluates the output of the HCG deterministic random bit generator (DRBG).
 *
 * \details
 * This function generates a random sample using the HCG DRBG and evaluates it using statistical tests.
 */
void qsctest_secrand_hcg_evaluate(void);

/**
 * \brief Evaluates the output of the RDP random provider.
 *
 * \details
 * This function generates a random sample using the RDP provider (compatible with RDRAND) and
 * performs statistical evaluations on the sample.
 */
void qsctest_secrand_rdp_evaluate(void);

/**
 * \brief Evaluates the output of the SCB key derivation function.
 *
 * \details
 * This function uses the SCB (SHAKE Cost-Based KDF) implementation to generate a random sample,
 * and then evaluates its statistical properties.
 */
void qsctest_secrand_scb_evaluate(void);

/**
 * \brief Performs a stress test on the secure random number generators.
 *
 * \details
 * This function tests various secure random generation functions by invoking calls that generate random
 * values of various types (e.g., char, unsigned char, double, int16, uint16, int32, uint32, int64, uint64)
 * and verifies that the outputs fall within expected ranges.
 *
 * \return Returns true if all random generation tests pass; otherwise, false.
 */
bool qsctest_secrand_stress(void);

/**
 * \brief Runs all secure random (entropy provider) tests.
 *
 * \details
 * This function executes a comprehensive test suite for secure random number generators and key derivation
 * functions. It first runs a stress test on the PRNG, then evaluates the output of various random providers,
 * including:
 * - ACP and CSP (and optionally RDP if available)
 * - Deterministic random bit generators (CSG and HCG)
 * - The SCB key derivation function.
 *
 * Test results and evaluation statistics are printed to the console.
 */
void qsctest_secrand_run(void);

#endif
