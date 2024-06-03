
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSCTEST_SECRAND_TEST_H
#define QSCTEST_SECRAND_TEST_H

#include "common.h"

/**
* \file secrand_test.h
* \brief Entropy provider tests \n
* The entropy providers and secure random stress and wellness tests.
* \author John Underhill
* \date August 19, 2020
*/

#define QSCTEST_SECRAND_SAMPLE_SIZE 65536

/**
* \brief Check the providers output using statistical mean, CH1 square, ordered runs, and successive zeroes tests
*
* \param name: The providers name
* \param sample: The random sample to be tested
* \param length: The length of the random sample
*/
void qsctest_secrand_evaluate(const char* name, const uint8_t* sample, size_t length);

/**
* \brief Evaluate the output of the ACP provider
*/
void qsctest_secrand_acp_evaluate(void);

/**
* \brief Evaluate the output of the CSG DRBG
*/
void qsctest_secrand_csg_evaluate(void);

/**
* \brief Evaluate the output of the CSP provider
*/
void qsctest_secrand_csp_evaluate(void);

/**
* \brief Evaluate the output of the HCG DRBG
*/
void qsctest_secrand_hcg_evaluate(void);

/**
* \brief Evaluate the output of the RDP provider
*/
void qsctest_secrand_rdp_evaluate(void);

/**
* \brief The secure random PRNG stress test
*
* \return Returns true for success
*/
bool qsctest_secrand_stress(void);

/**
* \brief Run all tests.
*/
void qsctest_secrand_run(void);

#endif
