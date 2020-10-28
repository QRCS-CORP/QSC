/**
* \file secrand_test.h
* \brief <b>Entropy provider tests</b> \n
* The entropy providers and secure random stress and wellness tests.
* \author John Underhill
* \date August 19, 2020
*/

#ifndef QSCTEST_SECRAND_TEST_H
#define QSCTEST_SECRAND_TEST_H

#include "common.h"

#define QSCTEST_SECRAND_SAMPLE_SIZE 65536

/**
* \brief Check the providers outpute using statistical mean, chi square, ordered runs, and succesive zeroes tests
*
* \param name: The providers name
* \param sample: The random sample to be tested
* \param length: The length of the random sample
*/
void qsctest_secrand_evaluate(const char* name, const uint8_t* sample, size_t length);

/**
* \brief Evaluate the output of the acp provider
*/
void qsctest_secrand_acp_evaluate();

/**
* \brief Evaluate the output of the csg DRBG
*/
void qsctest_secrand_csg_evaluate();

/**
* \brief Evaluate the output of the csp provider
*/
void qsctest_secrand_csp_evaluate();

/**
* \brief Evaluate the output of the hcg DRBG
*/
void qsctest_secrand_hcg_evaluate();

/**
* \brief Evaluate the output of the rdp provider
*/
void qsctest_secrand_rdp_evaluate();

/**
* \brief The secure random PRNG stress test
*
* \return Returns true for success
*/
bool qsctest_secrand_stress();

/**
* \brief Run all tests.
*/
void qsctest_secrand_run();

#endif