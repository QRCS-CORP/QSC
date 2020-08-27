#ifndef QSCTEST_SECRAND_TEST_H
#define QSCTEST_SECRAND_TEST_H

#include "common.h"

#define QSC_SECRAND_SAMPLE_SIZE 65536

/**
* \file secrand_test.h
* \brief <b>Entropy provider tests</b> \n
* The entropy providers and secure random stress and wellness tests.
* \author John Underhill
* \date August 19, 2020
*/

/**
* \brief Check the providers outpute uding mean, Chi square, ordered runs, and succesive zeroes tests
*
* \param name: The providers name
* \param sample: The random sample to be tested
* \param length: The length of the random sample
*/
void qsctest_secrand_evaluate(const char* name, const uint8_t* sample, size_t length);

void qsctest_secrand_acp_evaluate();

void qsctest_secrand_csg_evaluate();

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