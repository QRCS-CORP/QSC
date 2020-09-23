/**
* \file mceliece_test.c
* \brief <b>McEliece test functions</b> \n
* Contains the McEliece implementation KAT and wellness test functions.
*
* \author John Underhill
* \date August 1, 2020
*/

#ifndef QSCTEST_MCELIECE_TEST_H
#define QSCTEST_MCELIECE_TEST_H

#include "common.h"

#ifdef _DEBUG
#	define QSCTEST_MCELIECE_ITERATIONS 1
#else
#	define QSCTEST_MCELIECE_ITERATIONS 4
#endif

/**
* \brief Test the validity of a mutated cipher-text in a loop.
* \return Returns true for test success
*/
bool qsctest_mceliece_ciphertext_integrity();

/**
* \brief Test the known answer KATs for equivalence.
* \return Returns true for test success
*/
bool qsctest_mceliece_kat_test();

/**
* \brief Stress test the key generation, encryption, and decryption functions in a loop.
* \return Returns true for test success
*/
bool qsctest_mceliece_operations_test();

/**
* \brief Test the validity of a mutated public key in a loop.
* \return Returns true for test success
*/
bool qsctest_mceliece_publickey_integrity();

/**
* \brief Run all tests.
*/
void qsctest_mceliece_run();

#endif