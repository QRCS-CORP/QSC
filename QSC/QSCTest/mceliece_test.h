/**
* \file mceliece_test.c
* \brief <b>McEliece test functions</b> \n
* Contains the McEliece implementation KAT and wellness test functions.
*
* \author John Underhill
* \date August 1, 2020
* \updated July 1, 2021
*/

#ifndef QSCTEST_MCELIECE_TEST_H
#define QSCTEST_MCELIECE_TEST_H

#include "common.h"

/**
* \brief Test the validity of a mutated cipher-text
* \return Returns true for test success
*/
bool qsctest_mceliece_ciphertext_integrity();

/**
* \brief Test the known answer KATs for equivalence.
* \return Returns true for test success
*/
bool qsctest_mceliece_kat_test();

/**
* \brief Stress test the key generation, encryption, and decryption functions
* \return Returns true for test success
*/
bool qsctest_mceliece_operations_test();

/**
* \brief Test the validity of an altered public-key
* \return Returns true for test success
*/
bool qsctest_mceliece_publickey_integrity();

/**
* \brief Run all tests.
*/
void qsctest_mceliece_run();

#endif