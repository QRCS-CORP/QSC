/**
* \file mceliece_test.c
* \brief McEliece test functions \n
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
bool qsctest_mceliece_ciphertext_integrity(void);

/**
* \brief Test the known answer KATs for equivalence.
* \return Returns true for test success
*/
bool qsctest_mceliece_kat_test(void);

/**
* \brief Stress test the key generation, encryption, and decryption functions
* \return Returns true for test success
*/
bool qsctest_mceliece_operations_test(void);

/**
* \brief Test the validity of an altered public-key
* \return Returns true for test success
*/
bool qsctest_mceliece_publickey_integrity(void);

/**
* \brief Run the McEliece implementation stress and correctness tests tests
*/
void qsctest_mceliece_run(void);

#endif
