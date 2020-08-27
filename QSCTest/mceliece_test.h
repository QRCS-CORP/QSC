#ifndef QSCTEST_MCELIECE_TEST_H
#define QSCTEST_MCELIECE_TEST_H

#include "common.h"

#define MCELIECE_NTESTS 1

/**
* \brief Stress test the key generation, encryption, and decryption functions in a loop.
* \return Returns true for test success
*/
bool qsctest_mceliece_test_operations();

/**
* \brief Test the validity of a mutated public key in a loop.
* \return Returns true for test success
*/
bool qsctest_mceliece_test_publickey();

/**
* \brief Test the validity of a mutated cipher-text in a loop.
* \return Returns true for test success
*/
bool qsctest_mceliece_test_ciphertext();

/**
* \brief Test the known answer KATs for equivalence.
* \return Returns true for test success
*/
bool qsctest_mceliece_test_kats();

/**
* \brief Run all tests.
*/
void qsctest_mceliece_run();

#endif