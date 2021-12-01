/**
* \file ecdh_test.c
* \brief ECDH test functions \n
* Contains the ECDH implementation KAT and wellness test functions.
*
* \author John Underhill
* \date August 30, 2020
*/

#ifndef QSCTEST_ECDH_TEST_H
#define QSCTEST_ECDH_TEST_H

#include "common.h"

#define QSCTEST_ECDH_ITERATIONS 100

/**
* \brief Test the public and private keys, cipher-text and shared key
* \return Returns true for test success
*/
bool qsctest_ecdh_kat_test(void);

/**
* \brief Stress test the key generation, encryption, and decryption functions in a 100 round loop.
* \return Returns true for test success
*/
bool qsctest_ecdh_operations_test(void);

/**
* \brief Test the validity of a mutated secret key in a 100 round loop.
* \return Returns true for test success
*/
bool qsctest_ecdh_privatekey_integrity(void);

/**
* \brief Test the validity of a mutated cipher-text in a 100 round loop.
* \return Returns true for test success
*/
bool qsctest_ecdh_publickey_integrity(void);

/**
* \brief Run the ECDH implementation stress and correctness tests tests
*/
void qsctest_ecdh_run(void);

#endif
