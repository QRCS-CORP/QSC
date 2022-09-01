/**
* \file kyber_test.c
* \brief Kyber test functions \n
* Contains the Kyber implementation KAT and wellness test functions.
*
* \author John Underhill
* \date August 1, 2020
* \updated July 1, 2021
*/

#ifndef QSCTEST_KYBER_TEST_H
#define QSCTEST_KYBER_TEST_H

#include "common.h"

/**
* \brief Test the validity of a mutated cipher-text
* \return Returns true for test success
*/
bool qsctest_kyber_ciphertext_integrity(void);

/**
* \brief Test the public and private keys, cipher-text and shared key
* for correctness against the NIST PQC Round 3 vectors
* \return Returns true for test success
*/
bool qsctest_kyber_kat_test(void);

/**
* \brief Stress test the key generation, encryption, and decryption functions
* \return Returns true for test success
*/
bool qsctest_kyber_operations_test(void);

/**
* \brief Test the validity of an altered secret-key
* \return Returns true for test success
*/
bool qsctest_kyber_privatekey_integrity(void);

/**
* \brief Test the validity of an altered public key
* \return Returns true for test success
*/
bool qsctest_kyber_publickey_integrity(void);

/**
* \brief Run the Kyber implementation stress and correctness tests tests
*/
void qsctest_kyber_run(void);

#endif
