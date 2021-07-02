/**
* \file kyber_test.c
* \brief <b>Kyber test functions</b> \n
* Contains the Kyber implementation KAT and wellness test functions.
*
* \author John Underhill
* \date August 1, 2020
* \updated July 1, 2021
*/

#ifndef QSCTEST_KYBER_TEST_H
#define QSCTEST_KYBER_TEST_H

#include "common.h"

#define QSCTEST_KYBER_NTESTS 100

/**
* \brief Test the validity of a mutated cipher-text in a 100 round loop.
* \return Returns true for test success
*/
bool qsctest_kyber_ciphertext_integrity();

/**
* \brief Test the public and private keys, ciphertext and shared key
* for correctness against the NIST PQ Round 2 vectors
* \return Returns true for test success
*/
bool qsctest_kyber_kat_test();

/**
* \brief Stress test the key generation, encryption, and decryption functions
* \return Returns true for test success
*/
bool qsctest_kyber_operations_test();

/**
* \brief Test the validity of an altered secret-key
* \return Returns true for test success
*/
bool qsctest_kyber_privatekey_integrity();

/**
* \brief Test the validity of an altered public key
* \return Returns true for test success
*/
bool qsctest_kyber_publickey_integrity();

/**
* \brief Run the Kyber implementation stress and correctness tests tests
*/
void qsctest_kyber_run();

#endif