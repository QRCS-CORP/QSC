/**
* \file ntru_test.c
* \brief <b>NTRU test functions</b> \n
* Contains the Kyber implementation KAT and wellness test functions.
*
* \author John Underhill
* \date July 1, 2021
* \updated July 1, 2021
*/

#ifndef QSCTEST_NTRU_TEST_H
#define QSCTEST_NTRU_TEST_H

#include "common.h"

/**
* \brief Test the validity of a mutated cipher-text
* \return Returns true for test success
*/
bool qsctest_ntru_ciphertext_integrity();

/**
* \brief Test the public and private keys, ciphertext and shared key
* for correctness against the NIST PQC Round 3 vectors
* \return Returns true for test success
*/
bool qsctest_ntru_kat_test();

/**
* \brief Stress test the key generation, encryption, and decryption functions
* \return Returns true for test success
*/
bool qsctest_ntru_operations_test();

/**
* \brief Test the validity of an altered secret-key
* \return Returns true for test success
*/
bool qsctest_ntru_privatekey_integrity();

/**
* \brief Test the validity of an altered public key
* \return Returns true for test success
*/
bool qsctest_ntru_publickey_integrity();

/**
* \brief Run the Kyber implementation stress and correctness tests tests
*/
void qsctest_ntru_run();

#endif