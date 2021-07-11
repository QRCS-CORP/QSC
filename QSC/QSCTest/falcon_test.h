/**
* \file falcon_test.c
* \brief <b>Dilithium test functions</b> \n
* Contains the Dilithium implementation KAT and wellness test functions.
*
* \author John Underhill
* \date June 13, 2019
* \updated July 1, 2021
*/

#ifndef QSCTEST_FALCON_TEST_H
#define QSCTEST_FALCON_TEST_H

#include "common.h"

#define QSCTEST_FALCON_MLEN 33

/**
* \brief Test the public and private keys, ciphertext and shared key
* for correctness against the NIST PQC Round 3 vectors.
* tests the second vector in the NIST PQC Round 3, Kat file.
* \return Returns true for test success
*/
bool qsctest_falcon_operations_test();

/**
* \brief Test the validity of a mutated secret key
* \return Returns true for test success
*/
bool qsctest_falcon_privatekey_integrity();

/**
* \brief Test the validity of a mutated public key
* \return Returns true for test success
*/
bool qsctest_falcon_publickey_integrity();

/**
* \brief Test the validity of a mutated signature
* \return Returns true for test success
*/
bool qsctest_falcon_signature_integrity();

/**
* \brief Stress test the key generation, encryption, and decryption functions in a looping test.
* \return Returns true for test success
*/
bool qsctest_falcon_stress_test();

/**
* \brief Run the Dilithium implementation stress and correctness tests tests
*/
void qsctest_falcon_run();

#endif