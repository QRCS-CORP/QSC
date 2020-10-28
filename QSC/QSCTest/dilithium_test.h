/**
* \file dilithium_test.c
* \brief <b>Dilithium test functions</b> \n
* Contains the Dilithium implementation KAT and wellness test functions.
*
* \author John Underhill
* \date June 13, 2019
*/

#ifndef QSCTEST_DILITHIUM_TEST_H
#define QSCTEST_DILITHIUM_TEST_H

#include "common.h"

#define QSCTEST_DILITHIUM_MLEN0 33
#define QSCTEST_DILITHIUM_MLEN1 66
#define QSCTEST_DILITHIUM_MLEN2 99
#define QSCTEST_DILITHIUM_MLEN3 132

#ifdef _DEBUG
#	define QSCTEST_DILITHIUM_ITERATIONS 1
#else
#	define QSCTEST_DILITHIUM_ITERATIONS 10
#endif

/**
* \brief Test the first ten vectors of the NIST PQ Round 2 KAT tests
*/
bool qsctest_dilithium_kat_test();

/**
* \brief Test the public and private keys, ciphertext and shared key
* for correctness against the NIST PQ Round 2 vectors.
* tests the second vector in the NIST PQ Round 2, Kat file.
* \return Returns true for test success
*/
bool qsctest_dilithium_operations_test();

/**
* \brief Test the validity of a mutated secret key
* \return Returns true for test success
*/
bool qsctest_dilithium_privatekey_integrity();

/**
* \brief Test the validity of a mutated public key
* \return Returns true for test success
*/
bool qsctest_dilithium_publickey_integrity();

/**
* \brief Test the validity of a mutated signature
* \return Returns true for test success
*/
bool qsctest_dilithium_signature_integrity();

/**
* \brief Stress test the key generation, encryption, and decryption functions in a looping test.
* \return Returns true for test success
*/
bool qsctest_dilithium_stress_test();

/**
* \brief Run the Dilithium implementation stress and correctness tests tests
*/
void qsctest_dilithium_run();

#endif