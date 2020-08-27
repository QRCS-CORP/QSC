#ifndef QSCTEST_SPHINCSPLUS_TEST_H
#define QSCTEST_SPHINCSPLUS_TEST_H

/**
* \file sphincsplus_test.c
* \brief <b>SphincsPlus test functions</b> \n
* Contains the SphincsPlus implementation KAT and wellness test functions.
*
* \author John Underhill
* \date June 09, 2019
*/

#include "common.h"

#define TEST_SPHINCSPLUS_MLEN0 33
#define TEST_SPHINCSPLUS_MLEN1 66
#define TEST_SPHINCSPLUS_MLEN2 99
#define TEST_SPHINCSPLUS_MLEN3 132

#ifdef _DEBUG
#	define TEST_SPHINCSPLUS_ITERATIONS 1
#else
#	define TEST_SPHINCSPLUS_ITERATIONS 2
#endif

/**
* \brief Stress test the key generation, encryption, and decryption functions in a looping test.
* \return Returns one (true) for test success
*/
bool sphincsplus_stress_test();

/**
* \brief Test the validity of a mutated public key
* \return Returns one (true) for test success
*/
bool sphincsplus_publickey_integrity();

/**
* \brief Test the validity of a mutated secret key
* \return Returns one (true) for test success
*/
bool sphincsplus_secretkey_integrity();

/**
* \brief Test the validity of a mutated signature
* \return Returns one (NEWHOPE_STATUS_SUCCESS) for test success
*/
bool sphincsplus_signature_integrity();

/**
* \brief Test the public and private keys, ciphertext and shared key
* for correctness against the NIST PQ Round 2 vectors.
* tests the second vector in the NIST PQ Round 2, Kat file.
* \return Returns 0 for test success
*/
bool sphincsplus_integrity_test();

/**
* \brief Test the first ten vectors of the NIST PQ Round 2 KAT tests
*/
bool sphincsplus_kat_test();

/**
* \brief Run the Kyber implementation stress and correctness tests tests
*/
void qsc_sphincsplus_run();

#endif