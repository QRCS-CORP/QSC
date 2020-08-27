#ifndef QSCTEST_DILITHIUM_TEST_H
#define QSCTEST_DILITHIUM_TEST_H

#include "common.h"

/**
* \file dilithium_test.c
* \brief <b>Dilithium test functions</b> \n
* Contains the Dilithium implementation KAT and wellness test functions.
*
* \author John Underhill
* \date June 13, 2019
*/

/* jgu -suppressing repeated include warning, using include guards */
/*lint -e537 */
/* jgu -suppressing misra stdio header warning in example only */
/*lint -e829 */

#include "common.h"

#ifdef _DEBUG
#	define TEST_DILITHIUM_ITERATIONS 1
#else
#	define TEST_DILITHIUM_ITERATIONS 10
#endif

/**
* \brief Get a char from console input.
* \return Returns one user input char
*/
static void get_response();

/**
* \brief Stress test the key generation, encryption, and decryption functions in a looping test.
* \return Returns true for test success
*/
bool dilithium_stress_test();

/**
* \brief Test the validity of a mutated public key
* \return Returns true for test success
*/
bool dilithium_publickey_integrity();

/**
* \brief Test the validity of a mutated secret key
* \return Returns true for test success
*/
bool dilithium_secretkey_integrity();

/**
* \brief Test the validity of a mutated signature
* \return Returns one (NEWHOPE_STATUS_SUCCESS) for test success
*/
bool dilithium_signature_integrity();

/**
* \brief Test the first ten vectors of the NIST PQ Round 2 KAT tests
*/
bool dilithium_kat_test();

/**
* \brief Test the public and private keys, ciphertext and shared key
* for correctness against the NIST PQ Round 2 vectors.
* tests the second vector in the NIST PQ Round 2, Kat file.
* \return Returns true for test success
*/
bool dilithium_integrity_test();

/**
* \brief Run the Kyber implementation stress and correctness tests tests
*/
void qsctest_dilithium_run();

#endif