/**
* \file sphincsplus_test.c
* \brief SphincsPlus test functions \n
* Contains the SphincsPlus implementation KAT and wellness test functions.
*
* \author John Underhill
* \date June 09, 2019
* \updated July 1, 2021
*/

#ifndef QSCTEST_SPHINCSPLUS_TEST_H
#define QSCTEST_SPHINCSPLUS_TEST_H

#include "common.h"

#define QSCTEST_SPHINCSPLUS_MLEN 33

/**
* \brief Test the public and private keys, cipher-text and shared key
* for correctness against the NIST PQC Round 3 vectors.
* tests the second vector in the NIST PQC Round 3, KAT file.
* \return Returns 0 for test success
*/
bool qsctest_sphincsplus_operations_test(void);

/**
* \brief Test the validity of a mutated secret key
* \return Returns one (true) for test success
*/
bool qsctest_sphincsplus_privatekey_integrity(void);

/**
* \brief Test the validity of a mutated public key
* \return Returns one (true) for test success
*/
bool qsctest_sphincsplus_publickey_integrity(void);

/**
* \brief Test the validity of a mutated signature
* \return Returns one (NEWHOPE_STATUS_SUCCESS) for test success
*/
bool qsctest_sphincsplus_signature_integrity(void);

/**
* \brief Stress test the key generation, encryption, and decryption functions in a looping test.
* \return Returns one (true) for test success
*/
bool qsctest_sphincsplus_stress_test(void);

/**
* \brief Tests the 512-bit extended version of the signature scheme
* \return Returns one (true) for test success
*/
bool qsctest_sphincsplus_extended_test(void);

/**
* \brief Run the SPHINCS+ implementation stress and correctness tests tests
*/
void qsctest_sphincsplus_run(void);

#endif
