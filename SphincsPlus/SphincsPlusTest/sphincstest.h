#ifndef SPHINCS_TEST_H
#define SPHINCS_TEST_H

#include "common.h"
#include "../SphincsPlus/common.h"

#define SPHINCS_MSG_SIZE 32
#ifdef _DEBUG
#	define SPHINCS_NUM_TESTS 1
#else
#	define SPHINCS_NUM_TESTS 10
#endif

/**
* \brief Stress test the key generation, signing, and verification tests.
*/
void sphincs_test();

/**
* \brief Stress test the key generation, signing, and verification functions in a looping test.
* \return Returns one (QCC_STATUS_SUCCESS) for test success
*/
qcc_status sphincs_stress_test();

/**
* \brief Test the validity of a mutated public key
* \return Returns one (QCC_STATUS_SUCCESS) for test success
*/
qcc_status sphincs_publickey_integrity();

/**
* \brief Test the validity of a mutated secret key
* \return Returns one (QCC_STATUS_SUCCESS) for test success
*/
qcc_status sphincs_secretkey_integrity();

/**
* \brief Test the validity of a mutated signature
* \return Returns one (QCC_STATUS_SUCCESS) for test success
*/
qcc_status test_signature_integrity();

#endif
