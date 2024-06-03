
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSCTEST_MCELIECE_TEST_H
#define QSCTEST_MCELIECE_TEST_H

#include "common.h"

/**
* \file mceliece_test.c
* \brief McEliece test functions \n
* Contains the McEliece implementation KAT and wellness test functions.
*
* \author John Underhill
* \date August 1, 2020
* \updated July 1, 2021
*/

/**
* \brief Test the validity of a mutated cipher-text
* \return Returns true for test success
*/
bool qsctest_mceliece_ciphertext_integrity(void);

/**
* \brief Test the known answer KATs for equivalence.
* \return Returns true for test success
*/
bool qsctest_mceliece_kat_test(void);

/**
* \brief Stress test the key generation, encryption, and decryption functions
* \return Returns true for test success
*/
bool qsctest_mceliece_operations_test(void);

/**
* \brief Test the validity of an altered public-key
* \return Returns true for test success
*/
bool qsctest_mceliece_publickey_integrity(void);

/**
* \brief Run the McEliece implementation stress and correctness tests tests
*/
void qsctest_mceliece_run(void);

#endif
