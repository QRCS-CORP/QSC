
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

#ifndef QSCTEST_SCB_TEST_H
#define QSCTEST_SCB_TEST_H

#include "../QSC/common.h"

/**
* \file scb_test.h
* \brief SCB Known Answer Tests \n
* SHAKE Cost-Based KDF known answer comparison (KAT) tests. \n
* \author John Underhill \n
* \date January 12, 2022
*/

#define QSCTEST_SCB_TEST_CYCLES 100

/**
* \brief Tests the SCB 512-bit key KAT vectors from CEX.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* The test uses use original (and authoritative) vectors.</a>
*/
bool qsctest_scb_256_kat(void);

/**
* \brief Tests the SCB 512-bit key KAT vectors from CEX.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* The test uses use original (and authoritative) vectors.</a>
*/
bool qsctest_scb_512_kat(void);

/**
* \brief Run all tests.
*/
void qsctest_scb_run(void);

#endif
