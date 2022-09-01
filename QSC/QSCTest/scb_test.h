/**
* \file scb_test.h
* \brief SCB Known Answer Tests \n
* SHAKE Cost-Based KDF known answer comparison (KAT) tests. \n
* \author John Underhill \n
* \date January 12, 2022
*/

#ifndef QSCTEST_SCB_TEST_H
#define QSCTEST_SCB_TEST_H

#include "../QSC/common.h"

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
