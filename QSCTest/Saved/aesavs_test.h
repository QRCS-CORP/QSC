#ifndef QSCTEST_AESAVS_TEST_H
#define QSCTEST_AESAVS_TEST_H

#include "common.h"

/**
* \brief Tests the CBC 128 and 256-bit key and text KAT vectors from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS KAT CBC 6.2</a>
*/
bool qsctest_aesavs_cbc_kat();

/**
* \brief Tests the ECB 128 and 256-bit key and text KAT vectors from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS KAT ECB 6.2</a>
*/
bool qsctest_aesavs_ecb_kat();

/**
* \brief Tests the CBC 128 and 256-bit key monte carlo tests from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS MCT 6.4.2 CBC</a>
*/
bool qsctest_aesavs_cbc_mct();

/**
* \brief Tests the ECB 128 and 256-bit key monte carlo tests from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS 6.4.1 ECB</a>
*/
bool qsctest_aesavs_ecb_mct();

/**
* \brief Tests the CBC 128 and 256-bit key multi-block message tests from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS 6.3 CBC</a>
*/
bool qsctest_aesavs_cbc_mmt();

/**
* \brief Tests the ECB 128 and 256-bit key monte multi-block message tests from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS 6.3 ECB</a>
*/
bool qsctest_aesavs_ecb_mmt();

/**
* \brief Run all tests.
*/
void qsctest_aesavs_run();

#endif
