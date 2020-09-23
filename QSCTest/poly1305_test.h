/**
* \file poly1305_test.h
* \brief <b>Poly1305 Known Answer Tests</b> \n
* Poly1305 known answer comparison (KAT) tests. \n
* Test vectors from the official Poly1305 implementation. \n
* \author John Underhill \n
* \date April 04, 2018
*/

#ifndef QSCTEST_POLY1305_TEST_H
#define QSCTEST_POLY1305_TEST_H

#include "../QSC/common.h"

/**
* \brief Tests the Poly1305 implementation.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* RFC7539: <a href="https://tools.ietf.org/html/rfc7539">7539</a>ChaCha20 and Poly1305 for IETF Protocols.</a>
*/
bool qsctest_poly1305_kat();

/**
* \brief Run all Poly1305 MAC generator tests
*/
void qsctest_poly1305_run();

#endif