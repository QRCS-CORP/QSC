
/* 2025 Quantum Resistant Cryptographic Solutions Corporation
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
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSCTEST_POLY1305_TEST_H
#define QSCTEST_POLY1305_TEST_H

#include "../QSC/common.h"

/**
* \file poly1305_test.h
* \brief Poly1305 Known Answer Tests \n
* Poly1305 known answer comparison (KAT) tests. \n
* Test vectors from the official Poly1305 implementation. \n
* \author John Underhill \n
* \date April 04, 2018
*/

/**
* \brief Tests the Poly1305 implementation.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* RFC7539: <a href="https://tools.ietf.org/html/rfc7539">7539</a>ChaCha20 and Poly1305 for IETF Protocols.</a>
*/
bool qsctest_poly1305_kat(void);

/**
* \brief Run all Poly1305 MAC generator tests
*/
void qsctest_poly1305_run(void);

#endif
