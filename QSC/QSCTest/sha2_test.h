
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

#ifndef QSCTEST_SHA2_TEST_H
#define QSCTEST_SHA2_TEST_H

#include "common.h"

/**
* \file sha3_test.h
* \brief SHA2, HKDF, and HMAC, Known Answer Tests \n
* Uses Known Answer Tests from official sources to qsc_intutils_verify the
* correct operation of the SHA2 digests, HKDF, and HMAC implementations.
* \author John Underhill
* \date October 10, 2019
*/

/**
* \brief Tests the 256-bit version of the HFDF-Expand(HMAC(SHA2-256)) key derivation function for correct operation,
* using vectors from the official KAT file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Uses vectors from: RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
* KAT: <a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>
*/
bool qsctest_hkdf_256_kat(void);

/**
* \brief Tests the 512-bit version of the HFDF-Expand(HMAC(SHA2-512)) key derivation function for correct operation,
* using vectors from the official KAT file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Uses vectors from: RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
* KAT: <a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>
*/
bool qsctest_hkdf_512_kat(void);

/**
* \brief Tests the 256-bit version of the HMAC(SHA2-256) function for correct operation,
* using vectors from the official KAT file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Using vectors from: RFC 4321: Test Vectors for the SHA2-256 HMAC:
* KAT: <a href="http://tools.ietf.org/html/rfc4231">RFC 4321</a>
*/
bool qsctest_hmac_256_kat(void);

/**
* \brief Tests the 512-bit version of the HMAC(SHA2-512) function for correct operation,
* using vectors from the official KAT file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Using vectors from: RFC 4321: Test Vectors for the SHA2-512 HMAC:
* KAT: <a href="http://tools.ietf.org/html/rfc4231">RFC 4321</a>
*/
bool qsctest_hmac_512_kat(void);

/**
* \brief Tests the 256-bit version of the SHA2 message digest for correct operation,
* using selected vectors from the NIST SHA2 official KAT file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* KAT: <a href="https://www.di-mgt.com.au/sha_testvectors.html">SHA256</a>
*/
bool qsctest_sha2_256_kat(void);

/**
* \brief Tests the 384-bit version of the SHA2 message digest for correct operation,
* using selected vectors from the NIST SHA2 official KAT file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* KAT: <a href="https://www.di-mgt.com.au/sha_testvectors.html">SHA384</a>
*/
bool qsctest_sha2_384_kat(void);

/**
* \brief Tests the 512-bit version of the SHA2 message digest for correct operation,
* using selected vectors from the NIST SHA2 official KAT file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* KAT: <a href="https://www.di-mgt.com.au/sha_testvectors.html">SHA512</a>
*/
bool qsctest_sha2_512_kat(void);

/**
* \brief Run all tests.
*/
void qsctest_sha2_run(void);

#endif
