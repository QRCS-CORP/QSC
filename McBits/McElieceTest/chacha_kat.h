/**
* \file chacha_kat.h
* \brief <b>ChaCha Known Answer Tests</b> \n
* ChaChaP20 known answer comparison (KAT) tests. \n
* Test vectors from the official ChaCha implementation. \n
* FIPS 197: <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">The Advanced Encryption Standard</a>. \n
* New vectors have been added for the extended modes RSX256 and RSX512. \n
* \author John Underhill \n
* \date January 15, 2018
*/

#ifndef CHACHAKAT_H
#define CHACHAKAT_H

#include "common.h"

/**
* \brief Tests the ChaChaP20 implementation using a 128bit key.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* RFC7539: <a href="https://tools.ietf.org/html/rfc7539">ChaCha and Poly1305 based Cipher Suites for TLS</a>
*/
bool chacha128_kat_test();

/**
* \brief Tests the ChaChaP20 implementation using a 256bit key.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* RFC7539: <a href="https://tools.ietf.org/html/rfc7539">ChaCha and Poly1305 based Cipher Suites for TLS</a>
*/
bool chacha256_kat_test();

/**
* \brief Compare output between vectorized and sequential modes of operation.
*
* \return Returns true for success
*/
bool chacha_avx_equivalence();

#endif