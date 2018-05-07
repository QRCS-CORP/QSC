/**
* \file aes_kat.h
* \brief <b>AES Known Answer Tests</b> \n
* Rijndael known answer comparison (KAT) tests. \n
* Test vectors from the NIST standard tests contained in AES specification document, Appendix C. \n
* FIPS 197: <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">The Advanced Encryption Standard</a>. \n
* \author John Underhill
* \date January 15, 2018
*/

#ifndef AES_KAT_H
#define AES_KAT_H

#include "common.h"

/**
* \brief Tests the CBC 128bit key KAT vectors from NIST SP800-85a.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool aes128_cbc_kat_test();

/**
* \brief Tests the CBC 256bit key KAT vectors from NIST SP800-85a.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool aes256_cbc_kat_test();

/**
* \brief Tests the CTR 128bit key KAT vectors from NIST SP800-85a.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool aes128_ctr_kat_test();

/**
* \brief Tests the CTR 128bit key KAT vectors from NIST SP800-85a.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool aes256_ctr_kat_test();

/**
* \brief Tests the ECB mode 128bit key KAT vectors from NIST FIPS197 and SP800-85a
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Fips197: <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">The Advanced Encryption Standard, Appendix C.1</a>
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool aes128_ecb_kat_test();

/**
* \brief Tests the ECB 256bit key KAT vectors from NIST FIPS197 and SP800-85a.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Fips197: <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">The Advanced Encryption Standard, Appendix C.3</a>
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool aes256_ecb_kat_test();

#endif
