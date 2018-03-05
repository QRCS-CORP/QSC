/**
* \file kem.h
* \date March 4, 2018
*
* \brief <b>The NTRU KEM definitions</b> \n
* Contains the primary public api for the NTRU CCA-secure Key Encapsulation Mechanism implementation.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* uint8_t pk[NTRU_PUBLICKEYBYTES];
* uint8_t sk[NTRU_SECRETKEYBYTES];
* uint8_t key_a[NTRU_KEYBYTES];
* uint8_t key_b[NTRU_KEYBYTES];
* uint8_t sendb[NTRU_CIPHERTEXTBYTES];
*
* // create the public and secret keys
* crypto_kem_keypair(pk, sk);
* // output the cipher-text (sendb), and bob's shared key
* crypto_kem_enc(sendb, key_b, pk);
* // decrypt the cipher-text, and output alice's shared key
* if (crypto_kem_dec(key_a, sendb, sk) == KYBER_ERROR_AUTHFAIL)
* {
*     // authentication failed, do something..
* }
* \endcode
*
* \remarks Based entirely on the C reference implementation of NTRU Prime. \n
* Website: <a href="https://ntruprime.cr.yp.to/software.html">NTRU Prime Software</a>. \n
* Reference Paper: <a href="https://ntruprime.cr.yp.to/ntruprime-20160511.pdf">NTRU Prime</a>. \n
*/


#ifndef NTRU_KEM_H
#define NTRU_KEM_H

#include "common.h"

/**
* \brief Generates shared secret for given cipher text and private key
*
* \param ss Pointer to output shared secret (an already allocated array of NTRU_SECRETBYTES bytes)
* \param ct Pointer to input cipher text (an already allocated array of NTRU_CIPHERTEXTBYTES bytes)
* \param sk Pointer to input private key (an already allocated array of NTRU_SECRETKEYBYTES bytes)
* \return Returns one (QCC_STATUS_SUCCESS) for success
*/
qcc_status crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

/**
* \brief Generates cipher text and shared secret for given public key
*
* \param ct Pointer to output cipher text (an already allocated array of NTRU_CIPHERTEXTBYTES bytes)
* \param ss Pointer to output shared secret (an already allocated array of NTRU_KEYBYTES bytes)
* \param pk Pointer to input public key (an already allocated array of NTRU_PUBLICKEYBYTES bytes)
* \return Returns one (QCC_STATUS_SUCCESS) for success
*/
qcc_status crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk);

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism
*
* \param pk Pointer to output public key (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
* \param sk Pointer to output private key (an already allocated array of KYBER_SECRETKEYBYTES bytes)
* \return Returns one (KYBER_CRYPTO_SUCCESS) for success
*/
qcc_status crypto_kem_keypair(uint8_t* pk, uint8_t* sk);

#endif
