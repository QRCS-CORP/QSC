/**
* \file kem.h
* \date January 10, 2018
*
* \brief <b>The Kyber KEM definitions</b> \n
* Contains the primary public api for the Kyber CCA-secure Key Encapsulation Mechanism implementation.
*
* \para <b>Example</b> \n 
* \code
* // An example of key-pair creation, encryption, and decryption
* uint8_t pk[KYBER_PUBLICKEYBYTES];
* uint8_t sk[KYBER_SECRETKEYBYTES];
* uint8_t key_a[KYBER_SYMBYTES];
* uint8_t key_b[KYBER_SYMBYTES];
* uint8_t sendb[KYBER_CIPHERTEXTBYTES];
*
* // create the public and secret keys
* crypto_kem_keypair(pk, sk);
* // output the cipher-text (sendb), and bobs shared key
* crypto_kem_enc(sendb, key_b, pk);
* // decrypt the cipher-text, and output alices shared key
* if (crypto_kem_dec(key_a, sendb, sk) == KYBER_ERROR_AUTHFAIL)
* {
*     // authentication failed, do something..
* }
* \endcode
*
* \remarks Based entirely on the C reference branch of PQ-Crystals Kyber; including base code, comments, and api. \n
* PQ-Crystals <a href="https://github.com/pq-crystals/kyber">Kyber</a>. \n
* CRYSTALS - Kyber: <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">a CCA-secure module-lattice-based KEM</a>. \n
*/

#ifndef API_H
#define API_H

#include "common.h"
#include "params.h"

/*!
\def CRYPTO_ALGNAME
* The Kyber implementation name
*/
#if   (KYBER_K == 2)
#	define KYBER_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#	define KYBER_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#	define KYBER_ALGNAME "Kyber1024"
#else
#	error "KYBER_K must be in {2,3,4}"
#endif

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism
*
* \param pk Pointer to output public key (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
* \param sk Pointer to output private key (an already allocated array of KYBER_SECRETKEYBYTES bytes)
* \return Returns one (KYBER_CRYPTO_SUCCESS) for success
*/
kyber_status crypto_kem_keypair(uint8_t* pk, uint8_t* sk);

/**
* \brief Generates cipher text and shared secret for given public key
*
* \param ct Pointer to output cipher text (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
* \param ss Pointer to output shared secret (an already allocated array of KYBER_BYTES bytes)
* \param pk Pointer to input public key (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
* \return Returns one (KYBER_CRYPTO_SUCCESS) for success
*/
kyber_status crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk);

/**
* \brief Generates shared secret for given cipher text and private key
*
* \param ss Pointer to output shared secret (an already allocated array of KYBER_SECRET_BYTES bytes)
* \param ct Pointer to input cipher text (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
* \param sk Pointer to input private key (an already allocated array of KYBER_SECRETKEYBYTES bytes)
* \return Returns one (KYBER_CRYPTO_SUCCESS) for success
*/
kyber_status crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

#endif
