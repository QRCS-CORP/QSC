/**
* \file kem.h
* \brief <b>Kyber Key Encapsulation Mechanism definitions</b> \n
* Contains the public api for the Kyber for CCA-secure KEM implementation.
*
* \date January 08, 2018
* \remarks
* A simple example of key-pair creation, encryption, and decryption
* using the Kyber INDCPA secure api.
*
* \code
* 
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
* crypto_kem_dec(key_a, sendb, sk);
* \endcode
*/

#ifndef API_H
#define API_H

#include "params.h"
#include <stdint.h>

/*! \enum KYBER_CRYPTO_STATUS
* The KEMs function result state
*/
enum KYBER_CRYPTO_STATUS
{
	KYBER_CRYPTO_FAILURE = 0, /*!< signals operation failure */
	KYBER_CRYPTO_SUCCESS = 1  /*!< signals operation success */
};

/*!
\def CRYPTO_SECRETKEYBYTES
* The byte size of the secret key array
*/
#define CRYPTO_SECRETKEYBYTES KYBER_SECRETKEYBYTES

/*!
\def CRYPTO_PUBLICKEYBYTES
* The byte size of the public key array
*/
#define CRYPTO_PUBLICKEYBYTES KYBER_PUBLICKEYBYTES

/*!
\def CRYPTO_CIPHERTEXTBYTES
* The byte size of the cipher-text array
*/
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES

/*!
\def CRYPTO_BYTES
* The byte size of the shared symmetric key array
*/
#define CRYPTO_BYTES KYBER_SYMBYTES

/*!
\def CRYPTO_ALGNAME
* The Kyber implementation name
*/
#if   (KYBER_K == 2)
#	define CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#	define CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#	define CRYPTO_ALGNAME "Kyber1024"
#else
#	error "KYBER_K must be in {2,3,4}"
#endif

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism
*
* \param pk Pointer to output public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
* \param sk Pointer to output private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
* \return Returns one (KYBER_CRYPTO_SUCCESS) for success
*/
int32_t crypto_kem_keypair(uint8_t* pk, uint8_t* sk);

/**
* \brief Generates cipher text and shared secret for given public key
*
* \param ct Pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
* \param ss Pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
* \param pk Pointer to input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
* \return Returns one (KYBER_CRYPTO_SUCCESS) for success
*/
int32_t crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk);

/**
* \brief Generates shared secret for given cipher text and private key
*
* \param ss Pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
* \param ct Pointer to input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
* \param sk Pointer to input private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
* \return Returns one (KYBER_CRYPTO_SUCCESS) for success
*/
int32_t crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

#endif
