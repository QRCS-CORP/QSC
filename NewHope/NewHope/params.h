/**
* \file params.h
* \date February 16, 2018
*
* \brief <b>NewHope parameter settings</b> \n
* This is an internal class.
*/

#ifndef NEWHOPE_PARAMS_H
#define NEWHOPE_PARAMS_H

/*!
\def NEWHOPE_N
* The polynomial dimension N.
* Valid values are 1024 and 512
*/
#define NEWHOPE_N 1024

/*!
\def NEWHOPE_Q
* Read Only: The modulus prime factor Q
*/
#define NEWHOPE_Q 12289

/*!
\def NEWHOPE_K
* Read Only: The matrix dimension K; used in noise sampling
*/
#define NEWHOPE_K 8

/*!
\def NEWHOPE_SYMBYTES
* Read Only: The size in bytes of shared key, hashes, and seeds
*/
#define NEWHOPE_SYMBYTES 32

/*!
\def NEWHOPE_POLYBYTES
* Read Only: The secret key base multiplier
*/
#define NEWHOPE_POLYBYTES ((14 * NEWHOPE_N) / 8)

/*!
\def NEWHOPE_POLYCOMPRESSEDBYTES
* Read Only: The ciphertext compressed byte size
*/
#define NEWHOPE_POLYCOMPRESSEDBYTES ((3 * NEWHOPE_N) / 8)

/*!
\def NEWHOPE_CPAPKE_PUBLICKEYBYTES
* Read Only: The base CPA formatted public key size in bytes
*/
#define NEWHOPE_CPAPKE_PUBLICKEYBYTES  (NEWHOPE_POLYBYTES + NEWHOPE_SYMBYTES)

/*!
\def NEWHOPE_CPAPKE_SECRETKEYBYTES
* Read Only: The base CPA formatted secret key size in bytes
*/
#define NEWHOPE_CPAPKE_SECRETKEYBYTES (NEWHOPE_POLYBYTES)

/*!
\def NEWHOPE_CPAPKE_CIPHERTEXTBYTES
* Read Only: The CPA cipher-text size in bytes
*/
#define NEWHOPE_CPAPKE_CIPHERTEXTBYTES (NEWHOPE_POLYBYTES + NEWHOPE_POLYCOMPRESSEDBYTES)

/*!
\def NEWHOPE_CCAKEM_PUBLICKEYBYTES
* Read Only: The base CCA formatted public key size in bytes
*/
#define NEWHOPE_CCAKEM_PUBLICKEYBYTES NEWHOPE_CPAPKE_PUBLICKEYBYTES

/*!
\def NEWHOPE_CCAKEM_SECRETKEYBYTES
* Read Only: The base CCA formatted secret key size in bytes
*/
#define NEWHOPE_CCAKEM_SECRETKEYBYTES (NEWHOPE_CPAPKE_SECRETKEYBYTES + NEWHOPE_CPAPKE_PUBLICKEYBYTES + 2 * NEWHOPE_SYMBYTES)

/*!
\def NEWHOPE_CCAKEM_CIPHERTEXTBYTES
* Read Only: The CCA cipher-text size in bytes
*/
#define NEWHOPE_CCAKEM_CIPHERTEXTBYTES (NEWHOPE_CPAPKE_CIPHERTEXTBYTES + NEWHOPE_SYMBYTES)

#endif
