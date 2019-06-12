/**
* \file params.h
* \brief <b>Kyber implementation parameters</b> \n
* Contains the Kyber implementation constants.
*
* \date January 10, 2018
*/

#ifndef KYBER_PARAMS_H
#define KYBER_PARAMS_H

/* Modifiable Constants */

/*!
\def KYBER_K
* The matrix dimension K
* Change this for different security strengths. \n
* Valid options are 2: minimal-102bit, 3: strong-128bit, or 4: paranoid-218bit.
*/
#ifndef KYBER_K
#	define KYBER_K 3
#endif

/*!
\def MATRIX_GENERATOR_CSHAKE
* Enable the simple cSHAKE generator for polynomial generation.
* If disabled, reverts to the SHAKE generator.
*/
#define MATRIX_GENERATOR_CSHAKE

/* Don't change parameters below this line */

/*!
\def KYBER_N
* Read Only: The polynomial dimension N
*/
#define KYBER_N 256

/*!
\def KYBER_Q
* Read Only: The modulus prime factor Q
*/
#define KYBER_Q 3329

/*!
\def KYBER_ETA
* Read Only: The binomial distribution factor
*/
#define KYBER_ETA 2

/*!
\def KYBER_SYMBYTES
* Read Only: The size in bytes of hashes, and seeds
*/
#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */

/*!
\def KYBER_SHAREDSECRET_SIZE
* Read Only: The byte size of the shared secret key
*/
#define KYBER_SHAREDSECRET_SIZE 32

/*!
\def KYBER_POLYBYTES
* Read Only: The secret key base multiplier
*/
#define KYBER_POLYBYTES 384


/*!
\def KYBER_POLYVECBYTES
* Read Only: The base size of the compressed public key polynolial
*/
#if KYBER_K == 2
#define KYBER_POLYVECBASEBYTES 320
#elif KYBER_K == 3
#define KYBER_POLYVECBASEBYTES 320
#elif KYBER_K == 4
#define KYBER_POLYVECBASEBYTES 352
#endif

/*!
\def KYBER_POLYCOMPRESSEDBYTES
* Read Only: The ciphertext compressed byte size
*/
#if KYBER_K == 2
#define KYBER_POLYCOMPRESSEDBYTES 96
#elif KYBER_K == 3
#define KYBER_POLYCOMPRESSEDBYTES 128
#elif KYBER_K == 4
#define KYBER_POLYCOMPRESSEDBYTES 160
#endif

/*!
\def KYBER_POLYVECCOMPRESSEDBYTES
* Read Only: The base size of the public key
*/
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * KYBER_POLYVECBASEBYTES)

/*!
\def KYBER_POLYVECBYTES
* Read Only: The base size of the secret key
*/
#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)

/*!
\def KYBER_INDCPA_MSGBYTES
*  Read Only: The message size in bytes
*/
#define KYBER_INDCPA_MSGBYTES KYBER_SYMBYTES

/*!
\def KYBER_INDCPA_PUBLICKEYBYTES
* Read Only: The base INDCPA formatted public key size in bytes
*/
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)

/*!
\def KYBER_INDCPA_SECRETKEYBYTES
* Read Only: The base INDCPA formatted private key size in bytes
*/
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)

/*!
\def KYBER_INDCPA_BYTES
* Read Only: The size of the INDCPA formatted output cipher-text
*/
#define KYBER_INDCPA_BYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

/*!
\def KYBER_PUBLICKEY_SIZE
* Read Only: The public key size in bytes
*/
#define KYBER_PUBLICKEY_SIZE (KYBER_INDCPA_PUBLICKEYBYTES)

/*!
\def KYBER_INDCPA_SECRETKEYBYTES
* Read Only: The base INDCPA formatted secret key size in bytes
*/
#define KYBER_SECRETKEY_SIZE (KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + 2 * KYBER_SYMBYTES)

/*!
\def KYBER_CIPHERTEXT_SIZE
* Read Only: The cipher-text size in bytes
*/
#define KYBER_CIPHERTEXT_SIZE KYBER_INDCPA_BYTES

#endif
