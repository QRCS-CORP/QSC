/**
* \file params.h
* \brief <b>Kyber implementation parameters</b> \n
* Contains the Kyber implementation constants.
*
* \date January 07, 2018
*/

#ifndef PARAMS_H
#define PARAMS_H

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
* Enable the simple cSHAKE-128 generator for polynomial generation.
* If disabled, reverts to the SHAKE-128 generator.
*/
#define MATRIX_GENERATOR_CSHAKE

/* Internal Constants */

/*!
\def KYBER_N
* The polynomial dimension N
*/
#define KYBER_N 256

/*!
\def KYBER_Q
* The modulus prime factor Q
*/
#define KYBER_Q 7681

/*!
\def KYBER_ETA
* The binomial distribution factor
*/
#if (KYBER_K == 2)
	/* Kyber512 */
#	define KYBER_ETA 5
#elif (KYBER_K == 3) 
	/* Kyber768 */
#	define KYBER_ETA 4
#elif (KYBER_K == 4) 
	/* Kyber1024 */
#	define KYBER_ETA 3
#else
#	error "KYBER_K must be in {2,3,4}"
#endif

/*!
\def KYBER_SYMBYTES
* The size in bytes of shared key, hashes, and seeds
*/
#define KYBER_SYMBYTES 32

/*!
\def KYBER_POLYBYTES
* The secret key base polynomial multiplier
*/
#define KYBER_POLYBYTES 416

/*!
\def KYBER_POLYCOMPRESSEDBYTES
* The ciphertext compressed byte size
*/
#define KYBER_POLYCOMPRESSEDBYTES 96

/*!
\def KYBER_POLYVECBYTES
* The base size of the secret key
*/
#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)

/*!
\def KYBER_POLYVECCOMPRESSEDBYTES
* The base size of the public key
*/
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)

/*!
\def KYBER_INDCPA_MSGBYTES
*  The message size in bytes
*/
#define KYBER_INDCPA_MSGBYTES KYBER_SYMBYTES

/*!
\def KYBER_INDCPA_PUBLICKEYBYTES
* The base INDCPA formatted public key size in bytes
*/
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_SYMBYTES)

/*!
\def KYBER_INDCPA_SECRETKEYBYTES
* The base INDCPA formatted secret key size in bytes
*/
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)

/*!
\def KYBER_INDCPA_BYTES
* The size of the INDCPA formatted output cipher-text
*/
#define KYBER_INDCPA_BYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

/*!
\def KYBER_PUBLICKEYBYTES
* The public key size in bytes
*/
#define KYBER_PUBLICKEYBYTES (KYBER_INDCPA_PUBLICKEYBYTES)

/*!
\def KYBER_SECRETKEYBYTES
* The secret key size in bytes
*/
#define KYBER_SECRETKEYBYTES (KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + (2 * KYBER_SYMBYTES))

/*!
\def KYBER_CIPHERTEXTBYTES
* The cipher-text base size in bytes
*/
#define KYBER_CIPHERTEXTBYTES KYBER_INDCPA_BYTES

#endif
