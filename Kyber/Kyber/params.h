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

/* Internal Constants: -Read Only- */

/*!
\def KYBER_N
* Read Only: The polynomial dimension N
*/
#define KYBER_N 256

/*!
\def KYBER_Q
* Read Only: The modulus prime factor Q
*/
#define KYBER_Q 7681

/*!
\def KYBER_ETA
* Read Only: The binomial distribution factor
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
\def KYBER_KEYBYTES
* Read Only: The size in bytes of shared key, hashes, and seeds
*/
#define KYBER_KEYBYTES 32

/*!
\def KYBER_POLYBYTES
* Read Only: The secret key base multiplier
*/
#define KYBER_POLYBYTES 416

/*!
\def KYBER_POLYCOMPRESSEDBYTES
* Read Only: The ciphertext compressed byte size
*/
#define KYBER_POLYCOMPRESSEDBYTES 96

/*!
\def KYBER_POLYVECBYTES
* Read Only: The base size of the secret key
*/
#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)

/*!
\def KYBER_POLYVECCOMPRESSEDBYTES
* Read Only: The base size of the public key
*/
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)

/*!
\def KYBER_INDCPA_MSGBYTES
*  Read Only: The message size in bytes
*/
#define KYBER_INDCPA_MSGBYTES KYBER_KEYBYTES

/*!
\def KYBER_INDCPA_PUBLICKEYBYTES
* Read Only: The base INDCPA formatted public key size in bytes
*/
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_KEYBYTES)

/*!
\def KYBER_INDCPA_SECRETKEYBYTES
* Read Only: The base INDCPA formatted secret key size in bytes
*/
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)

/*!
\def KYBER_INDCPA_BYTES
* Read Only: The size of the INDCPA formatted output cipher-text
*/
#define KYBER_INDCPA_BYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

/*!
\def KYBER_PUBLICKEYBYTES
* Read Only: The public key size in bytes
*/
#define KYBER_PUBLICKEYBYTES (KYBER_INDCPA_PUBLICKEYBYTES)

/*!
\def KYBER_SECRETKEYBYTES
* Read Only: The secret key size in bytes
*/
#define KYBER_SECRETKEYBYTES (KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + (2 * KYBER_KEYBYTES))

/*!
\def KYBER_CIPHERTEXTBYTES
* Read Only: The cipher-text size in bytes
*/
#define KYBER_CIPHERTEXTBYTES KYBER_INDCPA_BYTES

#endif
