#ifndef NTRU_PARAMS_H
#define NTRU_PARAMS_H

/*!
\def NTRU_SPRIME_ENABLED
* Enable the Rounded Quotient implementation of NTRU Prime, default is Rounded Product L-Prime
* Added for testing, use as a pre-processor directive
*/
#define NTRU_SPRIME_ENABLED

/*!
\def NTRU_SPRIME_SIMPLE
* Optional simplified form of S-Prime
*/
#if defined NTRU_SPRIME_ENABLED
//#	define NTRU_SPRIME_SIMPLE
#endif

/*!
\def NTRU_SEED_SIZE
* Read Only: The size of the shared key in bytes
*/
#define NTRU_SEED_SIZE 32

/*!
\def NTRU_Q
* Read Only: The modulus prime factor Q
*/
#define NTRU_Q 4591

/*!
\def NTRU_QSHIFT
* Read Only: The Q shift factor
*/
#define NTRU_QSHIFT 2295

/*!
\def NTRU_P
* Read Only: The P factor
*/
#define NTRU_P 761

/*!
\def NTRU_SMALLENCODE_SIZE
* Read Only: Small encoding length
*/
#define NTRU_SMALLENCODE_SIZE 191

#if defined(NTRU_SPRIME_ENABLED)

	/*!
	\def NTRU_PRIVATEKEY_SIZE
	* Read Only: The secret key size in bytes
	*/
#	define NTRU_PRIVATEKEY_SIZE 1600

	/*!
	\def NTRU_PUBLICKEY_SIZE
	* Read Only: The public key size in bytes
	*/
#	define NTRU_PUBLICKEY_SIZE 1218

	/*!
	\def NTRU_CIPHERTEXT_SIZE
	* Read Only: The cipher-text size in bytes
	*/
#	define NTRU_CIPHERTEXT_SIZE 1047

	/*!
	\def NTRU_W
	* Read Only: The Weight factor
	*/
#	define NTRU_W 286

	/*!
	\def NTRU_RQENCODE_SIZE
	* Read Only: RQ encoding length
	*/
#	define NTRU_RQENCODE_SIZE 1218

#else

	/*!
	\def NTRU_PRIVATEKEY_SIZE
	* Read Only: The secret key size in bytes
	*/
#	define NTRU_PRIVATEKEY_SIZE 1238

	/*!
	\def NTRU_PUBLICKEY_SIZE
	* Read Only: The public key size in bytes
	*/
#	define NTRU_PUBLICKEY_SIZE 1047

	/*!
	\def NTRU_CIPHERTEXT_SIZE
	* Read Only: The cipher-text size in bytes
	*/
#	define NTRU_CIPHERTEXT_SIZE 1175

	/*!
	\def NTRU_W
	* Read Only: The Weight factor
	*/
#	define NTRU_W 250

	/*!
	\def NTRU_RQENCODE_SIZE
	* Read Only: RQ encoding length
	*/
#	define NTRU_RQENCODE_SIZE 1015

#endif
#endif
