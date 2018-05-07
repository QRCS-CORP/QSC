#ifndef NTRU_PARAMS_H
#define NTRU_PARAMS_H

/*!
\def NTRU_SPRIME_ENABLED
* Added for testing, use as a pre-processor directive: enable the Rounded Quotient implementation of NTRU Prime, default is Rounded Product L-Prime
*/
//#define NTRU_SPRIME_ENABLED

/*!
\def NTRU_KEYBYTES
* Read Only: The size of the shared key in bytes
*/
#define NTRU_KEYBYTES 32

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
\def NTRU_SMALLENCODE_LEN
* Read Only: Small encoding length
*/
#define NTRU_SMALLENCODE_LEN 191

#if defined(NTRU_SPRIME_ENABLED)

	/*!
	\def NTRU_SECRETKEYBYTES
	* Read Only: The secret key size in bytes
	*/
#	define NTRU_SECRETKEYBYTES 1600

	/*!
	\def NTRU_PUBLICKEYBYTES
	* Read Only: The public key size in bytes
	*/
#	define NTRU_PUBLICKEYBYTES 1218

	/*!
	\def NTRU_CIPHERTEXTBYTES
	* Read Only: The cipher-text size in bytes
	*/
#	define NTRU_CIPHERTEXTBYTES 1047

	/*!
	\def NTRU_W
	* Read Only: The Weight factor
	*/
#	define NTRU_W 286

	/*!
	\def NTRU_RQENCODE_LEN
	* Read Only: RQ encoding length
	*/
#	define NTRU_RQENCODE_LEN 1218

#else

	/*!
	\def NTRU_SECRETKEYBYTES
	* Read Only: The secret key size in bytes
	*/
#	define NTRU_SECRETKEYBYTES 1238

	/*!
	\def NTRU_PUBLICKEYBYTES
	* Read Only: The public key size in bytes
	*/
#	define NTRU_PUBLICKEYBYTES 1047

	/*!
	\def NTRU_CIPHERTEXTBYTES
	* Read Only: The cipher-text size in bytes
	*/
#	define NTRU_CIPHERTEXTBYTES 1175

	/*!
	\def NTRU_W
	* Read Only: The Weight factor
	*/
#	define NTRU_W 250

	/*!
	\def NTRU_RQENCODE_LEN
	* Read Only: RQ encoding length
	*/
#	define NTRU_RQENCODE_LEN 1015

#endif
#endif
