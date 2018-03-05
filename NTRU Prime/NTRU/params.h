#ifndef NTRU_PARAMS_H
#define NTRU_PARAMS_H

/*!
\def NTRU_SECRETKEYBYTES
* Read Only: The secret key size in bytes
*/
#define NTRU_SECRETKEYBYTES 1238

/*!
\def NTRU_PUBLICKEYBYTES
* Read Only: The public key size in bytes
*/
#define NTRU_PUBLICKEYBYTES 1047

/*!
\def NTRU_CIPHERTEXTBYTES
* Read Only: The cipher-text size in bytes
*/
#define NTRU_CIPHERTEXTBYTES 1175

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
\def NTRU_W
* Read Only: The W factor
*/
#define NTRU_W 250

#define NTRU_RQENCODE_LEN 1218
#define NTRU_RQENCODEROUNDED_LEN 1015
#define NTRU_SMALLENCODE_LEN 191

#endif
