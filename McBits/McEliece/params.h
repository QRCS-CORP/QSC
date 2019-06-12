#ifndef PARAMS_H
#define PARAMS_H

/* internal */
#define MCELIECE_GFBITS 12
#define MCELIECE_SYST 62
#define MCELIECE_PKNROWS (MCELIECE_SYST * MCELIECE_GFBITS)
#define MCELIECE_PKNCOLS ((1 << MCELIECE_GFBITS) - MCELIECE_SYST * MCELIECE_GFBITS)
#define MCELIECE_COLSIZE ((MCELIECE_PKNCOLS + 63) / 64)
#define MCELIECE_IRRBYTES (MCELIECE_GFBITS * 8)
#define MCELIECE_CONDBYTES (736 * 8)
#define MCELIECE_SYNDBYTES (MCELIECE_PKNROWS / 8)
#define MCELIECE_SYSN 1 << (MCELIECE_GFBITS)
#define MCELIECE_SYSE 1 << (MCELIECE_GFBITS - 3)

/*!
\def MCELIECE_ENCPASULATE
* Encryption function generates key using NewHope style kem
*/
//#define MCELIECE_ENCPASULATE

/*!
\def MCELIECE_KEY_SIZE
* The size of the key returned by the cipher
*/
#define MCELIECE_KEY_SIZE 32

/*!
\def MCELIECE_MAC_SIZE
* The (internal size of the Poly1305 MAC code
*/
#define MCELIECE_MAC_SIZE 16

/*!
\def MCELIECE_SECRETKEY_SIZE
* The byte size of the secret private key
*/
#define MCELIECE_SECRETKEY_SIZE 5984

/*!
\def MCELIECE_PUBLICKEY_SIZE
* The byte size of tyhe public key
*/
#define MCELIECE_PUBLICKEY_SIZE 311736

/*!
\def MCELIECE_CIPHERTEXT_SIZE
* The byte size of the ciphertext
*/
#define MCELIECE_CIPHERTEXT_SIZE (MCELIECE_SYNDBYTES + MCELIECE_MAC_SIZE + MCELIECE_KEY_SIZE)

/*!
\def MCELIECE_VERSION
* The version of this implementation of McEliece
*/
#define MCELIECE_VERSION "1.0"

#endif