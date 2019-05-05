#ifndef PARAMS_H
#define PARAMS_H

#define GFBITS 13
#define SYS_N 8192
#define SYS_T 128
#define COND_BYTES ((1 << (GFBITS - 4)) * (2 * GFBITS - 1))
#define IRR_BYTES (SYS_T * 2)
#define PK_NROWS (SYS_T * GFBITS) 
#define PK_NCOLS (SYS_N - PK_NROWS)
#define PK_ROW_BYTES ((PK_NCOLS + 7) / 8)
#define SK_BYTES (SYS_N / 8 + IRR_BYTES + COND_BYTES)
#define SYND_BYTES ((PK_NROWS + 7) / 8)
#define GFMASK ((1 << GFBITS) - 1)

/*!
\def MCELIECE_CIPHERTEXT_SIZE
* The byte size of the ciphertext
*/
#define MCELIECE_CIPHERTEXT_SIZE 240

/*!
\def MCELIECE_KEY_SIZE
* The size of the key reurned by the cipher
*/
#define MCELIECE_KEY_SIZE 32

/*!
\def MCELIECE_PUBLICKEY_SIZE
* The byte size of tyhe public key
*/
#define MCELIECE_PUBLICKEY_SIZE 1357824

/*!
\def MCELIECE_SECRETKEY_SIZE
* The byte size of the secret private key
*/
#define MCELIECE_SECRETKEY_SIZE 14080

/*!
\def MCELIECE_MAC_SIZE
* The byte size of the internal shake implementationc output MAC code
*/
#define MCELIECE_MAC_SIZE 32

#endif

