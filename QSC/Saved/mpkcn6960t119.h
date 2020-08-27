/*
  This file is for Benes network related functions
*/

#ifndef MCELIECE_N6960T119_H
#define MCELIECE_N6960T119_H

#include "common.h"


#ifndef QSC_MCELIECE_STRONG

#include "mceliece_support.h"

// params.h

#define QSC_MCELIECE_GFBITS 13
#define QSC_MCELIECE_SYS_N 6960
#define QSC_MCELIECE_SYS_T 119
#define QSC_MCELIECE_GF_MUL_FACTOR1 6400
#define QSC_MCELIECE_GF_MUL_FACTOR2 3134
#define QSC_MCELIECE_KEYGEN_RETRIES_MAX 100
#define QSC_MCELIECE_COND_BYTES ((1 << (QSC_MCELIECE_GFBITS - 4)) * ((2 * QSC_MCELIECE_GFBITS) - 1))
#define QSC_MCELIECE_IRR_BYTES (QSC_MCELIECE_SYS_T * 2)
#define QSC_MCELIECE_PK_NROWS (QSC_MCELIECE_SYS_T * QSC_MCELIECE_GFBITS) 
#define QSC_MCELIECE_PK_NCOLS (QSC_MCELIECE_SYS_N - QSC_MCELIECE_PK_NROWS)
#define QSC_MCELIECE_PK_ROW_BYTES ((QSC_MCELIECE_PK_NCOLS + 7) / 8)
#define QSC_MCELIECE_SK_BYTES ((QSC_MCELIECE_SYS_N / 8) + QSC_MCELIECE_IRR_BYTES + QSC_MCELIECE_COND_BYTES)
#define QSC_MCELIECE_SYND_BYTES ((QSC_MCELIECE_PK_NROWS + 7) / 8)
#define QSC_MCELIECE_GFMASK ((1 << QSC_MCELIECE_GFBITS) - 1)




/*!
\def QSC_MCELIECE_CIPHERTEXT_SIZE
* The byte size of the ciphertext
*/
#define QSC_MCELIECE_CIPHERTEXT_SIZE 226

/*!
\def QSC_MCELIECE_KEY_SIZE
* The size of the key reurned by the cipher
*/
#define QSC_MCELIECE_KEY_SIZE 32

/*!
\def QSC_MCELIECE_PUBLICKEY_SIZE
* The byte size of tyhe public key
*/
#define QSC_MCELIECE_PUBLICKEY_SIZE 1047319

/*!
\def QSC_MCELIECE_SECRETKEY_SIZE
* The byte size of the secret private key
*/
#define QSC_MCELIECE_SECRETKEY_SIZE 13908

/*!
\def QSC_MCELIECE_MAC_SIZE
* The byte size of the internal shake implementationc output MAC code
*/
#define QSC_MCELIECE_MAC_SIZE 32

// gf.h

void qsc_mceliece_gf_multiply(gf* out, const gf* in0, const gf* in1);

// benes.h

void qsc_mceliece_apply_benes(uint8_t* r, const uint8_t* bits, int32_t rev);

void qsc_mceliece_support_gen(gf* s, const uint8_t* c);

// bm.h

void qsc_mceliece_bm(gf *out, gf *s);

// controlbits.h

void qsc_mceliece_controlbits(uint8_t* out, const uint32_t* pi);

// decrypt.h


/* Nieddereiter decryption with the Berlekamp decoder */
/* input: sk, secret key */
/* input ciphertext: c */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
int32_t qsc_mceliece_decrypt(uint8_t* e, const uint8_t* sk, const uint8_t* c);

// encrypt.h


/* Nieddereiter encryption with the Berlekamp decoder */
/* output: c, ciphertext */
/* input public key: pk */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
void qsc_mceliece_encrypt(uint8_t* c, const uint8_t* pk, uint8_t* e, void (*rng_generate)(uint8_t*, size_t));

// pk_gen.h

/* input: secret key sk */
/* output: public key pk */
int32_t qsc_mceliece_pk_gen(uint8_t* pk, const uint8_t* sk);

// root.h

gf qsc_mceliece_root_eval(const gf* f, gf a);

void qsc_mceliece_root(gf* out, gf* f, gf* L);

// sk_gen.h

/* output: sk, the secret key */
int32_t qsc_mceliece_sk_part_gen(uint8_t* sk, void (*rng_generate)(uint8_t*, size_t));

// qsc_mceliece_synd.h

/* input: Goppa polynomial f, support L, received word r */
/* output: out, the syndrome of length 2t */
void qsc_mceliece_synd(gf* out, const gf* f, const gf* L, const uint8_t* r);

#endif
#endif

