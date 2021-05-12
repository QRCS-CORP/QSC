/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef QSC_MCELIECEBASE_H
#define QSC_MCELIECEBASE_H

#include "common.h"

#if defined(QSC_MCELIECE_N8192T128)
#	define QSC_MCELIECE_BENES_BPTR 12288
#	define QSC_MCELIECE_BENES_INC -1024
#	define QSC_MCELIECE_GFBITS 13
#	define QSC_MCELIECE_SYS_N 8192
#	define QSC_MCELIECE_SYS_T 128
#	define QSC_MCELIECE_COND_BYTES ((1 << (QSC_MCELIECE_GFBITS - 4)) * (2 * QSC_MCELIECE_GFBITS - 1))
#	define QSC_MCELIECE_IRR_BYTES (QSC_MCELIECE_SYS_T * 2)
#	define QSC_MCELIECE_PK_NROWS (QSC_MCELIECE_SYS_T * QSC_MCELIECE_GFBITS) 
#	define QSC_MCELIECE_PK_NCOLS (QSC_MCELIECE_SYS_N - QSC_MCELIECE_PK_NROWS)
#	define QSC_MCELIECE_PK_ROW_BYTES ((QSC_MCELIECE_PK_NCOLS + 7) / 8)
#	define QSC_MCELIECE_SK_BYTES (QSC_MCELIECE_SYS_N / 8 + QSC_MCELIECE_IRR_BYTES + QSC_MCELIECE_COND_BYTES)
#	define QSC_MCELIECE_SYND_BYTES ((QSC_MCELIECE_PK_NROWS + 7) / 8)
#	define QSC_MCELIECE_GFMASK ((1 << QSC_MCELIECE_GFBITS) - 1)
#	define QSC_MCELIECE_GF_MUL_FACTOR1 7682
#	define QSC_MCELIECE_GF_MUL_FACTOR2 2159
#	define QSC_MCELIECE_GF_MUL_FACTOR3 3597
#	define QSC_MCELIECE_KEYGEN_RETRIES_MAX 100
#elif defined(QSC_MCELIECE_N6960T119)
#	define QSC_MCELIECE_BENES_BPTR 12288
#	define QSC_MCELIECE_BENES_INC -1024
#	define QSC_MCELIECE_GFBITS 13
#	define QSC_MCELIECE_SYS_N 6960
#	define QSC_MCELIECE_SYS_T 119
#	define QSC_MCELIECE_GF_MUL_FACTOR1 6400
#	define QSC_MCELIECE_GF_MUL_FACTOR2 3134
#	define QSC_MCELIECE_KEYGEN_RETRIES_MAX 100
#	define QSC_MCELIECE_COND_BYTES ((1 << (QSC_MCELIECE_GFBITS - 4)) * ((2 * QSC_MCELIECE_GFBITS) - 1))
#	define QSC_MCELIECE_IRR_BYTES (QSC_MCELIECE_SYS_T * 2)
#	define QSC_MCELIECE_PK_NROWS (QSC_MCELIECE_SYS_T * QSC_MCELIECE_GFBITS) 
#	define QSC_MCELIECE_PK_NCOLS (QSC_MCELIECE_SYS_N - QSC_MCELIECE_PK_NROWS)
#	define QSC_MCELIECE_PK_ROW_BYTES ((QSC_MCELIECE_PK_NCOLS + 7) / 8)
#	define QSC_MCELIECE_SK_BYTES ((QSC_MCELIECE_SYS_N / 8) + QSC_MCELIECE_IRR_BYTES + QSC_MCELIECE_COND_BYTES)
#	define QSC_MCELIECE_SYND_BYTES ((QSC_MCELIECE_PK_NROWS + 7) / 8)
#	define QSC_MCELIECE_GFMASK ((1 << QSC_MCELIECE_GFBITS) - 1)
#else
#	error No McEliece implementation is defined, check common.h!
#endif

/*!
* \def QSC_MCELIECE_MAC_SIZE
* \brief The byte size of the internal shake implementationc output MAC code
*/
#define QSC_MCELIECE_MAC_SIZE 32

#define GFNBITS 13
#define GFNMASK ((1 << GFNBITS) - 1)

typedef char bit;
typedef uint16_t gf;

/* shared functions */

/* benes.h */

/* middle layers of the benes network */
void qsc_mceliece_benes_layer_in(uint64_t data[2][64], const uint64_t* bits, uint32_t lgs);

/* first and last layers of the benes network */
void qsc_mceliece_benes_layer_ex(uint64_t* data, const uint64_t* bits, uint32_t lgs);

/* qsc_mceliece_controlbits.c */

bit qsc_mceliece_is_smaller(uint32_t a, uint32_t b);

bit qsc_mceliece_is_smaller_63b(uint64_t a, uint64_t b);

void qsc_mceliece_cswap(uint32_t* x, uint32_t* y, bit swap);

void qsc_mceliece_cswap_63b(uint64_t* x, uint64_t* y, bit swap);

/* output x = min(input x,input y) */
/* output y = max(input x,input y) */
void qsc_mceliece_minmax(uint32_t* x, uint32_t* y);

void qsc_mceliece_minmax_63b(uint64_t* x, uint64_t* y);

/* merge first half of x[0],x[step],...,x[(2*n-1)*step] with second half */
/* requires n to be a power of 2 */
void qsc_mceliece_merge(uint32_t n, uint32_t* x, uint32_t step);

void qsc_mceliece_merge_63b(uint32_t n, uint64_t* x, uint32_t step);

/* sort x[0],x[1],...,x[n-1] in place */
/* requires n to be a power of 2 */
void qsc_mceliece_sort(uint32_t n, uint32_t* x);

void qsc_mceliece_sort_63b(uint32_t n, uint64_t* x);

void qsc_mceliece_composeinv(uint32_t n, uint32_t* y, const uint32_t* x, const uint32_t* pi);

void qsc_mceliece_invert(uint32_t n, uint32_t* ip, const uint32_t* pi);

void qsc_mceliece_flow(uint32_t w, uint32_t* x, const uint32_t* y, const uint32_t t);

void qsc_mceliece_compose(uint32_t w, uint32_t n, const uint32_t* pi, uint32_t* P);

void qsc_mceliece_permute(uint32_t w, uint32_t n, uint32_t off, uint32_t step, const uint32_t* P, const uint32_t* pi, uint8_t* c, uint32_t* piflip);

void qsc_mceliece_permutecontrolbits(uint32_t w, uint32_t n, uint32_t step, uint32_t off, uint8_t* c, const uint32_t* pi);

/* gf.h */

gf qsc_mceliece_gf_bitrev(gf a);

gf qsc_mceliece_gf_iszero(gf a);

gf qsc_mceliece_gf_add(gf in0, gf in1);

gf qsc_mceliece_gf_mul(gf in0, gf in1);

gf qsc_mceliece_gf_frac(gf den, gf num);

gf qsc_mceliece_gf_inv(gf den);

gf qsc_mceliece_gf_sq2(gf in);

gf qsc_mceliece_gf_sqmul(gf in, gf m);

gf qsc_mceliece_gf_sq2mul(gf in, gf m);

/* transpose.h */

/* input: in, a 64x64 matrix over GF(2) */
/* output: out, transpose of in */
void qsc_mceliece_transpose_64x64(uint64_t* out, const uint64_t* in);

/* unique functions */

/* gf.h */

void qsc_mceliece_gf_multiply(gf* out, gf* in0, const gf* in1);

/* benes.h */

void qsc_mceliece_apply_benes(uint8_t* r, const uint8_t* bits, int32_t rev);

void qsc_mceliece_support_gen(gf* s, const uint8_t* c);

/* bm.h */

void qsc_mceliece_bm(gf* out, const gf* s);

/* controlbits.h */

void qsc_mceliece_controlbits(uint8_t* out, const uint32_t* pi);

/* decrypt.h */

/* Nieddereiter decryption with the Berlekamp decoder */
/* input: sk, secret key */
/* input ciphertext: c */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
int32_t qsc_mceliece_decrypt(uint8_t* e, const uint8_t* sk, const uint8_t* c);

/* encrypt.h */

/* Nieddereiter encryption with the Berlekamp decoder */
/* output: c, ciphertext */
/* input public key: pk */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
void qsc_mceliece_encrypt(uint8_t* c, const uint8_t* pk, uint8_t* e, void (*rng_generate)(uint8_t*, size_t));

/* pk_gen.h */

/* input: secret key sk */
/* output: public key pk */
int32_t qsc_mceliece_pk_gen(uint8_t* pk, const uint8_t* sk);

/* root.h */

gf qsc_mceliece_root_eval(const gf* f, gf a);

void qsc_mceliece_root(gf* out, const gf* f, const gf* L);

/* sk_gen.h */

/* output: sk, the secret key */
int32_t qsc_mceliece_sk_part_gen(uint8_t* sk, void (*rng_generate)(uint8_t*, size_t));

/* qsc_mceliece_synd.h */

/* input: Goppa polynomial f, support L, received word r */
/* output: out, the qsc_mceliece_syndrome of length 2t */
void qsc_mceliece_synd(gf* out, const gf* f, const gf* L, const uint8_t* r);

/* kem.h */

/**
* \brief Decapsulates a ciphertext to produce a secret
*
* \param secret: Pointer to the output public-key array
* \param ciphertext: Pointer to the cipher-text
* \param privatekey: Pointer to the private-key array
* \return Returns true for success
*/
bool qsc_mceliece_kem_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
* \brief Encapsulates a secret key in cipher-text
*
* \param secret: Pointer to the shared secret
* \param ciphertext: Pointer to the cipher-text
* \param publickey: Pointer to the public-key array
* \param rng_generate: A pointer to a random generator
*/
void qsc_mceliece_kem_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private keys
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param rng_generate: A pointer to a random generator
*/
void qsc_mceliece_generate_kem_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t));

#endif