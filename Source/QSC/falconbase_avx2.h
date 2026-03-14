/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_FALCONBASE_AVX2_H
#define QSC_FALCONBASE_AVX2_H

 /* \cond NO_DOCUMENT */

#include "qsccommon.h"

#if defined(QSC_SYSTEM_HAS_AVX2)

#include "intrinsics.h"
#include "sha3.h"
#include <math.h>

/* api.h */

#if defined(QSC_FALCON_S3SHAKE256F512)
#	define FALCON_CRYPTO_SECRETKEYBYTES 1281
#	define FALCON_CRYPTO_PUBLICKEY_BYTES 897
#	define FALCON_CRYPTO_SIGNATURE_BYTES 658
#	define CRYPTO_ALGNAME "Falcon-512"
#elif defined(QSC_FALCON_S5SHAKE256F1024)
#	define FALCON_CRYPTO_SECRETKEYBYTES 2305
#	define FALCON_CRYPTO_PUBLICKEY_BYTES 1793
#	define FALCON_CRYPTO_SIGNATURE_BYTES 1276
#	define CRYPTO_ALGNAME "Falcon-1024"
#endif

/* falcon_fpr.h */

#define FALCON_FPR_GM_TAB_SIZE 2048
#define FALCON_FPR_INV_SIGMA_SIZE 11
#define FALCON_FPR_GM_P2_SIZE 11
#define FALCON_Q 12289
#define FALCON_Q0I 12287
#define FALCON_R 4091
#define FALCON_R2 10952
#define FALCON_GMB_SIZE 1024
#define FALCON_KEYGEN_TEMP_1 136
#define FALCON_KEYGEN_TEMP_2 272
#define FALCON_KEYGEN_TEMP_3 224
#define FALCON_KEYGEN_TEMP_4 448
#define FALCON_KEYGEN_TEMP_5 896
#define FALCON_KEYGEN_TEMP_6 1792
#define FALCON_KEYGEN_TEMP_7 3584
#define FALCON_KEYGEN_TEMP_8 7168
#define FALCON_KEYGEN_TEMP_9 14336
#define FALCON_KEYGEN_TEMP_10 28672
#define FALCON_SMALL_PRIME_SIZE 522
#define FALCON_GAUS_1024_12289_SIZE 27
#define FALCON_MAX_BL_SMALL_SIZE 11
#define FALCON_MAX_BL_LARGE_SIZE 10
#define FALCON_DEPTH_INT_FG 4
#define FALCON_NONCE_SIZE 40
#define FALCON_L2BOUND_SIZE 11
#define FALCON_MAXBITS_SIZE 11
#define FALCON_REV10_SIZE 1024

#if defined(__GNUC__)
#	if defined(FALCON_FMA)
#		define FALCON_TARGET_AVX2 __attribute__((target("avx2,fma")))
#	else
#		define FALCON_TARGET_AVX2 __attribute__((target("avx2")))
#	endif
#elif defined(_MSC_VER)
#	define FALCON_TARGET_AVX2
#	pragma warning( disable : 4752 )
#endif

inline static __m256d falcon_fmadd(__m256d a, __m256d b, __m256d c)
{
#if defined(FALCON_FMA)
	return _mm256_fmadd_pd(a, b, c);
#else
	__m256d tmp;
	tmp = _mm256_mul_pd(a, b);
	tmp = _mm256_add_pd(tmp, c);
	return tmp;
#endif
}

inline static __m256d falcon_fmsub(__m256d a, __m256d b, __m256d c)
{
	/* Note artifact, unused function */
#if defined(FALCON_FMA)
	return _mm256_fmsub_pd(a, b, c);
#else
	__m256d tmp;
	tmp = _mm256_mul_pd(a, b);
	return _mm256_sub_pd(tmp, c);
#endif
}

//inline static uint32_t falcon_set_fpu_cw(uint32_t x)
//{
//#if defined __GNUC__ && defined __i386__
//	uint32_t short t;
//	uint32_t old;
//
//	__asm__ __volatile__("fstcw %0" : "=m" (t) : : );
//	old = (t & 0x0300u) >> 8;
//	t = (uint32_t short)((t & ~0x0300u) | (x << 8));
//	__asm__ __volatile__("fldcw %0" : : "m" (t) : );
//	return old;
//#elif defined _M_IX86
//	uint32_t short t;
//	uint32_t old;
//
//	__asm { fstcw t }
//	old = (t & 0x0300u) >> 8;
//	t = (uint32_t short)((t & ~0x0300u) | (x << 8));
//	__asm { fldcw t }
//	return old;
//#else
//	return x;
//#endif
//}

/*
 * For optimal reproducibility of values, we need to disable contraction
 * of floating-point expressions; otherwise, on some architectures (e.g.
 * PowerPC), the compiler may generate fused-multiply-add opcodes that
 * may round differently than two successive separate opcodes. C99 defines
 * a standard pragma for that, but GCC-6.2.2 appears to ignore it,
 * hence the GCC-specific pragma (that Clang does not support).
 */
#if defined __clang__
#	pragma STDC FP_CONTRACT OFF
#elif defined __GNUC__
#	pragma GCC optimize ("fp-contract=off")
#endif

 /* prng.c */

typedef struct
{
	QSC_ALIGN(8) uint8_t buf[512];
	QSC_ALIGN(8) uint8_t state[256];
	size_t ptr;
	int32_t type;
} falcon_prng_state;

/*
 * We wrap the native 'double' type into a structure so that the C compiler
 * complains if we inadvertently use raw arithmetic operators on the 'falcon_fpr'
 * type instead of using the inline functions below. This should have no
 * extra runtime cost, since all the functions below are 'inline'.
 */
typedef struct { double v; } falcon_fpr;

static const falcon_fpr falcon_fpr_q = { 12289.0 };
static const falcon_fpr falcon_fpr_inverse_of_q = { 1.0 / 12289.0 };
static const falcon_fpr falcon_fpr_inv_2sqrsigma0 = { 0.150865048875372721532312163019 };
static const falcon_fpr falcon_fpr_log2 = { 0.69314718055994530941723212146 };
static const falcon_fpr falcon_fpr_inv_log2 = { 1.4426950408889634073599246810 };
static const falcon_fpr falcon_fpr_bnorm_max = { 16822.4121 };
static const falcon_fpr falcon_fpr_zero = { 0.0 };
static const falcon_fpr falcon_fpr_one = { 1.0 };
static const falcon_fpr falcon_fpr_two = { 2.0 };
static const falcon_fpr falcon_fpr_onehalf = { 0.5 };
static const falcon_fpr falcon_fpr_invsqrt2 = { 0.707106781186547524400844362105 };
static const falcon_fpr falcon_fpr_invsqrt8 = { 0.353553390593273762200422181052 };
static const falcon_fpr falcon_fpr_ptwo31 = { 2147483648.0 };
static const falcon_fpr falcon_fpr_ptwo31m1 = { 2147483647.0 };
static const falcon_fpr falcon_fpr_mtwo31m1 = { -2147483647.0 };
static const falcon_fpr falcon_fpr_ptwo63m1 = { 9223372036854775807.0 };
static const falcon_fpr falcon_fpr_mtwo63m1 = { -9223372036854775807.0 };
static const falcon_fpr falcon_fpr_ptwo63 = { 9223372036854775808.0 };

typedef struct
{
	uint32_t p;
	uint32_t g;
	uint32_t s;
} falcon_small_prime;

extern const falcon_fpr falcon_avx2_fpr_inv_sigma[FALCON_FPR_INV_SIGMA_SIZE];
extern const falcon_fpr falcon_avx2_fpr_sigma_min[FALCON_FPR_INV_SIGMA_SIZE];
extern const falcon_fpr falcon_avx2_fpr_gm_tab[FALCON_FPR_GM_TAB_SIZE];
extern const falcon_fpr falcon_avx2_fpr_p2_tab[FALCON_FPR_GM_P2_SIZE];
extern const uint8_t falcon_avx2_max_fg_bits[FALCON_MAXBITS_SIZE];
extern const uint8_t falcon_falcon_max_FG_bits[FALCON_MAXBITS_SIZE];
extern const uint32_t falcon_avx2_l2bound[FALCON_L2BOUND_SIZE];
extern const uint64_t falcon_avx2_gauss_1024_12289[FALCON_GAUS_1024_12289_SIZE];
extern const uint16_t falcon_avx2_falcon_rev10[FALCON_REV10_SIZE];
extern const size_t falcon_avx2_max_bl_small[FALCON_MAX_BL_SMALL_SIZE];
extern const size_t falcon_avx2_max_bl_large[FALCON_MAX_BL_LARGE_SIZE];
extern const uint16_t falcon_avx2_GMb[FALCON_GMB_SIZE];
extern const uint16_t falcon_avx2_iGMb[FALCON_GMB_SIZE];
extern const falcon_small_prime falcon_avx2_small_primes[FALCON_SMALL_PRIME_SIZE];

/**
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to FALCON_PUBLICKEY_SIZE and FALCON_SECRETKEY_SIZE.
*
* \param publickey: The public verification key
* \param secretkey: The private signature key
* \param rng_generate: The random generator
*/
int32_t qsc_falcon_avx2_generate_keypair(uint8_t *pk, uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message
*
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param message: The message to be signed
* \param msglen: The message length
* \param privatekey: The private signature key
* \param rng_generate: The random generator
*/
int32_t qsc_falcon_avx2_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: The message to be signed
* \param msglen: The message length
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param publickey: The public verification key
* \return Returns true for success
*/
bool qsc_falcon_avx2_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);\

/* \endcond NO_DOCUMENT */
#endif
#endif
