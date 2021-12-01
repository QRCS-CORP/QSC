/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef QSC_FALCONBASE_AVX2_H
#define QSC_FALCONBASE_AVX2_H

/* \cond DOXYGEN_IGNORE */

#include "common.h"

#if defined(QSC_SYSTEM_HAS_AVX2)

#include "intrinsics.h"
#include "sha3.h"
#include <math.h>

/* api.h */

#if defined(QSC_FALCON_S3SHAKE256F512)
#	define CRYPTO_SECRETKEYBYTES 1281
#	define CRYPTO_PUBLICKEYBYTES 897
#	define CRYPTO_BYTES 690
#	define CRYPTO_ALGNAME "Falcon-512"
#elif defined(QSC_FALCON_S5SHAKE256F1024)
#	define CRYPTO_SECRETKEYBYTES 2305
#	define CRYPTO_PUBLICKEYBYTES 1793
#	define CRYPTO_BYTES 1330
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

inline static void falcon_chacha_round(uint32_t state[16], size_t a, size_t b, size_t c, size_t d)
{
	state[a] += state[b];
	state[d] ^= state[a];
	state[d] = (state[d] << 16) | (state[d] >> 16);
	state[c] += state[d];
	state[b] ^= state[c];
	state[b] = (state[b] << 12) | (state[b] >> 20);
	state[a] += state[b];
	state[d] ^= state[a];
	state[d] = (state[d] << 8) | (state[d] >> 24);
	state[c] += state[d];
	state[b] ^= state[c];
	state[b] = (state[b] << 7) | (state[b] >> 25);
}

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

extern const falcon_fpr falcon_avx2_fpr_inv_sigma[FALCON_FPR_INV_SIGMA_SIZE];

extern const falcon_fpr falcon_avx2_fpr_sigma_min[FALCON_FPR_INV_SIGMA_SIZE];

extern const falcon_fpr falcon_avx2_fpr_gm_tab[FALCON_FPR_GM_TAB_SIZE];

extern const falcon_fpr falcon_avx2_fpr_p2_tab[FALCON_FPR_GM_P2_SIZE];

inline static falcon_fpr falcon_FPR(double v)
{
	falcon_fpr x = { 0 };

	x.v = v;

	return x;
}

inline static falcon_fpr falcon_fpr_of(int64_t i)
{
	return falcon_FPR((double)i);
}

inline static int64_t falcon_fpr_rint(falcon_fpr x)
{
	/*
	 * We do not want to use llrint() since it might be not
	 * constant-time.
	 *
	 * Suppose that x >= 0. If x >= 2^52, then it is already an
	 * integer. Otherwise, if x < 2^52, then computing x+2^52 will
	 * yield a value that will be rounded to the nearest integer
	 * with exactly the right rules (round-to-nearest-even).
	 *
	 * In order to have constant-time processing, we must do the
	 * computation for both x >= 0 and x < 0 cases, and use a
	 * cast to an integer to access the sign and select the proper
	 * value. Such casts also allow us to find out if |x| < 2^52.
	 */
	int64_t sx, tx, rp, rn, m;
	uint32_t ub;

	sx = (int64_t)(x.v - 1.0);
	tx = (int64_t)x.v;
	rp = (int64_t)(x.v + 4503599627370496.0) - 4503599627370496;
	rn = (int64_t)(x.v - 4503599627370496.0) + 4503599627370496;

	/*
	 * If tx >= 2^52 or tx < -2^52, then result is tx.
	 * Otherwise, if sx >= 0, then result is rp.
	 * Otherwise, result is rn. We use the fact that when x is
	 * close to 0 (|x| <= 0.25) then both rp and rn are correct;
	 * and if x is not close to 0, then trunc(x-1.0) yields the
	 * appropriate sign.
	 */

	 /*
	  * Clamp rp to zero if tx < 0.
	  * Clamp rn to zero if tx >= 0.
	  */
	m = sx >> 63;
	rn &= m;
	rp &= ~m;

	/*
	 * Get the 12 upper bits of tx; if they are not all zeros or
	 * all ones, then tx >= 2^52 or tx < -2^52, and we clamp both
	 * rp and rn to zero. Otherwise, we clamp tx to zero.
	 */
	ub = (uint32_t)((uint64_t)tx >> 52);
	m = -(int64_t)((((ub + 1) & 0xFFF) - 2) >> 31);
	rp &= m;
	rn &= m;
	tx &= ~m;

	/*
	 * Only one of tx, rn or rp (at most) can be non-zero at this
	 * point.
	 */
	return tx | rn | rp;
}

inline static int64_t falcon_fpr_floor(falcon_fpr x)
{
	int64_t r;

	/*
	 * The cast performs a trunc() (rounding toward 0) and thus is
	 * wrong by 1 for most negative values. The correction below is
	 * constant-time as long as the compiler turns the
	 * floating-point conversion result into a 0/1 integer without a
	 * conditional branch or another non-constant-time construction.
	 * This should hold on all modern architectures with an FPU (and
	 * if it is false on a given arch, then chances are that the FPU
	 * itself is not constant-time, making the point moot).
	 */
	r = (int64_t)x.v;
	return r - (x.v < (double)r);
}

inline static int64_t falcon_fpr_trunc(falcon_fpr x)
{
	return (int64_t)x.v;
}

inline static falcon_fpr falcon_fpr_add(falcon_fpr x, falcon_fpr y)
{
	return falcon_FPR(x.v + y.v);
}

inline static falcon_fpr falcon_fpr_sub(falcon_fpr x, falcon_fpr y)
{
	return falcon_FPR(x.v - y.v);
}

inline static falcon_fpr falcon_fpr_neg(falcon_fpr x)
{
	return falcon_FPR(-x.v);
}

inline static falcon_fpr falcon_fpr_half(falcon_fpr x)
{
	return falcon_FPR(x.v * 0.5);
}

inline static falcon_fpr falcon_fpr_double(falcon_fpr x)
{
	return falcon_FPR(x.v + x.v);
}

inline static falcon_fpr falcon_fpr_mul(falcon_fpr x, falcon_fpr y)
{
	return falcon_FPR(x.v * y.v);
}

inline static falcon_fpr falcon_fpr_sqr(falcon_fpr x)
{
	return falcon_FPR(x.v * x.v);
}

inline static falcon_fpr falcon_fpr_inv(falcon_fpr x)
{
	return falcon_FPR(1.0 / x.v);
}

inline static falcon_fpr falcon_fpr_div(falcon_fpr x, falcon_fpr y)
{
	return falcon_FPR(x.v / y.v);
}

inline static void falcon_fpr_sqrt_avx2(double *t)
{
	__m128d x;

	x = _mm_load1_pd(t);
	x = _mm_sqrt_pd(x);
	_mm_storel_pd(t, x);
}

inline static falcon_fpr falcon_fpr_sqrt(falcon_fpr x)
{
	/*
	 * We prefer not to have a dependency on libm when it can be
	 * avoided. On x86, calling the sqrt() libm function inlines
	 * the relevant opcode (fsqrt or sqrtsd, depending on whether
	 * the 387 FPU or SSE2 is used for floating-point operations)
	 * but then makes an optional call to the library function
	 * for proper error handling, in case the operand is negative.
	 *
	 * To avoid this dependency, we use intrinsics or inline assembly
	 * on recognized platforms:
	 *
	 *  - If AVX2 is explicitly enabled, then we use SSE2 intrinsics.
	 *
	 *  - On GCC/Clang with SSE maths, we use SSE2 intrinsics.
	 *
	 *  - On GCC/Clang on i386, or MSVC on i386, we use inline assembly
	 *    to call the 387 FPU fsqrt opcode.
	 *
	 *  - On GCC/Clang/XLC on PowerPC, we use inline assembly to call
	 *    the fsqrt opcode (Clang needs a special hack).
	 *
	 *  - On GCC/Clang on ARM with hardware floating-point, we use
	 *    inline assembly to call the vqsrt.f64 opcode. Due to a
	 *    complex ecosystem of compilers and assembly syntaxes, we
	 *    have to call it "fsqrt" or "fsqrtd", depending on case.
	 *
	 * If the platform is not recognized, a call to the system
	 * library function sqrt() is performed. On some compilers, this
	 * may actually inline the relevant opcode, and call the library
	 * function only when the input is invalid (e.g. negative);
	 * Falcon never actually calls sqrt() on a negative value, but
	 * the dependency to libm will still be there.
	 */

	falcon_fpr_sqrt_avx2(&x.v);

	return x;
}

inline static int32_t falcon_fpr_lt(falcon_fpr x, falcon_fpr y)
{
	return x.v < y.v;
}

inline static uint64_t falcon_fpr_expm_p63(falcon_fpr x, falcon_fpr ccs)
{
	/*
	 * Polynomial approximation of exp(-x) is taken from FACCT:
	 *   https://eprint.iacr.org/2018/1234
	 * Specifically, values are extracted from the implementation
	 * referenced from the FACCT article, and available at:
	 *   https://github.com/raykzhao/gaussian
	 * Tests over more than 24 billions of random inputs in the
	 * 0..log(2) range have never shown a deviation larger than
	 * 2^(-50) from the true mathematical value.
	 */

	 /*
	  * AVX2 implementation uses more operations than Horner's method,
	  * but with a lower expression tree depth. This helps because
	  * additions and multiplications have a latency of 4 cycles on
	  * a Skylake, but the CPU can issue two of them per cycle.
	  */

	static const union 
	{
		double d[12];
		__m256d v[3];
	} c = {
		{
			0.999999999999994892974086724280,
			0.500000000000019206858326015208,
			0.166666666666984014666397229121,
			0.041666666666110491190622155955,
			0.008333333327800835146903501993,
			0.001388888894063186997887560103,
			0.000198412739277311890541063977,
			0.000024801566833585381209939524,
			0.000002755586350219122514855659,
			0.000000275607356160477811864927,
			0.000000025299506379442070029551,
			0.000000002073772366009083061987
		}
	};

	__m256d d14;
	__m256d d58;
	__m256d d9c;
	double d1;
	double d2;
	double d4;
	double d8;
	double y;

	d1 = -x.v;
	d2 = d1 * d1;
	d4 = d2 * d2;
	d8 = d4 * d4;
	d14 = _mm256_set_pd(d4, d2 * d1, d2, d1);
	d58 = _mm256_mul_pd(d14, _mm256_set1_pd(d4));
	d9c = _mm256_mul_pd(d14, _mm256_set1_pd(d8));
	d14 = _mm256_mul_pd(d14, _mm256_loadu_pd(&c.d[0]));
	d58 = falcon_fmadd(d58, _mm256_loadu_pd(&c.d[4]), d14);
	d9c = falcon_fmadd(d9c, _mm256_loadu_pd(&c.d[8]), d58);
	d9c = _mm256_hadd_pd(d9c, d9c);
	y = 1.0 + _mm_cvtsd_f64(_mm256_castpd256_pd128(d9c)) + _mm_cvtsd_f64(_mm256_extractf128_pd(d9c, 1));
	y *= ccs.v;

	/*
	 * Final conversion goes through int64_t first, because that's what
	 * the underlying opcode (vcvttsd2si) will do, and we know that the
	 * result will fit, since x >= 0 and ccs < 1. If we did the
	 * conversion directly to uint64_t, then the compiler would add some
	 * extra code to cover the case of a source value of 2^63 or more,
	 * and though the alternate path would never be exercised, the
	 * extra comparison would cost us some cycles.
	 */
	return (uint64_t)(int64_t)(y * falcon_fpr_ptwo63.v);

}

inline static size_t falcon_mkn(uint32_t logn)
{
	return ((size_t)1 << logn);
}

/* fft.c */

inline static void falcon_fpc_add(falcon_fpr* d_re, falcon_fpr* d_im, falcon_fpr a_re, falcon_fpr a_im, falcon_fpr b_re, falcon_fpr b_im)
{
	falcon_fpr fpct_re;
	falcon_fpr fpct_im;

	fpct_re = falcon_fpr_add(a_re, b_re);
	fpct_im = falcon_fpr_add(a_im, b_im);
	*d_re = fpct_re;
	*d_im = fpct_im;
}

inline static void falcon_fpc_sub(falcon_fpr* d_re, falcon_fpr* d_im, falcon_fpr a_re, falcon_fpr a_im, falcon_fpr b_re, falcon_fpr b_im)
{
	falcon_fpr fpct_re;
	falcon_fpr fpct_im;

	fpct_re = falcon_fpr_sub(a_re, b_re);
	fpct_im = falcon_fpr_sub(a_im, b_im);
	*d_re = fpct_re;
	*d_im = fpct_im;
}

inline static void falcon_fpc_mul(falcon_fpr* d_re, falcon_fpr* d_im, falcon_fpr a_re, falcon_fpr a_im, falcon_fpr b_re, falcon_fpr b_im)
{
	falcon_fpr fpct_a_re;
	falcon_fpr fpct_a_im;
	falcon_fpr fpct_b_re;
	falcon_fpr fpct_b_im;
	falcon_fpr fpct_d_re;
	falcon_fpr fpct_d_im;

	fpct_a_re = a_re;
	fpct_a_im = a_im;
	fpct_b_re = b_re;
	fpct_b_im = b_im;
	fpct_d_re = falcon_fpr_sub(falcon_fpr_mul(fpct_a_re, fpct_b_re), falcon_fpr_mul(fpct_a_im, fpct_b_im));
	fpct_d_im = falcon_fpr_add(falcon_fpr_mul(fpct_a_re, fpct_b_im), falcon_fpr_mul(fpct_a_im, fpct_b_re));
	*d_re = fpct_d_re;
	*d_im = fpct_d_im;
}

inline static void falcon_fpc_div(falcon_fpr* d_re, falcon_fpr* d_im, falcon_fpr a_re, falcon_fpr a_im, falcon_fpr b_re, falcon_fpr b_im)
{
	falcon_fpr fpct_a_re;
	falcon_fpr fpct_a_im;
	falcon_fpr fpct_b_re;
	falcon_fpr fpct_b_im;
	falcon_fpr fpct_d_re;
	falcon_fpr fpct_d_im;
	falcon_fpr fpct_m;

	fpct_a_re = a_re;
	fpct_a_im = a_im;
	fpct_b_re = b_re;
	fpct_b_im = b_im;
	fpct_m = falcon_fpr_add(falcon_fpr_sqr(fpct_b_re), falcon_fpr_sqr(fpct_b_im));
	fpct_m = falcon_fpr_inv(fpct_m);
	fpct_b_re = falcon_fpr_mul(fpct_b_re, fpct_m);
	fpct_b_im = falcon_fpr_mul(falcon_fpr_neg(fpct_b_im), fpct_m);
	fpct_d_re = falcon_fpr_sub(falcon_fpr_mul(fpct_a_re, fpct_b_re), falcon_fpr_mul(fpct_a_im, fpct_b_im));
	fpct_d_im = falcon_fpr_add(falcon_fpr_mul(fpct_a_re, fpct_b_im), falcon_fpr_mul(fpct_a_im, fpct_b_re));
	*d_re = fpct_d_re;
	*d_im = fpct_d_im;
}

/* codec.c */

extern const uint8_t falcon_avx2_max_fg_bits[FALCON_MAXBITS_SIZE];
extern const uint8_t falcon_falcon_max_FG_bits[FALCON_MAXBITS_SIZE];

/* sign.c */

typedef struct
{
	falcon_prng_state p;
	falcon_fpr sigma_min;
} falcon_sampler_context;

typedef int32_t(*falcon_samplerZ)(void* ctx, falcon_fpr mu, falcon_fpr sigma);

inline static uint32_t falcon_ffLDL_treesize(uint32_t logn)
{
	/*
	* Get the size of the LDL tree for an input with polynomials of size
	* 2^logn. The size is expressed in the number of elements.
	* For logn = 0 (polynomials are constant), the "tree" is a
	* single element. Otherwise, the tree node has size 2^logn, and
	* has two child trees for size logn-1 each. Thus, treesize s()
	* must fulfill these two relations:
	*
	*   s(0) = 1
	*   s(logn) = (2^logn) + 2*s(logn-1)
	*/

	return (logn + 1) << logn;
}

inline static size_t falcon_skoff_b00(uint32_t logn)
{
	(void)logn;
	return 0;
}

inline static size_t falcon_skoff_b01(uint32_t logn)
{
	return falcon_mkn(logn);
}

inline static size_t falcon_skoff_b10(uint32_t logn)
{
	return 2 * falcon_mkn(logn);
}

inline static size_t falcon_skoff_b11(uint32_t logn)
{
	return 3 * falcon_mkn(logn);
}

inline static size_t falcon_skoff_tree(uint32_t logn)
{
	return 4 * falcon_mkn(logn);
}

/* keygen.c */

extern const uint32_t falcon_avx2_l2bound[FALCON_L2BOUND_SIZE];

extern const uint64_t falcon_avx2_gauss_1024_12289[FALCON_GAUS_1024_12289_SIZE];

extern const uint16_t falcon_avx2_falcon_rev10[FALCON_REV10_SIZE];

extern const size_t falcon_avx2_max_bl_small[FALCON_MAX_BL_SMALL_SIZE];

extern const size_t falcon_avx2_max_bl_large[FALCON_MAX_BL_LARGE_SIZE];

/*
 * Average and standard deviation for the maximum size (in bits) of
 * coefficients of (f,g), depending on depth. These values are used
 * to compute bounds for Babai's reduction.
 */
static const struct {
	int32_t avg;
	int32_t std;
} falcon_bit_length[] = {
	{    4,  0 },
	{   11,  1 },
	{   24,  1 },
	{   50,  1 },
	{  102,  1 },
	{  202,  2 },
	{  401,  4 },
	{  794,  5 },
	{ 1577,  8 },
	{ 3138, 13 },
	{ 6308, 25 }
};

inline static uint32_t falcon_modp_set(int32_t x, uint32_t p)
{
	/*
	* Reduce a small signed integer modulo a small prime. The source
	* value x MUST be such that -p < x < p.
	*/

	uint32_t w;

	w = (uint32_t)x;
	w += p & (uint32_t)-(int32_t)(w >> 31);
	return w;
}

inline static int32_t falcon_modp_norm(uint32_t x, uint32_t p)
{
	/*
	* Normalize a modular integer around 0.
	*/

	return (int32_t)(x - (p & (((x - ((p + 1) >> 1)) >> 31) - 1)));
}

inline static uint32_t falcon_modp_ninv31(uint32_t p)
{
	/*
	* Compute -1/p mod 2^31. This works for all odd integers p that fit on 31 bits.
	*/
	uint32_t y;

	y = 2 - p;
	y *= 2 - p * y;
	y *= 2 - p * y;
	y *= 2 - p * y;
	y *= 2 - p * y;

	return (uint32_t)0x7FFFFFFFUL & (uint32_t)-(int32_t)y;
}

inline static uint32_t falcon_modp_R(uint32_t p)
{
	/*
	* Since 2^30 < p < 2^31, we know that 2^31 mod p is simply 2^31 - p.
	*/

	return ((uint32_t)1 << 31) - p;
}

inline static uint32_t falcon_modp_add(uint32_t a, uint32_t b, uint32_t p)
{
	/*
	* Addition modulo p.
	*/

	uint32_t d;

	d = a + b - p;
	d += p & (uint32_t)-(int32_t)(d >> 31);

	return d;
}

inline static uint32_t falcon_modp_sub(uint32_t a, uint32_t b, uint32_t p)
{
	/*
	* Subtraction modulo p.
	*/

	uint32_t d;

	d = a - b;
	d += p & (uint32_t)-(int32_t)(d >> 31);

	return d;
}

inline static uint32_t falcon_modp_montymul(uint32_t a, uint32_t b, uint32_t p, uint32_t p0i)
{
	/*
	* Montgomery multiplication modulo p. The 'p0i' value is -1/p mod 2^31.
	* It is required that p is an odd integer.
	*/

	uint64_t w;
	uint64_t z;
	uint32_t d;

	z = (uint64_t)a * (uint64_t)b;
	w = ((z * p0i) & (uint64_t)0x7FFFFFFF) * p;
	d = (uint32_t)((z + w) >> 31) - p;
	d += p & (uint32_t)-(int32_t)(d >> 31);

	return d;
}

/* verify.c */

typedef struct
{
	uint32_t p;
	uint32_t g;
	uint32_t s;
} falcon_small_prime;

extern const uint16_t falcon_avx2_GMb[FALCON_GMB_SIZE];

extern const uint16_t falcon_avx2_iGMb[FALCON_GMB_SIZE];

extern const falcon_small_prime falcon_avx2_small_primes[FALCON_SMALL_PRIME_SIZE];

inline static uint32_t falcon_mq_conv_small(int32_t x)
{
	/*
	* Reduce a small signed integer modulo q. The source integer MUST
	* be between -q/2 and +q/2.
	* If x < 0, the cast to uint32_t will set the high bit to 1.
	*/
	uint32_t y;

	y = (uint32_t)x;
	y += FALCON_Q & (uint32_t)-(int32_t)(y >> 31);

	return y;
}

inline static uint32_t falcon_mq_add(uint32_t x, uint32_t y)
{
	/*
	 * Addition modulo q. Operands must be in the 0..q-1 range.
	* We compute x + y - q. If the result is negative, then the
	* high bit will be set, and 'd >> 31' will be equal to 1;
	* thus '-(d >> 31)' will be an all-one pattern. Otherwise,
	* it will be an all-zero pattern. In other words, this
	* implements a conditional addition of q.
	*/
	uint32_t d;

	d = x + y - FALCON_Q;
	d += FALCON_Q & (uint32_t)-(int32_t)(d >> 31);

	return d;
}

inline static uint32_t falcon_mq_sub(uint32_t x, uint32_t y)
{
	/*
	* Subtraction modulo q. Operands must be in the 0..q-1 range.
	* As in falcon_mq_add(), we use a conditional addition to ensure the
	* result is in the 0..q-1 range.
	*/

	uint32_t d;

	d = x - y;
	d += FALCON_Q & (uint32_t)-(int32_t)(d >> 31);

	return d;
}

inline static uint32_t falcon_mq_rshift1(uint32_t x)
{
	/*
	* Division by 2 modulo q. Operand must be in the 0..q-1 range.
	*/

	x += FALCON_Q & (uint32_t)-(int32_t)(x & 1);
	return (x >> 1);
}

inline static uint32_t falcon_mq_montymul(uint32_t x, uint32_t y)
{
	/*
	* Montgomery multiplication modulo q. If we set R = 2^16 mod q, then
	* this function computes: x * y / R mod q
	* Operands must be in the 0..q-1 range.
	*/

	uint32_t w;
	uint32_t z;

	/*
	 * We compute x*y + k*q with a value of k chosen so that the 16
	 * low bits of the result are 0. We can then shift the value.
	 * After the shift, result may still be larger than q, but it
	 * will be lower than 2*q, so a conditional subtraction works.
	 */

	z = x * y;
	w = ((z * FALCON_Q0I) & 0x0000FFFFUL) * FALCON_Q;

	/*
	 * When adding z and w, the result will have its low 16 bits
	 * equal to 0. Since x, y and z are lower than q, the sum will
	 * be no more than (2^15 - 1) * q + (q - 1)^2, which will
	 * fit on 29 bits.
	 */
	z = (z + w) >> 16;

	/*
	 * After the shift, analysis shows that the value will be less
	 * than 2q. We do a subtraction then conditional subtraction to
	 * ensure the result is in the expected range.
	 */
	z -= FALCON_Q;
	z += FALCON_Q & (uint32_t)-(int32_t)(z >> 31);
	return z;
}

inline static uint32_t falcon_mq_montysqr(uint32_t x)
{
	/*
	* Montgomery squaring (computes (x^2)/R).
	*/

	return falcon_mq_montymul(x, x);
}


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
bool qsc_falcon_avx2_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif
/* \endcond DOXYGEN_IGNORE */
#endif
