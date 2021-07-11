#ifndef QSC_FALCONBASE_H
#define QSC_FALCONBASE_H

#include "common.h"

/* api.h */

#if defined(QSC_FALCON_S3SHAKE256F512)
#	define FALCON_CRYPTO_SECRETKEYBYTES 1281
#	define FALCON_CRYPTO_PUBLICKEY_BYTES 897
#	define FALCON_CRYPTO_SIGNATURE_BYTES 690
#elif defined(QSC_FALCON_S5SHAKE256F1024)
#	define FALCON_CRYPTO_SECRETKEYBYTES 2305
#	define FALCON_CRYPTO_PUBLICKEY_BYTES 1793
#	define FALCON_CRYPTO_SIGNATURE_BYTES 1330
#endif

/* fpr.h */

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

/* fpr.c */

typedef uint64_t falcon_fpr;

static const falcon_fpr falcon_fpr_q = 4667981563525332992;
static const falcon_fpr falcon_fpr_inverse_of_q = 4545632735260551042;
static const falcon_fpr falcon_fpr_inv_2sqrsigma0 = 4594603506513722306;
static const falcon_fpr falcon_fpr_log2 = 4604418534313441775;
static const falcon_fpr falcon_fpr_inv_log2 = 4609176140021203710;
static const falcon_fpr falcon_fpr_bnorm_max = 4670353323383631276;
static const falcon_fpr falcon_fpr_zero = 0;
static const falcon_fpr falcon_fpr_one = 4607182418800017408;
static const falcon_fpr falcon_fpr_two = 4611686018427387904;
static const falcon_fpr falcon_fpr_onehalf = 4602678819172646912;
static const falcon_fpr falcon_fpr_invsqrt2 = 4604544271217802189;
static const falcon_fpr falcon_fpr_invsqrt8 = 4600040671590431693;
static const falcon_fpr falcon_fpr_ptwo31 = 4746794007248502784;
static const falcon_fpr falcon_fpr_ptwo31m1 = 4746794007244308480;
static const falcon_fpr falcon_fpr_mtwo31m1 = 13970166044099084288U;
static const falcon_fpr falcon_fpr_ptwo63m1 = 4890909195324358656;
static const falcon_fpr falcon_fpr_mtwo63m1 = 14114281232179134464U;
static const falcon_fpr falcon_fpr_ptwo63 = 4890909195324358656;

typedef struct
{
	uint32_t p;
	uint32_t g;
	uint32_t s;
} falcon_small_prime;

extern const falcon_fpr falcon_fpr_inv_sigma[FALCON_FPR_INV_SIGMA_SIZE];

extern const falcon_fpr falcon_fpr_sigma_min[FALCON_FPR_INV_SIGMA_SIZE];

extern const falcon_fpr falcon_fpr_gm_tab[FALCON_FPR_GM_TAB_SIZE];

extern const falcon_fpr falcon_fpr_p2_tab[FALCON_FPR_GM_P2_SIZE];

inline static uint64_t falcon_fpr_ursh(uint64_t x, int32_t n)
{
	/*
	* Right-shift a 64-bit uint32_t value by a possibly secret shift count.
	* We assumed that the underlying architecture had a barrel shifter for
	* 32-bit shifts, but for 64-bit shifts on a 32-bit system, this will
	* typically invoke a software routine that is not necessarily
	* constant-time; hence the function below.
	*
	* Shift count n MUST be in the 0..63 range.
	*/

	x ^= (x ^ (x >> 32)) & (uint64_t)-(int64_t)(n >> 5);

	return x >> (n & 31);
}

inline static int64_t falcon_fpr_irsh(int64_t x, int32_t n)
{
	/*
	 * Right-shift a 64-bit signed value by a possibly secret shift count
	 * (see falcon_fpr_ursh() for the rationale).
	 *
	 * Shift count n MUST be in the 0..63 range.
	 */

	x ^= (x ^ (x >> 32)) & -(int64_t)(n >> 5);

	return x >> (n & 31);
}

inline static uint64_t falcon_fpr_ulsh(uint64_t x, int32_t n)
{
	/*
	* Left-shift a 64-bit uint32_t value by a possibly secret shift count
	* (see falcon_fpr_ursh() for the rationale).
	*
	* Shift count n MUST be in the 0..63 range.
	*/

	x ^= (x ^ (x << 32)) & (uint64_t)-(int64_t)(n >> 5);

	return x << (n & 31);
}

inline static falcon_fpr falcon_FPR(int32_t s, int32_t e, uint64_t m)
{
	/*
	 * Expectations:
	 *   s = 0 or 1
	 *   exponent e is "arbitrary" and unbiased
	 *   2^54 <= m < 2^55
	 * Numerical value is (-1)^2 * m * 2^e
	 *
	 * Exponents which are too low lead to value zero. If the exponent is
	 * too large, the returned value is indeterminate.
	 *
	 * If m = 0, then a zero is returned (using the provided sign).
	 * If e < -1076, then a zero is returned (regardless of the value of m).
	 * If e >= -1076 and e != 0, m must be within the expected range
	 * (2^54 to 2^55-1).
	 */

	falcon_fpr x;
	uint32_t t;
	uint32_t f;

	/*
	 * If e >= -1076, then the value is "normal"; otherwise, it
	 * should be a subnormal, which we clamp down to zero.
	 */
	e += 1076;
	t = (uint32_t)e >> 31;
	m &= (uint64_t)t - 1;

	/*
	 * If m = 0 then we want a zero; make e = 0 too, but conserve
	 * the sign.
	 */
	t = (uint32_t)(m >> 54);
	e &= -(int32_t)t;

	/*
	 * The 52 mantissa bits come from m. Value m has its top bit set
	 * (unless it is a zero); we leave it "as is": the top bit will
	 * increment the exponent by 1, except when m = 0, which is
	 * exactly what we want.
	 */
	x = (((uint64_t)s << 63) | (m >> 2)) + ((uint64_t)(uint32_t)e << 52);

	/*
	 * Rounding: if the low three bits of m are 011, 110 or 111,
	 * then the value should be incremented to get the next
	 * representable value. This implements the usual
	 * round-to-nearest rule (with preference to even values in case
	 * of a tie). Note that the increment may make a carry spill
	 * into the exponent field, which is again exactly what we want
	 * in that case.
	 */
	f = (uint32_t)m & 7U;
	x += (0x0000000000000C8ULL >> f) & 1;

	return x;
}

inline static falcon_fpr falcon_fpr_neg(falcon_fpr x)
{
	x ^= (uint64_t)1 << 63;

	return x;
}

inline static falcon_fpr falcon_fpr_half(falcon_fpr x)
{
	/*
	 * To divide a value by 2, we just have to subtract 1 from its
	 * exponent, but we have to take care of zero.
	 */
	uint32_t t;

	x -= (uint64_t)1 << 52;
	t = (((uint32_t)(x >> 52) & 0x000007FFUL) + 1) >> 11;
	x &= (uint64_t)t - 1;

	return x;
}

inline static int64_t falcon_fpr_rint(falcon_fpr x)
{
	uint64_t d;
	uint64_t m;
	uint32_t dd;
	uint32_t f;
	uint32_t s;
	int32_t e;

	/*
	 * We assume that the value fits in -(2^63-1)..+(2^63-1). We can
	 * thus extract the mantissa as a 63-bit integer, then right-shift
	 * it as needed.
	 */
	m = ((x << 10) | ((uint64_t)1 << 62)) & (((uint64_t)1 << 63) - 1);
	e = 1085 - ((int32_t)(x >> 52) & 0x000007FFUL);

	/*
	 * If a shift of more than 63 bits is needed, then simply set m
	 * to zero. This also covers the case of an input operand equal
	 * to zero.
	 */
	m &= ~(uint64_t)((uint32_t)(e - 64) >> 31) + 1;
	e &= 63;

	/*
	 * Right-shift m as needed. Shift count is e. Proper rounding
	 * mandates that:
	 *   - If the highest dropped bit is zero, then round low.
	 *   - If the highest dropped bit is one, and at least one of the
	 *     other dropped bits is one, then round up.
	 *   - If the highest dropped bit is one, and all other dropped
	 *     bits are zero, then round up if the lowest kept bit is 1,
	 *     or low otherwise (i.e. ties are broken by "rounding to even").
	 *
	 * We thus first extract a word consisting of all the dropped bit
	 * AND the lowest kept bit; then we shrink it down to three bits,
	 * the lowest being "sticky".
	 */
	d = falcon_fpr_ulsh(m, 63 - e);
	dd = (uint32_t)d | ((uint32_t)(d >> 32) & 0x1FFFFFFFULL);
	f = (uint32_t)(d >> 61) | ((dd | (uint32_t)-(int32_t)dd) >> 31);
	m = falcon_fpr_ursh(m, e) + (uint64_t)((0x0000000000000C8ULL >> f) & 1U);

	/*
	 * Apply the sign bit.
	 */
	s = (uint32_t)(x >> 63);

	return ((int64_t)m ^ -(int64_t)s) + (int64_t)s;
}

inline static int64_t falcon_fpr_floor(falcon_fpr x)
{
	uint64_t t;
	int64_t xi;
	int32_t e;
	int32_t cc;

	/*
	 * We extract the integer as a _signed_ 64-bit integer with
	 * a scaling factor. Since we assume that the value fits
	 * in the -(2^63-1)..+(2^63-1) range, we can left-shift the
	 * absolute value to make it in the 2^62..2^63-1 range: we
	 * will only need a right-shift afterwards.
	 */
	e = (int32_t)(x >> 52) & 0x000007FFL;
	t = x >> 63;
	xi = (int64_t)(((x << 10) | ((uint64_t)1 << 62)) & (((uint64_t)1 << 63) - 1));
	xi = (xi ^ -(int64_t)t) + (int64_t)t;
	cc = 1085 - e;

	/*
	 * We perform an arithmetic right-shift on the value. This
	 * applies floor() semantics on both positive and negative values
	 * (rounding toward minus infinity).
	 */
	xi = falcon_fpr_irsh(xi, cc & 63);

	/*
	 * If the true shift count was 64 or more, then we should instead
	 * replace xi with 0 (if nonnegative) or -1 (if negative). Edge
	 * case: -0 will be floored to -1, not 0 (whether this is correct
	 * is debatable; in any case, the other functions normalize zero
	 * to +0).
	 *
	 * For an input of zero, the non-shifted xi was incorrect (we used
	 * a top implicit bit of value 1, not 0), but this does not matter
	 * since this operation will clamp it down.
	 */
	xi ^= (xi ^ -(int64_t)t) & -(int64_t)((uint32_t)(63 - cc) >> 31);

	return xi;
}

inline static int64_t falcon_fpr_trunc(falcon_fpr x)
{
	uint64_t t;
	uint64_t xu;
	int32_t cc;
	int32_t e;

	/*
	 * Extract the absolute value. Since we assume that the value
	 * fits in the -(2^63-1)..+(2^63-1) range, we can left-shift
	 * the absolute value into the 2^62..2^63-1 range, and then
	 * do a right shift afterwards.
	 */
	e = (int32_t)(x >> 52) & 0x000007FFL;
	xu = ((x << 10) | ((uint64_t)1 << 62)) & (((uint64_t)1 << 63) - 1);
	cc = 1085 - e;
	xu = falcon_fpr_ursh(xu, cc & 63);

	/*
	 * If the exponent is too low (cc > 63), then the shift was wrong
	 * and we must clamp the value to 0. This also covers the case
	 * of an input equal to zero.
	 */
	xu &= ~(uint64_t)((uint32_t)(cc - 64) >> 31) + 1;

	/*
	 * Apply back the sign, if the source value is negative.
	 */
	t = x >> 63;
	xu = (xu ^ (~t + 1)) + t;

	return *(int64_t *)&xu;
}

inline static int32_t falcon_fpr_lt(falcon_fpr x, falcon_fpr y)
{
	/*
	 * If x >= 0 or y >= 0, a signed comparison yields the proper
	 * result:
	 *   - For positive values, the order is preserved.
	 *   - The sign bit is at the same place as in integers, so
	 *     sign is preserved.
	 *
	 * If both x and y are negative, then the order is reversed.
	 * We cannot simply invert the comparison result in that case
	 * because it would not handle the edge case x = y properly.
	 */
	int32_t cc0, cc1;

	cc0 = *(int64_t *)&x < *(int64_t*)&y;
	cc1 = *(int64_t *)&x > *(int64_t*)&y;

	return cc0 ^ ((cc0 ^ cc1) & (int32_t)((x & y) >> 63));
}

inline static falcon_fpr_norm64(uint64_t* m, int32_t* e)
{
	uint32_t nt;

	*e -= 63;
	nt = (uint32_t)(*m >> 32);
	nt = (nt | (uint32_t)-(int32_t)nt) >> 31;
	*m ^= (*m ^ (*m << 32)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt << 5);

	nt = (uint32_t)(*m >> 48);
	nt = (nt | (uint32_t)-(int32_t)nt) >> 31;
	*m ^= (*m ^ (*m << 16)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt << 4);

	nt = (uint32_t)(*m >> 56);
	nt = (nt | (uint32_t)-(int32_t)nt) >> 31;
	*m ^= (*m ^ (*m << 8)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt << 3);

	nt = (uint32_t)(*m >> 60);
	nt = (nt | (uint32_t)-(int32_t)nt) >> 31;
	*m ^= (*m ^ (*m << 4)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt << 2);

	nt = (uint32_t)(*m >> 62);
	nt = (nt | (uint32_t)-(int32_t)nt) >> 31;
	*m ^= (*m ^ (*m << 2)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt << 1);

	nt = (uint32_t)(*m >> 63);
	*m ^= (*m ^ (*m << 1)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt);
}

inline static falcon_fpr falcon_fpr_scaled(int64_t i, int32_t sc)
{
	/*
	 * To convert from int32_t to float, we have to do the following:
	 *  1. Get the absolute value of the input, and its sign
	 *  2. Shift right or left the value as appropriate
	 *  3. Pack the result
	 *
	 * We can assume that the source integer is not -2^63.
	 */

	uint64_t m;
	uint32_t t;
	int32_t e;
	int32_t s;

	/*
	 * Extract sign bit.
	 * We have: -i = 1 + ~i
	 */
	s = (int32_t)((uint64_t)i >> 63);
	i ^= -(int64_t)s;
	i += s;

	/*
	 * For now we suppose that i != 0.
	 * Otherwise, we set m to i and left-shift it as much as needed
	 * to get a 1 in the top bit. We can do that in a logarithmic
	 * number of conditional shifts.
	 */
	m = (uint64_t)i;
	e = 9 + sc;
	falcon_fpr_norm64(&m, &e);

	/*
	 * Now m is in the 2^63..2^64-1 range. We must divide it by 512;
	 * if one of the dropped bits is a 1, this should go into the
	 * "sticky bit".
	 */
	m |= ((uint32_t)m & 0x000001FFUL) + 0x000001FFUL;
	m >>= 9;

	/*
	 * Corrective action: if i = 0 then all of the above was
	 * incorrect, and we clamp e and m down to zero.
	 */
	t = (uint32_t)((uint64_t)(i | -i) >> 63);
	m &= (uint64_t)-(int64_t)t;
	e &= -(int32_t)t;

	/*
	 * Assemble back everything. The falcon_FPR() function will handle cases
	 * where e is too low.
	 */
	return falcon_FPR(s, e, m);
}

inline static falcon_fpr falcon_fpr_of(int64_t i)
{
	return falcon_fpr_scaled(i, 0);
}

inline static falcon_fpr falcon_fpr_add(falcon_fpr x, falcon_fpr y)
{
	uint64_t m;
	uint64_t xu;
	uint64_t yu;
	uint64_t za;
	uint32_t cs;
	int32_t cc;
	int32_t ex;
	int32_t ey;
	int32_t sx;
	int32_t sy;

	/*
	 * Make sure that the first operand (x) has the larger absolute
	 * value. This guarantees that the exponent of y is less than
	 * or equal to the exponent of x, and, if they are equal, then
	 * the mantissa of y will not be greater than the mantissa of x.
	 *
	 * After this swap, the result will have the sign x, except in
	 * the following edge case: abs(x) = abs(y), and x and y have
	 * opposite sign bits; in that case, the result shall be +0
	 * even if the sign bit of x is 1. To handle this case properly,
	 * we do the swap is abs(x) = abs(y) AND the sign of x is 1.
	 */
	m = ((uint64_t)1 << 63) - 1;
	za = (x & m) - (y & m);
	cs = (uint32_t)(za >> 63) | ((1U - (uint32_t)(-(int64_t)za >> 63)) & (uint32_t)(x >> 63));
	m = (x ^ y) & (uint64_t)-(int64_t)cs;
	x ^= m;
	y ^= m;

	/*
	 * Extract sign bits, exponents and mantissas. The mantissas are
	 * scaled up to 2^55..2^56-1, and the exponent is unbiased. If
	 * an operand is zero, its mantissa is set to 0 at this step, and
	 * its exponent will be -1078.
	 */
	ex = (int32_t)(x >> 52);
	sx = ex >> 11;
	ex &= 0x000007FFL;
	m = (uint64_t)(uint32_t)((ex + 0x000007FFL) >> 11) << 52;
	xu = ((x & (((uint64_t)1 << 52) - 1)) | m) << 3;
	ex -= 1078;
	ey = (int32_t)(y >> 52);
	sy = ey >> 11;
	ey &= 0x000007FFL;
	m = (uint64_t)(uint32_t)((ey + 0x000007FFL) >> 11) << 52;
	yu = ((y & (((uint64_t)1 << 52) - 1)) | m) << 3;
	ey -= 1078;

	/*
	 * x has the larger exponent; hence, we only need to right-shift y.
	 * If the shift count is larger than 59 bits then we clamp the
	 * value to zero.
	 */
	cc = ex - ey;
	yu &= (uint64_t)-(int64_t)((uint32_t)(cc - 60) >> 31);
	cc &= 63;

	/*
	 * The lowest bit of yu is "sticky".
	 */
	m = falcon_fpr_ulsh(1, cc) - 1;
	yu |= (yu & m) + m;
	yu = falcon_fpr_ursh(yu, cc);

	/*
	 * If the operands have the same sign, then we add the mantissas;
	 * otherwise, we subtract the mantissas.
	 */
	xu += yu - ((yu << 1) & (uint64_t)-(int64_t)(sx ^ sy));

	/*
	 * The result may be smaller, or slightly larger. We normalize
	 * it to the 2^63..2^64-1 range (if xu is zero, then it stays
	 * at zero).
	 */
	falcon_fpr_norm64(&xu, &ex);

	/*
	 * Scale down the value to 2^54..s^55-1, handling the last bit
	 * as sticky.
	 */
	xu |= ((uint32_t)xu & 0x000001FFUL) + 0x000001FFUL;
	xu >>= 9;
	ex += 9;

	/*
	 * In general, the result has the sign of x. However, if the
	 * result is exactly zero, then the following situations may
	 * be encountered:
	 *   x > 0, y = -x   -> result should be +0
	 *   x < 0, y = -x   -> result should be +0
	 *   x = +0, y = +0  -> result should be +0
	 *   x = -0, y = +0  -> result should be +0
	 *   x = +0, y = -0  -> result should be +0
	 *   x = -0, y = -0  -> result should be -0
	 *
	 * But at the conditional swap step at the start of the
	 * function, we ensured that if abs(x) = abs(y) and the
	 * sign of x was 1, then x and y were swapped. Thus, the
	 * two following cases cannot actually happen:
	 *   x < 0, y = -x
	 *   x = -0, y = +0
	 * In all other cases, the sign bit of x is conserved, which
	 * is what the falcon_FPR() function does. The falcon_FPR() function also
	 * properly clamps values to zero when the exponent is too
	 * low, but does not alter the sign in that case.
	 */
	return falcon_FPR(sx, ex, xu);
}

inline  falcon_fpr falcon_fpr_mul(falcon_fpr x, falcon_fpr y)
{
	uint64_t xu;
	uint64_t yu;
	uint64_t w;
	uint64_t zu;
	uint64_t zv;
	uint64_t x1;
	uint64_t y0;
	uint64_t y1;
	uint64_t z0;
	uint64_t z1;
	uint64_t z2;
	uint32_t x0;
	int32_t ex;
	int32_t ey;
	int32_t d;
	int32_t e;
	int32_t s;

	/*
	 * Extract absolute values as scaled uint32_t integers. We
	 * don't extract exponents yet.
	 */
	xu = (x & (((uint64_t)1 << 52) - 1)) | ((uint64_t)1 << 52);
	yu = (y & (((uint64_t)1 << 52) - 1)) | ((uint64_t)1 << 52);

	/*
	 * We have two 53-bit integers to multiply; we need to split
	 * each into a lower half and a upper half. Moreover, we
	 * prefer to have lower halves to be of 25 bits each, for
	 * reasons explained later on.
	 */
	x0 = (uint32_t)xu & 0x01FFFFFFUL;
	x1 = (uint32_t)(xu >> 25);
	y0 = (uint32_t)yu & 0x01FFFFFFUL;
	y1 = (uint32_t)(yu >> 25);
	w = (uint64_t)x0 * (uint64_t)y0;
	z0 = (uint32_t)w & 0x01FFFFFFUL;
	z1 = (uint32_t)(w >> 25);
	w = (uint64_t)x0 * (uint64_t)y1;
	z1 += (uint32_t)w & 0x01FFFFFFUL;
	z2 = (uint32_t)(w >> 25);
	w = (uint64_t)x1 * (uint64_t)y0;
	z1 += (uint32_t)w & 0x01FFFFFFUL;
	z2 += (uint32_t)(w >> 25);
	zu = (uint64_t)x1 * (uint64_t)y1;
	z2 += (z1 >> 25);
	z1 &= 0x01FFFFFFUL;
	zu += z2;

	/*
	 * Since xu and yu are both in the 2^52..2^53-1 range, the
	 * product is in the 2^104..2^106-1 range. We first reassemble
	 * it and round it into the 2^54..2^56-1 range; the bottom bit
	 * is made "sticky". Since the low limbs z0 and z1 are 25 bits
	 * each, we just take the upper part (zu), and consider z0 and
	 * z1 only for purposes of stickiness.
	 * (This is the reason why we chose 25-bit limbs above.)
	 */
	zu |= ((z0 | z1) + 0x01FFFFFFUL) >> 25;

	/*
	 * We normalize zu to the 2^54..s^55-1 range: it could be one
	 * bit too large at this point. This is done with a conditional
	 * right-shift that takes into account the sticky bit.
	 */
	zv = (zu >> 1) | (zu & 1);
	w = zu >> 55;
	zu ^= (zu ^ zv) & (uint64_t)-(int64_t)w;

	/*
	 * Get the aggregate scaling factor:
	 *
	 *   - Each exponent is biased by 1023.
	 *
	 *   - Integral mantissas are scaled by 2^52, hence an
	 *     extra 52 bias for each exponent.
	 *
	 *   - However, we right-shifted z by 50 bits, and then
	 *     by 0 or 1 extra bit (depending on the value of w).
	 *
	 * In total, we must add the exponents, then subtract
	 * 2 * (1023 + 52), then add 50 + w.
	 */
	ex = (int32_t)((x >> 52) & 0x000007FFUL);
	ey = (int32_t)((y >> 52) & 0x000007FFUL);
	e = ex + ey - 2100 + (int32_t)w;

	/*
	 * Sign bit is the XOR of the operand sign bits.
	 */
	s = (int32_t)((x ^ y) >> 63);

	/*
	 * Corrective actions for zeros: if either of the operands is
	 * zero, then the computations above were wrong. Test for zero
	 * is whether ex or ey is zero. We just have to set the mantissa
	 * (zu) to zero, the falcon_FPR() function will normalize e.
	 */
	d = ((ex + 0x000007FFL) & (ey + 0x000007FFL)) >> 11;
	zu &= (uint64_t)-(int64_t)d;

	/*
	 * falcon_FPR() packs the result and applies proper rounding.
	 */
	return falcon_FPR(s, e, zu);
}

inline static falcon_fpr falcon_fpr_div(falcon_fpr x, falcon_fpr y)
{
	uint64_t xu;
	uint64_t yu;
	uint64_t q;
	uint64_t q2;
	uint64_t w;
	int32_t i;
	int32_t ex;
	int32_t ey;
	int32_t e;
	int32_t d;
	int32_t s;

	/*
	 * Extract mantissas of x and y (uint32_t).
	 */
	xu = (x & (((uint64_t)1 << 52) - 1)) | ((uint64_t)1 << 52);
	yu = (y & (((uint64_t)1 << 52) - 1)) | ((uint64_t)1 << 52);

	/*
	 * Perform bit-by-bit division of xu by yu. We run it for 55 bits.
	 */
	q = 0;

	for (i = 0; i < 55; ++i)
	{
		/*
		 * If yu is less than or equal xu, then subtract it and
		 * push a 1 in the quotient; otherwise, leave xu unchanged
		 * and push a 0.
		 */
		uint64_t b;

		b = ((xu - yu) >> 63) - 1;
		xu -= b & yu;
		q |= b & 1;
		xu <<= 1;
		q <<= 1;
	}

	/*
	 * We got 55 bits in the quotient, followed by an extra zero. We
	 * want that 56th bit to be "sticky": it should be a 1 if and
	 * only if the remainder (xu) is non-zero.
	 */
	q |= (xu | (uint64_t)-(int64_t)xu) >> 63;

	/*
	 * Quotient is at most 2^56-1. Its top bit may be zero, but in
	 * that case the next-to-top bit will be a one, since the
	 * initial xu and yu were both in the 2^52..2^53-1 range.
	 * We perform a conditional shift to normalize q to the
	 * 2^54..2^55-1 range (with the bottom bit being sticky).
	 */
	q2 = (q >> 1) | (q & 1);
	w = q >> 55;
	q ^= (q ^ q2) & (uint64_t)-(int64_t)w;

	/*
	 * Extract exponents to compute the scaling factor:
	 *
	 *   - Each exponent is biased and we scaled them up by
	 *     52 bits; but these biases will cancel out.
	 *
	 *   - The division loop produced a 55-bit shifted result,
	 *     so we must scale it down by 55 bits.
	 *
	 *   - If w = 1, we right-shifted the integer by 1 bit,
	 *     hence we must add 1 to the scaling.
	 */
	ex = (int32_t)((x >> 52) & 0x000007FFL);
	ey = (int32_t)((y >> 52) & 0x000007FFL);
	e = ex - ey - 55 + (int32_t)w;

	/*
	 * Sign is the XOR of the signs of the operands.
	 */
	s = (int32_t)((x ^ y) >> 63);

	/*
	 * Corrective actions for zeros: if x = 0, then the computation
	 * is wrong, and we must clamp e and q to 0. We do not care
	 * about the case y = 0 (as per assumptions in this module,
	 * the caller does not perform divisions by zero).
	 */
	d = (ex + 0x000007FFL) >> 11;
	s &= d;
	e &= -d;
	q &= (uint64_t)-(int64_t)d;

	/*
	 * falcon_FPR() packs the result and applies proper rounding.
	 */
	return falcon_FPR(s, e, q);
}

inline static falcon_fpr falcon_fpr_inv(falcon_fpr x)
{
	return falcon_fpr_div(4607182418800017408u, x);
}

inline static falcon_fpr falcon_fpr_sqr(falcon_fpr x)
{
	return falcon_fpr_mul(x, x);
}

inline static falcon_fpr falcon_fpr_sqrt(falcon_fpr x)
{
	uint64_t xu;
	uint64_t q;
	uint64_t s;
	uint64_t r;
	int32_t ex;
	int32_t e;

	/*
	 * Extract the mantissa and the exponent. We don't care about
	 * the sign: by assumption, the operand is nonnegative.
	 * We want the "true" exponent corresponding to a mantissa
	 * in the 1..2 range.
	 */
	xu = (x & (((uint64_t)1 << 52) - 1)) | ((uint64_t)1 << 52);
	ex = (int32_t)((x >> 52) & 0x000007FFL);
	e = ex - 1023;

	/*
	 * If the exponent is odd, double the mantissa and decrement
	 * the exponent. The exponent is then halved to account for
	 * the square root.
	 */
	xu += xu & (uint64_t)-(int64_t)(e & 1);
	e >>= 1;

	/*
	 * Double the mantissa.
	 */
	xu <<= 1;

	/*
	 * We now have a mantissa in the 2^53..2^55-1 range. It
	 * represents a value between 1 (inclusive) and 4 (exclusive)
	 * in fixed point notation (with 53 fractional bits). We
	 * compute the square root bit by bit.
	 */
	q = 0;
	s = 0;
	r = (uint64_t)1 << 53;

	for (int32_t i = 0; i < 54; ++i)
	{
		uint64_t b;
		uint64_t t;

		t = s + r;
		b = ((xu - t) >> 63) - 1;
		s += (r << 1) & b;
		xu -= t & b;
		q += r & b;
		xu <<= 1;
		r >>= 1;
	}

	/*
	 * Now, q is a rounded-low 54-bit value, with a leading 1,
	 * 52 fractional digits, and an additional guard bit. We add
	 * an extra sticky bit to account for what remains of the operand.
	 */
	q <<= 1;
	q |= (xu | (uint64_t)-(int64_t)xu) >> 63;

	/*
	 * Result q is in the 2^54..2^55-1 range; we bias the exponent
	 * by 54 bits (the value e at that point contains the "true"
	 * exponent, but q is now considered an integer, i.e. scaled
	 * up.
	 */
	e -= 54;

	/*
	 * Corrective action for an operand of value zero.
	 */
	q &= (uint64_t)-(int64_t)((ex + 0x7FF) >> 11);

	/*
	 * Apply rounding and back result.
	 */
	return falcon_FPR(0, e, q);
}

inline static falcon_fpr falcon_fpr_sub(falcon_fpr x, falcon_fpr y)
{
	y ^= (uint64_t)1 << 63;

	return falcon_fpr_add(x, y);
}

inline static uint64_t falcon_fpr_expm_p63(falcon_fpr x, falcon_fpr ccs)
{
	/*
	* Polynomial approximation of exp(-x) is taken from FACCT:
	*   https://eprint.iacr.org/2018/1234
	* Specifically, values are extracted from the implementation
	* referenced from the FACCT article, and available at:
	*   https://github.com/raykzhao/gaussian
	* Here, the coefficients have been scaled up by 2^63 and
	* converted to integers.
	*
	* Tests over more than 24 billions of random inputs in the
	* 0..log(2) range have never shown a deviation larger than
	* 2^(-50) from the true mathematical value.
	*/
	static const uint64_t C[] =
	{
		0X00000004741183A3ULL, 0X00000036548CFC06ULL, 0X0000024FDCBF140AULL, 0X0000171D939DE045ULL,
		0X0000D00CF58F6F84ULL, 0X000680681CF796E3ULL, 0X002D82D8305B0FEAULL, 0X011111110E066FD0ULL,
		0X0555555555070F00ULL, 0X155555555581FF00ULL, 0X400000000002B400ULL, 0X7FFFFFFFFFFF4800ULL,
		0X8000000000000000ULL
	};

	uint64_t a;
	uint64_t b;
	uint64_t y;
	uint64_t z;
	uint32_t u;
	uint32_t z0;
	uint32_t z1;
	uint32_t y0;
	uint32_t y1;

	y = C[0];
	z = (uint64_t)falcon_fpr_trunc(falcon_fpr_mul(x, falcon_fpr_ptwo63)) << 1;

	for (u = 1; u < (sizeof(C) / sizeof(C[0])); ++u)
	{
		/*
		 * Compute product z * y over 128 bits, but keep only
		 * the top 64 bits.
		 *
		 * TODO: On some architectures/compilers we could use
		 * some intrinsics (__umulh() on MSVC) or other compiler
		 * extensions (uint32_t __int128 on GCC / Clang) for
		 * improved speed; however, most 64-bit architectures
		 * also have appropriate IEEE754 floating-point support,
		 * which is better.
		 */
		uint64_t c;

		z0 = (uint32_t)z;
		z1 = (uint32_t)(z >> 32);
		y0 = (uint32_t)y;
		y1 = (uint32_t)(y >> 32);
		a = ((uint64_t)z0 * (uint64_t)y1) + (((uint64_t)z0 * (uint64_t)y0) >> 32);
		b = ((uint64_t)z1 * (uint64_t)y0);
		c = (a >> 32) + (b >> 32);
		c += (((uint64_t)(uint32_t)a + (uint64_t)(uint32_t)b) >> 32);
		c += (uint64_t)z1 * (uint64_t)y1;
		y = C[u] - c;
	}

	/*
	 * The scaling factor must be applied at the end. Since y is now
	 * in fixed-point notation, we have to convert the factor to the
	 * same format, and do an extra integer multiplication.
	 */
	z = (uint64_t)falcon_fpr_trunc(falcon_fpr_mul(ccs, falcon_fpr_ptwo63)) << 1;
	z0 = (uint32_t)z;
	z1 = (uint32_t)(z >> 32);
	y0 = (uint32_t)y;
	y1 = (uint32_t)(y >> 32);
	a = ((uint64_t)z0 * (uint64_t)y1) + (((uint64_t)z0 * (uint64_t)y0) >> 32);
	b = ((uint64_t)z1 * (uint64_t)y0);
	y = (a >> 32) + (b >> 32);
	y += (((uint64_t)(uint32_t)a + (uint64_t)(uint32_t)b) >> 32);
	y += (uint64_t)z1 * (uint64_t)y1;

	return y;
}

/* codec.c */

extern const uint8_t falcon_max_fg_bits[FALCON_MAXBITS_SIZE];

extern const uint8_t falcon_max_FG_bits[FALCON_MAXBITS_SIZE];

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

	fpct_a_re = (a_re);
	fpct_a_im = (a_im);
	fpct_b_re = (b_re);
	fpct_b_im = (b_im);
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

	fpct_a_re = (a_re);
	fpct_a_im = (a_im);
	fpct_b_re = (b_re);
	fpct_b_im = (b_im);
	fpct_m = falcon_fpr_add(falcon_fpr_sqr(fpct_b_re), falcon_fpr_sqr(fpct_b_im));
	fpct_m = falcon_fpr_inv(fpct_m);
	fpct_b_re = falcon_fpr_mul(fpct_b_re, fpct_m);
	fpct_b_im = falcon_fpr_mul(falcon_fpr_neg(fpct_b_im), fpct_m);
	fpct_d_re = falcon_fpr_sub(falcon_fpr_mul(fpct_a_re, fpct_b_re), falcon_fpr_mul(fpct_a_im, fpct_b_im));
	fpct_d_im = falcon_fpr_add(falcon_fpr_mul(fpct_a_re, fpct_b_im), falcon_fpr_mul(fpct_a_im, fpct_b_re));
	*d_re = fpct_d_re;
	*d_im = fpct_d_im;
}

/* verify.c */

extern const uint16_t falcon_GMb[FALCON_GMB_SIZE];

extern const uint16_t falcon_iGMb[FALCON_GMB_SIZE];

extern const falcon_small_prime falcon_small_primes[FALCON_SMALL_PRIME_SIZE];

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

/* keygen.c */

/*
 * Table below incarnates a discrete Gaussian distribution:
 *    D(x) = exp(-(x^2)/(2*sigma^2))
 * where sigma = 1.17*sqrt(q/(2*N)), q = 12289, and N = 1024.
 * Element 0 of the table is P(x = 0).
 * For k > 0, element k is P(x >= k+1 | x > 0).
 * Probabilities are scaled up by 2^63.
 */
extern const uint64_t falcon_gauss_1024_12289[FALCON_GAUS_1024_12289_SIZE];

extern const uint16_t falcon_rev10[FALCON_REV10_SIZE];

/*
 * The falcon_max_bl_small[] and falcon_max_bl_large[] contain the lengths, in 31-bit
 * words, of intermediate values in the computation:
 *
 *   falcon_max_bl_small[depth]: length for the input f and g at that depth
 *   falcon_max_bl_large[depth]: length for the unreduced F and G at that depth
 *
 * Rules:
 *
 *  - Within an array, values grow.
 *
 *  - The 'SMALL' array must have an entry for maximum depth, corresponding
 *    to the size of values used in the binary GCD. There is no such value
 *    for the 'LARGE' array (the binary GCD yields already reduced
 *    coefficients).
 *
 *  - falcon_max_bl_large[depth] >= falcon_max_bl_small[depth + 1].
 *
 *  - Values must be large enough to handle the common cases, with some
 *    margins.
 *
 *  - Values must not be "too large" either because we will convert some
 *    integers into floating-point values by considering the top 10 words,
 *    i.e. 310 bits; hence, for values of length more than 10 words, we
 *    should take care to have the length centered on the expected size.
 *
 * The following average lengths, in bits, have been measured on thousands
 * of random keys (fg = max length of the absolute value of coefficients
 * of f and g at that depth; FG = idem for the unreduced F and G; for the
 * maximum depth, F and G are the output of binary GCD, multiplied by q;
 * for each value, the average and standard deviation are provided).
 *
 * Binary case:
 *    depth: 10    fg: 6307.52 (24.48)    FG: 6319.66 (24.51)
 *    depth:  9    fg: 3138.35 (12.25)    FG: 9403.29 (27.55)
 *    depth:  8    fg: 1576.87 ( 7.49)    FG: 4703.30 (14.77)
 *    depth:  7    fg:  794.17 ( 4.98)    FG: 2361.84 ( 9.31)
 *    depth:  6    fg:  400.67 ( 3.10)    FG: 1188.68 ( 6.04)
 *    depth:  5    fg:  202.22 ( 1.87)    FG:  599.81 ( 3.87)
 *    depth:  4    fg:  101.62 ( 1.02)    FG:  303.49 ( 2.38)
 *    depth:  3    fg:   50.37 ( 0.53)    FG:  153.65 ( 1.39)
 *    depth:  2    fg:   24.07 ( 0.25)    FG:   78.20 ( 0.73)
 *    depth:  1    fg:   10.99 ( 0.08)    FG:   39.82 ( 0.41)
 *    depth:  0    fg:    4.00 ( 0.00)    FG:   19.61 ( 0.49)
 *
 * Integers are actually represented either in binary notation over
 * 31-bit words (signed, using two's complement), or in RNS, modulo
 * many small primes. These small primes are close to, but slightly
 * lower than, 2^31. Use of RNS loses less than two bits, even for
 * the largest values.
 *
 * IMPORTANT: if these values are modified, then the temporary buffer
 * sizes (FALCON_KEYGEN_TEMP_*, in inner.h) must be recomputed
 * accordingly.
 */
extern const size_t falcon_max_bl_small[FALCON_MAX_BL_SMALL_SIZE];

extern const size_t falcon_max_bl_large[FALCON_MAX_BL_LARGE_SIZE];

/*
 * Average and standard deviation for the maximum size (in bits) of
 * coefficients of (f,g), depending on depth. These values are used
 * to compute bounds for Babai's reduction.
 */
static const struct
{
	int32_t avg;
	int32_t std;
} falcon_bit_length[] =
{
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

inline static size_t falcon_mkn(uint32_t logn)
{
	return ((size_t)1 << (logn));
}

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

/* common.c */

const uint32_t falcon_l2bound[FALCON_L2BOUND_SIZE];

/* public functions */

/**
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to FALCON_PUBLICKEY_SIZE and FALCON_SECRETKEY_SIZE.
*
* \param publickey: The public verification key
* \param secretkey: The private signature key
* \param rng_generate: The random generator
*/
int32_t qsc_falcon_ref_generate_keypair(uint8_t *pk, uint8_t *sk, void (*rng_generate)(uint8_t*, size_t));

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
int32_t qsc_falcon_ref_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk, void (*rng_generate)(uint8_t*, size_t));

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
bool qsc_falcon_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif