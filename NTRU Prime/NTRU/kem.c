#include "kem.h"
#include "aesdrbg.h"
#include "common.h"
#include "sha3.h"
#include "sysrand.h"
#include <string.h>

/* Common Functions */

static void minmax(int32_t* x, int32_t* y)
{
	uint32_t xi;
	uint32_t yi;
	uint32_t xy;
	uint32_t c;

	xi = *x;
	yi = *y;
	xy = xi ^ yi;
	c = yi - xi;

	c ^= xy & (c ^ yi);
	c >>= 31;
	c = ~c + 1;
	c &= xy;
	*x = xi ^ c;
	*y = yi ^ c;
}

static int16_t modq_freeze(int32_t a)
{
	/* input between -9000000 and 9000000 output between -2295 and 2295 */
	a -= 4591 * ((228 * a) >> 20);
	a -= 4591 * ((58470 * a + 134217728) >> 28);

	return a;
}

static int16_t modq_plusproduct(int16_t a, int16_t b, int16_t c)
{
	int32_t A = a;
	int32_t B = b;
	int32_t C = c;

	return modq_freeze(A + B * C);
}

static int16_t modq_sum(int16_t a, int16_t b)
{
	int32_t s = a + b;

	return modq_freeze(s);
}

static void rq_decoderounded(int16_t* f, const uint8_t* c)
{
	uint32_t c0;
	uint32_t c1;
	uint32_t c2;
	uint32_t c3;
	uint32_t f0;
	uint32_t f1;
	uint32_t f2;
	size_t i;

	for (i = 0; i < NTRU_P / 3; ++i)
	{
		c0 = *c++;
		c1 = *c++;
		c2 = *c++;
		c3 = *c++;

		/* f0 + f1*1536 + f2*1536^2 */
		/* = c0 + c1*256 + c2*256^2 + c3*256^3 */
		/* with each f between 0 and 1530 */
		/* f2 = (64/9)c3 + (1/36)c2 + (1/9216)c1 + (1/2359296)c0 - [0,0.99675] */
		/* claim: 2^21 f2 < x < 2^21(f2+1) */
		/* where x = 14913081*c3 + 58254*c2 + 228*(c1+2) */
		/* proof: x - 2^21 f2 = 456 - (8/9)c0 + (4/9)c1 - (2/9)c2 + (1/9)c3 + 2^21 [0,0.99675] */
		/* at least 456 - (8/9)255 - (2/9)255 > 0 */
		/* at most 456 + (4/9)255 + (1/9)255 + 2^21 0.99675 < 2^21 */
		f2 = (14913081 * c3 + 58254 * c2 + 228 * (c1 + 2)) >> 21;
		c2 += c3 << 8;
		c2 -= (f2 * 9) << 2;

		/* f0 + f1*1536 */
		/* = c0 + c1*256 + c2*256^2 */
		/* c2 <= 35 = floor((1530+1530*1536)/256^2) */
		/* f1 = (128/3)c2 + (1/6)c1 + (1/1536)c0 - (1/1536)f0 */
		/* claim: 2^21 f1 < x < 2^21(f1+1) */
		/* where x = 89478485*c2 + 349525*c1 + 1365*(c0+1) */
		/* proof: x - 2^21 f1 = 1365 - (1/3)c2 - (1/3)c1 - (1/3)c0 + (4096/3)f0 */
		/* at least 1365 - (1/3)35 - (1/3)255 - (1/3)255 > 0 */
		/* at most 1365 + (4096/3)1530 < 2^21 */
		f1 = (89478485 * c2 + 349525 * c1 + 1365 * (c0 + 1)) >> 21;
		c1 += c2 << 8;
		c1 -= (f1 * 3) << 1;
		c0 += c1 << 8;
		f0 = c0;

		*f++ = modq_freeze(f0 * 3 + NTRU_Q - NTRU_QSHIFT);
		*f++ = modq_freeze(f1 * 3 + NTRU_Q - NTRU_QSHIFT);
		*f++ = modq_freeze(f2 * 3 + NTRU_Q - NTRU_QSHIFT);
	}

	c0 = *c++;
	c1 = *c++;
	c2 = *c++;
	f1 = (89478485 * c2 + 349525 * c1 + 1365 * (c0 + 1)) >> 21;

	c1 += c2 << 8;
	c1 -= (f1 * 3) << 1;
	c0 += c1 << 8;
	f0 = c0;

	*f++ = modq_freeze(f0 * 3 + NTRU_Q - NTRU_QSHIFT);
	*f++ = modq_freeze(f1 * 3 + NTRU_Q - NTRU_QSHIFT);
}

static void rq_encoderounded(uint8_t* c, const int16_t* f)
{
	int32_t f0;
	int32_t f1;
	int32_t f2;
	size_t i;

	for (i = 0; i < NTRU_P / 3; ++i)
	{
		f0 = *f++ + NTRU_QSHIFT;
		f1 = *f++ + NTRU_QSHIFT;
		f2 = *f++ + NTRU_QSHIFT;
		f0 = (21846 * f0) >> 16;
		f1 = (21846 * f1) >> 16;
		f2 = (21846 * f2) >> 16;
		/* now want f0 + f1*1536 + f2*1536^2 as a 32-bit integer */
		f2 *= 3;
		f1 += f2 << 9;
		f1 *= 3;
		f0 += f1 << 9;
		*c++ = f0;
		f0 >>= 8;
		*c++ = f0;
		f0 >>= 8;
		*c++ = f0;
		f0 >>= 8;
		*c++ = f0;
	}

	/* XXX: using p mod 3 = 2 */
	f0 = *f++ + NTRU_QSHIFT;
	f1 = *f++ + NTRU_QSHIFT;
	f0 = (21846 * f0) >> 16;
	f1 = (21846 * f1) >> 16;
	f1 *= 3;
	f0 += f1 << 9;
	*c++ = f0;
	f0 >>= 8;
	*c++ = f0;
	f0 >>= 8;
	*c++ = f0;
}

static void rq_mult(int16_t* h, const int16_t* f, const int8_t* g)
{
	int16_t fg[NTRU_P + NTRU_P - 1];
	size_t i;
	size_t j;
	int16_t result;

	for (i = 0; i < NTRU_P; ++i)
	{
		result = 0;

		for (j = 0; j <= i; ++j)
		{
			result = modq_plusproduct(result, f[j], g[i - j]);
		}

		fg[i] = result;
	}

	for (i = NTRU_P; i < NTRU_P + NTRU_P - 1; ++i)
	{
		result = 0;

		for (j = i - NTRU_P + 1; j < NTRU_P; ++j)
		{
			result = modq_plusproduct(result, f[j], g[i - j]);
		}

		fg[i] = result;
	}

	for (i = NTRU_P + NTRU_P - 2; i >= NTRU_P; --i)
	{
		fg[i - NTRU_P] = modq_sum(fg[i - NTRU_P], fg[i]);
		fg[i - NTRU_P + 1] = modq_sum(fg[i - NTRU_P + 1], fg[i]);
	}

	for (i = 0; i < NTRU_P; ++i)
	{
		h[i] = fg[i];
	}
}

static void rq_round3(int16_t* h, const int16_t* f)
{
	int32_t i;

	for (i = 0; i < NTRU_P; ++i)
	{
		h[i] = ((21846 * (f[i] + 2295) + 32768) >> 16) * 3 - 2295;
	}
}

static void small_decode(int8_t* f, const uint8_t* c)
{
	size_t i;
	uint8_t c0;

	for (i = 0; i < NTRU_P / 4; ++i) 
	{
		c0 = *c++;
		*f++ = ((int8_t)(c0 & 3)) - 1; c0 >>= 2;
		*f++ = ((int8_t)(c0 & 3)) - 1; c0 >>= 2;
		*f++ = ((int8_t)(c0 & 3)) - 1; c0 >>= 2;
		*f++ = ((int8_t)(c0 & 3)) - 1;
	}

	c0 = *c++;
	*f++ = ((int8_t)(c0 & 3)) - 1;
}

static void small_encode(uint8_t* c, const int8_t* f)
{
	/* all coefficients in -1, 0, 1 */
	uint8_t c0;
	size_t i;

	for (i = 0; i < NTRU_P / 4; ++i)
	{
		c0 = *f++ + 1;
		c0 += (*f++ + 1) << 2;
		c0 += (*f++ + 1) << 4;
		c0 += (*f++ + 1) << 6;
		*c++ = c0;
	}

	c0 = *f++ + 1;
	*c++ = c0;
}

#if defined(NTRU_SPRIME_ENABLED)

/* Rounded Quotient NTRU: S:Prime */

static void swap(void* x, void* y, size_t length, int32_t mask)
{
	int8_t c;
	int8_t t;
	int8_t xi;
	int8_t yi;
	size_t i;

	c = mask;

	for (i = 0; i < length; ++i)
	{
		xi = i[(int8_t*)x];
		yi = i[(int8_t*)y];
		t = c & (xi ^ yi);
		xi ^= t;
		yi ^= t;
		i[(int8_t*)x] = xi;
		i[(int8_t*)y] = yi;
	}
}

static void sort_int32(int32_t* x, int32_t n)
{
	int32_t i;
	int32_t p;
	int32_t q;
	int32_t top;

	if (n > 1)
	{
		top = 1;

		while (top < n - top)
		{
			top += top;
		}

		for (p = top; p > 0; p >>= 1)
		{
			for (i = 0; i < n - p; ++i)
			{
				if (!(i & p))
				{
					minmax(x + i, x + i + p);
				}
			}
			for (q = top; q > p; q >>= 1)
			{
				for (i = 0; i < n - q; ++i)
				{
					if (!(i & p))
					{
						minmax(x + i + p, x + i + q);
					}
				}
			}
		}
	}
}

static int mod3_nonzero_mask(int8_t x)
{
	/* -1 if x is nonzero, 0 otherwise */
	return -x * x;
}

static int8_t mod3_freeze(int32_t a)
{
	/* input between -100000 and 100000 */
	/* output between -1 and 1 */
	a -= 3 * ((10923 * a) >> 15);
	a -= 3 * ((89478485 * a + 134217728) >> 28);

	return a;
}

static int8_t mod3_minusproduct(int8_t a, int8_t b, int8_t c)
{
	int32_t A = a;
	int32_t B = b;
	int32_t C = c;

	return mod3_freeze(A - B * C);
}

static int8_t mod3_plusproduct(int8_t a, int8_t b, int8_t c)
{
	int32_t A = a;
	int32_t B = b;
	int32_t C = c;

	return mod3_freeze(A + B * C);
}

static int8_t mod3_product(int8_t a, int8_t b)
{
	return a * b;
}

static int8_t mod3_sum(int8_t a, int8_t b)
{
	int32_t A = a;
	int32_t B = b;

	return mod3_freeze(A + B);
}

static int8_t mod3_reciprocal(int8_t a1)
{
	return a1;
}

static int8_t mod3_quotient(int8_t num, int8_t den)
{
	return mod3_product(num, mod3_reciprocal(den));
}

static int16_t modq_minusproduct(int16_t a, int16_t b, int16_t c)
{
	int32_t A = a;
	int32_t B = b;
	int32_t C = c;

	return modq_freeze(A - B * C);
}

static int modq_nonzero_mask(int16_t x)
{
	/* -1 if x is nonzero, 0 otherwise */
	int32_t r;

	r = (uint16_t)x;
	r = -r;
	r >>= 30;

	return r;
}

static int16_t modq_product(int16_t a, int16_t b)
{
	int32_t A = a;
	int32_t B = b;

	return modq_freeze(A * B);
}

static int16_t modq_square(int16_t a)
{
	int32_t A = a;

	return modq_freeze(A * A);
}

static int16_t modq_reciprocal(int16_t a1)
{
	int16_t a2 = modq_square(a1);
	int16_t a3 = modq_product(a2, a1);
	int16_t a4 = modq_square(a2);
	int16_t a8 = modq_square(a4);
	int16_t a16 = modq_square(a8);
	int16_t a32 = modq_square(a16);
	int16_t a35 = modq_product(a32, a3);
	int16_t a70 = modq_square(a35);
	int16_t a140 = modq_square(a70);
	int16_t a143 = modq_product(a140, a3);
	int16_t a286 = modq_square(a143);
	int16_t a572 = modq_square(a286);
	int16_t a1144 = modq_square(a572);
	int16_t a1147 = modq_product(a1144, a3);
	int16_t a2294 = modq_square(a1147);
	int16_t a4588 = modq_square(a2294);
	int16_t a4589 = modq_product(a4588, a1);

	return a4589;
}

static int16_t modq_quotient(int16_t num, int16_t den)
{
	return modq_product(num, modq_reciprocal(den));
}

static void r3_mult(int8_t *h, const int8_t *f, const int8_t *g)
{
	int8_t fg[NTRU_P + NTRU_P - 1];
	size_t i;
	size_t j;
	int8_t result;

	for (i = 0; i < NTRU_P; ++i) 
	{
		result = 0;

		for (j = 0; j <= i; ++j)
		{
			result = mod3_plusproduct(result, f[j], g[i - j]);
		}

		fg[i] = result;
	}
	for (i = NTRU_P; i < NTRU_P + NTRU_P - 1; ++i)
	{
		result = 0;

		for (j = i - NTRU_P + 1; j < NTRU_P; ++j)
		{
			result = mod3_plusproduct(result, f[j], g[i - j]);
		}

		fg[i] = result;
	}

	for (i = NTRU_P + NTRU_P - 2; i >= NTRU_P; --i) 
	{
		fg[i - NTRU_P] = mod3_sum(fg[i - NTRU_P], fg[i]);
		fg[i - NTRU_P + 1] = mod3_sum(fg[i - NTRU_P + 1], fg[i]);
	}

	for (i = 0; i < NTRU_P; ++i)
	{
		h[i] = fg[i];
	}
}

static int smaller_mask(int x, int y)
{
	/* caller must ensure that x-y does not overflow */
	return (x - y) >> 31;
}

static int32_t small_random32(void)
{
	uint8_t x[4];

	sysrand_getbytes(x, 4);

	return x[0] + (x[1] << 8) + (x[2] << 16) + (x[3] << 24);
}

static void small_random_weightw(int8_t *f)
{
	int32_t r[NTRU_P];
	size_t i;

	for (i = 0; i < NTRU_P; ++i)
	{
		r[i] = small_random32();
	}

	for (i = 0; i < NTRU_W; ++i)
	{
		r[i] &= -2;
	}

	for (i = NTRU_W; i < NTRU_P; ++i)
	{
		r[i] = (r[i] & -3) | 1;
	}

	sort_int32(r, NTRU_P);

	for (i = 0; i < NTRU_P; ++i)
	{
		f[i] = ((int8_t)(r[i] & 3)) - 1;
	}
}

static void vectormod3_product(int8_t* z, size_t length, const int8_t* x, const int8_t c)
{
	size_t i;

	for (i = 0; i < length; ++i)
	{
		z[i] = mod3_product(x[i], c);
	}
}

static void vectormod3_minusproduct(int8_t* z, size_t length, const int8_t* x, const int8_t* y, const int8_t c)
{
	size_t i;

	for (i = 0; i < length; ++i)
	{
		z[i] = mod3_minusproduct(x[i], y[i], c);
	}
}

static void vectormod3_shift(int8_t* z, size_t length)
{
	int32_t i;

	for (i = length - 1; i > 0; --i)
		z[i] = z[i - 1];

	z[0] = 0;
}

static void rq_encode(uint8_t* c, const int16_t* f)
{
	int32_t f0;
	int32_t f1;
	int32_t f2;
	int32_t f3;
	int32_t f4;
	size_t  i;

	for (i = 0; i < NTRU_P / 5; ++i)
	{
		f0 = *f++ + NTRU_QSHIFT;
		f1 = *f++ + NTRU_QSHIFT;
		f2 = *f++ + NTRU_QSHIFT;
		f3 = *f++ + NTRU_QSHIFT;
		f4 = *f++ + NTRU_QSHIFT;
		/* now want f0 + 6144*f1 + ... as a 64-bit integer */
		f1 *= 3;
		f2 *= 9;
		f3 *= 27;
		f4 *= 81;
		/* now want f0 + f1<<11 + f2<<22 + f3<<33 + f4<<44 */
		f0 += f1 << 11;
		*c++ = f0; f0 >>= 8;
		*c++ = f0; f0 >>= 8;
		f0 += f2 << 6;
		*c++ = f0; f0 >>= 8;
		*c++ = f0; f0 >>= 8;
		f0 += f3 << 1;
		*c++ = f0; f0 >>= 8;
		f0 += f4 << 4;
		*c++ = f0; f0 >>= 8;
		*c++ = f0; f0 >>= 8;
		*c++ = f0;
	}

	/* XXX: using p mod 5 = 1 */
	f0 = *f++ + NTRU_QSHIFT;
	*c++ = f0; f0 >>= 8;
	*c++ = f0;
}

static void rq_decode(int16_t* f, const uint8_t* c)
{
	uint32_t c0;
	uint32_t c1;
	uint32_t c2;
	uint32_t c3;
	uint32_t c4;
	uint32_t c5;
	uint32_t c6;
	uint32_t c7;
	uint32_t f0;
	uint32_t f1;
	uint32_t f2;
	uint32_t f3;
	uint32_t f4;
	size_t i;

	for (i = 0; i < NTRU_P / 5; ++i) 
	{
		c0 = *c++;
		c1 = *c++;
		c2 = *c++;
		c3 = *c++;
		c4 = *c++;
		c5 = *c++;
		c6 = *c++;
		c7 = *c++;

		/* f0 + f1*6144 + f2*6144^2 + f3*6144^3 + f4*6144^4 */
		/* = c0 + c1*256 + ... + c6*256^6 + c7*256^7 */
		/* with each f between 0 and 4590 */
		c6 += c7 << 8;
		/* c6 <= 23241 = floor(4591*6144^4/2^48) */
		/* f4 = (16/81)c6 + (1/1296)(c5+[0,1]) - [0,0.75] */
		/* claim: 2^19 f4 < x < 2^19(f4+1) */
		/* where x = 103564 c6 + 405(c5+1) */
		/* proof: x - 2^19 f4 = (76/81)c6 + (37/81)c5 + 405 - (32768/81)[0,1] + 2^19[0,0.75] */
		/* at least 405 - 32768/81 > 0 */
		/* at most (76/81)23241 + (37/81)255 + 405 + 2^19 0.75 < 2^19 */
		f4 = (103564 * c6 + 405 * (c5 + 1)) >> 19;
		c5 += c6 << 8;
		c5 -= (f4 * 81) << 4;
		c4 += c5 << 8;

		/* f0 + f1*6144 + f2*6144^2 + f3*6144^3 */
		/* = c0 + c1*256 + c2*256^2 + c3*256^3 + c4*256^4 */
		/* c4 <= 247914 = floor(4591*6144^3/2^32) */
		/* f3 = (1/54)(c4+[0,1]) - [0,0.75] */
		/* claim: 2^19 f3 < x < 2^19(f3+1) */
		/* where x = 9709(c4+2) */
		/* proof: x - 2^19 f3 = 19418 - (1/27)c4 - (262144/27)[0,1] + 2^19[0,0.75] */
		/* at least 19418 - 247914/27 - 262144/27 > 0 */
		/* at most 19418 + 2^19 0.75 < 2^19 */
		f3 = (9709 * (c4 + 2)) >> 19;
		c4 -= (f3 * 27) << 1;
		c3 += c4 << 8;

		/* f0 + f1*6144 + f2*6144^2 */
		/* = c0 + c1*256 + c2*256^2 + c3*256^3 */
		/* c3 <= 10329 = floor(4591*6144^2/2^24) */
		/* f2 = (4/9)c3 + (1/576)c2 + (1/147456)c1 + (1/37748736)c0 - [0,0.75] */
		/* claim: 2^19 f2 < x < 2^19(f2+1) */
		/* where x = 233017 c3 + 910(c2+2) */
		/* proof: x - 2^19 f2 = 1820 + (1/9)c3 - (2/9)c2 - (32/9)c1 - (1/72)c0 + 2^19[0,0.75] */
		/* at least 1820 - (2/9)255 - (32/9)255 - (1/72)255 > 0 */
		/* at most 1820 + (1/9)10329 + 2^19 0.75 < 2^19 */
		f2 = (233017 * c3 + 910 * (c2 + 2)) >> 19;
		c2 += c3 << 8;
		c2 -= (f2 * 9) << 6;
		c1 += c2 << 8;

		/* f0 + f1*6144 */
		/* = c0 + c1*256 */
		/* c1 <= 110184 = floor(4591*6144/2^8) */
		/* f1 = (1/24)c1 + (1/6144)c0 - (1/6144)f0 */
		/* claim: 2^19 f1 < x < 2^19(f1+1) */
		/* where x = 21845(c1+2) + 85 c0 */
		/* proof: x - 2^19 f1 = 43690 - (1/3)c1 - (1/3)c0 + 2^19 [0,0.75] */
		/* at least 43690 - (1/3)110184 - (1/3)255 > 0 */
		/* at most 43690 + 2^19 0.75 < 2^19 */
		f1 = (21845 * (c1 + 2) + 85 * c0) >> 19;
		c1 -= (f1 * 3) << 3;
		c0 += c1 << 8;
		f0 = c0;

		*f++ = modq_freeze(f0 + NTRU_Q - NTRU_QSHIFT);
		*f++ = modq_freeze(f1 + NTRU_Q - NTRU_QSHIFT);
		*f++ = modq_freeze(f2 + NTRU_Q - NTRU_QSHIFT);
		*f++ = modq_freeze(f3 + NTRU_Q - NTRU_QSHIFT);
		*f++ = modq_freeze(f4 + NTRU_Q - NTRU_QSHIFT);
	}

	c0 = *c++;
	c1 = *c++;
	c0 += c1 << 8;
	*f++ = modq_freeze(c0 + NTRU_Q - NTRU_QSHIFT);
}

static int r3_recip(int8_t* r, const int8_t* s)
{
	/*
	r = s^(-1) mod m, returning 0, if s is invertible mod m
	or returning -1 if s is not invertible mod m
	r,s are polys of degree <p
	m is x^p-x-1
	*/
	const size_t LOOPS = 2 * NTRU_P + 1;
	size_t loop;
	int8_t f[NTRU_P + 1];
	int8_t g[NTRU_P + 1];
	int8_t u[2 * NTRU_P + 2];
	int8_t v[2 * NTRU_P + 2];
	size_t i;
	int32_t d = NTRU_P;
	int32_t e = NTRU_P;
	int32_t swapmask;
	int8_t c;

	for (i = 2; i < NTRU_P; ++i)
	{
		f[i] = 0;
	}

	f[0] = -1;
	f[1] = -1;
	f[NTRU_P] = 1;

	/* generalization: can initialize f to any polynomial m */
	/* requirements: m has degree exactly p, nonzero constant coefficient */
	for (i = 0; i < NTRU_P; ++i)
	{
		g[i] = s[i];
	}

	g[NTRU_P] = 0;

	for (i = 0; i <= LOOPS; ++i)
	{
		u[i] = 0;
	}

	v[0] = 1;

	for (i = 1; i <= LOOPS; ++i)
	{
		v[i] = 0;
	}

	loop = 0;
	for (;;) 
	{
		/* e == -1 or d + e + loop <= 2*p */
		/* f has degree p: i.e., f[p]!=0 */
		/* f[i]==0 for i < p-d */
		/* g has degree <=p (so it fits in p+1 coefficients) */
		/* g[i]==0 for i < p-e */
		/* u has degree <=loop (so it fits in loop+1 coefficients) */
		/* u[i]==0 for i < p-d */
		/* if invertible: u[i]==0 for i < loop-p (so can look at just p+1 coefficients) */
		/* v has degree <=loop (so it fits in loop+1 coefficients) */
		/* v[i]==0 for i < p-e */
		/* v[i]==0 for i < loop-p (so can look at just p+1 coefficients) */

		if (loop >= LOOPS)
		{
			break;
		}

		c = mod3_quotient(g[NTRU_P], f[NTRU_P]);
		vectormod3_minusproduct(g, NTRU_P + 1, g, f, c);
		vectormod3_shift(g, NTRU_P + 1);

#ifdef SIMPLER
		vectormod3_minusproduct(v, LOOPS + 1, v, u, c);
		vectormod3_shift(v, LOOPS + 1);
#else
		if (loop < NTRU_P)
		{
			vectormod3_minusproduct(v, loop + 1, v, u, c);
			vectormod3_shift(v, loop + 2);
		}
		else 
		{
			vectormod3_minusproduct(v + loop - NTRU_P, NTRU_P + 1, v + loop - NTRU_P, u + loop - NTRU_P, c);
			vectormod3_shift(v + loop - NTRU_P, NTRU_P + 2);
		}
#endif

		e -= 1;
		++loop;
		swapmask = smaller_mask(e, d) & mod3_nonzero_mask(g[NTRU_P]);
		swap(&e, &d, sizeof e, swapmask);
		swap(f, g, (NTRU_P + 1) * sizeof(int8_t), swapmask);

#ifdef SIMPLER
		swap(u, v, (LOOPS + 1) * sizeof(int8_t), swapmask);
#else
		if (loop < NTRU_P)
		{
			swap(u, v, (loop + 1) * sizeof(int8_t), swapmask);
		}
		else
		{
			swap(u + loop - NTRU_P, v + loop - NTRU_P, (NTRU_P + 1) * sizeof(int8_t), swapmask);
		}
#endif
	}

	c = mod3_reciprocal(f[NTRU_P]);
	vectormod3_product(r, NTRU_P, u + NTRU_P, c);

	return smaller_mask(0, d);
}

static void small_random(int8_t* g)
{
	size_t i;

	for (i = 0; i < NTRU_P; ++i) 
	{
		uint32_t r = small_random32();
		g[i] = (int8_t)(((1073741823 & r) * 3) >> 30) - 1;
	}
}

static void vectormodq_product(int16_t* z, size_t length, const int16_t* x, const int16_t c)
{
	size_t i;

	for (i = 0; i < length; ++i)
	{
		z[i] = modq_product(x[i], c);
	}
}

static void vectormodq_minusproduct(int16_t* z, size_t length, const int16_t* x, const int16_t* y, const int16_t c)
{
	size_t i;

	for (i = 0; i < length; ++i)
	{
		z[i] = modq_minusproduct(x[i], y[i], c);
	}
}

static void vectormodq_shift(int16_t* z, size_t length)
{
	int32_t i;

	for (i = length - 1; i > 0; --i)
	{
		z[i] = z[i - 1];
	}

	z[0] = 0;
}

static int rq_recip3(int16_t* r, const int8_t* s)
{
	/*
	r = (3s)^(-1) mod m, returning 0, if s is invertible mod m
	or returning -1 if s is not invertible mod m
	r,s are polys of degree <p
	m is x^p-x-1
	*/
	const size_t LOOPS = 2 * NTRU_P + 1;

	size_t loop;
	int16_t f[NTRU_P + 1];
	int16_t g[NTRU_P + 1];
	int16_t u[2 * NTRU_P + 2];
	int16_t v[2 * NTRU_P + 2];
	int16_t c;
	size_t i;
	int32_t d = NTRU_P;
	int32_t e = NTRU_P;
	int32_t swapmask;

	for (i = 2; i < NTRU_P; ++i)
	{
		f[i] = 0;
	}

	f[0] = -1;
	f[1] = -1;
	f[NTRU_P] = 1;

	/* generalization: can initialize f to any polynomial m */
	/* requirements: m has degree exactly p, nonzero constant coefficient */
	for (i = 0; i < NTRU_P; ++i) g[i] = 3 * s[i];
	g[NTRU_P] = 0;

	for (i = 0; i <= LOOPS; ++i)
	{
		u[i] = 0;
	}

	v[0] = 1;

	for (i = 1; i <= LOOPS; ++i)
	{
		v[i] = 0;
	}

	loop = 0;

	for (;;)
	{
		/* e == -1 or d + e + loop <= 2*p */
		/* f has degree p: i.e., f[p]!=0 */
		/* f[i]==0 for i < p-d */
		/* g has degree <=p (so it fits in p+1 coefficients) */
		/* g[i]==0 for i < p-e */
		/* u has degree <=loop (so it fits in loop+1 coefficients) */
		/* u[i]==0 for i < p-d */
		/* if invertible: u[i]==0 for i < loop-p (so can look at just p+1 coefficients) */
		/* v has degree <=loop (so it fits in loop+1 coefficients) */
		/* v[i]==0 for i < p-e */
		/* v[i]==0 for i < loop-p (so can look at just p+1 coefficients) */
		if (loop >= LOOPS)
		{
			break;
		}

		c = modq_quotient(g[NTRU_P], f[NTRU_P]);
		vectormodq_minusproduct(g, NTRU_P + 1, g, f, c);
		vectormodq_shift(g, NTRU_P + 1);

#ifdef SIMPLER
		vectormodq_minusproduct(v, LOOPS + 1, v, u, c);
		vectormodq_shift(v, LOOPS + 1);
#else
		if (loop < NTRU_P)
		{
			vectormodq_minusproduct(v, loop + 1, v, u, c);
			vectormodq_shift(v, loop + 2);
		}
		else
		{
			vectormodq_minusproduct(v + loop - NTRU_P, NTRU_P + 1, v + loop - NTRU_P, u + loop - NTRU_P, c);
			vectormodq_shift(v + loop - NTRU_P, NTRU_P + 2);
		}
#endif

		e -= 1;
		++loop;
		swapmask = smaller_mask(e, d) & modq_nonzero_mask(g[NTRU_P]);
		swap(&e, &d, sizeof e, swapmask);
		swap(f, g, (NTRU_P + 1) * sizeof(int16_t), swapmask);

#ifdef SIMPLER
		swap(u, v, (LOOPS + 1) * sizeof(int16_t), swapmask);
#else
		if (loop < NTRU_P)
		{
			swap(u, v, (loop + 1) * sizeof(int16_t), swapmask);
		}
		else
		{
			swap(u + loop - NTRU_P, v + loop - NTRU_P, (NTRU_P + 1) * sizeof(int16_t), swapmask);
		}
#endif
	}

	c = modq_reciprocal(f[NTRU_P]);
	vectormodq_product(r, NTRU_P, u + NTRU_P, c);
	return smaller_mask(0, d);
}

static int32_t verify32(const uint8_t* x, const uint8_t* y)
{
	uint32_t differentbits = 0;
	size_t i;

	for (i = 0; i < 32; ++i)
	{
		differentbits |= x[i] ^ y[i];
	}

	return (1 & ((differentbits - 1) >> 8)) - 1;
}

mqc_status crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
	int16_t c[NTRU_P];
	int16_t h[NTRU_P];
	int16_t hr[NTRU_P];
	int16_t t[NTRU_P];
	int8_t f[NTRU_P];
	int8_t grecip[NTRU_P];
	uint8_t hash[64];
	int8_t r[NTRU_P];
	uint8_t rstr[NTRU_SMALLENCODE_LEN];
	int8_t t3[NTRU_P];
	size_t i;
	int32_t result = 0;
	int32_t weight;

	small_decode(f, sk);
	small_decode(grecip, sk + NTRU_SMALLENCODE_LEN);
	rq_decode(h, sk + 2 * NTRU_SMALLENCODE_LEN);
	rq_decoderounded(c, ct + 32);
	rq_mult(t, c, f);

	for (i = 0; i < NTRU_P; ++i)
	{
		t3[i] = mod3_freeze(modq_freeze(3 * t[i]));
	}

	r3_mult(r, t3, grecip);
	weight = 0;

	for (i = 0; i < NTRU_P; ++i)
	{
		weight += (1 & r[i]);
	}

	weight -= NTRU_W;
	/* XXX: puts limit on p */
	result |= modq_nonzero_mask(weight);
	rq_mult(hr, h, r);
	rq_round3(hr, hr);

	for (i = 0; i < NTRU_P; ++i)
	{
		result |= modq_nonzero_mask(hr[i] - c[i]);
	}

	small_encode(rstr, r);
	sha3_compute512(hash, rstr, sizeof rstr);
	result |= verify32(hash, ct);

	for (i = 0; i < 32; ++i)
	{
		ss[i] = (hash[32 + i] & ~result);
	}

	return (result == 0) ? MQC_STATUS_SUCCESS : MQC_STATUS_FAILURE;
}

mqc_status crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
	int16_t h[NTRU_P];
	int16_t c[NTRU_P];
	int8_t r[NTRU_P];
	uint8_t rstr[NTRU_SMALLENCODE_LEN];
	uint8_t hash[64];

	small_random_weightw(r);
	small_encode(rstr, r);
	sha3_compute512(hash, rstr, sizeof rstr);
	rq_decode(h, pk);
	rq_mult(c, h, r);
	rq_round3(c, c);
	memcpy(ss, hash + 32, 32);
	memcpy(ct, hash, 32);
	rq_encoderounded(ct + 32, c);

	return MQC_STATUS_SUCCESS;
}

mqc_status crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
{
	int16_t f3recip[NTRU_P];
	int16_t h[NTRU_P];
	int8_t g[NTRU_P];
	int8_t grecip[NTRU_P];
	int8_t f[NTRU_P];

	do
	{
		small_random(g);
	}
	while (r3_recip(grecip, g) != 0);

	small_random_weightw(f);
	rq_recip3(f3recip, f);
	rq_mult(h, f3recip, g);

	rq_encode(pk, h);
	small_encode(sk, f);
	small_encode(sk + NTRU_SMALLENCODE_LEN, grecip);
	memcpy(sk + 2 * NTRU_SMALLENCODE_LEN, pk, NTRU_RQENCODE_LEN);

	return MQC_STATUS_SUCCESS;
}

#else

/* Rounded Product NTRU: L:Prime */

static int16_t modq_fromuint32(uint32_t a)
{
	/* input between 0 and 4294967295 output = (input % 4591) - 2295 */
	int32_t r;

	r = (a & 524287) + (a >> 19) * 914; /* <= 8010861 */

	return modq_freeze(r - 2295);
}

static void rq_fromseed(int16_t* h, const uint8_t* K)
{
	uint32_t buf[NTRU_P];
	size_t i;
	uint8_t n[16];

	for (i = 0; i < 16; i++)
	{
		n[i] = 0;
	}

	/*lint -e534 */
	aes256_generate((uint8_t*)buf, sizeof buf, n, K);

	for (i = 0; i < NTRU_P; ++i)
	{
		h[i] = modq_fromuint32(buf[i]);
	}
}

static void sort(int32_t* x, int32_t n)
{
	int32_t top;
	int32_t p;
	int32_t q;
	int32_t i;

	if (n < 2)
	{
		return;
	}

	top = 1;

	while (top < n - top)
	{
		top += top;
	}

	for (p = top; p > 0; p >>= 1)
	{
		for (i = 0; i < n - p; ++i)
		{
			if (!(i & p))
			{
				minmax(x + i, x + i + p);
			}
		}

		for (q = top; q > p; q >>= 1)
		{
			for (i = 0; i < n - q; ++i)
			{
				if (!(i & p))
				{
					minmax(x + i + p, x + i + q);
				}
			}
		}
	}
}

static void small_seeded_weightw(int8_t* f, const uint8_t* k)
{
	int32_t r[NTRU_P];
	uint8_t n[16];
	size_t i;

	for (i = 0; i < 16; i++)
	{
		n[i] = 0;
	}

	/*lint -e534 */
	aes256_generate((uint8_t*)r, sizeof r, n, k);

	for (i = 0; i < NTRU_P; ++i)
	{
		r[i] ^= 0x80000000;
	}

	for (i = 0; i < NTRU_W; ++i)
	{
		r[i] &= -2;
	}

	for (i = NTRU_W; i < NTRU_P; ++i)
	{
		r[i] = (r[i] & -3) | 1;
	}

	sort(r, NTRU_P);

	for (i = 0; i < NTRU_P; ++i)
	{
		f[i] = ((uint8_t)(r[i] & 3)) - 1;
	}
}

static void small_random_weightw(int8_t* f)
{
	uint8_t k[32];

	/*lint -e534 */
	sysrand_getbytes(k, 32);
	small_seeded_weightw(f, k);
}

static int32_t verify(const uint8_t* x, const uint8_t* y)
{
	uint32_t differentbits = 0;
	size_t i;

	for (i = 0; i < NTRU_CIPHERTEXTBYTES; ++i)
	{
		differentbits |= x[i] ^ y[i];
	}

	return (1 & ((differentbits - 1) >> 8)) - 1;
}

static void hide(uint8_t* cstr, uint8_t* k, const uint8_t* pk, const uint8_t* r)
{
	int16_t G[NTRU_P];
	int16_t A[NTRU_P];
	int16_t B[NTRU_P];
	int16_t C[NTRU_P];
	int8_t b[NTRU_P];
	uint8_t k12[64];
	uint8_t k34[64];
	size_t i;
	int16_t x;

	rq_fromseed(G, pk);
	rq_decoderounded(A, pk + 32);

	sha3_compute512(k12, r, 32);
	small_seeded_weightw(b, k12);
	sha3_compute512(k34, k12 + 32, 32);

	rq_mult(B, G, b);
	rq_round3(B, B);
	rq_mult(C, A, b);

	for (i = 0; i < 256; ++i)
	{
		x = C[i];
		x = modq_sum(x, 2295 * (1 & (r[i / 8] >> (i & 7))));
		x = (((x + 2156) * 114) + 16384) >> 15;
		C[i] = x; /* between 0 and 15 */
	}

	memcpy(cstr, k34, 32);
	cstr += 32;
	memcpy(k, k34 + 32, 32);
	rq_encoderounded(cstr, B);
	cstr += NTRU_RQENCODE_LEN;

	for (i = 0; i < 128; ++i)
	{
		*cstr++ = C[2 * i] + (C[(2 * i) + 1] << 4);
	}
}

mqc_status crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
	int8_t a[NTRU_P];
	int16_t B[NTRU_P];
	int16_t aB[NTRU_P];
	int16_t C[256];
	uint8_t r[32];
	uint8_t checkcstr[NTRU_CIPHERTEXTBYTES];
	uint8_t maybek[32];
	size_t i;
	uint32_t result;

	small_decode(a, sk);
	sk += NTRU_SMALLENCODE_LEN;
	rq_decoderounded(B, ct + 32);
	rq_mult(aB, B, a);

	for (i = 0; i < 128; ++i)
	{
		uint32_t x = ct[32 + NTRU_RQENCODE_LEN + i];
		C[2 * i] = (x & 15) * 287 - 2007;
		C[2 * i + 1] = (x >> 4) * 287 - 2007;
	}

	for (i = 0; i < 256; ++i)
	{
		C[i] = -(modq_freeze(C[i] - aB[i] + 4 * NTRU_W + 1) >> 14);
	}

	for (i = 0; i < 32; ++i)
	{
		r[i] = 0;
	}

	for (i = 0; i < 256; ++i)
	{
		r[i / 8] |= (C[i] << (i & 7));
	}

	hide(checkcstr, maybek, sk, r);
	result = verify(ct, checkcstr);

	for (i = 0; i < 32; ++i)
	{
		ss[i] = maybek[i] & ~result;
	}

	return (result == 0) ? MQC_STATUS_SUCCESS : MQC_STATUS_FAILURE;
}

mqc_status crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
	uint8_t r[32];
	mqc_status ret;

	ret = sysrand_getbytes(r, 32);
	hide(ct, ss, pk, r);

	return ret;
}

mqc_status crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
{
	uint8_t K[32];
	int16_t G[NTRU_P];
	int8_t a[NTRU_P];
	int16_t A[NTRU_P];
	mqc_status ret;

	ret = sysrand_getbytes(K, 32);
	rq_fromseed(G, K);

	small_random_weightw(a);

	rq_mult(A, G, a);
	rq_round3(A, A);

	memcpy(pk, K, 32);
	rq_encoderounded(pk + 32, A);

	small_encode(sk, a);
	memcpy(sk + NTRU_SMALLENCODE_LEN, pk, NTRU_PUBLICKEYBYTES);

	return ret;
}

#endif