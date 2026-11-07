#include "ed25519.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "intrinsics.h"

/* \cond DOXYGEN_NO_DOCUMENT */

/*! \brief X25519 arithmetic and immutable Edwards generator table.
 * \details Based in part on the Botan implementation and public-domain SUPERCOP ref10.
 * Curve decoding, clamping and the Montgomery ladder follow RFC 7748.
 * Reference: x25519_fe.h, x25519_scalarmult.cpp, ed25519_fe.h,
 * ed25519_scalar.cpp, ed25519_ge.cpp, mp_asmi.h, mp_comba.cpp,
 * mp_monty_n.cpp, mp_core.h, donna128.h, mul128.h and ct_utils.h.
 * (C) 2017 Ribose Inc; (C) 1999-2010,2013-2015,2018,2025-2026 Jack Lloyd;
 * (C) 2006 Luca Piccarreta. Group formulas originate in public-domain SUPERCOP ref10.
 * Native 128-bit and split-word paths retain the reference arithmetic schedules.
 */

/* fe */

/*! \brief Immutable arithmetic constant in the declared field representation. */
static const qsc_fe25519 ed25519_d = 
{
	/* 37095705934669439343138083508754565189542113879843219016388785533085940283555 */
	-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116
};

/*! \brief Immutable arithmetic constant in the declared field representation. */
static const qsc_fe25519 fe25519_sqrtm1 = 
{
	/* sqrt(-1) */
	-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482
};

/*! \brief Immutable arithmetic constant in the declared field representation. */
static const qsc_fe25519 ed25519_d2 = 
{
	/* 2 * d = 16295367250680780974490674513165176452449235426866156013048779062215315747161 */
	-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199
};

/* helper */

static int32_t ed25518_is_zero(const uint8_t* n, const size_t nlen)
{
	size_t i;
	uint8_t d;

	d = 0U;

	for (i = 0U; i < nlen; ++i)
	{
		d |= n[i];
	}

	return 1L & (int32_t)((uint32_t)(d - 1U) >> 8);
}

static uint64_t ed25518_load3(const uint8_t* in)
{
	uint64_t res;

	res = (uint64_t)in[0U];
	res |= ((uint64_t)in[1U]) << 8;
	res |= ((uint64_t)in[2U]) << 16;

	return res;
}

static uint64_t ed25518_load4(const uint8_t* in)
{
	uint64_t res;

	res = (uint64_t)in[0U];
	res |= ((uint64_t)in[1U]) << 8;
	res |= ((uint64_t)in[2U]) << 16;
	res |= ((uint64_t)in[3U]) << 24;

	return res;
}

static void ed25518_slide_vartime(int8_t* r, const uint8_t* a)
{
	size_t i;
	int32_t cmp;
	int32_t ribs;

	for (i = 0U; i < 256U; ++i)
	{
		r[i] = 1U & (a[i >> 3] >> (i & 7));
	}

	r[256U] = 0;

	for (i = 0U; i < 257U; ++i)
	{
		int32_t b;

		if (r[i] == 0)
		{
			continue;
		}

		for (b = 1; b <= 6 && i + b < 257; ++b)
		{
			if (r[i + b] == 0)
			{
				continue;
			}

			ribs = r[i + b] << b;
			cmp = r[i] + ribs;

			if (cmp <= 15)
			{
				r[i] = (int8_t)cmp;
				r[i + b] = 0;
			}
			else
			{
				size_t k;

				cmp = r[i] - ribs;

				if (cmp < -15)
				{
					break;
				}

				r[i] = (int8_t)cmp;

				for (k = i + b; k < 257U; ++k)
				{
					if (r[k] == 0)
					{
						r[k] = 1;
						break;
					}

					r[k] = 0;
				}
			}
		}
	}
}

int32_t qsc_sc25519_verify(const uint8_t* x, const uint8_t* y, const size_t n)
{
	size_t i;

	QSC_ASSERT(x != NULL);
	QSC_ASSERT(y != NULL);

	uint16_t d;

	d = 0U;

	for (i = 0U; i < n; ++i)
	{
		d |= x[i] ^ y[i];
	}

	return (1L & ((d - 1) >> 8)) - 1;
}

void qsc_fe25519_0(qsc_fe25519 h)
{
	qsc_memutils_secure_erase(h, 10U * sizeof(int32_t));
}

void qsc_fe25519_1(qsc_fe25519 h)
{
	qsc_memutils_secure_erase(h, 10U * sizeof(int32_t));
	h[0U] = 1;
}

void qsc_fe25519_copy(qsc_fe25519 h, const qsc_fe25519 f)
{
	qsc_memutils_copy((uint8_t*)h, (const uint8_t*)f, 10U * sizeof(int32_t));
}

void qsc_fe25519_add(qsc_fe25519 h, const qsc_fe25519 f, const qsc_fe25519 g)
{
	h[0U] = f[0U] + g[0U];
	h[1U] = f[1U] + g[1U];
	h[2U] = f[2U] + g[2U];
	h[3U] = f[3U] + g[3U];
	h[4U] = f[4U] + g[4U];
	h[5U] = f[5U] + g[5U];
	h[6U] = f[6U] + g[6U];
	h[7U] = f[7U] + g[7U];
	h[8U] = f[8U] + g[8U];
	h[9U] = f[9U] + g[9U];
}

void qsc_fe25519_cswap(qsc_fe25519 f, qsc_fe25519 g, uint32_t b)
{
	const int32_t MASK = -(int32_t)b;
	int32_t f0;
	int32_t f1;
	int32_t f2;
	int32_t f3;
	int32_t f4;
	int32_t f5;
	int32_t f6;
	int32_t f7;
	int32_t f8;
	int32_t f9;
	int32_t g0;
	int32_t g1;
	int32_t g2;
	int32_t g3;
	int32_t g4;
	int32_t g5;
	int32_t g6;
	int32_t g7;
	int32_t g8;
	int32_t g9;
	int32_t x0;
	int32_t x1;
	int32_t x2;
	int32_t x3;
	int32_t x4;
	int32_t x5;
	int32_t x6;
	int32_t x7;
	int32_t x8;
	int32_t x9;

	f0 = f[0U];
	f1 = f[1U];
	f2 = f[2U];
	f3 = f[3U];
	f4 = f[4U];
	f5 = f[5U];
	f6 = f[6U];
	f7 = f[7U];
	f8 = f[8U];
	f9 = f[9U];

	g0 = g[0U];
	g1 = g[1U];
	g2 = g[2U];
	g3 = g[3U];
	g4 = g[4U];
	g5 = g[5U];
	g6 = g[6U];
	g7 = g[7U];
	g8 = g[8U];
	g9 = g[9U];

	x0 = f0 ^ g0;
	x1 = f1 ^ g1;
	x2 = f2 ^ g2;
	x3 = f3 ^ g3;
	x4 = f4 ^ g4;
	x5 = f5 ^ g5;
	x6 = f6 ^ g6;
	x7 = f7 ^ g7;
	x8 = f8 ^ g8;
	x9 = f9 ^ g9;

	x0 &= MASK;
	x1 &= MASK;
	x2 &= MASK;
	x3 &= MASK;
	x4 &= MASK;
	x5 &= MASK;
	x6 &= MASK;
	x7 &= MASK;
	x8 &= MASK;
	x9 &= MASK;

	f[0U] = f0 ^ x0;
	f[1U] = f1 ^ x1;
	f[2U] = f2 ^ x2;
	f[3U] = f3 ^ x3;
	f[4U] = f4 ^ x4;
	f[5U] = f5 ^ x5;
	f[6U] = f6 ^ x6;
	f[7U] = f7 ^ x7;
	f[8U] = f8 ^ x8;
	f[9U] = f9 ^ x9;

	g[0U] = g0 ^ x0;
	g[1U] = g1 ^ x1;
	g[2U] = g2 ^ x2;
	g[3U] = g3 ^ x3;
	g[4U] = g4 ^ x4;
	g[5U] = g5 ^ x5;
	g[6U] = g6 ^ x6;
	g[7U] = g7 ^ x7;
	g[8U] = g8 ^ x8;
	g[9U] = g9 ^ x9;
}

void qsc_fe25519_sub(qsc_fe25519 h, const qsc_fe25519 f, const qsc_fe25519 g)
{
	/* h = f - g
	 * Can overlap h with f or g.
	 * Preconditions:
	 * |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	 * |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	 * Postconditions:
	 * |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc. */
	h[0U] = f[0U] - g[0U];
	h[1U] = f[1U] - g[1U];
	h[2U] = f[2U] - g[2U];
	h[3U] = f[3U] - g[3U];
	h[4U] = f[4U] - g[4U];
	h[5U] = f[5U] - g[5U];
	h[6U] = f[6U] - g[6U];
	h[7U] = f[7U] - g[7U];
	h[8U] = f[8U] - g[8U];
	h[9U] = f[9U] - g[9U];
}

void qsc_fe25519_neg(qsc_fe25519 h, const qsc_fe25519 f)
{
	h[0U] = -f[0U];
	h[1U] = -f[1U];
	h[2U] = -f[2U];
	h[3U] = -f[3U];
	h[4U] = -f[4U];
	h[5U] = -f[5U];
	h[6U] = -f[6U];
	h[7U] = -f[7U];
	h[8U] = -f[8U];
	h[9U] = -f[9U];
}

void qsc_fe25519_cmov(qsc_fe25519 f, const qsc_fe25519 g, uint32_t b)
{
	const int32_t MASK = -(int32_t)b;
	int32_t f0;
	int32_t f1;
	int32_t f2;
	int32_t f3;
	int32_t f4;
	int32_t f5;
	int32_t f6;
	int32_t f7;
	int32_t f8;
	int32_t f9;

	f0 = f[0U];
	f1 = f[1U];
	f2 = f[2U];
	f3 = f[3U];
	f4 = f[4U];
	f5 = f[5U];
	f6 = f[6U];
	f7 = f[7U];
	f8 = f[8U];
	f9 = f[9U];

	f0 ^= ((f0 ^ g[0U]) & MASK);
	f1 ^= ((f1 ^ g[1U]) & MASK);
	f2 ^= ((f2 ^ g[2U]) & MASK);
	f3 ^= ((f3 ^ g[3U]) & MASK);
	f4 ^= ((f4 ^ g[4U]) & MASK);
	f5 ^= ((f5 ^ g[5U]) & MASK);
	f6 ^= ((f6 ^ g[6U]) & MASK);
	f7 ^= ((f7 ^ g[7U]) & MASK);
	f8 ^= ((f8 ^ g[8U]) & MASK);
	f9 ^= ((f9 ^ g[9U]) & MASK);

	f[0U] = f0;
	f[1U] = f1;
	f[2U] = f2;
	f[3U] = f3;
	f[4U] = f4;
	f[5U] = f5;
	f[6U] = f6;
	f[7U] = f7;
	f[8U] = f8;
	f[9U] = f9;
}

int32_t qsc_fe25519_is_negative(const qsc_fe25519 f)
{
	uint8_t s[32U] = { 0U };

	qsc_fe25519_to_bytes(s, f);

	return s[0U] & 1;
}

int32_t qsc_fe25519_is_zero(const qsc_fe25519 f)
{
	uint8_t s[32U] = { 0U };

	qsc_fe25519_to_bytes(s, f);

	return ed25518_is_zero(s, 32U);
}

void qsc_fe25519_mul(qsc_fe25519 h, const qsc_fe25519 f, const qsc_fe25519 g)
{
	int64_t carry;
	int64_t f0;
	int64_t f1;
	int64_t f2;
	int64_t f3;
	int64_t f4;
	int64_t f5;
	int64_t f6;
	int64_t f7;
	int64_t f8;
	int64_t f9;
	int64_t f1x2;
	int64_t f3x2;
	int64_t f5x2;
	int64_t f7x2;
	int64_t f9x2;
	int64_t g0;
	int64_t g1;
	int64_t g2;
	int64_t g3;
	int64_t g4;
	int64_t g5;
	int64_t g6;
	int64_t g7;
	int64_t g8;
	int64_t g9;
	int64_t g1x19;
	int64_t g2x19;
	int64_t g3x19;
	int64_t g4x19;
	int64_t g5x19;
	int64_t g6x19;
	int64_t g7x19;
	int64_t g8x19;
	int64_t g9x19;
	int64_t h0;
	int64_t h1;
	int64_t h2;
	int64_t h3;
	int64_t h4;
	int64_t h5;
	int64_t h6;
	int64_t h7;
	int64_t h8;
	int64_t h9;

	f0 = (int64_t)f[0U];
	f1 = (int64_t)f[1U];
	f2 = (int64_t)f[2U];
	f3 = (int64_t)f[3U];
	f4 = (int64_t)f[4U];
	f5 = (int64_t)f[5U];
	f6 = (int64_t)f[6U];
	f7 = (int64_t)f[7U];
	f8 = (int64_t)f[8U];
	f9 = (int64_t)f[9U];
	g0 = (int64_t)g[0U];
	g1 = (int64_t)g[1U];
	g2 = (int64_t)g[2U];
	g3 = (int64_t)g[3U];
	g4 = (int64_t)g[4U];
	g5 = (int64_t)g[5U];
	g6 = (int64_t)g[6U];
	g7 = (int64_t)g[7U];
	g8 = (int64_t)g[8U];
	g9 = (int64_t)g[9U];

	/* 1.959375*2^29 */
	g1x19 = 19 * g1;
	/* 1.959375*2^30; still ok */
	g2x19 = 19 * g2;
	g3x19 = 19 * g3;
	g4x19 = 19 * g4;
	g5x19 = 19 * g5;
	g6x19 = 19 * g6;
	g7x19 = 19 * g7;
	g8x19 = 19 * g8;
	g9x19 = 19 * g9;
	f1x2 = 2 * f1;
	f3x2 = 2 * f3;
	f5x2 = 2 * f5;
	f7x2 = 2 * f7;
	f9x2 = 2 * f9;

	h0 = (f0 * g0) + (f1x2 * g9x19) + (f2 * g8x19) + (f3x2 * g7x19) + (f4 * g6x19) + (f5x2 * g5x19) + (f6 * g4x19) + (f7x2 * g3x19) + (f8 * g2x19) + (f9x2 * g1x19);
	h1 = (f0 * g1) + (f1 * g0) + (f2 * g9x19) + (f3 * g8x19) + (f4 * g7x19) + (f5 * g6x19) + (f6 * g5x19) + (f7 * g4x19) + (f8 * g3x19) + (f9 * g2x19);
	h2 = (f0 * g2) + (f1x2 * g1) + (f2 * g0) + (f3x2 * g9x19) + (f4 * g8x19) + (f5x2 * g7x19) + (f6 * g6x19) + (f7x2 * g5x19) + (f8 * g4x19) + (f9x2 * g3x19);
	h3 = (f0 * g3) + (f1 * g2) + (f2 * g1) + (f3 * g0) + (f4 * g9x19) + (f5 * g8x19) + (f6 * g7x19) + (f7 * g6x19) + (f8 * g5x19) + (f9 * g4x19);
	h4 = (f0 * g4) + (f1x2 * g3) + (f2 * g2) + (f3x2 * g1) + (f4 * g0) + (f5x2 * g9x19) + (f6 * g8x19) + (f7x2 * g7x19) + (f8 * g6x19) + (f9x2 * g5x19);
	h5 = (f0 * g5) + (f1 * g4) + (f2 * g3) + (f3 * g2) + (f4 * g1) + (f5 * g0) + (f6 * g9x19) + (f7 * g8x19) + (f8 * g7x19) + (f9 * g6x19);
	h6 = (f0 * g6) + (f1x2 * g5) + (f2 * g4) + (f3x2 * g3) + (f4 * g2) + (f5x2 * g1) + (f6 * g0) + (f7x2 * g9x19) + (f8 * g8x19) + (f9x2 * g7x19);
	h7 = (f0 * g7) + (f1 * g6) + (f2 * g5) + (f3 * g4) + (f4 * g3) + (f5 * g2) + (f6 * g1) + (f7 * g0) + (f8 * g9x19) + (f9 * g8x19);
	h8 = (f0 * g8) + (f1x2 * g7) + (f2 * g6) + (f3x2 * g5) + (f4 * g4) + (f5x2 * g3) + (f6 * g2) + (f7x2 * g1) + (f8 * g0) + (f9x2 * g9x19);
	h9 = (f0 * g9) + (f1 * g8) + (f2 * g7) + (f3 * g6) + (f4 * g5) + (f5 * g4) + (f6 * g3) + (f7 * g2) + (f8 * g1) + (f9 * g0);

	/* |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
	 i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
	 |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
	 i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9 */
	carry = (h0 + (1 << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1 << 26);
	carry = (h4 + (1 << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1 << 26);
	/* |h0| <= 2^25 */
	/* |h4| <= 2^25 */
	/* |h1| <= 1.71*2^59 */
	/* |h5| <= 1.71*2^59 */
	carry = (h1 + (1 << 24)) >> 25;
	h2 += carry;
	h1 -= carry * (1 << 25);
	carry = (h5 + (1 << 24)) >> 25;
	h6 += carry;
	h5 -= carry * (1 << 25);
	/* |h1| <= 2^24; from now on fits into int32 */
	/* |h5| <= 2^24; from now on fits into int32 */
	/* |h2| <= 1.41*2^60 */
	/* |h6| <= 1.41*2^60 */
	carry = (h2 + (1 << 25)) >> 26;
	h3 += carry;
	h2 -= carry * (1 << 26);
	carry = (h6 + (1 << 25)) >> 26;
	h7 += carry;
	h6 -= carry * (1 << 26);
	/* |h2| <= 2^25; from now on fits into int32 unchanged */
	/* |h6| <= 2^25; from now on fits into int32 unchanged */
	/* |h3| <= 1.71*2^59 */
	/* |h7| <= 1.71*2^59 */
	carry = (h3 + (1 << 24)) >> 25;
	h4 += carry;
	h3 -= carry * (1 << 25);
	carry = (h7 + (1 << 24)) >> 25;
	h8 += carry;
	h7 -= carry * (1 << 25);
	/* |h3| <= 2^24; from now on fits into int32 unchanged */
	/* |h7| <= 2^24; from now on fits into int32 unchanged */
	/* |h4| <= 1.72*2^34 */
	/* |h8| <= 1.41*2^60 */
	carry = (h4 + (1 << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1 << 26);
	carry = (h8 + (1 << 25)) >> 26;
	h9 += carry;
	h8 -= carry * (1 << 26);
	/* |h4| <= 2^25; from now on fits into int32 unchanged */
	/* |h8| <= 2^25; from now on fits into int32 unchanged */
	/* |h5| <= 1.01*2^24 */
	/* |h9| <= 1.71*2^59 */
	carry = (h9 + (1 << 24)) >> 25;
	h0 += carry * 19;
	h9 -= carry * (1 << 25);
	/* |h9| <= 2^24; from now on fits into int32 unchanged */
	/* |h0| <= 1.1*2^39 */
	carry = (h0 + (1 << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1 << 26);
	/* |h0| <= 2^25; from now on fits into int32 unchanged */
	/* |h1| <= 1.01*2^24 */

	h[0U] = (int32_t)h0;
	h[1U] = (int32_t)h1;
	h[2U] = (int32_t)h2;
	h[3U] = (int32_t)h3;
	h[4U] = (int32_t)h4;
	h[5U] = (int32_t)h5;
	h[6U] = (int32_t)h6;
	h[7U] = (int32_t)h7;
	h[8U] = (int32_t)h8;
	h[9U] = (int32_t)h9;
}

void qsc_fe25519_mul32(qsc_fe25519 h, const qsc_fe25519 f, uint32_t n)
{
	int64_t carry;
	int64_t h0;
	int64_t h1;
	int64_t h2;
	int64_t h3;
	int64_t h4;
	int64_t h5;
	int64_t h6;
	int64_t h7;
	int64_t h8;
	int64_t h9;
	int64_t sn;

	sn = (int64_t)n;
	h0 = f[0U] * sn;
	h1 = f[1U] * sn;
	h2 = f[2U] * sn;
	h3 = f[3U] * sn;
	h4 = f[4U] * sn;
	h5 = f[5U] * sn;
	h6 = f[6U] * sn;
	h7 = f[7U] * sn;
	h8 = f[8U] * sn;
	h9 = f[9U] * sn;

	carry = (h9 + (1 << 24)) >> 25;
	h0 += carry * 19;
	h9 -= carry * (1 << 25);
	carry = (h1 + (1 << 24)) >> 25;
	h2 += carry;
	h1 -= carry * (1 << 25);
	carry = (h3 + (1 << 24)) >> 25;
	h4 += carry;
	h3 -= carry * (1 << 25);
	carry = (h5 + (1 << 24)) >> 25;
	h6 += carry;
	h5 -= carry * (1 << 25);
	carry = (h7 + (1 << 24)) >> 25;
	h8 += carry;
	h7 -= carry * (1 << 25);

	carry = (h0 + (1 << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1 << 26);
	carry = (h2 + (1 << 25)) >> 26;
	h3 += carry;
	h2 -= carry * (1 << 26);
	carry = (h4 + (1 << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1 << 26);
	carry = (h6 + (1 << 25)) >> 26;
	h7 += carry;
	h6 -= carry * (1 << 26);
	carry = (h8 + (1 << 25)) >> 26;
	h9 += carry;
	h8 -= carry * (1 << 26);

	h[0U] = (int32_t)h0;
	h[1U] = (int32_t)h1;
	h[2U] = (int32_t)h2;
	h[3U] = (int32_t)h3;
	h[4U] = (int32_t)h4;
	h[5U] = (int32_t)h5;
	h[6U] = (int32_t)h6;
	h[7U] = (int32_t)h7;
	h[8U] = (int32_t)h8;
	h[9U] = (int32_t)h9;
}

void qsc_fe25519_sq(qsc_fe25519 h, const qsc_fe25519 f)
{
	int64_t carry;
	int64_t f0;
	int64_t f1;
	int64_t f2;
	int64_t f3;
	int64_t f4;
	int64_t f5;
	int64_t f6;
	int64_t f7;
	int64_t f8;
	int64_t f9;
	int64_t f0x2;
	int64_t f1x2;
	int64_t f2x2;
	int64_t f3x2;
	int64_t f4x2;
	int64_t f5x2;
	int64_t f6x2;
	int64_t f7x2;
	int64_t f5x38;
	int64_t f6x19;
	int64_t f7x38;
	int64_t f8x19;
	int64_t f9x38;
	int64_t f0f0;
	int64_t f0f1x2;
	int64_t f0f2x2;
	int64_t f0f3x2;
	int64_t f0f4x2;
	int64_t f0f5x2;
	int64_t f0f6x2;
	int64_t f0f7x2;
	int64_t f0f8x2;
	int64_t f0f9x2;
	int64_t f1f1x2;
	int64_t f1f2x2;
	int64_t f1f3x4;
	int64_t f1f4x2;
	int64_t f1f5x4;
	int64_t f1f6x2;
	int64_t f1f7x4;
	int64_t f1f8x2;
	int64_t f1f9x76;
	int64_t h0;
	int64_t h1;
	int64_t h2;
	int64_t h3;
	int64_t h4;
	int64_t h5;
	int64_t h6;
	int64_t h7;
	int64_t h8;
	int64_t h9;

	f0 = (int64_t)f[0U];
	f1 = (int64_t)f[1U];
	f2 = (int64_t)f[2U];
	f3 = (int64_t)f[3U];
	f4 = (int64_t)f[4U];
	f5 = (int64_t)f[5U];
	f6 = (int64_t)f[6U];
	f7 = (int64_t)f[7U];
	f8 = (int64_t)f[8U];
	f9 = (int64_t)f[9U];

	f0x2 = 2 * f0;
	f1x2 = 2 * f1;
	f2x2 = 2 * f2;
	f3x2 = 2 * f3;
	f4x2 = 2 * f4;
	f5x2 = 2 * f5;
	f6x2 = 2 * f6;
	f7x2 = 2 * f7;
	/* 1.959375*2^30 */
	f5x38 = 38 * f5;
	/* 1.959375*2^30 */
	f6x19 = 19 * f6;
	/* 1.959375*2^30 */
	f7x38 = 38 * f7;
	/* 1.959375*2^30 */
	f8x19 = 19 * f8;
	/* 1.959375*2^30 */
	f9x38 = 38 * f9;

	f0f0 = f0 * f0;
	f0f1x2 = f0x2 * f1;
	f0f2x2 = f0x2 * f2;
	f0f3x2 = f0x2 * f3;
	f0f4x2 = f0x2 * f4;
	f0f5x2 = f0x2 * f5;
	f0f6x2 = f0x2 * f6;
	f0f7x2 = f0x2 * f7;
	f0f8x2 = f0x2 * f8;
	f0f9x2 = f0x2 * f9;
	f1f1x2 = f1x2 * f1;
	f1f2x2 = f1x2 * f2;
	f1f3x4 = f1x2 * f3x2;
	f1f4x2 = f1x2 * f4;
	f1f5x4 = f1x2 * f5x2;
	f1f6x2 = f1x2 * f6;
	f1f7x4 = f1x2 * f7x2;
	f1f8x2 = f1x2 * f8;
	f1f9x76 = f1x2 * f9x38;

	h0 = f0f0 + f1f9x76 + (f2x2 * f8x19) + (f3x2 * f7x38) + (f4x2 * f6x19) + (f5 * f5x38);
	h1 = f0f1x2 + (f2 * f9x38) + (f3x2 * f8x19) + (f4 * f7x38) + (f5x2 * f6x19);
	h2 = f0f2x2 + f1f1x2 + (f3x2 * f9x38) + (f4x2 * f8x19) + (f5x2 * f7x38) + (f6 * f6x19);
	h3 = f0f3x2 + f1f2x2 + (f4 * f9x38) + (f5x2 * f8x19) + (f6 * f7x38);
	h4 = f0f4x2 + f1f3x4 + (f2 * f2) + (f5x2 * f9x38) + (f6x2 * f8x19) + (f7 * f7x38);
	h5 = f0f5x2 + f1f4x2 + (f2x2 * f3) + (f6 * f9x38) + (f7x2 * f8x19);
	h6 = f0f6x2 + f1f5x4 + (f2x2 * f4) + (f3x2 * f3) + (f7x2 * f9x38) + (f8 * f8x19);
	h7 = f0f7x2 + f1f6x2 + (f2x2 * f5) + (f3x2 * f4) + (f8 * f9x38);
	h8 = f0f8x2 + f1f7x4 + (f2x2 * f6) + (f3x2 * f5x2) + (f4 * f4) + (f9 * f9x38);
	h9 = f0f9x2 + f1f8x2 + (f2x2 * f7) + (f3x2 * f6) + (f4x2 * f5);

	carry = (h0 + (1 << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1 << 26);
	carry = (h4 + (1 << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1 << 26);

	carry = (h1 + (1 << 24)) >> 25;
	h2 += carry;
	h1 -= carry * (1 << 25);
	carry = (h5 + (1 << 24)) >> 25;
	h6 += carry;
	h5 -= carry * (1 << 25);

	carry = (h2 + (1 << 25)) >> 26;
	h3 += carry;
	h2 -= carry * (1 << 26);
	carry = (h6 + (1 << 25)) >> 26;
	h7 += carry;
	h6 -= carry * (1 << 26);

	carry = (h3 + (1 << 24)) >> 25;
	h4 += carry;
	h3 -= carry * (1 << 25);
	carry = (h7 + (1 << 24)) >> 25;
	h8 += carry;
	h7 -= carry * (1 << 25);

	carry = (h4 + (1 << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1 << 26);
	carry = (h8 + (1 << 25)) >> 26;
	h9 += carry;
	h8 -= carry * (1 << 26);

	carry = (h9 + (1 << 24)) >> 25;
	h0 += carry * 19;
	h9 -= carry * (1 << 25);

	carry = (h0 + (1 << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1 << 26);

	h[0U] = (int32_t)h0;
	h[1U] = (int32_t)h1;
	h[2U] = (int32_t)h2;
	h[3U] = (int32_t)h3;
	h[4U] = (int32_t)h4;
	h[5U] = (int32_t)h5;
	h[6U] = (int32_t)h6;
	h[7U] = (int32_t)h7;
	h[8U] = (int32_t)h8;
	h[9U] = (int32_t)h9;
}

void qsc_fe25519_sq2(qsc_fe25519 h, const qsc_fe25519 f)
{
	/* h = 2 * f * f
	* Can overlap h with f.
	* Preconditions:
	* |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
	* Postconditions:
	* |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc. */
	int64_t carry;
	int64_t f0;
	int64_t f1;
	int64_t f2;
	int64_t f3;
	int64_t f4;
	int64_t f5;
	int64_t f6;
	int64_t f7;
	int64_t f8;
	int64_t f9;
	int64_t f0x2;
	int64_t f1x2;
	int64_t f2x2;
	int64_t f3x2;
	int64_t f4x2;
	int64_t f5x2;
	int64_t f6x2;
	int64_t f7x2;
	int64_t f5x38;
	int64_t f6x19;
	int64_t f7x38;
	int64_t f8x19;
	int64_t f9x38;
	int64_t h0;
	int64_t h1;
	int64_t h2;
	int64_t h3;
	int64_t h4;
	int64_t h5;
	int64_t h6;
	int64_t h7;
	int64_t h8;
	int64_t h9;

	f0 = (int64_t)f[0U];
	f1 = (int64_t)f[1U];
	f2 = (int64_t)f[2U];
	f3 = (int64_t)f[3U];
	f4 = (int64_t)f[4U];
	f5 = (int64_t)f[5U];
	f6 = (int64_t)f[6U];
	f7 = (int64_t)f[7U];
	f8 = (int64_t)f[8U];
	f9 = (int64_t)f[9U];

	f0x2 = 2 * f0;
	f1x2 = 2 * f1;
	f2x2 = 2 * f2;
	f3x2 = 2 * f3;
	f4x2 = 2 * f4;
	f5x2 = 2 * f5;
	f6x2 = 2 * f6;
	f7x2 = 2 * f7;
	/* 1.959375*2^30 */
	f5x38 = 38 * f5;
	/* 1.959375*2^30 */
	f6x19 = 19 * f6;
	/* 1.959375*2^30 */
	f7x38 = 38 * f7;
	/* 1.959375*2^30 */
	f8x19 = 19 * f8;
	/* 1.959375*2^30 */
	f9x38 = 38 * f9;

	h0 = (f0 * f0) + (f1x2 * f9x38) + (f2x2 * f8x19) + (f3x2 * f7x38) + (f4x2 * f6x19) + (f5 * f5x38);
	h1 = (f0x2 * f1) + (f2 * f9x38) + (f3x2 * f8x19) + (f4 * f7x38) + (f5x2 * f6x19);
	h2 = (f0x2 * f2) + (f1x2 * f1) + (f3x2 * f9x38) + (f4x2 * f8x19) + (f5x2 * f7x38) + (f6 * f6x19);
	h3 = (f0x2 * f3) + (f1x2 * f2) + (f4 * f9x38) + (f5x2 * f8x19) + (f6 * f7x38);
	h4 = (f0x2 * f4) + (f1x2 * f3x2) + (f2 * f2) + (f5x2 * f9x38) + (f6x2 * f8x19) + (f7 * f7x38);
	h5 = (f0x2 * f5) + (f1x2 * f4) + (f2x2 * f3) + (f6 * f9x38) + (f7x2 * f8x19);
	h6 = (f0x2 * f6) + (f1x2 * f5x2) + (f2x2 * f4) + (f3x2 * f3) + (f7x2 * f9x38) + (f8 * f8x19);
	h7 = (f0x2 * f7) + (f1x2 * f6) + (f2x2 * f5) + (f3x2 * f4) + (f8 * f9x38);
	h8 = (f0x2 * f8) + (f1x2 * f7x2) + (f2x2 * f6) + (f3x2 * f5x2) + (f4 * f4) + (f9 * f9x38);
	h9 = (f0x2 * f9) + (f1x2 * f8) + (f2x2 * f7) + (f3x2 * f6) + (f4x2 * f5);

	h0 += h0;
	h1 += h1;
	h2 += h2;
	h3 += h3;
	h4 += h4;
	h5 += h5;
	h6 += h6;
	h7 += h7;
	h8 += h8;
	h9 += h9;

	carry = (h0 + (1 << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1 << 26);
	carry = (h4 + (1 << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1 << 26);

	carry = (h1 + (1 << 24)) >> 25;
	h2 += carry;
	h1 -= carry * (1 << 25);
	carry = (h5 + (1 << 24)) >> 25;
	h6 += carry;
	h5 -= carry * (1 << 25);

	carry = (h2 + (1 << 25)) >> 26;
	h3 += carry;
	h2 -= carry * (1 << 26);
	carry = (h6 + (1 << 25)) >> 26;
	h7 += carry;
	h6 -= carry * (1 << 26);

	carry = (h3 + (1 << 24)) >> 25;
	h4 += carry;
	h3 -= carry * (1 << 25);
	carry = (h7 + (1 << 24)) >> 25;
	h8 += carry;
	h7 -= carry * (1 << 25);

	carry = (h4 + (1 << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1 << 26);
	carry = (h8 + (1 << 25)) >> 26;
	h9 += carry;
	h8 -= carry * (1 << 26);

	carry = (h9 + (1 << 24)) >> 25;
	h0 += carry * 19;
	h9 -= carry * (1 << 25);

	carry = (h0 + (1 << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1 << 26);

	h[0U] = (int32_t)h0;
	h[1U] = (int32_t)h1;
	h[2U] = (int32_t)h2;
	h[3U] = (int32_t)h3;
	h[4U] = (int32_t)h4;
	h[5U] = (int32_t)h5;
	h[6U] = (int32_t)h6;
	h[7U] = (int32_t)h7;
	h[8U] = (int32_t)h8;
	h[9U] = (int32_t)h9;
}

void qsc_fe25519_from_bytes(qsc_fe25519 h, const uint8_t* s)
{
	int64_t carry;
	int64_t h0;
	int64_t h1;
	int64_t h2;
	int64_t h3;
	int64_t h4;
	int64_t h5;
	int64_t h6;
	int64_t h7;
	int64_t h8;
	int64_t h9;

	h0 = ed25518_load4(s);
	h1 = ed25518_load3(s + 4) << 6;
	h2 = ed25518_load3(s + 7) << 5;
	h3 = ed25518_load3(s + 10) << 3;
	h4 = ed25518_load3(s + 13) << 2;
	h5 = ed25518_load4(s + 16);
	h6 = ed25518_load3(s + 20) << 7;
	h7 = ed25518_load3(s + 23) << 5;
	h8 = ed25518_load3(s + 26) << 4;
	h9 = (ed25518_load3(s + 29) & 8388607) << 2;

	carry = (h9 + (1 << 24)) >> 25;
	h0 += carry * 19;
	h9 -= carry * (1 << 25);
	carry = (h1 + (1 << 24)) >> 25;
	h2 += carry;
	h1 -= carry * (1 << 25);
	carry = (h3 + (1 << 24)) >> 25;
	h4 += carry;
	h3 -= carry * (1 << 25);
	carry = (h5 + (1 << 24)) >> 25;
	h6 += carry;
	h5 -= carry * (1 << 25);
	carry = (h7 + (1 << 24)) >> 25;
	h8 += carry;
	h7 -= carry * (1 << 25);

	carry = (h0 + (1 << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1 << 26);
	carry = (h2 + (1 << 25)) >> 26;
	h3 += carry;
	h2 -= carry * (1 << 26);
	carry = (h4 + (1 << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1 << 26);
	carry = (h6 + (1 << 25)) >> 26;
	h7 += carry;
	h6 -= carry * (1 << 26);
	carry = (h8 + (1 << 25)) >> 26;
	h9 += carry;
	h8 -= carry * (1 << 26);

	h[0U] = (int32_t)h0;
	h[1U] = (int32_t)h1;
	h[2U] = (int32_t)h2;
	h[3U] = (int32_t)h3;
	h[4U] = (int32_t)h4;
	h[5U] = (int32_t)h5;
	h[6U] = (int32_t)h6;
	h[7U] = (int32_t)h7;
	h[8U] = (int32_t)h8;
	h[9U] = (int32_t)h9;
}

void qsc_fe25519_reduce(qsc_fe25519 h, const qsc_fe25519 f)
{
	/* Preconditions:
	* |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
	* Write p=2^255-19; q=floor(h/p).
	* Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).
	* Proof:
	* Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
	* Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.
	* Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
	* Then 0<y<1.
	* Write r=h-pq.
	* Have 0<=r<=p-1=2^255-20.
	* Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.
	* Write x=r+19(2^-255)r+y.
	* Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.
	* Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
	* so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q. */
	int32_t carry;
	int32_t h0;
	int32_t h1;
	int32_t h2;
	int32_t h3;
	int32_t h4;
	int32_t h5;
	int32_t h6;
	int32_t h7;
	int32_t h8;
	int32_t h9;
	int32_t q;

	h0 = f[0U];
	h1 = f[1U];
	h2 = f[2U];
	h3 = f[3U];
	h4 = f[4U];
	h5 = f[5U];
	h6 = f[6U];
	h7 = f[7U];
	h8 = f[8U];
	h9 = f[9U];

	q = (19 * h9 + (INT64_C(1) << 24)) >> 25;
	q = (h0 + q) >> 26;
	q = (h1 + q) >> 25;
	q = (h2 + q) >> 26;
	q = (h3 + q) >> 25;
	q = (h4 + q) >> 26;
	q = (h5 + q) >> 25;
	q = (h6 + q) >> 26;
	q = (h7 + q) >> 25;
	q = (h8 + q) >> 26;
	q = (h9 + q) >> 25;

	/* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
	h0 += 19 * q;
	/* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */
	carry = h0 >> 26;
	h1 += carry;
	h0 -= carry * (INT64_C(1) << 26);
	carry = h1 >> 25;
	h2 += carry;
	h1 -= carry * (INT64_C(1) << 25);
	carry = h2 >> 26;
	h3 += carry;
	h2 -= carry * (INT64_C(1) << 26);
	carry = h3 >> 25;
	h4 += carry;
	h3 -= carry * (INT64_C(1) << 25);
	carry = h4 >> 26;
	h5 += carry;
	h4 -= carry * (INT64_C(1) << 26);
	carry = h5 >> 25;
	h6 += carry;
	h5 -= carry * (INT64_C(1) << 25);
	carry = h6 >> 26;
	h7 += carry;
	h6 -= carry * (INT64_C(1) << 26);
	carry = h7 >> 25;
	h8 += carry;
	h7 -= carry * (INT64_C(1) << 25);
	carry = h8 >> 26;
	h9 += carry;
	h8 -= carry * (INT64_C(1) << 26);
	carry = h9 >> 25;
	h9 -= carry * (INT64_C(1) << 25);

	h[0U] = h0;
	h[1U] = h1;
	h[2U] = h2;
	h[3U] = h3;
	h[4U] = h4;
	h[5U] = h5;
	h[6U] = h6;
	h[7U] = h7;
	h[8U] = h8;
	h[9U] = h9;
}

void qsc_fe25519_to_bytes(uint8_t* s, const qsc_fe25519 h)
{
	QSC_ASSERT(s != NULL);

	qsc_fe25519 t = { 0 };

	qsc_fe25519_reduce(t, h);

	s[0U] = (uint8_t)t[0U];
	s[1U] = (uint8_t)(t[0U] >> 8);
	s[2U] = (uint8_t)(t[0U] >> 16);
	s[3U] = (uint8_t)((t[0U] >> 24) | (t[1U] * (INT64_C(1) << 2)));
	s[4U] = (uint8_t)(t[1U] >> 6);
	s[5U] = (uint8_t)(t[1U] >> 14);
	s[6U] = (uint8_t)((t[1U] >> 22) | (t[2U] * (INT64_C(1) << 3)));
	s[7U] = (uint8_t)(t[2U] >> 5);
	s[8U] = (uint8_t)(t[2U] >> 13);
	s[9U] = (uint8_t)((t[2U] >> 21) | (t[3U] * (INT64_C(1) << 5)));
	s[10U] = (uint8_t)(t[3U] >> 3);
	s[11U] = (uint8_t)(t[3U] >> 11);
	s[12U] = (uint8_t)((t[3U] >> 19) | (t[4U] * (INT64_C(1) << 6)));
	s[13U] = (uint8_t)(t[4U] >> 2);
	s[14U] = (uint8_t)(t[4U] >> 10);
	s[15U] = (uint8_t)(t[4U] >> 18);
	s[16U] = (uint8_t)t[5U];
	s[17U] = (uint8_t)(t[5U] >> 8);
	s[18U] = (uint8_t)(t[5U] >> 16);
	s[19U] = (uint8_t)((t[5U] >> 24) | (t[6U] * (INT64_C(1) << 1)));
	s[20U] = (uint8_t)(t[6U] >> 7);
	s[21U] = (uint8_t)(t[6U] >> 15);
	s[22U] = (uint8_t)((t[6U] >> 23) | (t[7U] * (INT64_C(1) << 3)));
	s[23U] = (uint8_t)(t[7U] >> 5);
	s[24U] = (uint8_t)(t[7U] >> 13);
	s[25U] = (uint8_t)((t[7U] >> 21) | (t[8U] * (INT64_C(1) << 4)));
	s[26U] = (uint8_t)(t[8U] >> 4);
	s[27U] = (uint8_t)(t[8U] >> 12);
	s[28U] = (uint8_t)((t[8U] >> 20) | (t[9U] * (INT64_C(1) << 6)));
	s[29U] = (uint8_t)(t[9U] >> 2);
	s[30U] = (uint8_t)(t[9U] >> 10);
	s[31U] = (uint8_t)(t[9U] >> 18);
}

static void fe25519_pow22523(qsc_fe25519 out, const qsc_fe25519 z)
{
	qsc_fe25519 t0 = { 0 };
	qsc_fe25519 t1 = { 0 };
	qsc_fe25519 t2 = { 0 };
	size_t i;

	qsc_fe25519_sq(t0, z);
	qsc_fe25519_sq(t1, t0);
	qsc_fe25519_sq(t1, t1);
	qsc_fe25519_mul(t1, z, t1);
	qsc_fe25519_mul(t0, t0, t1);
	qsc_fe25519_sq(t0, t0);
	qsc_fe25519_mul(t0, t1, t0);
	qsc_fe25519_sq(t1, t0);

	for (i = 1; i < 5; ++i)
	{
		qsc_fe25519_sq(t1, t1);
	}

	qsc_fe25519_mul(t0, t1, t0);
	qsc_fe25519_sq(t1, t0);

	for (i = 1; i < 10; ++i)
	{
		qsc_fe25519_sq(t1, t1);
	}

	qsc_fe25519_mul(t1, t1, t0);
	qsc_fe25519_sq(t2, t1);

	for (i = 1; i < 20; ++i)
	{
		qsc_fe25519_sq(t2, t2);
	}

	qsc_fe25519_mul(t1, t2, t1);

	for (i = 1; i < 11; ++i)
	{
		qsc_fe25519_sq(t1, t1);
	}

	qsc_fe25519_mul(t0, t1, t0);
	qsc_fe25519_sq(t1, t0);

	for (i = 1; i < 50; ++i)
	{
		qsc_fe25519_sq(t1, t1);
	}

	qsc_fe25519_mul(t1, t1, t0);
	qsc_fe25519_sq(t2, t1);

	for (i = 1; i < 100; ++i)
	{
		qsc_fe25519_sq(t2, t2);
	}

	qsc_fe25519_mul(t1, t2, t1);

	for (i = 1; i < 51; ++i)
	{
		qsc_fe25519_sq(t1, t1);
	}

	qsc_fe25519_mul(t0, t1, t0);
	qsc_fe25519_sq(t0, t0);
	qsc_fe25519_sq(t0, t0);
	qsc_fe25519_mul(out, t0, z);
}

void qsc_fe25519_invert(qsc_fe25519 out, const qsc_fe25519 z)
{
	/* Inversion - returns 0 if z=0 */
	qsc_fe25519 t0 = { 0 };
	qsc_fe25519 t1 = { 0 };
	qsc_fe25519 t2 = { 0 };
	qsc_fe25519 t3 = { 0 };
	size_t i;

	qsc_fe25519_sq(t0, z);
	qsc_fe25519_sq(t1, t0);
	qsc_fe25519_sq(t1, t1);
	qsc_fe25519_mul(t1, z, t1);
	qsc_fe25519_mul(t0, t0, t1);
	qsc_fe25519_sq(t2, t0);
	qsc_fe25519_mul(t1, t1, t2);
	qsc_fe25519_sq(t2, t1);

	for (i = 1; i < 5; ++i)
	{
		qsc_fe25519_sq(t2, t2);
	}

	qsc_fe25519_mul(t1, t2, t1);
	qsc_fe25519_sq(t2, t1);

	for (i = 1; i < 10; ++i)
	{
		qsc_fe25519_sq(t2, t2);
	}

	qsc_fe25519_mul(t2, t2, t1);
	qsc_fe25519_sq(t3, t2);

	for (i = 1; i < 20; ++i)
	{
		qsc_fe25519_sq(t3, t3);
	}

	qsc_fe25519_mul(t2, t3, t2);

	for (i = 1; i < 11; ++i)
	{
		qsc_fe25519_sq(t2, t2);
	}

	qsc_fe25519_mul(t1, t2, t1);
	qsc_fe25519_sq(t2, t1);

	for (i = 1; i < 50; ++i)
	{
		qsc_fe25519_sq(t2, t2);
	}

	qsc_fe25519_mul(t2, t2, t1);
	qsc_fe25519_sq(t3, t2);

	for (i = 1; i < 100; ++i)
	{
		qsc_fe25519_sq(t3, t3);
	}

	qsc_fe25519_mul(t2, t3, t2);

	for (i = 1; i < 51; ++i)
	{
		qsc_fe25519_sq(t2, t2);
	}

	qsc_fe25519_mul(t1, t2, t1);

	for (i = 1; i < 6; ++i)
	{
		qsc_fe25519_sq(t1, t1);
	}

	qsc_fe25519_mul(out, t1, t0);
}

/* ge */

void qsc_ge25519_p1p1_to_p3(qsc_ge25519_p3* r, const qsc_ge25519_p1p1* p)
{
	QSC_ASSERT(r != NULL);
	QSC_ASSERT(p != NULL);

	qsc_fe25519_mul(r->x, p->x, p->t);
	qsc_fe25519_mul(r->y, p->y, p->z);
	qsc_fe25519_mul(r->z, p->z, p->t);
	qsc_fe25519_mul(r->t, p->x, p->y);
}

void qsc_ge25519_p1p1_to_p2(qsc_ge25519_p2* r, const qsc_ge25519_p1p1* p)
{
	QSC_ASSERT(r != NULL);
	QSC_ASSERT(p != NULL);

	qsc_fe25519_mul(r->x, p->x, p->t);
	qsc_fe25519_mul(r->y, p->y, p->z);
	qsc_fe25519_mul(r->z, p->z, p->t);
}

int32_t qsc_ge25519_is_canonical(const uint8_t* s)
{
	int32_t i;

	QSC_ASSERT(s != NULL);

	uint8_t c;
	uint8_t d;

	c = (s[31U] & 0x7F) ^ 0x7F;

	for (i = 30; i > 0; i--)
	{
		c |= s[i] ^ 0xFF;
	}

	c = (uint8_t)((uint32_t)(c - 1UL) >> 8);
	d = (uint8_t)((uint32_t)(0x000000EDUL - 1UL - (uint32_t)s[0U]) >> 8);

	return 1 - (c & d & 1);
}

int32_t qsc_ge25519_has_small_order(const uint8_t s[32U])
{
	static const uint8_t blocklist[][32U] = 
	{
		/* 0 (order 4) */
		{
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
		},
		/* 1 (order 1) */
		{
			0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U},
		/* 2707385501144840649318225287225658788936804267575313519463743609750303402022 (order 8) */
		{
			0x26U, 0xE8U, 0x95U, 0x8fU, 0xC2U, 0xB2U, 0x27U, 0xB0U, 
			0x45U, 0xC3U, 0xf4U, 0x89U, 0xf2U, 0xEfU, 0x98U, 0xf0U, 
			0xD5U, 0xDfU, 0xACU, 0x05U, 0xD3U, 0xC6U, 0x33U, 0x39U, 
			0xB1U, 0x38U, 0x02U, 0x88U, 0x6DU, 0x53U, 0xfCU, 0x05U
		},
		/* 55188659117513257062467267217118295137698188065244968500265048394206261417927 (orDEr 8) */
		{
			0xC7U, 0x17U, 0x6AU, 0x70U, 0x3DU, 0x4DU, 0xD8U, 0x4fU, 
			0xBAU, 0x3CU, 0x0BU, 0x76U, 0x0DU, 0x10U, 0x67U, 0x0fU, 
			0x2AU, 0x20U, 0x53U, 0xfAU, 0x2CU, 0x39U, 0xCCU, 0xC6U, 
			0x4EU, 0xC7U, 0xFDU, 0x77U, 0x92U, 0xACU, 0x03U, 0x7AU
		},
		/* p-1 (orDEr 2) */
		{
			0xECU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x7FU
		},
		/* p (=0, orDEr 4) */
		{
			0xED, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x7FU
		},
		/* p+1 (=1, orDEr 1) */
		{
			0xEEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x7FU
		}
	};

	uint8_t c[7U] = { 0U };
	uint32_t k;
	size_t i;
	size_t j;

	for (j = 0U; j < 31U; ++j)
	{
		for (i = 0U; i < sizeof(blocklist) / sizeof(blocklist[0U]); ++i)
		{
			c[i] |= s[j] ^ blocklist[i][j];
		}
	}

	for (i = 0U; i < sizeof(blocklist) / sizeof(blocklist[0U]); ++i)
	{
		c[i] |= (s[j] & 0x7f) ^ blocklist[i][j];
	}

	k = 0U;

	for (i = 0U; i < sizeof(blocklist) / sizeof(blocklist[0U]); ++i)
	{
		k |= (c[i] - 1U);
	}

	return (int32_t)((k >> 8) & 1);
}

int32_t qsc_ge25519_from_bytes_negate_vartime(qsc_ge25519_p3* h, const uint8_t* s)
{
	QSC_ASSERT(h != NULL);
	QSC_ASSERT(s != NULL);

	qsc_fe25519 u = { 0 };
	qsc_fe25519 v = { 0 };
	qsc_fe25519 v3 = { 0 };
	qsc_fe25519 vxx = { 0 };
	qsc_fe25519 mrcheck = { 0 };
	qsc_fe25519 prcheck = { 0 };
	int32_t res;

	res = 0;
	qsc_fe25519_from_bytes(h->y, s);
	qsc_fe25519_1(h->z);
	qsc_fe25519_sq(u, h->y);
	qsc_fe25519_mul(v, u, ed25519_d);
	/* u = y^2-1 */
	qsc_fe25519_sub(u, u, h->z);
	/* v = dy^2+1 */
	qsc_fe25519_add(v, v, h->z);

	qsc_fe25519_sq(v3, v);
	/* v3 = v^3 */
	qsc_fe25519_mul(v3, v3, v);
	qsc_fe25519_sq(h->x, v3);
	/* x = uv^7 */
	qsc_fe25519_mul(h->x, h->x, v);
	qsc_fe25519_mul(h->x, h->x, u);
	/* x = (uv^7)^((q-5)/8) */
	fe25519_pow22523(h->x, h->x);
	qsc_fe25519_mul(h->x, h->x, v3);
	qsc_fe25519_mul(h->x, h->x, u);
	/* x = uv^3(uv^7)^((q-5)/8) */
	qsc_fe25519_sq(vxx, h->x);
	qsc_fe25519_mul(vxx, vxx, v);
	/* vx^2-u */
	qsc_fe25519_sub(mrcheck, vxx, u);

	if (qsc_fe25519_is_zero(mrcheck) == 0)
	{
		/* vx^2+u */
		qsc_fe25519_add(prcheck, vxx, u);

		if (qsc_fe25519_is_zero(prcheck) == 0)
		{
			res = -1;
		}
		else
		{
			qsc_fe25519_mul(h->x, h->x, fe25519_sqrtm1);
		}
	}

	if (res != -1)
	{
		if (qsc_fe25519_is_negative(h->x) == (s[31U] >> 7))
		{
			qsc_fe25519_neg(h->x, h->x);
		}

		qsc_fe25519_mul(h->t, h->x, h->y);
	}

	return res;
}

void qsc_ge25519_p3_to_cached(qsc_ge25519_cached* r, const qsc_ge25519_p3* p)
{
	QSC_ASSERT(r != NULL);
	QSC_ASSERT(p != NULL);

	qsc_fe25519_add(r->yplusx, p->y, p->x);
	qsc_fe25519_sub(r->yminusx, p->y, p->x);
	qsc_fe25519_copy(r->z, p->z);
	qsc_fe25519_mul(r->t2d, p->t, ed25519_d2);
}

void qsc_ge25519_add_cached(qsc_ge25519_p1p1* r, const qsc_ge25519_p3* p, const qsc_ge25519_cached* q)
{
	QSC_ASSERT(r != NULL);
	QSC_ASSERT(p != NULL);
	QSC_ASSERT(q != NULL);

	qsc_fe25519 t0 = { 0 };

	qsc_fe25519_add(r->x, p->y, p->x);
	qsc_fe25519_sub(r->y, p->y, p->x);
	qsc_fe25519_mul(r->z, r->x, q->yplusx);
	qsc_fe25519_mul(r->y, r->y, q->yminusx);
	qsc_fe25519_mul(r->t, q->t2d, p->t);
	qsc_fe25519_mul(r->x, p->z, q->z);
	qsc_fe25519_add(t0, r->x, r->x);
	qsc_fe25519_sub(r->x, r->z, r->y);
	qsc_fe25519_add(r->y, r->z, r->y);
	qsc_fe25519_add(r->z, t0, r->t);
	qsc_fe25519_sub(r->t, t0, r->t);
}

void qsc_ge25519_sub_precomp(qsc_ge25519_p1p1* r, const qsc_ge25519_p3* p, const qsc_ge25519_precomp* q)
{
	QSC_ASSERT(r != NULL);
	QSC_ASSERT(p != NULL);
	QSC_ASSERT(q != NULL);

	/* r = a * A + b * B
	 * where a = a[0U]+256*a[1U]+...+256^31 a[31U].
	 * and b = b[0U]+256*b[1U]+...+256^31 b[31U].
	 * B is the Ed25519 base point (x,4/5) with x positive.
	 * only used for signatures verification. */
	qsc_fe25519 t0 = { 0 };

	qsc_fe25519_add(r->x, p->y, p->x);
	qsc_fe25519_sub(r->y, p->y, p->x);
	qsc_fe25519_mul(r->z, r->x, q->yminusx);
	qsc_fe25519_mul(r->y, r->y, q->yplusx);
	qsc_fe25519_mul(r->t, q->xy2d, p->t);
	qsc_fe25519_add(t0, p->z, p->z);
	qsc_fe25519_sub(r->x, r->z, r->y);
	qsc_fe25519_add(r->y, r->z, r->y);
	qsc_fe25519_sub(r->z, t0, r->t);
	qsc_fe25519_add(r->t, t0, r->t);
}

void qsc_ge25519_sub_cached(qsc_ge25519_p1p1* r, const qsc_ge25519_p3* p, const qsc_ge25519_cached* q)
{
	QSC_ASSERT(r != NULL);
	QSC_ASSERT(p != NULL);
	QSC_ASSERT(q != NULL);

	qsc_fe25519 t0 = { 0 };

	qsc_fe25519_add(r->x, p->y, p->x);
	qsc_fe25519_sub(r->y, p->y, p->x);
	qsc_fe25519_mul(r->z, r->x, q->yminusx);
	qsc_fe25519_mul(r->y, r->y, q->yplusx);
	qsc_fe25519_mul(r->t, q->t2d, p->t);
	qsc_fe25519_mul(r->x, p->z, q->z);
	qsc_fe25519_add(t0, r->x, r->x);
	qsc_fe25519_sub(r->x, r->z, r->y);
	qsc_fe25519_add(r->y, r->z, r->y);
	qsc_fe25519_sub(r->z, t0, r->t);
	qsc_fe25519_add(r->t, t0, r->t);
}

/* main */

/*! \brief Clamp an Ed25519 scalar in place.
 * \param t Caller-owned 32-byte writable scalar; must not be null.
 */
void qsc_sc25519_clamp(uint8_t* t)
{
	QSC_ASSERT(t != NULL);

	t[0U] &= 248;
	t[31U] &= 127;
	t[31U] |= 64;
}

int32_t qsc_ed25519_small_order(const uint8_t s[32U])
{
	/*
	 * Reject small order points early to mitigate the implications of
	 * unexpected optimizations that would affect the ref10 code.
	 * See https://eprint.iacr.org/2017/806.pdf for reference.
	 */
	static const uint8_t blocklist[][32U] = 
	{
		/* 0 (order 4) */
		{
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
		},
		/* 1 (order 1) */
		{
			0x01, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
		},
		/* 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8) */
		{
			0xE0U, 0xEBU, 0x7AU, 0x7CU, 0x3BU, 0x41U, 0xB8U, 0xAEU, 
			0x16U, 0x56U, 0xE3U, 0xFAU, 0xF1U, 0x9FU, 0xC4U, 0x6AU, 
			0xDAU, 0x09U, 0x8DU, 0xEBU, 0x9CU, 0x32U, 0xB1U, 0xFDU, 
			0x86U, 0x62U, 0x05U, 0x16U, 0x5FU, 0x49U, 0xB8U, 0x00U
		},
		/* 39382357235489614581723060781553021112529911719440698176882885853963445705823 (orDEr 8) */
		{
			0x5FU, 0x9CU, 0x95U, 0xBCU, 0xA3U, 0x50U, 0x8CU, 0x24U, 
			0xB1U, 0xD0U, 0xB1U, 0x55U, 0x9CU, 0x83U, 0xEFU, 0x5BU, 
			0x04U, 0x44U, 0x5CU, 0xC4U, 0x58U, 0x1CU, 0x8EU, 0x86U, 
			0xD8U, 0x22U, 0x4EU, 0xDDU, 0xD0U, 0x9FU, 0x11U, 0x57U
		},
		/* p-1 (order 2) */
		{
			0xECU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x7FU
		},
		/* p (=0, order 4) */
		{
			0xEDU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x7FU
		},
		/* p+1 (=1, order 1) */
		{
			0xEEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 
			0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x7FU
		}
	};

	uint8_t c[7U] = { 0U };
	uint32_t k;
	size_t i;
	size_t j;

	QSC_ASSERT(7 == sizeof(blocklist) / sizeof(blocklist[0U]));

	for (j = 0U; j < 31U; j++)
	{
		for (i = 0U; i < sizeof(blocklist) / sizeof(blocklist[0U]); ++i)
		{
			c[i] |= s[j] ^ blocklist[i][j];
		}
	}

	for (i = 0U; i < sizeof(blocklist) / sizeof(blocklist[0U]); ++i)
	{
		c[i] |= (s[j] & 0x7f) ^ blocklist[i][j];
	}

	k = 0;

	for (i = 0U; i < sizeof(blocklist) / sizeof(blocklist[0U]); ++i)
	{
		k |= (c[i] - 1U);
	}

	return (int32_t)((k >> 8) & 1);
}

int32_t qsc_sc25519_is_canonical(const uint8_t s[32U])
{
	static const uint8_t L[32U] = 
	{
		0xEDU, 0xD3U, 0xF5U, 0x5CU, 0x1AU, 0x63U, 0x12U, 0x58U, 
		0xD6U, 0x9CU, 0xF7U, 0xA2U, 0xDEU, 0xF9U, 0xDEU, 0x14U,
		0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 
		0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x10U
	};

	uint8_t c;
	uint8_t n;
	uint32_t i;

	c = 0;
	n = 1;
	i = 32;

	do
	{
		i--;
		c |= (((s[i] - L[i]) >> 8) & n);
		n &= (((s[i] ^ L[i]) - 1) >> 8);
	} while (i != 0);

	return (c != 0);
}

void qsc_sc25519_muladd(uint8_t s[32U], const uint8_t a[32U], const uint8_t b[32U], const uint8_t c[32U])
{
	int64_t a0;
	int64_t a1;
	int64_t a2;
	int64_t a3;
	int64_t a4;
	int64_t a5;
	int64_t a6;
	int64_t a7;
	int64_t a8;
	int64_t a9;
	int64_t a10;
	int64_t a11;
	int64_t b0;
	int64_t b1;
	int64_t b2;
	int64_t b3;
	int64_t b4;
	int64_t b5;
	int64_t b6;
	int64_t b7;
	int64_t b8;
	int64_t b9;
	int64_t b10;
	int64_t b11;
	int64_t carry;
	int64_t c0;
	int64_t c1;
	int64_t c2;
	int64_t c3;
	int64_t c4;
	int64_t c5;
	int64_t c6;
	int64_t c7;
	int64_t c8;
	int64_t c9;
	int64_t c10;
	int64_t c11;
	int64_t s0;
	int64_t s1;
	int64_t s2;
	int64_t s3;
	int64_t s4;
	int64_t s5;
	int64_t s6;
	int64_t s7;
	int64_t s8;
	int64_t s9;
	int64_t s10;
	int64_t s11;
	int64_t s12;
	int64_t s13;
	int64_t s14;
	int64_t s15;
	int64_t s16;
	int64_t s17;
	int64_t s18;
	int64_t s19;
	int64_t s20;
	int64_t s21;
	int64_t s22;
	int64_t s23;

	a0 = 2097151 & ed25518_load3(a);
	a1 = 2097151 & (ed25518_load4(a + 2) >> 5);
	a2 = 2097151 & (ed25518_load3(a + 5) >> 2);
	a3 = 2097151 & (ed25518_load4(a + 7) >> 7);
	a4 = 2097151 & (ed25518_load4(a + 10) >> 4);
	a5 = 2097151 & (ed25518_load3(a + 13) >> 1);
	a6 = 2097151 & (ed25518_load4(a + 15) >> 6);
	a7 = 2097151 & (ed25518_load3(a + 18) >> 3);
	a8 = 2097151 & ed25518_load3(a + 21);
	a9 = 2097151 & (ed25518_load4(a + 23) >> 5);
	a10 = 2097151 & (ed25518_load3(a + 26) >> 2);
	a11 = (ed25518_load4(a + 28) >> 7);

	b0 = 2097151 & ed25518_load3(b);
	b1 = 2097151 & (ed25518_load4(b + 2) >> 5);
	b2 = 2097151 & (ed25518_load3(b + 5) >> 2);
	b3 = 2097151 & (ed25518_load4(b + 7) >> 7);
	b4 = 2097151 & (ed25518_load4(b + 10) >> 4);
	b5 = 2097151 & (ed25518_load3(b + 13) >> 1);
	b6 = 2097151 & (ed25518_load4(b + 15) >> 6);
	b7 = 2097151 & (ed25518_load3(b + 18) >> 3);
	b8 = 2097151 & ed25518_load3(b + 21);
	b9 = 2097151 & (ed25518_load4(b + 23) >> 5);
	b10 = 2097151 & (ed25518_load3(b + 26) >> 2);
	b11 = (ed25518_load4(b + 28) >> 7);

	c0 = 2097151 & ed25518_load3(c);
	c1 = 2097151 & (ed25518_load4(c + 2) >> 5);
	c2 = 2097151 & (ed25518_load3(c + 5) >> 2);
	c3 = 2097151 & (ed25518_load4(c + 7) >> 7);
	c4 = 2097151 & (ed25518_load4(c + 10) >> 4);
	c5 = 2097151 & (ed25518_load3(c + 13) >> 1);
	c6 = 2097151 & (ed25518_load4(c + 15) >> 6);
	c7 = 2097151 & (ed25518_load3(c + 18) >> 3);
	c8 = 2097151 & ed25518_load3(c + 21);
	c9 = 2097151 & (ed25518_load4(c + 23) >> 5);
	c10 = 2097151 & (ed25518_load3(c + 26) >> 2);
	c11 = (ed25518_load4(c + 28) >> 7);

	s0 = c0 + (a0 * b0);
	s1 = c1 + (a0 * b1) + (a1 * b0);
	s2 = c2 + (a0 * b2) + (a1 * b1) + (a2 * b0);
	s3 = c3 + (a0 * b3) + (a1 * b2) + (a2 * b1) + (a3 * b0);
	s4 = c4 + (a0 * b4) + (a1 * b3) + (a2 * b2) + (a3 * b1) + (a4 * b0);
	s5 = c5 + (a0 * b5) + (a1 * b4) + (a2 * b3) + (a3 * b2) + (a4 * b1) + (a5 * b0);
	s6 = c6 + (a0 * b6) + (a1 * b5) + (a2 * b4) + (a3 * b3) + (a4 * b2) + (a5 * b1) + (a6 * b0);
	s7 = c7 + (a0 * b7) + (a1 * b6) + (a2 * b5) + (a3 * b4) + (a4 * b3) + (a5 * b2) + (a6 * b1) + (a7 * b0);
	s8 = c8 + (a0 * b8) + (a1 * b7) + (a2 * b6) + (a3 * b5) + (a4 * b4) + (a5 * b3) + (a6 * b2) + (a7 * b1) + (a8 * b0);
	s9 = c9 + (a0 * b9) + (a1 * b8) + (a2 * b7) + (a3 * b6) + (a4 * b5) + (a5 * b4) + (a6 * b3) + (a7 * b2) + (a8 * b1) + (a9 * b0);
	s10 = c10 + (a0 * b10) + (a1 * b9) + (a2 * b8) + (a3 * b7) + (a4 * b6) + (a5 * b5) + (a6 * b4) + (a7 * b3) + (a8 * b2) + (a9 * b1) + (a10 * b0);
	s11 =
		c11 + (a0 * b11) + (a1 * b10) + (a2 * b9) + (a3 * b8) + (a4 * b7) + (a5 * b6) + (a6 * b5) + (a7 * b4) + (a8 * b3) + (a9 * b2) + (a10 * b1) + (a11 * b0);
	s12 = (a1 * b11) + (a2 * b10) + (a3 * b9) + (a4 * b8) + (a5 * b7) + (a6 * b6) + (a7 * b5) + (a8 * b4) + (a9 * b3) + (a10 * b2) + (a11 * b1);
	s13 = (a2 * b11) + (a3 * b10) + (a4 * b9) + (a5 * b8) + (a6 * b7) + (a7 * b6) + (a8 * b5) + (a9 * b4) + (a10 * b3) + (a11 * b2);
	s14 = (a3 * b11) + (a4 * b10) + (a5 * b9) + (a6 * b8) + (a7 * b7) + (a8 * b6) + (a9 * b5) + (a10 * b4) + (a11 * b3);
	s15 = (a4 * b11) + (a5 * b10) + (a6 * b9) + (a7 * b8) + (a8 * b7) + (a9 * b6) + (a10 * b5) + (a11 * b4);
	s16 = (a5 * b11) + (a6 * b10) + (a7 * b9) + (a8 * b8) + (a9 * b7) + (a10 * b6) + (a11 * b5);
	s17 = (a6 * b11) + (a7 * b10) + (a8 * b9) + (a9 * b8) + (a10 * b7) + (a11 * b6);
	s18 = (a7 * b11) + (a8 * b10) + (a9 * b9) + (a10 * b8) + (a11 * b7);
	s19 = (a8 * b11) + (a9 * b10) + (a10 * b9) + (a11 * b8);
	s20 = (a9 * b11) + (a10 * b10) + (a11 * b9);
	s21 = (a10 * b11) + (a11 * b10);
	s22 = (a11 * b11);
	s23 = 0;

	carry = (s0 + (1 << 20)) >> 21;
	s1 += carry;
	s0 -= carry * (1 << 21);
	carry = (s2 + (1 << 20)) >> 21;
	s3 += carry;
	s2 -= carry * (1 << 21);
	carry = (s4 + (1 << 20)) >> 21;
	s5 += carry;
	s4 -= carry * (1 << 21);
	carry = (s6 + (1 << 20)) >> 21;
	s7 += carry;
	s6 -= carry * (1 << 21);
	carry = (s8 + (1 << 20)) >> 21;
	s9 += carry;
	s8 -= carry * (1 << 21);
	carry = (s10 + (1 << 20)) >> 21;
	s11 += carry;
	s10 -= carry * (1 << 21);
	carry = (s12 + (1 << 20)) >> 21;
	s13 += carry;
	s12 -= carry * (1 << 21);
	carry = (s14 + (1 << 20)) >> 21;
	s15 += carry;
	s14 -= carry * (1 << 21);
	carry = (s16 + (1 << 20)) >> 21;
	s17 += carry;
	s16 -= carry * (1 << 21);
	carry = (s18 + (1 << 20)) >> 21;
	s19 += carry;
	s18 -= carry * (1 << 21);
	carry = (s20 + (1 << 20)) >> 21;
	s21 += carry;
	s20 -= carry * (1 << 21);
	carry = (s22 + (1 << 20)) >> 21;
	s23 += carry;
	s22 -= carry * (1 << 21);

	carry = (s1 + (1 << 20)) >> 21;
	s2 += carry;
	s1 -= carry * (1 << 21);
	carry = (s3 + (1 << 20)) >> 21;
	s4 += carry;
	s3 -= carry * (1 << 21);
	carry = (s5 + (1 << 20)) >> 21;
	s6 += carry;
	s5 -= carry * (1 << 21);
	carry = (s7 + (1 << 20)) >> 21;
	s8 += carry;
	s7 -= carry * (1 << 21);
	carry = (s9 + (1 << 20)) >> 21;
	s10 += carry;
	s9 -= carry * (1 << 21);
	carry = (s11 + (1 << 20)) >> 21;
	s12 += carry;
	s11 -= carry * (1 << 21);
	carry = (s13 + (1 << 20)) >> 21;
	s14 += carry;
	s13 -= carry * (1 << 21);
	carry = (s15 + (1 << 20)) >> 21;
	s16 += carry;
	s15 -= carry * (1 << 21);
	carry = (s17 + (1 << 20)) >> 21;
	s18 += carry;
	s17 -= carry * (1 << 21);
	carry = (s19 + (1 << 20)) >> 21;
	s20 += carry;
	s19 -= carry * (1 << 21);
	carry = (s21 + (1 << 20)) >> 21;
	s22 += carry;
	s21 -= carry * (1 << 21);

	s11 += s23 * 666643;
	s12 += s23 * 470296;
	s13 += s23 * 654183;
	s14 -= s23 * 997805;
	s15 += s23 * 136657;
	s16 -= s23 * 683901;

	s10 += s22 * 666643;
	s11 += s22 * 470296;
	s12 += s22 * 654183;
	s13 -= s22 * 997805;
	s14 += s22 * 136657;
	s15 -= s22 * 683901;

	s9 += s21 * 666643;
	s10 += s21 * 470296;
	s11 += s21 * 654183;
	s12 -= s21 * 997805;
	s13 += s21 * 136657;
	s14 -= s21 * 683901;

	s8 += s20 * 666643;
	s9 += s20 * 470296;
	s10 += s20 * 654183;
	s11 -= s20 * 997805;
	s12 += s20 * 136657;
	s13 -= s20 * 683901;

	s7 += s19 * 666643;
	s8 += s19 * 470296;
	s9 += s19 * 654183;
	s10 -= s19 * 997805;
	s11 += s19 * 136657;
	s12 -= s19 * 683901;

	s6 += s18 * 666643;
	s7 += s18 * 470296;
	s8 += s18 * 654183;
	s9 -= s18 * 997805;
	s10 += s18 * 136657;
	s11 -= s18 * 683901;

	carry = (s6 + (1 << 20)) >> 21;
	s7 += carry;
	s6 -= carry * (1 << 21);
	carry = (s8 + (1 << 20)) >> 21;
	s9 += carry;
	s8 -= carry * (1 << 21);
	carry = (s10 + (1 << 20)) >> 21;
	s11 += carry;
	s10 -= carry * (1 << 21);
	carry = (s12 + (1 << 20)) >> 21;
	s13 += carry;
	s12 -= carry * (1 << 21);
	carry = (s14 + (1 << 20)) >> 21;
	s15 += carry;
	s14 -= carry * (1 << 21);
	carry = (s16 + (1 << 20)) >> 21;
	s17 += carry;
	s16 -= carry * (1 << 21);

	carry = (s7 + (1 << 20)) >> 21;
	s8 += carry;
	s7 -= carry * (1 << 21);
	carry = (s9 + (1 << 20)) >> 21;
	s10 += carry;
	s9 -= carry * (1 << 21);
	carry = (s11 + (1 << 20)) >> 21;
	s12 += carry;
	s11 -= carry * (1 << 21);
	carry = (s13 + (1 << 20)) >> 21;
	s14 += carry;
	s13 -= carry * (1 << 21);
	carry = (s15 + (1 << 20)) >> 21;
	s16 += carry;
	s15 -= carry * (1 << 21);

	s5 += s17 * 666643;
	s6 += s17 * 470296;
	s7 += s17 * 654183;
	s8 -= s17 * 997805;
	s9 += s17 * 136657;
	s10 -= s17 * 683901;

	s4 += s16 * 666643;
	s5 += s16 * 470296;
	s6 += s16 * 654183;
	s7 -= s16 * 997805;
	s8 += s16 * 136657;
	s9 -= s16 * 683901;

	s3 += s15 * 666643;
	s4 += s15 * 470296;
	s5 += s15 * 654183;
	s6 -= s15 * 997805;
	s7 += s15 * 136657;
	s8 -= s15 * 683901;

	s2 += s14 * 666643;
	s3 += s14 * 470296;
	s4 += s14 * 654183;
	s5 -= s14 * 997805;
	s6 += s14 * 136657;
	s7 -= s14 * 683901;

	s1 += s13 * 666643;
	s2 += s13 * 470296;
	s3 += s13 * 654183;
	s4 -= s13 * 997805;
	s5 += s13 * 136657;
	s6 -= s13 * 683901;

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry = (s0 + (1 << 20)) >> 21;
	s1 += carry;
	s0 -= carry * (1 << 21);
	carry = (s2 + (1 << 20)) >> 21;
	s3 += carry;
	s2 -= carry * (1 << 21);
	carry = (s4 + (1 << 20)) >> 21;
	s5 += carry;
	s4 -= carry * (1 << 21);
	carry = (s6 + (1 << 20)) >> 21;
	s7 += carry;
	s6 -= carry * (1 << 21);
	carry = (s8 + (1 << 20)) >> 21;
	s9 += carry;
	s8 -= carry * (1 << 21);
	carry = (s10 + (1 << 20)) >> 21;
	s11 += carry;
	s10 -= carry * (1 << 21);

	carry = (s1 + (1 << 20)) >> 21;
	s2 += carry;
	s1 -= carry * (1 << 21);
	carry = (s3 + (1 << 20)) >> 21;
	s4 += carry;
	s3 -= carry * (1 << 21);
	carry = (s5 + (1 << 20)) >> 21;
	s6 += carry;
	s5 -= carry * (1 << 21);
	carry = (s7 + (1 << 20)) >> 21;
	s8 += carry;
	s7 -= carry * (1 << 21);
	carry = (s9 + (1 << 20)) >> 21;
	s10 += carry;
	s9 -= carry * (1 << 21);
	carry = (s11 + (1 << 20)) >> 21;
	s12 += carry;
	s11 -= carry * (1 << 21);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry = s0 >> 21;
	s1 += carry;
	s0 -= carry * (1 << 21);
	carry = s1 >> 21;
	s2 += carry;
	s1 -= carry * (1 << 21);
	carry = s2 >> 21;
	s3 += carry;
	s2 -= carry * (1 << 21);
	carry = s3 >> 21;
	s4 += carry;
	s3 -= carry * (1 << 21);
	carry = s4 >> 21;
	s5 += carry;
	s4 -= carry * (1 << 21);
	carry = s5 >> 21;
	s6 += carry;
	s5 -= carry * (1 << 21);
	carry = s6 >> 21;
	s7 += carry;
	s6 -= carry * (1 << 21);
	carry = s7 >> 21;
	s8 += carry;
	s7 -= carry * (1 << 21);
	carry = s8 >> 21;
	s9 += carry;
	s8 -= carry * (1 << 21);
	carry = s9 >> 21;
	s10 += carry;
	s9 -= carry * (1 << 21);
	carry = s10 >> 21;
	s11 += carry;
	s10 -= carry * (1 << 21);
	carry = s11 >> 21;
	s12 += carry;
	s11 -= carry * (1 << 21);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;

	carry = s0 >> 21;
	s1 += carry;
	s0 -= carry * (1 << 21);
	carry = s1 >> 21;
	s2 += carry;
	s1 -= carry * (1 << 21);
	carry = s2 >> 21;
	s3 += carry;
	s2 -= carry * (1 << 21);
	carry = s3 >> 21;
	s4 += carry;
	s3 -= carry * (1 << 21);
	carry = s4 >> 21;
	s5 += carry;
	s4 -= carry * (1 << 21);
	carry = s5 >> 21;
	s6 += carry;
	s5 -= carry * (1 << 21);
	carry = s6 >> 21;
	s7 += carry;
	s6 -= carry * (1 << 21);
	carry = s7 >> 21;
	s8 += carry;
	s7 -= carry * (1 << 21);
	carry = s8 >> 21;
	s9 += carry;
	s8 -= carry * (1 << 21);
	carry = s9 >> 21;
	s10 += carry;
	s9 -= carry * (1 << 21);
	carry = s10 >> 21;
	s11 += carry;
	s10 -= carry * (1 << 21);

	s[0U] = (uint8_t)s0;
	s[1U] = (uint8_t)(s0 >> 8);
	s[2U] = (uint8_t)((s0 >> 16) | (s1 * (1 << 5)));
	s[3U] = (uint8_t)(s1 >> 3);
	s[4U] = (uint8_t)(s1 >> 11);
	s[5U] = (uint8_t)((s1 >> 19) | (s2 * (1 << 2)));
	s[6U] = (uint8_t)(s2 >> 6);
	s[7U] = (uint8_t)((s2 >> 14) | (s3 * (1 << 7)));
	s[8U] = (uint8_t)(s3 >> 1);
	s[9U] = (uint8_t)(s3 >> 9);
	s[10U] = (uint8_t)((s3 >> 17) | (s4 * (1 << 4)));
	s[11U] = (uint8_t)(s4 >> 4);
	s[12U] = (uint8_t)(s4 >> 12);
	s[13U] = (uint8_t)((s4 >> 20) | (s5 * (1 << 1)));
	s[14U] = (uint8_t)(s5 >> 7);
	s[15U] = (uint8_t)((s5 >> 15) | (s6 * (1 << 6)));
	s[16U] = (uint8_t)(s6 >> 2);
	s[17U] = (uint8_t)(s6 >> 10);
	s[18U] = (uint8_t)((s6 >> 18) | (s7 * (1 << 3)));
	s[19U] = (uint8_t)(s7 >> 5);
	s[20U] = (uint8_t)(s7 >> 13);
	s[21U] = (uint8_t)s8;
	s[22U] = (uint8_t)(s8 >> 8);
	s[23U] = (uint8_t)((s8 >> 16) | (s9 * (1 << 5)));
	s[24U] = (uint8_t)(s9 >> 3);
	s[25U] = (uint8_t)(s9 >> 11);
	s[26U] = (uint8_t)((s9 >> 19) | (s10 * (1 << 2)));
	s[27U] = (uint8_t)(s10 >> 6);
	s[28U] = (uint8_t)((s10 >> 14) | (s11 * (1 << 7)));
	s[29U] = (uint8_t)(s11 >> 1);
	s[30U] = (uint8_t)(s11 >> 9);
	s[31U] = (uint8_t)(s11 >> 17);
}

void qsc_sc25519_reduce(uint8_t s[64U])
{
	int64_t carry;
	int64_t s0;
	int64_t s1;
	int64_t s2;
	int64_t s3;
	int64_t s4;
	int64_t s5;
	int64_t s6;
	int64_t s7;
	int64_t s8;
	int64_t s9;
	int64_t s10;
	int64_t s11;
	int64_t s12;
	int64_t s13;
	int64_t s14;
	int64_t s15;
	int64_t s16;
	int64_t s17;
	int64_t s18;
	int64_t s19;
	int64_t s20;
	int64_t s21;
	int64_t s22;
	int64_t s23;

	s0 = 2097151 & ed25518_load3(s);
	s1 = 2097151 & (ed25518_load4(s + 2) >> 5);
	s2 = 2097151 & (ed25518_load3(s + 5) >> 2);
	s3 = 2097151 & (ed25518_load4(s + 7) >> 7);
	s4 = 2097151 & (ed25518_load4(s + 10) >> 4);
	s5 = 2097151 & (ed25518_load3(s + 13) >> 1);
	s6 = 2097151 & (ed25518_load4(s + 15) >> 6);
	s7 = 2097151 & (ed25518_load3(s + 18) >> 3);
	s8 = 2097151 & ed25518_load3(s + 21);
	s9 = 2097151 & (ed25518_load4(s + 23) >> 5);
	s10 = 2097151 & (ed25518_load3(s + 26) >> 2);
	s11 = 2097151 & (ed25518_load4(s + 28) >> 7);
	s12 = 2097151 & (ed25518_load4(s + 31) >> 4);
	s13 = 2097151 & (ed25518_load3(s + 34) >> 1);
	s14 = 2097151 & (ed25518_load4(s + 36) >> 6);
	s15 = 2097151 & (ed25518_load3(s + 39) >> 3);
	s16 = 2097151 & ed25518_load3(s + 42);
	s17 = 2097151 & (ed25518_load4(s + 44) >> 5);
	s18 = 2097151 & (ed25518_load3(s + 47) >> 2);
	s19 = 2097151 & (ed25518_load4(s + 49) >> 7);
	s20 = 2097151 & (ed25518_load4(s + 52) >> 4);
	s21 = 2097151 & (ed25518_load3(s + 55) >> 1);
	s22 = 2097151 & (ed25518_load4(s + 57) >> 6);
	s23 = (ed25518_load4(s + 60) >> 3);

	s11 += s23 * 666643;
	s12 += s23 * 470296;
	s13 += s23 * 654183;
	s14 -= s23 * 997805;
	s15 += s23 * 136657;
	s16 -= s23 * 683901;

	s10 += s22 * 666643;
	s11 += s22 * 470296;
	s12 += s22 * 654183;
	s13 -= s22 * 997805;
	s14 += s22 * 136657;
	s15 -= s22 * 683901;

	s9 += s21 * 666643;
	s10 += s21 * 470296;
	s11 += s21 * 654183;
	s12 -= s21 * 997805;
	s13 += s21 * 136657;
	s14 -= s21 * 683901;

	s8 += s20 * 666643;
	s9 += s20 * 470296;
	s10 += s20 * 654183;
	s11 -= s20 * 997805;
	s12 += s20 * 136657;
	s13 -= s20 * 683901;

	s7 += s19 * 666643;
	s8 += s19 * 470296;
	s9 += s19 * 654183;
	s10 -= s19 * 997805;
	s11 += s19 * 136657;
	s12 -= s19 * 683901;

	s6 += s18 * 666643;
	s7 += s18 * 470296;
	s8 += s18 * 654183;
	s9 -= s18 * 997805;
	s10 += s18 * 136657;
	s11 -= s18 * 683901;

	carry = (s6 + (1 << 20)) >> 21;
	s7 += carry;
	s6 -= carry * (1 << 21);
	carry = (s8 + (1 << 20)) >> 21;
	s9 += carry;
	s8 -= carry * (1 << 21);
	carry = (s10 + (1 << 20)) >> 21;
	s11 += carry;
	s10 -= carry * (1 << 21);
	carry = (s12 + (1 << 20)) >> 21;
	s13 += carry;
	s12 -= carry * (1 << 21);
	carry = (s14 + (1 << 20)) >> 21;
	s15 += carry;
	s14 -= carry * (1 << 21);
	carry = (s16 + (1 << 20)) >> 21;
	s17 += carry;
	s16 -= carry * (1 << 21);

	carry = (s7 + (1 << 20)) >> 21;
	s8 += carry;
	s7 -= carry * (1 << 21);
	carry = (s9 + (1 << 20)) >> 21;
	s10 += carry;
	s9 -= carry * (1 << 21);
	carry = (s11 + (1 << 20)) >> 21;
	s12 += carry;
	s11 -= carry * (1 << 21);
	carry = (s13 + (1 << 20)) >> 21;
	s14 += carry;
	s13 -= carry * (1 << 21);
	carry = (s15 + (1 << 20)) >> 21;
	s16 += carry;
	s15 -= carry * (1 << 21);

	s5 += s17 * 666643;
	s6 += s17 * 470296;
	s7 += s17 * 654183;
	s8 -= s17 * 997805;
	s9 += s17 * 136657;
	s10 -= s17 * 683901;

	s4 += s16 * 666643;
	s5 += s16 * 470296;
	s6 += s16 * 654183;
	s7 -= s16 * 997805;
	s8 += s16 * 136657;
	s9 -= s16 * 683901;

	s3 += s15 * 666643;
	s4 += s15 * 470296;
	s5 += s15 * 654183;
	s6 -= s15 * 997805;
	s7 += s15 * 136657;
	s8 -= s15 * 683901;

	s2 += s14 * 666643;
	s3 += s14 * 470296;
	s4 += s14 * 654183;
	s5 -= s14 * 997805;
	s6 += s14 * 136657;
	s7 -= s14 * 683901;

	s1 += s13 * 666643;
	s2 += s13 * 470296;
	s3 += s13 * 654183;
	s4 -= s13 * 997805;
	s5 += s13 * 136657;
	s6 -= s13 * 683901;

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry = (s0 + (1 << 20)) >> 21;
	s1 += carry;
	s0 -= carry * (1 << 21);
	carry = (s2 + (1 << 20)) >> 21;
	s3 += carry;
	s2 -= carry * (1 << 21);
	carry = (s4 + (1 << 20)) >> 21;
	s5 += carry;
	s4 -= carry * (1 << 21);
	carry = (s6 + (1 << 20)) >> 21;
	s7 += carry;
	s6 -= carry * (1 << 21);
	carry = (s8 + (1 << 20)) >> 21;
	s9 += carry;
	s8 -= carry * (1 << 21);
	carry = (s10 + (1 << 20)) >> 21;
	s11 += carry;
	s10 -= carry * (1 << 21);

	carry = (s1 + (1 << 20)) >> 21;
	s2 += carry;
	s1 -= carry * (1 << 21);
	carry = (s3 + (1 << 20)) >> 21;
	s4 += carry;
	s3 -= carry * (1 << 21);
	carry = (s5 + (1 << 20)) >> 21;
	s6 += carry;
	s5 -= carry * (1 << 21);
	carry = (s7 + (1 << 20)) >> 21;
	s8 += carry;
	s7 -= carry * (1 << 21);
	carry = (s9 + (1 << 20)) >> 21;
	s10 += carry;
	s9 -= carry * (1 << 21);
	carry = (s11 + (1 << 20)) >> 21;
	s12 += carry;
	s11 -= carry * (1 << 21);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry = s0 >> 21;
	s1 += carry;
	s0 -= carry * (1 << 21);
	carry = s1 >> 21;
	s2 += carry;
	s1 -= carry * (1 << 21);
	carry = s2 >> 21;
	s3 += carry;
	s2 -= carry * (1 << 21);
	carry = s3 >> 21;
	s4 += carry;
	s3 -= carry * (1 << 21);
	carry = s4 >> 21;
	s5 += carry;
	s4 -= carry * (1 << 21);
	carry = s5 >> 21;
	s6 += carry;
	s5 -= carry * (1 << 21);
	carry = s6 >> 21;
	s7 += carry;
	s6 -= carry * (1 << 21);
	carry = s7 >> 21;
	s8 += carry;
	s7 -= carry * (1 << 21);
	carry = s8 >> 21;
	s9 += carry;
	s8 -= carry * (1 << 21);
	carry = s9 >> 21;
	s10 += carry;
	s9 -= carry * (1 << 21);
	carry = s10 >> 21;
	s11 += carry;
	s10 -= carry * (1 << 21);
	carry = s11 >> 21;
	s12 += carry;
	s11 -= carry * (1 << 21);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;

	carry = s0 >> 21;
	s1 += carry;
	s0 -= carry * (1 << 21);
	carry = s1 >> 21;
	s2 += carry;
	s1 -= carry * (1 << 21);
	carry = s2 >> 21;
	s3 += carry;
	s2 -= carry * (1 << 21);
	carry = s3 >> 21;
	s4 += carry;
	s3 -= carry * (1 << 21);
	carry = s4 >> 21;
	s5 += carry;
	s4 -= carry * (1 << 21);
	carry = s5 >> 21;
	s6 += carry;
	s5 -= carry * (1 << 21);
	carry = s6 >> 21;
	s7 += carry;
	s6 -= carry * (1 << 21);
	carry = s7 >> 21;
	s8 += carry;
	s7 -= carry * (1 << 21);
	carry = s8 >> 21;
	s9 += carry;
	s8 -= carry * (1 << 21);
	carry = s9 >> 21;
	s10 += carry;
	s9 -= carry * (1 << 21);
	carry = s10 >> 21;
	s11 += carry;
	s10 -= carry * (1 << 21);

	s[0U] = (uint8_t)s0;
	s[1U] = (uint8_t)(s0 >> 8);
	s[2U] = (uint8_t)((s0 >> 16) | (s1 * (1 << 5)));
	s[3U] = (uint8_t)(s1 >> 3);
	s[4U] = (uint8_t)(s1 >> 11);
	s[5U] = (uint8_t)((s1 >> 19) | (s2 * (1 << 2)));
	s[6U] = (uint8_t)(s2 >> 6);
	s[7U] = (uint8_t)((s2 >> 14) | (s3 * (1 << 7)));
	s[8U] = (uint8_t)(s3 >> 1);
	s[9U] = (uint8_t)(s3 >> 9);
	s[10U] = (uint8_t)((s3 >> 17) | (s4 * (1 << 4)));
	s[11U] = (uint8_t)(s4 >> 4);
	s[12U] = (uint8_t)(s4 >> 12);
	s[13U] = (uint8_t)((s4 >> 20) | (s5 * (1 << 1)));
	s[14U] = (uint8_t)(s5 >> 7);
	s[15U] = (uint8_t)((s5 >> 15) | (s6 * (1 << 6)));
	s[16U] = (uint8_t)(s6 >> 2);
	s[17U] = (uint8_t)(s6 >> 10);
	s[18U] = (uint8_t)((s6 >> 18) | (s7 * (1 << 3)));
	s[19U] = (uint8_t)(s7 >> 5);
	s[20U] = (uint8_t)(s7 >> 13);
	s[21U] = (uint8_t)s8;
	s[22U] = (uint8_t)(s8 >> 8);
	s[23U] = (uint8_t)((s8 >> 16) | (s9 * (1 << 5)));
	s[24U] = (uint8_t)(s9 >> 3);
	s[25U] = (uint8_t)(s9 >> 11);
	s[26U] = (uint8_t)((s9 >> 19) | (s10 * (1 << 2)));
	s[27U] = (uint8_t)(s10 >> 6);
	s[28U] = (uint8_t)((s10 >> 14) | (s11 * (1 << 7)));
	s[29U] = (uint8_t)(s11 >> 1);
	s[30U] = (uint8_t)(s11 >> 9);
	s[31U] = (uint8_t)(s11 >> 17);
}

/*! \def ED25519_FORCE_PORTABLE
 * \brief Define to select split-word multiplication and portable group arithmetic.
 */
/*! \def ED25519_FORCE_WORD32
 * \brief Define to represent fixed-base group values with eight 32-bit words.
 */
#if defined(__SIZEOF_INT128__) && !defined(ED25519_FORCE_PORTABLE)

/*! \brief Private Ed25519 xwide representation. */
typedef __uint128_t qsc_ed25519_xwide;

/*! \def ED25519_NATIVE128
 * \brief Private configuration or constant for the X25519 arithmetic.
 */
#define ED25519_NATIVE128

#else

/*! \brief Private Ed25519 xwide representation. */
typedef struct
{
	uint64_t lo; /*!< Low 64 bits. */
	uint64_t hi; /*!< High 64 bits. */
} qsc_ed25519_xwide;

#endif

/*! \brief Private Ed25519 xarray representation. */
typedef struct
{
	uint64_t val[5U]; /*!< Five radix-2^51 limbs. */
} qsc_ed25519_xarray;

/*! \brief Private Ed25519 xfe representation. */
typedef struct
{
	qsc_ed25519_xarray m_v; /*!< Radix-2^51 field storage. */
} qsc_ed25519_xfe;

#if defined(_MSC_VER)

/*! \def ED25519_XINLINE
 * \brief Request inlining for hot shared Curve25519/Ed25519 arithmetic.
 */
#define ED25519_XINLINE static __forceinline

#elif defined(__GNUC__) || defined(__clang__)

/*! \def ED25519_XINLINE
 * \brief Request inlining for hot shared Curve25519/Ed25519 arithmetic.
 */
#define ED25519_XINLINE static inline __attribute__((always_inline))

#else

/*! \def ED25519_XINLINE
 * \brief Request inlining for hot shared Curve25519/Ed25519 arithmetic.
 */
#define ED25519_XINLINE static inline

#endif

/*! \def ED25519_XMASK51
 * \brief Private configuration or constant for the X25519 arithmetic.
 */
#define ED25519_XMASK51 ((UINT64_C(1) << 51) - 1)

ED25519_XINLINE qsc_ed25519_xwide ed25519_xwide_from64(uint64_t x)
{
#if defined(ED25519_NATIVE128)
	return (qsc_ed25519_xwide)x;
#else
	qsc_ed25519_xwide r = {x, 0};

	return r;
#endif
}

ED25519_XINLINE uint64_t ed25519_xwide_low(qsc_ed25519_xwide x)
{
#if defined(ED25519_NATIVE128)
	return (uint64_t)x;
#else
	return x.lo;
#endif
}

#if !defined(ED25519_NATIVE128)

ED25519_XINLINE uint64_t ed25519_xwide_carry(uint64_t x, uint64_t y)
{
#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
	/* x is the post-addition low word. The comparison detects unsigned wrap. */
	return (uint64_t)(x < y);
#else
	uint64_t u;
	uint64_t top;
	uint64_t mask;

	u = x ^ ((x ^ y) | ((x - y) ^ x));
	top = u >> 63;
#if defined(__GNUC__) || defined(__clang__)
	__asm__("" : "+r"(top));
#endif
	mask = ((uint64_t)0) - top;
#if defined(__GNUC__) || defined(__clang__)
	__asm__("" : "+r"(mask));
#endif
	return mask & 1U;
#endif
}

#endif

ED25519_XINLINE qsc_ed25519_xwide ed25519_xwide_add(qsc_ed25519_xwide x, qsc_ed25519_xwide y)
{
#if defined(ED25519_NATIVE128)
	return x + y;
#else
	x.lo += y.lo;
	x.hi += y.hi;
	x.hi += ed25519_xwide_carry(x.lo, y.lo);

	return x;
#endif
}

ED25519_XINLINE qsc_ed25519_xwide ed25519_xwide_add64(qsc_ed25519_xwide x, uint64_t y)
{
#if defined(ED25519_NATIVE128)
	return x + y;
#else
	x.lo += y;
	x.hi += ed25519_xwide_carry(x.lo, y);

	return x;
#endif
}

ED25519_XINLINE qsc_ed25519_xwide ed25519_xwide_right(qsc_ed25519_xwide x, size_t shift)
{
#if defined(ED25519_NATIVE128)
	return x >> shift;
#else
	if (shift > 64)
	{
		x.lo = x.hi >> (shift - 64);
		x.hi = 0;
	}
	else
	{
		if (shift == 64)
		{
			x.lo = x.hi;
			x.hi = 0;
		}
		else
		{
			if (shift > 0)
			{
				uint64_t carry;

				carry = x.hi << (64 - shift);
				x.hi >>= shift;
				x.lo >>= shift;
				x.lo |= carry;
			}
		}
	}

	return x;
#endif
}

ED25519_XINLINE qsc_ed25519_xwide ed25519_xwide_left(qsc_ed25519_xwide x, size_t shift)
{
#if defined(ED25519_NATIVE128)
	return x << shift;
#else
	if (shift > 64)
	{
		x.hi = x.lo << (shift - 64);
		x.lo = 0;
	}
	else
	{
		if (shift == 64)
		{
			x.hi = x.lo;
			x.lo = 0;
		}
		else
		{
			if (shift > 0)
			{
				uint64_t carry;

				carry = x.lo >> (64 - shift);
				x.lo <<= shift;
				x.hi = (x.hi << shift) | carry;
			}
		}
	}

	return x;
#endif
}

ED25519_XINLINE qsc_ed25519_xwide ed25519_xwide_or(qsc_ed25519_xwide x, qsc_ed25519_xwide y)
{
#if defined(ED25519_NATIVE128)
	return x | y;
#else
	x.lo |= y.lo;
	x.hi |= y.hi;

	return x;
#endif
}

ED25519_XINLINE qsc_ed25519_xwide ed25519_xwide_and(qsc_ed25519_xwide x, uint64_t mask)
{
#if defined(ED25519_NATIVE128)
	return x & mask;
#else
	x.lo &= mask;
	x.hi = 0;

	return x;
#endif
}

ED25519_XINLINE qsc_ed25519_xwide ed25519_xmul64(uint64_t a, uint64_t b)
{
#if defined(ED25519_NATIVE128)
	return ((qsc_ed25519_xwide)a) * b;
#else
	qsc_ed25519_xwide r;
#if defined(_MSC_VER) && defined(_M_X64) && !defined(_M_ARM64EC) && !defined(ED25519_FORCE_PORTABLE)
	r.lo = _umul128(a, b, &r.hi);
#elif defined(_MSC_VER) && defined(_M_ARM64) && !defined(ED25519_FORCE_PORTABLE)
	r.lo = a * b;
	r.hi = __umulh(a, b);
#else
	uint32_t ah;

	ah = (uint32_t)(a >> 32);
	uint32_t al;

	al = (uint32_t)a;
	uint32_t bh;

	bh = (uint32_t)(b >> 32);
	uint32_t bl;

	bl = (uint32_t)b;
	uint64_t x0;

	x0 = ((uint64_t)ah) * bh;
	uint64_t x1;

	x1 = ((uint64_t)al) * bh;
	uint64_t x2;

	x2 = ((uint64_t)ah) * bl;
	uint64_t x3;

	x3 = ((uint64_t)al) * bl;
	uint64_t middle;

	middle = (x2 + (x3 >> 32)) + (x1 & UINT32_MAX);
	r.hi = (x0 + (middle >> 32)) + (x1 >> 32);
	r.lo = (middle << 32) + (x3 & UINT32_MAX);
#endif
	return r;
#endif
}

ED25519_XINLINE qsc_ed25519_xwide ed25519_xwide_mulword(qsc_ed25519_xwide x, uint64_t y)
{
#if defined(ED25519_NATIVE128)
	return x * y;
#else
	return ed25519_xmul64(x.lo, y);
#endif
}

static inline uint64_t ed25519_xshift128(qsc_ed25519_xwide a, size_t shift)
{
	return ed25519_xwide_low(ed25519_xwide_right(a, shift));
}

static inline uint64_t ed25519_xcombine128(qsc_ed25519_xwide a, size_t s1, qsc_ed25519_xwide b, size_t s2)
{
	return ed25519_xwide_low(ed25519_xwide_or(ed25519_xwide_right(a, s1), ed25519_xwide_left(b, s2)));
}

static inline qsc_ed25519_xfe ed25519_xzero(void)
{
	qsc_ed25519_xfe r = {{{ 0 }}};

	return r;
}

static inline void ed25519_xone(qsc_ed25519_xfe* r)
{
	qsc_memutils_clear(r, sizeof(*r));
	r->m_v.val[0U] = 1;
}

static inline uint64_t ed25519_xload64(const uint8_t* in)
{
	uint64_t r;
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_copy(&r, in, sizeof(r));
#else
	r = qsc_intutils_le8to64(in);
#endif
	return r;
}

static inline void ed25519_xstore64(uint8_t* out, uint64_t v)
{
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_copy(out, &v, sizeof(v));
#else
	qsc_intutils_le64to8(out, v);
#endif
}

ED25519_XINLINE qsc_ed25519_xfe ed25519_xdecode(const uint8_t* in)
{
	qsc_ed25519_xfe r = {{{ 0 }}};

	r.m_v.val[0U] = ed25519_xload64(in) & ED25519_XMASK51;
	r.m_v.val[1U] = (ed25519_xload64(in + 6) >> 3) & ED25519_XMASK51;
	r.m_v.val[2U] = (ed25519_xload64(in + 12) >> 6) & ED25519_XMASK51;
	r.m_v.val[3U] = (ed25519_xload64(in + 19) >> 1) & ED25519_XMASK51;
	r.m_v.val[4U] = (ed25519_xload64(in + 24) >> 12) & ED25519_XMASK51;

	return r;
}

ED25519_XINLINE qsc_ed25519_xfe ed25519_xcarry(const qsc_ed25519_xwide* t0, qsc_ed25519_xwide t1, qsc_ed25519_xwide t2, qsc_ed25519_xwide t3, qsc_ed25519_xwide t4)
{
	qsc_ed25519_xfe r = {{{ 0 }}};

	r.m_v.val[0U] = ed25519_xwide_low(*t0) & ED25519_XMASK51;
	t1 = ed25519_xwide_add64(t1, ed25519_xshift128(*t0, 51));
	r.m_v.val[1U] = ed25519_xwide_low(t1) & ED25519_XMASK51;
	t2 = ed25519_xwide_add64(t2, ed25519_xshift128(t1, 51));
	r.m_v.val[2U] = ed25519_xwide_low(t2) & ED25519_XMASK51;
	t3 = ed25519_xwide_add64(t3, ed25519_xshift128(t2, 51));
	r.m_v.val[3U] = ed25519_xwide_low(t3) & ED25519_XMASK51;
	t4 = ed25519_xwide_add64(t4, ed25519_xshift128(t3, 51));
	r.m_v.val[4U] = ed25519_xwide_low(t4) & ED25519_XMASK51;
	r.m_v.val[0U] += ed25519_xshift128(t4, 51) * 19;
	r.m_v.val[1U] += r.m_v.val[0U] >> 51;
	r.m_v.val[0U] &= ED25519_XMASK51;

	return r;
}

ED25519_XINLINE void ed25519_xadd(qsc_ed25519_xfe* restrict r, const qsc_ed25519_xfe* a, const qsc_ed25519_xfe* b)
{
	size_t i;
	*r = (qsc_ed25519_xfe){{{ 0 }}};
	for (i = 0U; i != 5; ++i)
	{
		r->m_v.val[i] = a->m_v.val[i] + b->m_v.val[i];
	}
}

ED25519_XINLINE void ed25519_xsub(qsc_ed25519_xfe* restrict r, const qsc_ed25519_xfe* a, const qsc_ed25519_xfe* b)
{
	*r = (qsc_ed25519_xfe){{{ 0 }}};
	const uint64_t two54m152 = (UINT64_C(1) << 54) - 152;
	const uint64_t two54m8 = (UINT64_C(1) << 54) - 8;

	r->m_v.val[0U] = (a->m_v.val[0U] + two54m152) - b->m_v.val[0U];
	r->m_v.val[1U] = (a->m_v.val[1U] + two54m8) - b->m_v.val[1U];
	r->m_v.val[2U] = (a->m_v.val[2U] + two54m8) - b->m_v.val[2U];
	r->m_v.val[3U] = (a->m_v.val[3U] + two54m8) - b->m_v.val[3U];
	r->m_v.val[4U] = (a->m_v.val[4U] + two54m8) - b->m_v.val[4U];
}

ED25519_XINLINE qsc_ed25519_xfe ed25519_xmul(const qsc_ed25519_xfe* a, const qsc_ed25519_xfe* b)
{
	const uint64_t a0 = a->m_v.val[0U];
	const uint64_t a1 = a->m_v.val[1U];
	const uint64_t a2 = a->m_v.val[2U];
	const uint64_t a3 = a->m_v.val[3U];
	const uint64_t a4 = a->m_v.val[4U];
	const uint64_t b0 = b->m_v.val[0U];
	const uint64_t b1 = b->m_v.val[1U];
	const uint64_t b2 = b->m_v.val[2U];
	const uint64_t b3 = b->m_v.val[3U];
	const uint64_t b4 = b->m_v.val[4U];
	const uint64_t b119 = b1 * 19;
	const uint64_t b219 = b2 * 19;
	const uint64_t b319 = b3 * 19;
	const uint64_t b419 = b4 * 19;

	const qsc_ed25519_xwide t0 =
		ed25519_xwide_add(ed25519_xwide_add(ed25519_xwide_add(ed25519_xwide_add(ed25519_xmul64(a0, b0), ed25519_xmul64(a1, b419)), ed25519_xmul64(a2, b319)),
							  ed25519_xmul64(a3, b219)),
			ed25519_xmul64(a4, b119));
	const qsc_ed25519_xwide t1 =
		ed25519_xwide_add(ed25519_xwide_add(ed25519_xwide_add(ed25519_xwide_add(ed25519_xmul64(a0, b1), ed25519_xmul64(a1, b0)), ed25519_xmul64(a2, b419)),
							  ed25519_xmul64(a3, b319)),
			ed25519_xmul64(a4, b219));
	const qsc_ed25519_xwide t2 =
		ed25519_xwide_add(ed25519_xwide_add(ed25519_xwide_add(ed25519_xwide_add(ed25519_xmul64(a0, b2), ed25519_xmul64(a1, b1)), ed25519_xmul64(a2, b0)),
							  ed25519_xmul64(a3, b419)),
			ed25519_xmul64(a4, b319));
	const qsc_ed25519_xwide t3 = ed25519_xwide_add(
		ed25519_xwide_add(ed25519_xwide_add(ed25519_xwide_add(ed25519_xmul64(a0, b3), ed25519_xmul64(a1, b2)), ed25519_xmul64(a2, b1)), ed25519_xmul64(a3, b0)),
		ed25519_xmul64(a4, b419));
	const qsc_ed25519_xwide t4 = ed25519_xwide_add(
		ed25519_xwide_add(ed25519_xwide_add(ed25519_xwide_add(ed25519_xmul64(a0, b4), ed25519_xmul64(a1, b3)), ed25519_xmul64(a2, b2)), ed25519_xmul64(a3, b1)),
		ed25519_xmul64(a4, b0));

	return ed25519_xcarry(&t0, t1, t2, t3, t4);
}

ED25519_XINLINE qsc_ed25519_xfe ed25519_xsqr(const qsc_ed25519_xfe* a)
{
	const uint64_t a0 = a->m_v.val[0U];
	const uint64_t a1 = a->m_v.val[1U];
	const uint64_t a2 = a->m_v.val[2U];
	const uint64_t a3 = a->m_v.val[3U];
	const uint64_t a4 = a->m_v.val[4U];
	const uint64_t a02 = a0 * 2;
	const uint64_t a12 = a1 * 2;
	const uint64_t a238 = a2 * 38;
	const uint64_t a319 = a3 * 19;
	const uint64_t a419 = a4 * 19;
	const uint64_t a438 = a419 * 2;
	const qsc_ed25519_xwide t0 = ed25519_xwide_add(ed25519_xwide_add(ed25519_xmul64(a0, a0), ed25519_xmul64(a1, a438)), ed25519_xmul64(a3, a238));
	const qsc_ed25519_xwide t1 = ed25519_xwide_add(ed25519_xwide_add(ed25519_xmul64(a02, a1), ed25519_xmul64(a2, a438)), ed25519_xmul64(a3, a319));
	const qsc_ed25519_xwide t2 = ed25519_xwide_add(ed25519_xwide_add(ed25519_xmul64(a02, a2), ed25519_xmul64(a1, a1)), ed25519_xmul64(a3, a438));
	const qsc_ed25519_xwide t3 = ed25519_xwide_add(ed25519_xwide_add(ed25519_xmul64(a02, a3), ed25519_xmul64(a12, a2)), ed25519_xmul64(a4, a419));
	const qsc_ed25519_xwide t4 = ed25519_xwide_add(ed25519_xwide_add(ed25519_xmul64(a02, a4), ed25519_xmul64(a12, a3)), ed25519_xmul64(a2, a2));

	return ed25519_xcarry(&t0, t1, t2, t3, t4);
}

ED25519_XINLINE qsc_ed25519_xfe ed25519_xsqrn(const qsc_ed25519_xfe* a, size_t n)
{
	size_t i;
	qsc_ed25519_xfe r = *a;

	for (i = 0U; i != n; ++i)
	{
		r = ed25519_xsqr(&r);
	}

	return r;
}

ED25519_XINLINE void ed25519_xmul_a24(qsc_ed25519_xfe* restrict r, const qsc_ed25519_xfe* a)
{
	const uint64_t a24 = 121665;
	*r = (qsc_ed25519_xfe){{{ 0 }}};
	qsc_ed25519_xwide t = ed25519_xmul64(a->m_v.val[0U], a24);

	r->m_v.val[0U] = ed25519_xwide_low(t) & ED25519_XMASK51;
	t = ed25519_xwide_add64(ed25519_xmul64(a->m_v.val[1U], a24), ed25519_xshift128(t, 51));
	r->m_v.val[1U] = ed25519_xwide_low(t) & ED25519_XMASK51;
	t = ed25519_xwide_add64(ed25519_xmul64(a->m_v.val[2U], a24), ed25519_xshift128(t, 51));
	r->m_v.val[2U] = ed25519_xwide_low(t) & ED25519_XMASK51;
	t = ed25519_xwide_add64(ed25519_xmul64(a->m_v.val[3U], a24), ed25519_xshift128(t, 51));
	r->m_v.val[3U] = ed25519_xwide_low(t) & ED25519_XMASK51;
	t = ed25519_xwide_add64(ed25519_xmul64(a->m_v.val[4U], a24), ed25519_xshift128(t, 51));
	r->m_v.val[4U] = ed25519_xwide_low(t) & ED25519_XMASK51;
	r->m_v.val[0U] += ed25519_xshift128(t, 51) * 19;
}

ED25519_XINLINE void ed25519_xencode(uint8_t* out, const qsc_ed25519_xfe* a)
{
	size_t i;
	qsc_ed25519_xwide t0 = ed25519_xwide_from64(a->m_v.val[0U]);
	qsc_ed25519_xwide t1 = ed25519_xwide_from64(a->m_v.val[1U]);
	qsc_ed25519_xwide t2 = ed25519_xwide_from64(a->m_v.val[2U]);
	qsc_ed25519_xwide t3 = ed25519_xwide_from64(a->m_v.val[3U]);
	qsc_ed25519_xwide t4 = ed25519_xwide_from64(a->m_v.val[4U]);

	for (i = 0U; i != 2; ++i)
	{
		t1 = ed25519_xwide_add(t1, ed25519_xwide_right(t0, 51U));
		t0 = ed25519_xwide_and(t0, ED25519_XMASK51);
		t2 = ed25519_xwide_add(t2, ed25519_xwide_right(t1, 51U));
		t1 = ed25519_xwide_and(t1, ED25519_XMASK51);
		t3 = ed25519_xwide_add(t3, ed25519_xwide_right(t2, 51U));
		t2 = ed25519_xwide_and(t2, ED25519_XMASK51);
		t4 = ed25519_xwide_add(t4, ed25519_xwide_right(t3, 51U));
		t3 = ed25519_xwide_and(t3, ED25519_XMASK51);
		t0 = ed25519_xwide_add(t0, ed25519_xwide_mulword(ed25519_xwide_right(t4, 51U), 19));
		t4 = ed25519_xwide_and(t4, ED25519_XMASK51);
	}

	t0 = ed25519_xwide_add64(t0, 19);
	t1 = ed25519_xwide_add(t1, ed25519_xwide_right(t0, 51U));
	t0 = ed25519_xwide_and(t0, ED25519_XMASK51);
	t2 = ed25519_xwide_add(t2, ed25519_xwide_right(t1, 51U));
	t1 = ed25519_xwide_and(t1, ED25519_XMASK51);
	t3 = ed25519_xwide_add(t3, ed25519_xwide_right(t2, 51U));
	t2 = ed25519_xwide_and(t2, ED25519_XMASK51);
	t4 = ed25519_xwide_add(t4, ed25519_xwide_right(t3, 51U));
	t3 = ed25519_xwide_and(t3, ED25519_XMASK51);
	t0 = ed25519_xwide_add(t0, ed25519_xwide_mulword(ed25519_xwide_right(t4, 51U), 19));
	t4 = ed25519_xwide_and(t4, ED25519_XMASK51);
	t0 = ed25519_xwide_add64(t0, 0x8000000000000 - 19);
	t1 = ed25519_xwide_add64(t1, 0x8000000000000 - 1);
	t2 = ed25519_xwide_add64(t2, 0x8000000000000 - 1);
	t3 = ed25519_xwide_add64(t3, 0x8000000000000 - 1);
	t4 = ed25519_xwide_add64(t4, 0x8000000000000 - 1);
	t1 = ed25519_xwide_add(t1, ed25519_xwide_right(t0, 51U));
	t0 = ed25519_xwide_and(t0, ED25519_XMASK51);
	t2 = ed25519_xwide_add(t2, ed25519_xwide_right(t1, 51U));
	t1 = ed25519_xwide_and(t1, ED25519_XMASK51);
	t3 = ed25519_xwide_add(t3, ed25519_xwide_right(t2, 51U));
	t2 = ed25519_xwide_and(t2, ED25519_XMASK51);
	t4 = ed25519_xwide_add(t4, ed25519_xwide_right(t3, 51U));
	t3 = ed25519_xwide_and(t3, ED25519_XMASK51);
	t4 = ed25519_xwide_and(t4, ED25519_XMASK51);
	ed25519_xstore64(out, ed25519_xcombine128(t0, 0, t1, 51));
	ed25519_xstore64(out + 8, ed25519_xcombine128(t1, 13, t2, 38));
	ed25519_xstore64(out + 16, ed25519_xcombine128(t2, 26, t3, 25));
	ed25519_xstore64(out + 24, ed25519_xcombine128(t3, 39, t4, 12));
}

ED25519_XINLINE qsc_ed25519_xfe ed25519_xinvert(const qsc_ed25519_xfe* z)
{
	qsc_ed25519_xfe a = ed25519_xsqr(z);
	qsc_ed25519_xfe t = ed25519_xsqrn(&a, 2);
	qsc_ed25519_xfe b = ed25519_xmul(&t, z);

	a = ed25519_xmul(&b, &a);
	t = ed25519_xsqr(&a);
	b = ed25519_xmul(&t, &b);
	t = ed25519_xsqrn(&b, 5);
	b = ed25519_xmul(&t, &b);
	t = ed25519_xsqrn(&b, 10);
	qsc_ed25519_xfe c = ed25519_xmul(&t, &b);

	t = ed25519_xsqrn(&c, 20);
	t = ed25519_xmul(&t, &c);
	t = ed25519_xsqrn(&t, 10);
	b = ed25519_xmul(&t, &b);
	t = ed25519_xsqrn(&b, 50);
	c = ed25519_xmul(&t, &b);
	t = ed25519_xsqrn(&c, 100);
	t = ed25519_xmul(&t, &c);
	t = ed25519_xsqrn(&t, 50);
	t = ed25519_xmul(&t, &b);
	t = ed25519_xsqrn(&t, 5);

	return ed25519_xmul(&t, &a);
}

static inline uint64_t ed25519_xbarrier64(uint64_t x)
{
#if defined(_MSC_VER)
	volatile uint64_t guarded;

	guarded = x;
	x = guarded;
#elif defined(__GNUC__) || defined(__clang__)
	__asm__("" : "+r"(x));
#endif
	return x;
}

ED25519_XINLINE uint64_t ed25519_xexpand_top(uint64_t a)
{
	const uint64_t top = ed25519_xbarrier64(a >> 63);

	return ((uint64_t)0) - top;
}

static inline uint64_t ed25519_xexpand_bit(uint64_t v, size_t bit)
{
	return ed25519_xexpand_top(v << ((((sizeof(v)) * 8) - 1) - bit));
}

static inline uint64_t ed25519_xmask_xor(uint64_t x, uint64_t y)
{
	return ed25519_xbarrier64(x) ^ ed25519_xbarrier64(y);
}

static inline uint64_t ed25519_xmask_apply(uint64_t mask, uint64_t x)
{
	return ed25519_xbarrier64(mask) & x;
}

ED25519_XINLINE void ed25519_xcswap(uint64_t swap, qsc_ed25519_xfe* a, qsc_ed25519_xfe* b)
{
	size_t i;

	for (i = 0U; i != 5; ++i)
	{
		const uint64_t x = ed25519_xmask_apply(swap, a->m_v.val[i] ^ b->m_v.val[i]);

		a->m_v.val[i] ^= x;
		b->m_v.val[i] ^= x;
	}
}

ED25519_XINLINE void ed25519_xladder(uint8_t* out, const uint8_t* k, const uint8_t* u)
{
	size_t t;
	qsc_ed25519_xfe x1 = ed25519_xdecode(u);
	qsc_ed25519_xfe x2;

	ed25519_xone(&x2);
	qsc_ed25519_xfe z2 = ed25519_xzero();
	qsc_ed25519_xfe x3 = x1;
	qsc_ed25519_xfe z3;

	ed25519_xone(&z3);
	uint64_t swap;

	swap = 0U;

	for (t = 255; (t--) > 0;)
	{
		const uint64_t kt = ed25519_xexpand_bit((uint64_t)k[t / 8], t % 8);

		swap = ed25519_xmask_xor(swap, kt);
		ed25519_xcswap(swap, &x2, &x3);
		ed25519_xcswap(swap, &z2, &z3);
		swap = kt;
		qsc_ed25519_xfe init_A;

		ed25519_xadd(&init_A, &x2, &z2);
		const qsc_ed25519_xfe A = init_A;
		qsc_ed25519_xfe init_B;

		ed25519_xsub(&init_B, &x2, &z2);
		const qsc_ed25519_xfe B = init_B;
		qsc_ed25519_xfe init_C;

		ed25519_xadd(&init_C, &x3, &z3);
		const qsc_ed25519_xfe C = init_C;
		qsc_ed25519_xfe init_D;

		ed25519_xsub(&init_D, &x3, &z3);
		const qsc_ed25519_xfe D = init_D;
		const qsc_ed25519_xfe AA = ed25519_xsqr(&A);
		const qsc_ed25519_xfe BB = ed25519_xsqr(&B);
		qsc_ed25519_xfe init_E;

		ed25519_xsub(&init_E, &AA, &BB);
		const qsc_ed25519_xfe E = init_E;
		const qsc_ed25519_xfe DA = ed25519_xmul(&D, &A);
		const qsc_ed25519_xfe CB = ed25519_xmul(&C, &B);

		{
			qsc_ed25519_xfe s;
			qsc_ed25519_xfe v;

			ed25519_xadd(&s, &DA, &CB);
			v = ed25519_xsqr(&s);
			x3 = v;
		}
		{
			qsc_ed25519_xfe s;
			qsc_ed25519_xfe v;
			qsc_ed25519_xfe w;

			ed25519_xsub(&s, &DA, &CB);
			v = ed25519_xsqr(&s);
			w = ed25519_xmul(&x1, &v);
			z3 = w;
		}
		{
			qsc_ed25519_xfe v;

			v = ed25519_xmul(&AA, &BB);
			x2 = v;
		}
		{
			qsc_ed25519_xfe m;
			qsc_ed25519_xfe s;
			qsc_ed25519_xfe v;

			ed25519_xmul_a24(&m, &E);
			ed25519_xadd(&s, &AA, &m);
			v = ed25519_xmul(&E, &s);
			z2 = v;
		}
	}

	ed25519_xcswap(swap, &x2, &x3);
	ed25519_xcswap(swap, &z2, &z3);
	qsc_ed25519_xfe inv;
	qsc_ed25519_xfe result;

	inv = ed25519_xinvert(&z2);
	result = ed25519_xmul(&x2, &inv);
	ed25519_xencode(out, &result);
	qsc_memutils_secure_erase(&x1, sizeof(x1));
	qsc_memutils_secure_erase(&x2, sizeof(x2));
	qsc_memutils_secure_erase(&z2, sizeof(z2));
	qsc_memutils_secure_erase(&x3, sizeof(x3));
	qsc_memutils_secure_erase(&z3, sizeof(z3));
	qsc_memutils_secure_erase(&inv, sizeof(inv));
	qsc_memutils_secure_erase(&result, sizeof(result));
	qsc_memutils_secure_erase(&swap, sizeof(swap));
}

#if UINTPTR_MAX > UINT32_MAX && !defined(ED25519_FORCE_WORD32)

/*! \brief Private Ed25519 gword representation. */
typedef uint64_t qsc_ed25519_gword;

/*! \def ED25519_GWORDS
 * \brief Four saturated 64-bit words represent one 256-bit field value.
 */
#define ED25519_GWORDS 4

/*! \def ED25519_GBITS
 * \brief Private configuration or constant for the X25519 arithmetic.
 */
#define ED25519_GBITS 64

/*! \def ED25519_GMAX
 * \brief Private configuration or constant for the X25519 arithmetic.
 */
#define ED25519_GMAX UINT64_MAX

/*! \def ED25519_GWORD64
 * \brief Encode a 64-bit public constant in the configured word representation.
 * \param x: Unsigned 64-bit constant.
 */
#define ED25519_GWORD64(x) x

#else

/*! \brief Private Ed25519 gword representation. */
typedef uint32_t qsc_ed25519_gword;

/*! \def ED25519_GWORDS
 * \brief Eight saturated 32-bit words represent one 256-bit field value.
 */
#define ED25519_GWORDS 8

/*! \def ED25519_GBITS
 * \brief Private configuration or constant for the X25519 arithmetic.
 */
#define ED25519_GBITS 32

/*! \def ED25519_GMAX
 * \brief Private configuration or constant for the X25519 arithmetic.
 */
#define ED25519_GMAX UINT32_MAX

/*! \def ED25519_GWORD64
 * \brief Encode a 64-bit public constant in the configured word representation.
 * \param x: Unsigned 64-bit constant.
 */
#define ED25519_GWORD64(x) (uint32_t)(x), (uint32_t)((uint64_t)(x) >> 32)

#endif

static inline qsc_ed25519_gword ed25519_gloadword(const uint8_t* in)
{
#if ED25519_GBITS == 64
	return ed25519_xload64(in);
#else
	uint32_t x;
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_copy(&x, in, sizeof(x));
#else
	x = qsc_intutils_le8to32(in);
#endif
	return x;
#endif
}

static inline void ed25519_gstoreword(uint8_t* out, qsc_ed25519_gword x)
{
#if ED25519_GBITS == 64
	ed25519_xstore64(out, x);
#else
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_copy(out, &x, sizeof(x));
#else
	qsc_intutils_le32to8(out, x);
#endif
#endif
}

/*! \brief Private Ed25519 gfe representation. */
typedef struct
{
	qsc_ed25519_gword v[ED25519_GWORDS]; /*!< Little-endian saturated limbs. */
} qsc_ed25519_gfe;

/*! \brief Private Ed25519 gword3 representation. */
typedef struct
{
	qsc_ed25519_gword w0; /*!< Reference coordinate or accumulator component. */
	qsc_ed25519_gword w1; /*!< Reference coordinate or accumulator component. */
	qsc_ed25519_gword w2; /*!< Reference coordinate or accumulator component. */
} qsc_ed25519_gword3;

static inline qsc_ed25519_gword ed25519_gaddword(qsc_ed25519_gword x, qsc_ed25519_gword y, qsc_ed25519_gword* carry)
{
#if ED25519_GBITS == 32
	uint64_t s;

	s = (((uint64_t)x) + y) + ((*carry) & 1);
	*carry = (uint32_t)(s >> 32);
	return (uint32_t)s;
#elif defined(__clang__) || (defined(__GNUC__) && defined(__x86_64__) && !defined(ED25519_FORCE_PORTABLE))
	qsc_ed25519_gword cb;
	qsc_ed25519_gword z;
	qsc_ed25519_gword c1;

	cb = (*carry) & 1U;
	z = x + y;
	c1 = (qsc_ed25519_gword)(z < x);
	z += cb;
	*carry = c1 | (qsc_ed25519_gword)(z < cb);
	return z;
#else
	qsc_ed25519_xwide s = ed25519_xwide_add64(ed25519_xwide_add64(ed25519_xwide_from64(x), y), (*carry) & 1);
	*carry = ed25519_xshift128(s, 64);
	return ed25519_xwide_low(s);
#endif
}

static inline qsc_ed25519_gword ed25519_gsubword(qsc_ed25519_gword x, qsc_ed25519_gword y, qsc_ed25519_gword* carry)
{
	qsc_ed25519_gword cb = (*carry) & 1;
	qsc_ed25519_gword t0 = x - y;
	qsc_ed25519_gword c1 = t0 > x;
	qsc_ed25519_gword z = t0 - cb;
	*carry = c1 | (z > t0);
	return z;
}

static inline qsc_ed25519_gword ed25519_gmadd3(qsc_ed25519_gword a, qsc_ed25519_gword b, qsc_ed25519_gword c, qsc_ed25519_gword* d)
{
#if ED25519_GBITS == 64 && defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(ED25519_FORCE_PORTABLE)
	__asm__("mulq %[b]\n\taddq %[c],%[a]\n\tadcq $0,%[carry]\n\taddq %[d],%[a]\n\tadcq $0,%[carry]"
			: [a] "=a"(a), [b] "=rm"(b), [carry] "=&d"(*d)
			: "0"(a), "1"(b), [c] "g"(c), [d] "g"(*d)
			: "cc");

	return a;
#elif ED25519_GBITS == 32
	uint64_t s;

	s = ((((uint64_t)a) * b) + c) + (*d);
	*d = (uint32_t)(s >> 32);
	return (uint32_t)s;
#else
	qsc_ed25519_xwide s = ed25519_xwide_add64(ed25519_xwide_add64(ed25519_xmul64(a, b), c), *d);
	*d = ed25519_xshift128(s, 64);
	return ed25519_xwide_low(s);
#endif
}

static inline qsc_ed25519_gword3 ed25519_gword3_zero(void)
{
	qsc_ed25519_gword3 r = {0, 0, 0};

	return r;
}

static inline void ed25519_gword3_mul(qsc_ed25519_gword3* v, qsc_ed25519_gword x, qsc_ed25519_gword y)
{
#if ED25519_GBITS == 64 && defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(ED25519_FORCE_PORTABLE)
	qsc_ed25519_gword z0 = 0;
	qsc_ed25519_gword z1 = 0;

	__asm__("mulq %[y]" : "=a"(z0), "=d"(z1) : "a"(x), [y] "rm"(y) : "cc");
	__asm__("addq %[z0],%[w0]\n\tadcq %[z1],%[w1]\n\tadcq $0,%[w2]\n\t"
			: [w0] "=r"(v->w0), [w1] "=r"(v->w1), [w2] "=r"(v->w2)
			: [z0] "r"(z0), [z1] "r"(z1), "0"(v->w0), "1"(v->w1), "2"(v->w2)
			: "cc");
#else
	qsc_ed25519_gword z0;
	qsc_ed25519_gword z1;
	qsc_ed25519_gword carry = 0;
#if ED25519_GBITS == 32
	uint64_t z;

	z = ((uint64_t)x) * y;
	z0 = (uint32_t)z;
	z1 = (uint32_t)(z >> 32);
#else
	qsc_ed25519_xwide z = ed25519_xmul64(x, y);

	z0 = ed25519_xwide_low(z);
	z1 = ed25519_xshift128(z, 64);
#endif
	v->w0 = ed25519_gaddword(v->w0, z0, &carry);
	v->w1 = ed25519_gaddword(v->w1, z1, &carry);
	v->w2 += carry;
#endif
}

static inline void ed25519_gword3_mul2(qsc_ed25519_gword3* v, qsc_ed25519_gword x, qsc_ed25519_gword y)
{
#if ED25519_GBITS == 64 && defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(ED25519_FORCE_PORTABLE)
	qsc_ed25519_gword z0 = 0;
	qsc_ed25519_gword z1 = 0;

	__asm__("mulq %[y]" : "=a"(z0), "=d"(z1) : "a"(x), [y] "rm"(y) : "cc");
	__asm__("addq %[z0],%[w0]\n\tadcq %[z1],%[w1]\n\tadcq $0,%[w2]\n\taddq %[z0],%[w0]\n\tadcq %[z1],%[w1]\n\tadcq $0,%[w2]\n\t"
			: [w0] "=r"(v->w0), [w1] "=r"(v->w1), [w2] "=r"(v->w2)
			: [z0] "r"(z0), [z1] "r"(z1), "0"(v->w0), "1"(v->w1), "2"(v->w2)
			: "cc");
#else
	qsc_ed25519_gword z0;
	qsc_ed25519_gword z1;
	qsc_ed25519_gword carry = 0;
#if ED25519_GBITS == 32
	uint64_t z;

	z = ((uint64_t)x) * y;
	z0 = (uint32_t)z;
	z1 = (uint32_t)(z >> 32);
#else
	qsc_ed25519_xwide z = ed25519_xmul64(x, y);

	z0 = ed25519_xwide_low(z);
	z1 = ed25519_xshift128(z, 64);
#endif
	v->w0 = ed25519_gaddword(v->w0, z0, &carry);
	v->w1 = ed25519_gaddword(v->w1, z1, &carry);
	v->w2 += carry;
	carry = 0;
	v->w0 = ed25519_gaddword(v->w0, z0, &carry);
	v->w1 = ed25519_gaddword(v->w1, z1, &carry);
	v->w2 += carry;
#endif
}

static inline void ed25519_gword3_add(qsc_ed25519_gword3* r, qsc_ed25519_gword x)
{
	qsc_ed25519_gword c = 0;

	r->w0 = ed25519_gaddword(r->w0, x, &c);
	r->w1 = ed25519_gaddword(r->w1, 0, &c);
	r->w2 += c;
}

static inline qsc_ed25519_gword ed25519_gword3_extract(qsc_ed25519_gword3* r)
{
	qsc_ed25519_gword z = r->w0;

	r->w0 = r->w1;
	r->w1 = r->w2;
	r->w2 = 0;

	return z;
}

static inline qsc_ed25519_gword ed25519_gword3_monty(qsc_ed25519_gword3* r, qsc_ed25519_gword p0, qsc_ed25519_gword pdash)
{
	qsc_ed25519_gword z = r->w0 * pdash;

	ed25519_gword3_mul(r, z, p0);
	r->w0 = r->w1;
	r->w1 = r->w2;
	r->w2 = 0;

	return z;
}

static QSC_NO_INLINE void ed25519_gsquare(qsc_ed25519_gword z[2 * ED25519_GWORDS], const qsc_ed25519_gword x[ED25519_GWORDS])
{
#if ED25519_GWORDS == 4
	qsc_ed25519_gword3 accum = ed25519_gword3_zero();

	ed25519_gword3_mul(&accum, x[0U], x[0U]);
	z[0U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[0U], x[1U]);
	z[1U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[0U], x[2U]);
	ed25519_gword3_mul(&accum, x[1U], x[1U]);
	z[2U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[0U], x[3U]);
	ed25519_gword3_mul2(&accum, x[1U], x[2U]);
	z[3U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[1U], x[3U]);
	ed25519_gword3_mul(&accum, x[2U], x[2U]);
	z[4U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[2U], x[3U]);
	z[5U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[3U], x[3U]);
	z[6U] = ed25519_gword3_extract(&accum);
	z[7U] = ed25519_gword3_extract(&accum);
#else
	qsc_ed25519_gword3 accum = ed25519_gword3_zero();

	ed25519_gword3_mul(&accum, x[0U], x[0U]);
	z[0U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[0U], x[1U]);
	z[1U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[0U], x[2U]);
	ed25519_gword3_mul(&accum, x[1U], x[1U]);
	z[2U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[0U], x[3U]);
	ed25519_gword3_mul2(&accum, x[1U], x[2U]);
	z[3U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[0U], x[4U]);
	ed25519_gword3_mul2(&accum, x[1U], x[3U]);
	ed25519_gword3_mul(&accum, x[2U], x[2U]);
	z[4U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[0U], x[5U]);
	ed25519_gword3_mul2(&accum, x[1U], x[4U]);
	ed25519_gword3_mul2(&accum, x[2U], x[3U]);
	z[5U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[0U], x[6U]);
	ed25519_gword3_mul2(&accum, x[1U], x[5U]);
	ed25519_gword3_mul2(&accum, x[2U], x[4U]);
	ed25519_gword3_mul(&accum, x[3U], x[3U]);
	z[6U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[0U], x[7U]);
	ed25519_gword3_mul2(&accum, x[1U], x[6U]);
	ed25519_gword3_mul2(&accum, x[2U], x[5U]);
	ed25519_gword3_mul2(&accum, x[3U], x[4U]);
	z[7U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[1U], x[7U]);
	ed25519_gword3_mul2(&accum, x[2U], x[6U]);
	ed25519_gword3_mul2(&accum, x[3U], x[5U]);
	ed25519_gword3_mul(&accum, x[4U], x[4U]);
	z[8U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[2U], x[7U]);
	ed25519_gword3_mul2(&accum, x[3U], x[6U]);
	ed25519_gword3_mul2(&accum, x[4U], x[5U]);
	z[9U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[3U], x[7U]);
	ed25519_gword3_mul2(&accum, x[4U], x[6U]);
	ed25519_gword3_mul(&accum, x[5U], x[5U]);
	z[10U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[4U], x[7U]);
	ed25519_gword3_mul2(&accum, x[5U], x[6U]);
	z[11U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[5U], x[7U]);
	ed25519_gword3_mul(&accum, x[6U], x[6U]);
	z[12U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul2(&accum, x[6U], x[7U]);
	z[13U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[7U], x[7U]);
	z[14U] = ed25519_gword3_extract(&accum);
	z[15U] = ed25519_gword3_extract(&accum);
#endif
}

static QSC_NO_INLINE void ed25519_gmultiply(qsc_ed25519_gword z[2 * ED25519_GWORDS], const qsc_ed25519_gword x[ED25519_GWORDS], const qsc_ed25519_gword y[ED25519_GWORDS])
{
#if ED25519_GWORDS == 4
	qsc_ed25519_gword3 accum = ed25519_gword3_zero();

	ed25519_gword3_mul(&accum, x[0U], y[0U]);
	z[0U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[0U], y[1U]);
	ed25519_gword3_mul(&accum, x[1U], y[0U]);
	z[1U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[0U], y[2U]);
	ed25519_gword3_mul(&accum, x[1U], y[1U]);
	ed25519_gword3_mul(&accum, x[2U], y[0U]);
	z[2U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[0U], y[3U]);
	ed25519_gword3_mul(&accum, x[1U], y[2U]);
	ed25519_gword3_mul(&accum, x[2U], y[1U]);
	ed25519_gword3_mul(&accum, x[3U], y[0U]);
	z[3U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[1U], y[3U]);
	ed25519_gword3_mul(&accum, x[2U], y[2U]);
	ed25519_gword3_mul(&accum, x[3U], y[1U]);
	z[4U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[2U], y[3U]);
	ed25519_gword3_mul(&accum, x[3U], y[2U]);
	z[5U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[3U], y[3U]);
	z[6U] = ed25519_gword3_extract(&accum);
	z[7U] = ed25519_gword3_extract(&accum);
#else
	qsc_ed25519_gword3 accum = ed25519_gword3_zero();

	ed25519_gword3_mul(&accum, x[0U], y[0U]);
	z[0U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[0U], y[1U]);
	ed25519_gword3_mul(&accum, x[1U], y[0U]);
	z[1U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[0U], y[2U]);
	ed25519_gword3_mul(&accum, x[1U], y[1U]);
	ed25519_gword3_mul(&accum, x[2U], y[0U]);
	z[2U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[0U], y[3U]);
	ed25519_gword3_mul(&accum, x[1U], y[2U]);
	ed25519_gword3_mul(&accum, x[2U], y[1U]);
	ed25519_gword3_mul(&accum, x[3U], y[0U]);
	z[3U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[0U], y[4U]);
	ed25519_gword3_mul(&accum, x[1U], y[3U]);
	ed25519_gword3_mul(&accum, x[2U], y[2U]);
	ed25519_gword3_mul(&accum, x[3U], y[1U]);
	ed25519_gword3_mul(&accum, x[4U], y[0U]);
	z[4U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[0U], y[5U]);
	ed25519_gword3_mul(&accum, x[1U], y[4U]);
	ed25519_gword3_mul(&accum, x[2U], y[3U]);
	ed25519_gword3_mul(&accum, x[3U], y[2U]);
	ed25519_gword3_mul(&accum, x[4U], y[1U]);
	ed25519_gword3_mul(&accum, x[5U], y[0U]);
	z[5U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[0U], y[6U]);
	ed25519_gword3_mul(&accum, x[1U], y[5U]);
	ed25519_gword3_mul(&accum, x[2U], y[4U]);
	ed25519_gword3_mul(&accum, x[3U], y[3U]);
	ed25519_gword3_mul(&accum, x[4U], y[2U]);
	ed25519_gword3_mul(&accum, x[5U], y[1U]);
	ed25519_gword3_mul(&accum, x[6U], y[0U]);
	z[6U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[0U], y[7U]);
	ed25519_gword3_mul(&accum, x[1U], y[6U]);
	ed25519_gword3_mul(&accum, x[2U], y[5U]);
	ed25519_gword3_mul(&accum, x[3U], y[4U]);
	ed25519_gword3_mul(&accum, x[4U], y[3U]);
	ed25519_gword3_mul(&accum, x[5U], y[2U]);
	ed25519_gword3_mul(&accum, x[6U], y[1U]);
	ed25519_gword3_mul(&accum, x[7U], y[0U]);
	z[7U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[1U], y[7U]);
	ed25519_gword3_mul(&accum, x[2U], y[6U]);
	ed25519_gword3_mul(&accum, x[3U], y[5U]);
	ed25519_gword3_mul(&accum, x[4U], y[4U]);
	ed25519_gword3_mul(&accum, x[5U], y[3U]);
	ed25519_gword3_mul(&accum, x[6U], y[2U]);
	ed25519_gword3_mul(&accum, x[7U], y[1U]);
	z[8U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[2U], y[7U]);
	ed25519_gword3_mul(&accum, x[3U], y[6U]);
	ed25519_gword3_mul(&accum, x[4U], y[5U]);
	ed25519_gword3_mul(&accum, x[5U], y[4U]);
	ed25519_gword3_mul(&accum, x[6U], y[3U]);
	ed25519_gword3_mul(&accum, x[7U], y[2U]);
	z[9U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[3U], y[7U]);
	ed25519_gword3_mul(&accum, x[4U], y[6U]);
	ed25519_gword3_mul(&accum, x[5U], y[5U]);
	ed25519_gword3_mul(&accum, x[6U], y[4U]);
	ed25519_gword3_mul(&accum, x[7U], y[3U]);
	z[10U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[4U], y[7U]);
	ed25519_gword3_mul(&accum, x[5U], y[6U]);
	ed25519_gword3_mul(&accum, x[6U], y[5U]);
	ed25519_gword3_mul(&accum, x[7U], y[4U]);
	z[11U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[5U], y[7U]);
	ed25519_gword3_mul(&accum, x[6U], y[6U]);
	ed25519_gword3_mul(&accum, x[7U], y[5U]);
	z[12U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[6U], y[7U]);
	ed25519_gword3_mul(&accum, x[7U], y[6U]);
	z[13U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, x[7U], y[7U]);
	z[14U] = ed25519_gword3_extract(&accum);
	z[15U] = ed25519_gword3_extract(&accum);
#endif
}

static inline qsc_ed25519_gword ed25519_gbarrier(qsc_ed25519_gword x)
{
#if defined(_MSC_VER)
	volatile qsc_ed25519_gword guarded;

	guarded = x;
	x = guarded;
#elif defined(__GNUC__) || defined(__clang__)
	__asm__("" : "+r"(x));
#endif
	return x;
}

static inline qsc_ed25519_gword ed25519_gctzero(qsc_ed25519_gword x)
{
	qsc_ed25519_gword top = (qsc_ed25519_gword)((~x) & (x - 1));

	top = ed25519_gbarrier(top >> (ED25519_GBITS - 1));

	return ((qsc_ed25519_gword)0) - top;
}

static inline qsc_ed25519_gword ed25519_gselectword(qsc_ed25519_gword mask, qsc_ed25519_gword a, qsc_ed25519_gword b)
{
	return b ^ (mask & (a ^ b));
}

static inline void ed25519_gassign(qsc_ed25519_gword c, qsc_ed25519_gword* out, const qsc_ed25519_gword* in)
{
	size_t i;
	qsc_ed25519_gword mask = ed25519_gctzero(ed25519_gbarrier(ed25519_gbarrier(c)));

	mask = ~ed25519_gbarrier(mask);
	mask = ed25519_gbarrier(mask);

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		out[i] = ed25519_gselectword(mask, in[i], out[i]);
	}
}

static inline void ed25519_gfold_carry(qsc_ed25519_gfe* r, qsc_ed25519_gword carry)
{
	size_t fold;

	for (fold = 0U; fold != 2; ++fold)
	{
		size_t i;
		qsc_ed25519_gword c = 0;

		r->v[0U] = ed25519_gaddword(r->v[0U], carry * 38, &c);

		for (i = 1; i != ED25519_GWORDS; ++i)
		{
			r->v[i] = ed25519_gaddword(r->v[i], 0, &c);
		}

		carry = c;
	}
}

static inline void ed25519_gfold_borrow(qsc_ed25519_gfe* r, qsc_ed25519_gword borrow)
{
	size_t fold;

	for (fold = 0U; fold != 2; ++fold)
	{
		size_t i;
		qsc_ed25519_gword c = 0;

		r->v[0U] = ed25519_gsubword(r->v[0U], borrow * 38, &c);

		for (i = 1; i != ED25519_GWORDS; ++i)
		{
			r->v[i] = ed25519_gsubword(r->v[i], 0, &c);
		}

		borrow = c;
	}
}

static inline void ed25519_greduce(qsc_ed25519_gfe* r, const qsc_ed25519_gword z[2 * ED25519_GWORDS])
{
	size_t fold;
	size_t i;
	qsc_ed25519_gword carry = 0;

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		r->v[i] = ed25519_gmadd3(z[i + ED25519_GWORDS], 38, z[i], &carry);
	}

	for (fold = 0U; fold != 2; ++fold)
	{
		const qsc_ed25519_gword top = (carry << 1) | (r->v[ED25519_GWORDS - 1] >> (ED25519_GBITS - 1));

		r->v[ED25519_GWORDS - 1] &= ED25519_GMAX >> 1;
		carry = 0;
		qsc_ed25519_gword c = 0;

		r->v[0U] = ed25519_gaddword(r->v[0U], top * 19, &c);

		for (i = 1; i != ED25519_GWORDS; ++i)
		{
			r->v[i] = ed25519_gaddword(r->v[i], 0, &c);
		}
	}
}

/*! \brief Reference constant in little-endian saturated words. */
static const qsc_ed25519_gword ed25519_gp[ED25519_GWORDS] = {
	ED25519_GWORD64(UINT64_C(0xFFFFFFFFFFFFFFED)), ED25519_GWORD64(UINT64_MAX), ED25519_GWORD64(UINT64_MAX), ED25519_GWORD64(UINT64_C(0x7FFFFFFFFFFFFFFF))};

static inline qsc_ed25519_gfe ed25519_gcanonical(qsc_ed25519_gfe a)
{
	size_t i;
	qsc_ed25519_gfe t = a;
	qsc_ed25519_gword top = t.v[ED25519_GWORDS - 1] >> (ED25519_GBITS - 1);

	t.v[ED25519_GWORDS - 1] &= ED25519_GMAX >> 1;
	qsc_ed25519_gword c = 0;

	t.v[0U] = ed25519_gaddword(t.v[0U], top * 19, &c);

	for (i = 1; i != ED25519_GWORDS; ++i)
	{
		t.v[i] = ed25519_gaddword(t.v[i], 0, &c);
	}

	qsc_ed25519_gfe r = {{ 0 }};
	qsc_ed25519_gword borrow = 0;

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		r.v[i] = ed25519_gsubword(t.v[i], ed25519_gp[i], &borrow);
	}

	ed25519_gassign(borrow, r.v, t.v);

	return r;
}

static inline qsc_ed25519_gfe ed25519_gzero(void)
{
	qsc_ed25519_gfe r = {{ 0 }};

	return r;
}

static inline qsc_ed25519_gfe ed25519_gone(void)
{
	qsc_ed25519_gfe r = {{ 0 }};

	r.v[0U] = 1;

	return r;
}

static inline qsc_ed25519_gfe ed25519_gadd(qsc_ed25519_gfe a, qsc_ed25519_gfe b)
{
	size_t i;
	qsc_ed25519_gfe z = {{ 0 }};
	qsc_ed25519_gword c = 0;

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		z.v[i] = ed25519_gaddword(a.v[i], b.v[i], &c);
	}

	ed25519_gfold_carry(&z, c);

	return z;
}

static inline qsc_ed25519_gfe ed25519_gsub(qsc_ed25519_gfe a, qsc_ed25519_gfe b)
{
	size_t i;
	qsc_ed25519_gfe z = {{ 0 }};
	qsc_ed25519_gword c = 0;

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		z.v[i] = ed25519_gsubword(a.v[i], b.v[i], &c);
	}

	ed25519_gfold_borrow(&z, c);

	return z;
}

static inline qsc_ed25519_gfe ed25519_gnegate(qsc_ed25519_gfe a)
{
	return ed25519_gsub(ed25519_gzero(), a);
}

static inline qsc_ed25519_gfe ed25519_gmul(qsc_ed25519_gfe a, qsc_ed25519_gfe b)
{
	qsc_ed25519_gword z[2 * ED25519_GWORDS];

	ed25519_gmultiply(z, a.v, b.v);
	qsc_ed25519_gfe r = {{ 0 }};

	ed25519_greduce(&r, z);

	return r;
}

static inline qsc_ed25519_gfe ed25519_gsqr(qsc_ed25519_gfe a)
{
	qsc_ed25519_gword z[2 * ED25519_GWORDS];

	ed25519_gsquare(z, a.v);
	qsc_ed25519_gfe r = {{ 0 }};

	ed25519_greduce(&r, z);

	return r;
}

static inline qsc_ed25519_gfe ed25519_gsqrn(qsc_ed25519_gfe a, size_t n)
{
	size_t i;
	qsc_ed25519_gfe r = a;
	qsc_ed25519_gword z[2 * ED25519_GWORDS];

	for (i = 0U; i != n; ++i)
	{
		ed25519_gsquare(z, r.v);
		ed25519_greduce(&r, z);
	}

	return r;
}

static inline qsc_ed25519_gfe ed25519_gsqr2(qsc_ed25519_gfe a)
{
	qsc_ed25519_gfe z = ed25519_gsqr(a);

	return ed25519_gadd(z, z);
}

static inline qsc_ed25519_gfe ed25519_ginvert(qsc_ed25519_gfe a)
{
	qsc_ed25519_gfe t0 = ed25519_gsqr(a);
	qsc_ed25519_gfe t1 = ed25519_gsqrn(t0, 2);

	t1 = ed25519_gmul(a, t1);
	t0 = ed25519_gmul(t0, t1);
	qsc_ed25519_gfe t2 = ed25519_gsqr(t0);

	t1 = ed25519_gmul(t1, t2);
	t2 = ed25519_gsqrn(t1, 5);
	t1 = ed25519_gmul(t2, t1);
	t2 = ed25519_gsqrn(t1, 10);
	t2 = ed25519_gmul(t2, t1);
	qsc_ed25519_gfe t3 = ed25519_gsqrn(t2, 20);

	t2 = ed25519_gmul(t3, t2);
	t2 = ed25519_gsqrn(t2, 10);
	t1 = ed25519_gmul(t2, t1);
	t2 = ed25519_gsqrn(t1, 50);
	t2 = ed25519_gmul(t2, t1);
	t3 = ed25519_gsqrn(t2, 100);
	t2 = ed25519_gmul(t3, t2);
	t2 = ed25519_gsqrn(t2, 50);
	t1 = ed25519_gmul(t2, t1);
	t1 = ed25519_gsqrn(t1, 5);
	t0 = ed25519_gmul(t1, t0);

	return t0;
}

static inline void ed25519_gserialize(uint8_t out[32U], qsc_ed25519_gfe a)
{
	size_t i;
	qsc_ed25519_gfe w = ed25519_gcanonical(a);

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		ed25519_gstoreword(out + ((sizeof(qsc_ed25519_gword)) * i), w.v[i]);
	}
}

static inline void ed25519_gcondassign(qsc_ed25519_gword mask, qsc_ed25519_gfe* a, qsc_ed25519_gfe b)
{
	size_t i;

	mask = ed25519_gbarrier(mask);

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		a->v[i] = ed25519_gselectword(mask, b.v[i], a->v[i]);
	}
}

static inline void ed25519_gcondswap(qsc_ed25519_gword mask, qsc_ed25519_gfe* x, qsc_ed25519_gfe* y)
{
	size_t i;

	mask = ed25519_gbarrier(mask);

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		qsc_ed25519_gword nx = ed25519_gselectword(mask, y->v[i], x->v[i]);
		qsc_ed25519_gword ny = ed25519_gselectword(mask, x->v[i], y->v[i]);

		x->v[i] = nx;
		y->v[i] = ny;
	}
}

/*! \brief Private Ed25519 gcompleted representation. */
typedef struct
{
	qsc_ed25519_gfe x; /*!< X coordinate. */
	qsc_ed25519_gfe y; /*!< Y coordinate. */
	qsc_ed25519_gfe z; /*!< Z coordinate. */
	qsc_ed25519_gfe t; /*!< T coordinate. */
} qsc_ed25519_gcompleted;

/*! \brief Private Ed25519 gprojective representation. */
typedef struct
{
	qsc_ed25519_gfe x; /*!< X coordinate. */
	qsc_ed25519_gfe y; /*!< Y coordinate. */
	qsc_ed25519_gfe z; /*!< Z coordinate. */
} qsc_ed25519_gprojective;

/*! \brief Private Ed25519 gextended representation. */
typedef struct
{
	qsc_ed25519_gfe x; /*!< X coordinate. */
	qsc_ed25519_gfe y; /*!< Y coordinate. */
	qsc_ed25519_gfe z; /*!< Z coordinate. */
	qsc_ed25519_gfe t; /*!< T coordinate. */
} qsc_ed25519_gextended;

/*! \brief Private Ed25519 gniels representation. */
typedef struct
{
	qsc_ed25519_gfe yplusx;	 /*!< Reference coordinate or accumulator component. */
	qsc_ed25519_gfe yminusx; /*!< Reference coordinate or accumulator component. */
	qsc_ed25519_gfe xy2d;	 /*!< Reference coordinate or accumulator component. */
} qsc_ed25519_gniels;

static inline qsc_ed25519_gprojective ed25519_gprojective_from(qsc_ed25519_gcompleted p)
{
	qsc_ed25519_gprojective r;

	r.x = ed25519_gmul(p.x, p.t);
	r.y = ed25519_gmul(p.y, p.z);
	r.z = ed25519_gmul(p.z, p.t);

	return r;
}

static inline qsc_ed25519_gcompleted ed25519_gprojective_dbl(qsc_ed25519_gprojective p)
{
	qsc_ed25519_gcompleted r;

	r.x = ed25519_gsqr(p.x);
	r.z = ed25519_gsqr(p.y);
	r.t = ed25519_gsqr2(p.z);
	r.y = ed25519_gadd(p.x, p.y);
	qsc_ed25519_gfe t0 = ed25519_gsqr(r.y);

	r.y = ed25519_gadd(r.z, r.x);
	r.z = ed25519_gsub(r.z, r.x);
	r.x = ed25519_gsub(t0, r.y);
	r.t = ed25519_gsub(r.t, r.z);

	return r;
}

static inline qsc_ed25519_gextended ed25519_gextended_identity(void)
{
	qsc_ed25519_gextended h;

	h.x = ed25519_gzero();
	h.y = ed25519_gone();
	h.z = ed25519_gone();
	h.t = ed25519_gzero();

	return h;
}

static inline qsc_ed25519_gcompleted ed25519_gextended_dbl(qsc_ed25519_gextended p)
{
	qsc_ed25519_gprojective q;

	q.x = p.x;
	q.y = p.y;
	q.z = p.z;

	return ed25519_gprojective_dbl(q);
}

ED25519_XINLINE qsc_ed25519_gextended ed25519_gextended_from(qsc_ed25519_gcompleted p)
{
	qsc_ed25519_gextended r;

	r.x = ed25519_gmul(p.x, p.t);
	r.y = ed25519_gmul(p.y, p.z);
	r.z = ed25519_gmul(p.z, p.t);
	r.t = ed25519_gmul(p.x, p.y);

	return r;
}

static inline qsc_ed25519_gniels ed25519_gniels_identity(void)
{
	qsc_ed25519_gniels h;

	h.yplusx = ed25519_gone();
	h.yminusx = ed25519_gone();
	h.xy2d = ed25519_gzero();

	return h;
}

static inline qsc_ed25519_gcompleted ed25519_gadd_niels(qsc_ed25519_gextended p, qsc_ed25519_gniels q)
{
	qsc_ed25519_gcompleted r;

	r.x = ed25519_gadd(p.y, p.x);
	r.y = ed25519_gsub(p.y, p.x);
	r.z = ed25519_gmul(r.x, q.yplusx);
	r.y = ed25519_gmul(r.y, q.yminusx);
	r.t = ed25519_gmul(q.xy2d, p.t);
	qsc_ed25519_gfe t0 = ed25519_gadd(p.z, p.z);

	r.x = ed25519_gsub(r.z, r.y);
	r.y = ed25519_gadd(r.z, r.y);
	r.z = ed25519_gadd(t0, r.t);
	r.t = ed25519_gsub(t0, r.t);

	return r;
}

static inline qsc_ed25519_gextended ed25519_gextended_from_niels(qsc_ed25519_gniels p)
{
	qsc_ed25519_gextended r;

	r.x = ed25519_gsub(p.yplusx, p.yminusx);
	r.y = ed25519_gadd(p.yplusx, p.yminusx);
	r.t = ed25519_gmul(r.x, r.y);
	r.x = ed25519_gadd(r.x, r.x);
	r.y = ed25519_gadd(r.y, r.y);
	r.z = ed25519_gzero();
	r.z.v[0U] = 4U;
	qsc_memutils_secure_erase(&p, sizeof(p));

	return r;
}

static inline qsc_ed25519_gword ed25519_gequal8(uint8_t a, uint8_t b)
{
	qsc_ed25519_gword diff;

	diff = (qsc_ed25519_gword)(a ^ b);

	return ed25519_gctzero(ed25519_gbarrier(diff));
}

static inline qsc_ed25519_gniels ed25519_gselect(const qsc_ed25519_gniels base[8U], int8_t b)
{
	size_t i;
	uint8_t bn;

	bn = ((uint8_t)b) >> 7;
	uint8_t ba;

	ba = (uint8_t)(b - (((-((int)bn)) & b) * 2));
	qsc_ed25519_gniels t = ed25519_gniels_identity();

	for (i = 0U; i != 8; ++i)
	{
		qsc_ed25519_gword mask = ed25519_gequal8(ba, (uint8_t)(i + 1));

		ed25519_gcondassign(mask, &t.yplusx, base[i].yplusx);
		ed25519_gcondassign(mask, &t.yminusx, base[i].yminusx);
		ed25519_gcondassign(mask, &t.xy2d, base[i].xy2d);
	}

	qsc_ed25519_gword neg = (qsc_ed25519_gword)0 - ed25519_gbarrier((qsc_ed25519_gword)bn);

	ed25519_gcondswap(neg, &t.yplusx, &t.yminusx);
	ed25519_gcondassign(neg, &t.xy2d, ed25519_gnegate(t.xy2d));

	return t;
}

static inline void ed25519_gmontysub(qsc_ed25519_gword r[ED25519_GWORDS], qsc_ed25519_gword x0, const qsc_ed25519_gword x[ED25519_GWORDS], const qsc_ed25519_gword p[ED25519_GWORDS])
{
	size_t i;
	qsc_ed25519_gword borrow = 0;

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		r[i] = ed25519_gsubword(x[i], p[i], &borrow);
	}

	borrow = (x0 - borrow) > x0;
	ed25519_gassign(borrow, r, x);
}

static QSC_NO_INLINE void ed25519_gmonty(qsc_ed25519_gword r[ED25519_GWORDS], const qsc_ed25519_gword z[2 * ED25519_GWORDS], const qsc_ed25519_gword p[ED25519_GWORDS], qsc_ed25519_gword p_dash, qsc_ed25519_gword ws[ED25519_GWORDS])
{
#if ED25519_GWORDS == 4
	qsc_ed25519_gword3 accum = ed25519_gword3_zero();

	ed25519_gword3_add(&accum, z[0U]);
	ws[0U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[0U], p[1U]);
	ed25519_gword3_add(&accum, z[1U]);
	ws[1U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[0U], p[2U]);
	ed25519_gword3_mul(&accum, ws[1U], p[1U]);
	ed25519_gword3_add(&accum, z[2U]);
	ws[2U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[0U], p[3U]);
	ed25519_gword3_mul(&accum, ws[1U], p[2U]);
	ed25519_gword3_mul(&accum, ws[2U], p[1U]);
	ed25519_gword3_add(&accum, z[3U]);
	ws[3U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[1U], p[3U]);
	ed25519_gword3_mul(&accum, ws[2U], p[2U]);
	ed25519_gword3_mul(&accum, ws[3U], p[1U]);
	ed25519_gword3_add(&accum, z[4U]);
	ws[0U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, ws[2U], p[3U]);
	ed25519_gword3_mul(&accum, ws[3U], p[2U]);
	ed25519_gword3_add(&accum, z[5U]);
	ws[1U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, ws[3U], p[3U]);
	ed25519_gword3_add(&accum, z[6U]);
	ws[2U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_add(&accum, z[7U]);
	ws[3U] = ed25519_gword3_extract(&accum);
	const qsc_ed25519_gword w1 = ed25519_gword3_extract(&accum);

	ed25519_gmontysub(r, w1, ws, p);
#else
	qsc_ed25519_gword3 accum = ed25519_gword3_zero();

	ed25519_gword3_add(&accum, z[0U]);
	ws[0U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[0U], p[1U]);
	ed25519_gword3_add(&accum, z[1U]);
	ws[1U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[0U], p[2U]);
	ed25519_gword3_mul(&accum, ws[1U], p[1U]);
	ed25519_gword3_add(&accum, z[2U]);
	ws[2U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[0U], p[3U]);
	ed25519_gword3_mul(&accum, ws[1U], p[2U]);
	ed25519_gword3_mul(&accum, ws[2U], p[1U]);
	ed25519_gword3_add(&accum, z[3U]);
	ws[3U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[0U], p[4U]);
	ed25519_gword3_mul(&accum, ws[1U], p[3U]);
	ed25519_gword3_mul(&accum, ws[2U], p[2U]);
	ed25519_gword3_mul(&accum, ws[3U], p[1U]);
	ed25519_gword3_add(&accum, z[4U]);
	ws[4U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[0U], p[5U]);
	ed25519_gword3_mul(&accum, ws[1U], p[4U]);
	ed25519_gword3_mul(&accum, ws[2U], p[3U]);
	ed25519_gword3_mul(&accum, ws[3U], p[2U]);
	ed25519_gword3_mul(&accum, ws[4U], p[1U]);
	ed25519_gword3_add(&accum, z[5U]);
	ws[5U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[0U], p[6U]);
	ed25519_gword3_mul(&accum, ws[1U], p[5U]);
	ed25519_gword3_mul(&accum, ws[2U], p[4U]);
	ed25519_gword3_mul(&accum, ws[3U], p[3U]);
	ed25519_gword3_mul(&accum, ws[4U], p[2U]);
	ed25519_gword3_mul(&accum, ws[5U], p[1U]);
	ed25519_gword3_add(&accum, z[6U]);
	ws[6U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[0U], p[7U]);
	ed25519_gword3_mul(&accum, ws[1U], p[6U]);
	ed25519_gword3_mul(&accum, ws[2U], p[5U]);
	ed25519_gword3_mul(&accum, ws[3U], p[4U]);
	ed25519_gword3_mul(&accum, ws[4U], p[3U]);
	ed25519_gword3_mul(&accum, ws[5U], p[2U]);
	ed25519_gword3_mul(&accum, ws[6U], p[1U]);
	ed25519_gword3_add(&accum, z[7U]);
	ws[7U] = ed25519_gword3_monty(&accum, p[0U], p_dash);
	ed25519_gword3_mul(&accum, ws[1U], p[7U]);
	ed25519_gword3_mul(&accum, ws[2U], p[6U]);
	ed25519_gword3_mul(&accum, ws[3U], p[5U]);
	ed25519_gword3_mul(&accum, ws[4U], p[4U]);
	ed25519_gword3_mul(&accum, ws[5U], p[3U]);
	ed25519_gword3_mul(&accum, ws[6U], p[2U]);
	ed25519_gword3_mul(&accum, ws[7U], p[1U]);
	ed25519_gword3_add(&accum, z[8U]);
	ws[0U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, ws[2U], p[7U]);
	ed25519_gword3_mul(&accum, ws[3U], p[6U]);
	ed25519_gword3_mul(&accum, ws[4U], p[5U]);
	ed25519_gword3_mul(&accum, ws[5U], p[4U]);
	ed25519_gword3_mul(&accum, ws[6U], p[3U]);
	ed25519_gword3_mul(&accum, ws[7U], p[2U]);
	ed25519_gword3_add(&accum, z[9U]);
	ws[1U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, ws[3U], p[7U]);
	ed25519_gword3_mul(&accum, ws[4U], p[6U]);
	ed25519_gword3_mul(&accum, ws[5U], p[5U]);
	ed25519_gword3_mul(&accum, ws[6U], p[4U]);
	ed25519_gword3_mul(&accum, ws[7U], p[3U]);
	ed25519_gword3_add(&accum, z[10U]);
	ws[2U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, ws[4U], p[7U]);
	ed25519_gword3_mul(&accum, ws[5U], p[6U]);
	ed25519_gword3_mul(&accum, ws[6U], p[5U]);
	ed25519_gword3_mul(&accum, ws[7U], p[4U]);
	ed25519_gword3_add(&accum, z[11U]);
	ws[3U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, ws[5U], p[7U]);
	ed25519_gword3_mul(&accum, ws[6U], p[6U]);
	ed25519_gword3_mul(&accum, ws[7U], p[5U]);
	ed25519_gword3_add(&accum, z[12U]);
	ws[4U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, ws[6U], p[7U]);
	ed25519_gword3_mul(&accum, ws[7U], p[6U]);
	ed25519_gword3_add(&accum, z[13U]);
	ws[5U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_mul(&accum, ws[7U], p[7U]);
	ed25519_gword3_add(&accum, z[14U]);
	ws[6U] = ed25519_gword3_extract(&accum);
	ed25519_gword3_add(&accum, z[15U]);
	ws[7U] = ed25519_gword3_extract(&accum);
	const qsc_ed25519_gword w1 = ed25519_gword3_extract(&accum);

	ed25519_gmontysub(r, w1, ws, p);
#endif
}

/*! \brief Reference constant in little-endian saturated words. */
static const qsc_ed25519_gword ed25519_gl[ED25519_GWORDS] = {ED25519_GWORD64(UINT64_C(0x5812631a5cf5d3ed)), ED25519_GWORD64(UINT64_C(0x14def9dea2f79cd6)),
	ED25519_GWORD64(UINT64_C(0x0000000000000000)), ED25519_GWORD64(UINT64_C(0x1000000000000000))};

/*! \brief Reference constant in little-endian saturated words. */
static const qsc_ed25519_gword ed25519_gr1[ED25519_GWORDS] = {ED25519_GWORD64(UINT64_C(0xd6ec31748d98951d)), ED25519_GWORD64(UINT64_C(0xc6ef5bf4737dcf70)),
	ED25519_GWORD64(UINT64_C(0xfffffffffffffffe)), ED25519_GWORD64(UINT64_C(0x0fffffffffffffff))};

static void ed25519_gscalar(uint8_t out[32U], const uint8_t b[32U])
{
	size_t i;
	qsc_ed25519_gword x[ED25519_GWORDS];

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		x[i] = ed25519_gloadword(b + ((sizeof(qsc_ed25519_gword)) * i));
	}

	qsc_ed25519_gword z[2 * ED25519_GWORDS];
	qsc_ed25519_gword r[ED25519_GWORDS];
	qsc_ed25519_gword ws[ED25519_GWORDS];

	ed25519_gmultiply(z, x, ed25519_gr1);
	ed25519_gmonty(r, z, ed25519_gl, (qsc_ed25519_gword)UINT64_C(0xd2b51da312547e1b), ws);

	for (i = 0U; i != ED25519_GWORDS; ++i)
	{
		ed25519_gstoreword(out + ((sizeof(qsc_ed25519_gword)) * i), r[i]);
	}

	qsc_memutils_secure_erase(x, sizeof(x));
	qsc_memutils_secure_erase(z, sizeof(z));
	qsc_memutils_secure_erase(r, sizeof(r));
	qsc_memutils_secure_erase(ws, sizeof(ws));
}

static qsc_ed25519_gextended ed25519_gbasepoint(const uint8_t a[32U], const qsc_ed25519_gniels table[32U][8U])
{
	size_t i;
	int8_t e[64U] = { 0 };

	for (i = 0U; i != 32; ++i)
	{
		e[2 * i] = (a[i] >> 0) & 0x0f;
		e[(2 * i) + 1] = (a[i] >> 4) & 0x0f;
	}

	int8_t carry;

	carry = 0;

	for (i = 0U; i < 63; ++i)
	{
		e[i] += carry;
		carry = e[i] + 8;
		carry >>= 4;
		e[i] -= carry << 4;
	}

	e[63U] += carry;
	qsc_ed25519_gextended h = ed25519_gextended_from_niels(ed25519_gselect(table[0U], e[1U]));

	for (i = 3U; i < 64; i += 2)
	{
		h = ed25519_gextended_from(ed25519_gadd_niels(h, ed25519_gselect(table[i / 2], e[i])));
	}

	qsc_ed25519_gprojective s = ed25519_gprojective_from(ed25519_gextended_dbl(h));

	s = ed25519_gprojective_from(ed25519_gprojective_dbl(s));
	s = ed25519_gprojective_from(ed25519_gprojective_dbl(s));
	h = ed25519_gextended_from(ed25519_gprojective_dbl(s));

	for (i = 0U; i != 64; i += 2)
	{
		h = ed25519_gextended_from(ed25519_gadd_niels(h, ed25519_gselect(table[i / 2], e[i])));
	}

	qsc_memutils_secure_erase(e, sizeof(e));
	qsc_memutils_secure_erase(&s, sizeof(s));

	return h;
}

static void ed25519_gpublic(uint8_t out[32U], const uint8_t scalar[32U], const qsc_ed25519_gniels table[32U][8U])
{
	qsc_ed25519_gextended h = ed25519_gbasepoint(scalar, table);
	qsc_ed25519_gfe u = ed25519_gmul(ed25519_gadd(h.z, h.y), ed25519_ginvert(ed25519_gsub(h.z, h.y)));

	ed25519_gserialize(out, u);
	qsc_memutils_secure_erase(&h, sizeof(h));
	qsc_memutils_secure_erase(&u, sizeof(u));
}

static inline void ed25519_xclamp(uint8_t k[32U], const uint8_t scalar[32U])
{
	qsc_memutils_copy(k, scalar, 32U);
	k[0U] &= 248;
	k[31U] &= 127;
	k[31U] |= 64;
}

/*!
 * \brief Computes the raw 32-byte X25519 Montgomery result.
 * \param out: Caller-owned output; capacity is given by the array extent or result type.
 * \param scalar: Caller-owned 32-byte little-endian scalar; not modified.
 * \param u: Caller-owned 32-byte peer u-coordinate; its high bit is ignored.
 * \details All buffers contain 32 bytes and must be non-null. No allocation or shared mutable state.
 * The clamped scalar and terminal ladder state are securely erased.
 * Low-order/all-zero rejection belongs to the public wrapper.
 */
void qsc_ed25519_x25519_exchange(uint8_t out[32U], const uint8_t scalar[32U], const uint8_t u[32U])
{
	uint8_t k[32U] = { 0 };

	ed25519_xclamp(k, scalar);
	ed25519_xladder(out, k, u);
	qsc_memutils_secure_erase(k, sizeof(k));
}

/*! \brief Immutable Edwards basepoint table: (j+1)*256^i*B in Niels coordinates.
 * Generated from the public Edwards base point; provenance is recorded above.
 * Avoids runtime allocation, mutable initialization and first-use synchronization.
 */
static const qsc_ed25519_gniels ed25519_gbase_table[32U][8U] = {
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2FBC93C6F58C3B72)), ED25519_GWORD64(UINT64_C(0xCF932DC6FB8C0E19)),
				ED25519_GWORD64(UINT64_C(0x270B4898643D42C2)), ED25519_GWORD64(UINT64_C(0x87CF9D3A33D4BA65))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9D103905D740913E)), ED25519_GWORD64(UINT64_C(0xFD399F05D140BEB3)),
				ED25519_GWORD64(UINT64_C(0xA5C18434688F8A09)), ED25519_GWORD64(UINT64_C(0x44FD2F9298F81267))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xABC91205877AAA68)), ED25519_GWORD64(UINT64_C(0x26D9E823CCAAC49E)),
				ED25519_GWORD64(UINT64_C(0x5A1B7DCBDD43598C)), ED25519_GWORD64(UINT64_C(0x6F117B689F0C65A8))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9224E7FC933C71D7)), ED25519_GWORD64(UINT64_C(0x9F469D967A0FF5B5)),
				ED25519_GWORD64(UINT64_C(0x5AA69A65E1D60702)), ED25519_GWORD64(UINT64_C(0x590C063FA87D2E2E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8A99A56042B4D595)), ED25519_GWORD64(UINT64_C(0x8F2B810C4E60ACF6)),
				ED25519_GWORD64(UINT64_C(0xE09E236BB16E37AA)), ED25519_GWORD64(UINT64_C(0xEBB595A669C92555))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x43FAA8B3A59B7A5F)), ED25519_GWORD64(UINT64_C(0x36C16BDD5D9ACF78)),
				ED25519_GWORD64(UINT64_C(0x500FA0840B3D6A31)), ED25519_GWORD64(UINT64_C(0x701AF5B13EA50B73))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xAF25B0A84CEE9730)), ED25519_GWORD64(UINT64_C(0x025A8430E8864B8A)),
				ED25519_GWORD64(UINT64_C(0xC11B50029F016732)), ED25519_GWORD64(UINT64_C(0x7A164E1B9A80F8F4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x56611FE8A4FCD252)), ED25519_GWORD64(UINT64_C(0x3BD353FDE5C1BA7D)),
				ED25519_GWORD64(UINT64_C(0x8131F31A214BD6BD)), ED25519_GWORD64(UINT64_C(0xAAB91587555BDA62))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x14AE933F0DD0D889)), ED25519_GWORD64(UINT64_C(0x589423221C35DA62)),
				ED25519_GWORD64(UINT64_C(0xD170E5458CF2DB4C)), ED25519_GWORD64(UINT64_C(0x5A2826AF12B9B4C6))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x287351B98EFC099F)), ED25519_GWORD64(UINT64_C(0x6765C6F47DFD2538)),
				ED25519_GWORD64(UINT64_C(0xCA348D3DFB0A9265)), ED25519_GWORD64(UINT64_C(0x680E910321E58727))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x95FE050A056818BF)), ED25519_GWORD64(UINT64_C(0x327E89715660FAA9)),
				ED25519_GWORD64(UINT64_C(0xC3E8E3CD06A05073)), ED25519_GWORD64(UINT64_C(0x27933F4C7445A49A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5A13FBE9C476FF09)), ED25519_GWORD64(UINT64_C(0x6E9E39457B5CC172)),
				ED25519_GWORD64(UINT64_C(0x5DDBDCF9102B4494)), ED25519_GWORD64(UINT64_C(0x7F9D0CBF63553E2B))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA212BC4408A5BB20)), ED25519_GWORD64(UINT64_C(0x8D5048C3C75EED02)),
				ED25519_GWORD64(UINT64_C(0xDD1BEB0C5ABFEC44)), ED25519_GWORD64(UINT64_C(0xA945CCF146E206EB))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7F9182C3A447D6BA)), ED25519_GWORD64(UINT64_C(0xD50014D14B2729B7)),
				ED25519_GWORD64(UINT64_C(0xE33CF11CB864A087)), ED25519_GWORD64(UINT64_C(0x154A7E73EB1B55F3))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xBCBBDBF1812A8285)), ED25519_GWORD64(UINT64_C(0x270E0807D0BDD1FC)),
				ED25519_GWORD64(UINT64_C(0xB41B670B1BBDA72D)), ED25519_GWORD64(UINT64_C(0x43AABE696B3BB69A))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3A0CEEEB77157131)), ED25519_GWORD64(UINT64_C(0x9B27158900C8AF88)),
				ED25519_GWORD64(UINT64_C(0x8065B668DA59A736)), ED25519_GWORD64(UINT64_C(0x51E57BB6A2CC38BD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x499806B67B7D8C91)), ED25519_GWORD64(UINT64_C(0x575BE28427D22739)),
				ED25519_GWORD64(UINT64_C(0xBB085CE7204553B9)), ED25519_GWORD64(UINT64_C(0xB8B64C41AE417884))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x85AC326702EA4B71)), ED25519_GWORD64(UINT64_C(0xBE70E00341A1BB01)),
				ED25519_GWORD64(UINT64_C(0x53E4A24B083BC144)), ED25519_GWORD64(UINT64_C(0x10B8E91A9F0D61E3))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6B1A5CD0944EA3BF)), ED25519_GWORD64(UINT64_C(0x7470353AB39DC0D2)),
				ED25519_GWORD64(UINT64_C(0x71B2528228542E49)), ED25519_GWORD64(UINT64_C(0x461BEA69283C927E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xBA6F2C9AAA3221B1)), ED25519_GWORD64(UINT64_C(0x6CA021533BBA23A7)),
				ED25519_GWORD64(UINT64_C(0x9DEA764F92192C3A)), ED25519_GWORD64(UINT64_C(0x1D6EDD5D2E5317E0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF1836DC801B8B3A2)), ED25519_GWORD64(UINT64_C(0xB3035F47053EA49A)),
				ED25519_GWORD64(UINT64_C(0x529C41BA5877ADF3)), ED25519_GWORD64(UINT64_C(0x7A9FBB1C6A0F90A7))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x59B7596604DD3E7C)), ED25519_GWORD64(UINT64_C(0x6CB30377E288702C)),
				ED25519_GWORD64(UINT64_C(0xB1339C665ED9C323)), ED25519_GWORD64(UINT64_C(0x8915E76061BCE52F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE2A75DEDF39234C6)), ED25519_GWORD64(UINT64_C(0x963D7680E1B558F9)),
				ED25519_GWORD64(UINT64_C(0x2C2741AC6E3C23FB)), ED25519_GWORD64(UINT64_C(0xBA9024A1320E01C3))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE7C1F5D9C9A2911A)), ED25519_GWORD64(UINT64_C(0xB8A371788BCCA7D7)),
				ED25519_GWORD64(UINT64_C(0x636412190EB62A32)), ED25519_GWORD64(UINT64_C(0x26907C5C2ECC4E95))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2ECCDD0E632F9C1D)), ED25519_GWORD64(UINT64_C(0x51D0B69676893115)),
				ED25519_GWORD64(UINT64_C(0x52DFB76BA8637A58)), ED25519_GWORD64(UINT64_C(0x6DD37D49A00EEF39))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xED5B635449AA514B)), ED25519_GWORD64(UINT64_C(0xA865C49F0BC6823A)),
				ED25519_GWORD64(UINT64_C(0x850C1FE95B42D1C4)), ED25519_GWORD64(UINT64_C(0xB0D76D6F03D315B9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6C4444172106E4C7)), ED25519_GWORD64(UINT64_C(0xFB53D680928D7F69)),
				ED25519_GWORD64(UINT64_C(0xB4739EA4694D3F26)), ED25519_GWORD64(UINT64_C(0x10C697112E864BB0))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x0CA62AA08358C7F2)), ED25519_GWORD64(UINT64_C(0x6A3D4AE37A204247)),
				ED25519_GWORD64(UINT64_C(0x7464D3A63B11EDDC)), ED25519_GWORD64(UINT64_C(0x83BF9BAF550806EF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6493C4277DBE5FDE)), ED25519_GWORD64(UINT64_C(0x265D4FAD19AD7EA2)),
				ED25519_GWORD64(UINT64_C(0x0E00DFC846304590)), ED25519_GWORD64(UINT64_C(0x25E61CABED66FE09))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3F13E128CC586604)), ED25519_GWORD64(UINT64_C(0x6F5873ECB459747E)),
				ED25519_GWORD64(UINT64_C(0xA0B63DEDCC1268F5)), ED25519_GWORD64(UINT64_C(0x566D78634586E22C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA1054285C65A2FBD)), ED25519_GWORD64(UINT64_C(0x6C64112AF31667C3)),
				ED25519_GWORD64(UINT64_C(0x680AE240731AEE58)), ED25519_GWORD64(UINT64_C(0x94FBA5F34793B22A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1637A49F9CC10821)), ED25519_GWORD64(UINT64_C(0xBC8E56D5A89BC451)),
				ED25519_GWORD64(UINT64_C(0x1CB5EC0F7F7FD2DB)), ED25519_GWORD64(UINT64_C(0xB3975BCA5ECC35D9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3CD746166985F7D4)), ED25519_GWORD64(UINT64_C(0x593E5E84C9C80057)),
				ED25519_GWORD64(UINT64_C(0x2FC3F2B67B61131E)), ED25519_GWORD64(UINT64_C(0x14829CEA83FC526C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x21E70B2F4E71ECA5)), ED25519_GWORD64(UINT64_C(0xE656DDB940A477E3)),
				ED25519_GWORD64(UINT64_C(0xBF6556CECE1D4F80)), ED25519_GWORD64(UINT64_C(0x85FC3BC4535D7B7E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xFF437B8497DD95AF)), ED25519_GWORD64(UINT64_C(0x6C744E30AA4EB5A7)),
				ED25519_GWORD64(UINT64_C(0x9E0C5D613C85E88B)), ED25519_GWORD64(UINT64_C(0xAFD9C71E5F758173))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x24B8B3AE52AFDEDD)), ED25519_GWORD64(UINT64_C(0x3495638CED3B30CF)),
				ED25519_GWORD64(UINT64_C(0x33A4BC83A9BE8195)), ED25519_GWORD64(UINT64_C(0x373767475C651F04))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x634095CB14246590)), ED25519_GWORD64(UINT64_C(0xEF12144016C15535)),
				ED25519_GWORD64(UINT64_C(0x9E38140C8910BC60)), ED25519_GWORD64(UINT64_C(0x6BF5905730907C8C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2FBA99FD40D1ADC6)), ED25519_GWORD64(UINT64_C(0xB307166F96F4D027)),
				ED25519_GWORD64(UINT64_C(0x4363F05215F03BAE)), ED25519_GWORD64(UINT64_C(0x9FBEA56C3B18F999))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0FA778F1E1415B8A)), ED25519_GWORD64(UINT64_C(0x06409FF7BAC3A77E)),
				ED25519_GWORD64(UINT64_C(0x6F52D7B89AA29A50)), ED25519_GWORD64(UINT64_C(0x02521CF67A635A56))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xB1146720772F5ED1)), ED25519_GWORD64(UINT64_C(0xE8F894B196079ACE)),
				ED25519_GWORD64(UINT64_C(0x4AF8224D00AC824A)), ED25519_GWORD64(UINT64_C(0x801753D9F7CD6CC4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x513FEE0B0A9D5281)), ED25519_GWORD64(UINT64_C(0x8F98E75C0FDF5A66)),
				ED25519_GWORD64(UINT64_C(0xD4618688BFE107CE)), ED25519_GWORD64(UINT64_C(0xBFA00A7E71382CED))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3C69232D963DDB34)), ED25519_GWORD64(UINT64_C(0x1DDE87DAB4973858)),
				ED25519_GWORD64(UINT64_C(0xAAD7D1F9A091F285)), ED25519_GWORD64(UINT64_C(0x12B5FE2FA048EDB6))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xDF2B7C26AD6F1E92)), ED25519_GWORD64(UINT64_C(0x4B66D323504B8913)),
				ED25519_GWORD64(UINT64_C(0x8C409DC0751C8BC3)), ED25519_GWORD64(UINT64_C(0x6F7E93C20796C7B8))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x71F0FBC496FCE33A)), ED25519_GWORD64(UINT64_C(0x73B9826BADF35BED)),
				ED25519_GWORD64(UINT64_C(0xD2047261FF28C561)), ED25519_GWORD64(UINT64_C(0xF49B76F96FB1206F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1F5AF604AEA6AE05)), ED25519_GWORD64(UINT64_C(0xC12351F1BEE49C99)),
				ED25519_GWORD64(UINT64_C(0x61A808B5EEFF6B66)), ED25519_GWORD64(UINT64_C(0x0FCEC10F01E02151))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3DF2D29DC4244E45)), ED25519_GWORD64(UINT64_C(0x2B020E7493D8DE0A)),
				ED25519_GWORD64(UINT64_C(0x6CC8067E820C214D)), ED25519_GWORD64(UINT64_C(0x413779166FEAB90A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x644D58A649FE1E31)), ED25519_GWORD64(UINT64_C(0x21FCAEA231AD777E)),
				ED25519_GWORD64(UINT64_C(0x02441C5A887FD0D2)), ED25519_GWORD64(UINT64_C(0xC901AA7183C511F3))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x08B1B7548C1AF8F0)), ED25519_GWORD64(UINT64_C(0xCE0F7A7C246299B4)),
				ED25519_GWORD64(UINT64_C(0xF760B0F91E06D939)), ED25519_GWORD64(UINT64_C(0x41BB887B726D1213))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x7E234C597C66919B)), ED25519_GWORD64(UINT64_C(0x64889D3D0A85B4C8)),
				ED25519_GWORD64(UINT64_C(0xDAE2C90C354AFAE7)), ED25519_GWORD64(UINT64_C(0x8A871E070C6A9E1D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x40E87D44744346AB)), ED25519_GWORD64(UINT64_C(0x1D48DAD415B52B25)),
				ED25519_GWORD64(UINT64_C(0x7C3A8A18A13B603E)), ED25519_GWORD64(UINT64_C(0xCEB728C12FCDBDF7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3301B5994BBC8989)), ED25519_GWORD64(UINT64_C(0x736BAE3A5BDD4260)),
				ED25519_GWORD64(UINT64_C(0x0D61ADE219D59E3C)), ED25519_GWORD64(UINT64_C(0x3EE7300F2685D464))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x43FA7947841E7518)), ED25519_GWORD64(UINT64_C(0xE5C6FA59639C46D7)),
				ED25519_GWORD64(UINT64_C(0xA1065E1DE3052B74)), ED25519_GWORD64(UINT64_C(0x7D47C6A2CFB89030))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF5D255E49E7DD6A4)), ED25519_GWORD64(UINT64_C(0x8016115C610B1EAC)),
				ED25519_GWORD64(UINT64_C(0x3C99975D92E187CA)), ED25519_GWORD64(UINT64_C(0x93815762979125C2))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3FDAD0148EF0D6E0)), ED25519_GWORD64(UINT64_C(0x9D3E749A91546F3C)),
				ED25519_GWORD64(UINT64_C(0x71EC621026BB8157)), ED25519_GWORD64(UINT64_C(0x148CF58D34C9EC80))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE2572F7D9AE4755A)), ED25519_GWORD64(UINT64_C(0x56C345BB88F3487F)),
				ED25519_GWORD64(UINT64_C(0x9FD10B6D6960A88D)), ED25519_GWORD64(UINT64_C(0xA78FEBAD4EAEA1B9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x46A492F67934F014)), ED25519_GWORD64(UINT64_C(0x469984BEF6840AA9)),
				ED25519_GWORD64(UINT64_C(0x5CA1BC2A89611854)), ED25519_GWORD64(UINT64_C(0xBFF2FA1EBD5DBBD4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB1AA681F8C933966)), ED25519_GWORD64(UINT64_C(0x8C21949C20290C98)),
				ED25519_GWORD64(UINT64_C(0x39115291219D3C52)), ED25519_GWORD64(UINT64_C(0x4104DD02FE9C677B))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x81214E06DB096AA5)), ED25519_GWORD64(UINT64_C(0x21A8B6C90CE44F35)),
				ED25519_GWORD64(UINT64_C(0x6524C12A409E2AF5)), ED25519_GWORD64(UINT64_C(0x8165B5A48EFCA481))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x72B2BF5E11244217)), ED25519_GWORD64(UINT64_C(0xA1FA0C3398A33AB5)),
				ED25519_GWORD64(UINT64_C(0x94CB6101FA52B666)), ED25519_GWORD64(UINT64_C(0xAC863B00AFAF53D5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF190A474A0846A76)), ED25519_GWORD64(UINT64_C(0x12EFF984CD2F7CC0)),
				ED25519_GWORD64(UINT64_C(0x695E290658AA2B8F)), ED25519_GWORD64(UINT64_C(0x591B67D9BFFEC8B8))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x99B9B3719F18B55D)), ED25519_GWORD64(UINT64_C(0xE465E5FAA18C641E)),
				ED25519_GWORD64(UINT64_C(0x61081136C29F05ED)), ED25519_GWORD64(UINT64_C(0x489B4F867030128B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x312F0D1C80B49BE7)), ED25519_GWORD64(UINT64_C(0x5979515EABF3EC8A)),
				ED25519_GWORD64(UINT64_C(0x727033C09EF01C88)), ED25519_GWORD64(UINT64_C(0xBDE02EC7CA8F7BCB))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD232102D3AEB92EF)), ED25519_GWORD64(UINT64_C(0xE16253B46116A861)),
				ED25519_GWORD64(UINT64_C(0x3D7EABE7190BAA24)), ED25519_GWORD64(UINT64_C(0x49F5FBBA496CBEBF))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x155D628C1E9C571B)), ED25519_GWORD64(UINT64_C(0x8A4D86ACC5884741)),
				ED25519_GWORD64(UINT64_C(0x91A352F6515763EB)), ED25519_GWORD64(UINT64_C(0x86A1A6C28867515B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x30949A108A5BCFC1)), ED25519_GWORD64(UINT64_C(0xDC40DD70BC6473EB)),
				ED25519_GWORD64(UINT64_C(0x92C294C1307C0D1C)), ED25519_GWORD64(UINT64_C(0xD604A86DCBFA6E74))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7288D1D47C1764B6)), ED25519_GWORD64(UINT64_C(0x72541140E0418B51)),
				ED25519_GWORD64(UINT64_C(0x9F031A6018ACF6D1)), ED25519_GWORD64(UINT64_C(0x20989E89FE2742C6))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x1674278B85EAEC1B)), ED25519_GWORD64(UINT64_C(0x5621DC077ACB2BDF)),
				ED25519_GWORD64(UINT64_C(0x640A4C1661CBF45A)), ED25519_GWORD64(UINT64_C(0xF30B9950F70595D3))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x499777FD3A2DCC7F)), ED25519_GWORD64(UINT64_C(0x32857C2CA54FD892)),
				ED25519_GWORD64(UINT64_C(0xA279D864D207E3A0)), ED25519_GWORD64(UINT64_C(0x0403ED1D0CA67E29))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC94B2D35874EC552)), ED25519_GWORD64(UINT64_C(0xC5E6C8CF98246F8D)),
				ED25519_GWORD64(UINT64_C(0xF7CB46FA16C035CE)), ED25519_GWORD64(UINT64_C(0x5BD7454308303DCC))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x85C4932115E7792A)), ED25519_GWORD64(UINT64_C(0xC64C89A2BDCDDDC9)),
				ED25519_GWORD64(UINT64_C(0x9D1E3DA8ADA3D762)), ED25519_GWORD64(UINT64_C(0x5BB7DB123067F82C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7F9AD19528B24CC2)), ED25519_GWORD64(UINT64_C(0x7F6B54656335C181)),
				ED25519_GWORD64(UINT64_C(0x66B8B66E4FC07236)), ED25519_GWORD64(UINT64_C(0x133A78007380AD83))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0961F467C6CA62BE)), ED25519_GWORD64(UINT64_C(0x04EC21D6211952EE)),
				ED25519_GWORD64(UINT64_C(0x182360779BD54770)), ED25519_GWORD64(UINT64_C(0x740DCA6D58F0E0D2))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x231A8C570478433C)), ED25519_GWORD64(UINT64_C(0xB7B5270EC281439D)),
				ED25519_GWORD64(UINT64_C(0xDBAA99EAE3D9079F)), ED25519_GWORD64(UINT64_C(0x2C03F5256C2B03D9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDF48EE0752CFCE4E)), ED25519_GWORD64(UINT64_C(0xC3FFFAF306EC08B7)),
				ED25519_GWORD64(UINT64_C(0x05710B2AB95459C4)), ED25519_GWORD64(UINT64_C(0x161D25FA963EA38D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x790F18757B53A47D)), ED25519_GWORD64(UINT64_C(0x307B0130CF0C5879)),
				ED25519_GWORD64(UINT64_C(0x31903D77257EF7F9)), ED25519_GWORD64(UINT64_C(0x699468BDBD96BBAF))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD8DD3DE66AA91935)), ED25519_GWORD64(UINT64_C(0x485064C22FC0D2CC)),
				ED25519_GWORD64(UINT64_C(0x9B48246634FDEA2F)), ED25519_GWORD64(UINT64_C(0xA93E1C4E6C4A2E3A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xBD1F2F46F4DAFECF)), ED25519_GWORD64(UINT64_C(0x7CEF0114A47FD6F7)),
				ED25519_GWORD64(UINT64_C(0xD31FFDDA4A47B37F)), ED25519_GWORD64(UINT64_C(0x525219A473905785))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x376E134B925112E1)), ED25519_GWORD64(UINT64_C(0x703778B5DCA15DA0)),
				ED25519_GWORD64(UINT64_C(0xB04589AF461C3111)), ED25519_GWORD64(UINT64_C(0x5B605C447F032823))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3BE9FEC6F0E7F039)), ED25519_GWORD64(UINT64_C(0x866A579E75E34962)),
				ED25519_GWORD64(UINT64_C(0x5542EF161E1DE61A)), ED25519_GWORD64(UINT64_C(0xAF12FEF4CC5ABDD5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB965805920C47C89)), ED25519_GWORD64(UINT64_C(0xE7F0100C923B8FCC)),
				ED25519_GWORD64(UINT64_C(0x0001256502E2EF77)), ED25519_GWORD64(UINT64_C(0x24A76DCEA8AEB3EE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0A4522B2DFC0C740)), ED25519_GWORD64(UINT64_C(0x10D06E7F40C9A407)),
				ED25519_GWORD64(UINT64_C(0xC6CF144178CFF668)), ED25519_GWORD64(UINT64_C(0x5E607B2518A43790))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA02C431CA596CF01)), ED25519_GWORD64(UINT64_C(0xE3C42D40AED3E400)),
				ED25519_GWORD64(UINT64_C(0xD24526802E0F26DB)), ED25519_GWORD64(UINT64_C(0xA01F33139E457068))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x58B31D8F6CDF1805)), ED25519_GWORD64(UINT64_C(0x35CFA74FC36258A2)),
				ED25519_GWORD64(UINT64_C(0xE1B3FF4F66E61D6E)), ED25519_GWORD64(UINT64_C(0xD067ACAB6CCDD5F7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xFD527F6B08039D51)), ED25519_GWORD64(UINT64_C(0x18B14964017C0006)),
				ED25519_GWORD64(UINT64_C(0xD5220EB02E25A4A8)), ED25519_GWORD64(UINT64_C(0x397CBA8862460375))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x7815C3FBC81379E7)), ED25519_GWORD64(UINT64_C(0xA6619420DDE12AF1)),
				ED25519_GWORD64(UINT64_C(0xFFA9C0F885A8FDD5)), ED25519_GWORD64(UINT64_C(0x771B4022C1E1C252))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x30C13093F059599F)), ED25519_GWORD64(UINT64_C(0xE23AA18DE9A97976)),
				ED25519_GWORD64(UINT64_C(0x222FD491721D5E26)), ED25519_GWORD64(UINT64_C(0xA339D320766E6C3A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD87DD986513A2FA7)), ED25519_GWORD64(UINT64_C(0xF5AC9B71F9D4CF08)),
				ED25519_GWORD64(UINT64_C(0xD06BC31B1EA283B3)), ED25519_GWORD64(UINT64_C(0x331A189219971A76))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x26512F3A9D75729C)), ED25519_GWORD64(UINT64_C(0x5BCBE28868074A9E)),
				ED25519_GWORD64(UINT64_C(0x84EDC1C11180F7C4)), ED25519_GWORD64(UINT64_C(0x9AC9619FF649A67B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF5166F45FB4F80C6)), ED25519_GWORD64(UINT64_C(0x9C36C7DE61C775CF)),
				ED25519_GWORD64(UINT64_C(0xE3D4E81B9041D91C)), ED25519_GWORD64(UINT64_C(0x31167C6B83BDFE21))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF22B3842524B1068)), ED25519_GWORD64(UINT64_C(0x5068343BEE9CE987)),
				ED25519_GWORD64(UINT64_C(0xFC9D71844A6250C8)), ED25519_GWORD64(UINT64_C(0x612436341F08B111))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x8B6349E31A2D2625)), ED25519_GWORD64(UINT64_C(0x9DDFB7009BD3FD35)),
				ED25519_GWORD64(UINT64_C(0x7F8BF1B8A3A06BA4)), ED25519_GWORD64(UINT64_C(0x9522AA3178D90445))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD99D41DB874E898D)), ED25519_GWORD64(UINT64_C(0x09FEA5F16C07DC20)),
				ED25519_GWORD64(UINT64_C(0x793D2C67D00F9BBC)), ED25519_GWORD64(UINT64_C(0x46EBE2309E5EFF40))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2C382F5369614938)), ED25519_GWORD64(UINT64_C(0xDAFE409AB72D6D10)),
				ED25519_GWORD64(UINT64_C(0xE8C83391B646F227)), ED25519_GWORD64(UINT64_C(0x45FE70F50524306C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x62F24920C895147E)), ED25519_GWORD64(UINT64_C(0x05F007C83F630CA2)),
				ED25519_GWORD64(UINT64_C(0x6FBB45D2F5C9D4B8)), ED25519_GWORD64(UINT64_C(0x96619F6DB57A2245))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDA4875A6960C0B8C)), ED25519_GWORD64(UINT64_C(0x5B68D076EF0E2F20)),
				ED25519_GWORD64(UINT64_C(0x07FB51CF3D0B8FD4)), ED25519_GWORD64(UINT64_C(0x428D1623A0E392D4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x084F4A4401A308FD)), ED25519_GWORD64(UINT64_C(0xA82219C376A5CAAC)),
				ED25519_GWORD64(UINT64_C(0xDEB8DE4643D1BC7D)), ED25519_GWORD64(UINT64_C(0x1D81592D60BD38C6))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x8765B69F7B85C5D5)), ED25519_GWORD64(UINT64_C(0x6FF0678BD168BAB2)),
				ED25519_GWORD64(UINT64_C(0x3A70E77C1D330F9B)), ED25519_GWORD64(UINT64_C(0xBA5F6D51B0AF8E7C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x61368756A60DAC5F)), ED25519_GWORD64(UINT64_C(0x17E02F6AEBABDC57)),
				ED25519_GWORD64(UINT64_C(0x7F193F2D4CCE0F7D)), ED25519_GWORD64(UINT64_C(0x20234A7789ECDCF0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x76D20DB67178B252)), ED25519_GWORD64(UINT64_C(0x071C34F9D51ED160)),
				ED25519_GWORD64(UINT64_C(0xF62A4A20B3E41170)), ED25519_GWORD64(UINT64_C(0x7CD682353CFFE366))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA665CD6068ACF4E0)), ED25519_GWORD64(UINT64_C(0x42D92D183CD7E3D3)),
				ED25519_GWORD64(UINT64_C(0x5759389D336025D9)), ED25519_GWORD64(UINT64_C(0xBEF0253B2B2CD8FF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0BE1A45BD887FAB6)), ED25519_GWORD64(UINT64_C(0x2A846A32BA403B6E)),
				ED25519_GWORD64(UINT64_C(0xD9921012E96E6000)), ED25519_GWORD64(UINT64_C(0x2838C8863BDC0943))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD16BB0CF4A465030)), ED25519_GWORD64(UINT64_C(0xFA496B4115C577AB)),
				ED25519_GWORD64(UINT64_C(0x82CFAE8AF4AB419D)), ED25519_GWORD64(UINT64_C(0x21DCB8A606A82812))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9A8D00FABE7731BA)), ED25519_GWORD64(UINT64_C(0x8203607E629E1889)),
				ED25519_GWORD64(UINT64_C(0xB2CC023743F3D97F)), ED25519_GWORD64(UINT64_C(0x5D840DBF6C6F678B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5C6004468C9D9FC8)), ED25519_GWORD64(UINT64_C(0x2540096ED42AA3CB)),
				ED25519_GWORD64(UINT64_C(0x125B4D4C12EE2F9C)), ED25519_GWORD64(UINT64_C(0x0BC3D08194A31DAB))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x706E380D309FE18B)), ED25519_GWORD64(UINT64_C(0x6EB02DA6B9E165C7)),
				ED25519_GWORD64(UINT64_C(0x57BBBA997DAE20AB)), ED25519_GWORD64(UINT64_C(0x3A4276232AC196DD))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3BF8C172DB447EB8)), ED25519_GWORD64(UINT64_C(0x5FCFC41FC6282DBD)),
				ED25519_GWORD64(UINT64_C(0x80ACFFC075AA15FE)), ED25519_GWORD64(UINT64_C(0x8770C9E824E1A9F9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x4B42432C8A7084FA)), ED25519_GWORD64(UINT64_C(0x898A19E3DFB9E545)),
				ED25519_GWORD64(UINT64_C(0xBE9F00219C58E45D)), ED25519_GWORD64(UINT64_C(0x1FF177CEA16DEBD1))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xCF61D99A45B5B5FD)), ED25519_GWORD64(UINT64_C(0x860984E91B3A7924)),
				ED25519_GWORD64(UINT64_C(0xE7300919303E3E89)), ED25519_GWORD64(UINT64_C(0x39F264FD41500B1E))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD19B4AABFE097BCE)), ED25519_GWORD64(UINT64_C(0xA46DFCE1DFE01929)),
				ED25519_GWORD64(UINT64_C(0xC3C908942CA6F1FF)), ED25519_GWORD64(UINT64_C(0xE5C621272C35F14E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA7AD3417DBE7E29C)), ED25519_GWORD64(UINT64_C(0xBD94376A2B9C139C)),
				ED25519_GWORD64(UINT64_C(0xA0E91B8E93597BA9)), ED25519_GWORD64(UINT64_C(0x1712D73468889840))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE72B89F8CE3193DD)), ED25519_GWORD64(UINT64_C(0x4D103356A125C0BB)),
				ED25519_GWORD64(UINT64_C(0x0419A93D2E1CFE83)), ED25519_GWORD64(UINT64_C(0x22F9800AB19CE272))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x42029FDD9A6EFD99)), ED25519_GWORD64(UINT64_C(0xB912CEBE34A54941)),
				ED25519_GWORD64(UINT64_C(0x640F64B987BDF37B)), ED25519_GWORD64(UINT64_C(0xC171A4D38598CAB4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x605A368A3E9EF8CB)), ED25519_GWORD64(UINT64_C(0xE3E9C022A5504715)),
				ED25519_GWORD64(UINT64_C(0x553D48B05F24248F)), ED25519_GWORD64(UINT64_C(0x13F416CD647626E5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xFA2758AA99C94C8C)), ED25519_GWORD64(UINT64_C(0x23006F6FB000B807)),
				ED25519_GWORD64(UINT64_C(0xFBD291DDADDA5392)), ED25519_GWORD64(UINT64_C(0x508214FA574BD1AB))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x461A15BB53D003C3)), ED25519_GWORD64(UINT64_C(0xB2102888BCF3C965)),
				ED25519_GWORD64(UINT64_C(0x27C576756C683A5A)), ED25519_GWORD64(UINT64_C(0xBA7758A4C86CB447))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC20269153ED6FE4B)), ED25519_GWORD64(UINT64_C(0xA65A6739511D77C4)),
				ED25519_GWORD64(UINT64_C(0xCBDE26462C14AF94)), ED25519_GWORD64(UINT64_C(0x22F960EC6FABA74B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x548111F693AE5076)), ED25519_GWORD64(UINT64_C(0x1DAE21DF1DFD54A6)),
				ED25519_GWORD64(UINT64_C(0x12248C90F3115E65)), ED25519_GWORD64(UINT64_C(0x5D9FD15F8DE7F494))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3F244D2AEED7520B)), ED25519_GWORD64(UINT64_C(0x8E3A9028432E9615)),
				ED25519_GWORD64(UINT64_C(0xE164BA772E9C16D4)), ED25519_GWORD64(UINT64_C(0xBBC187FA47EB98D8))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x031408D36D63727F)), ED25519_GWORD64(UINT64_C(0x6A379AEFD7C7B533)),
				ED25519_GWORD64(UINT64_C(0xA9E18FC5CCAEE24B)), ED25519_GWORD64(UINT64_C(0x332F35914F8FBED3))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6D470115EA86C20C)), ED25519_GWORD64(UINT64_C(0x998AB7CB6C46D125)),
				ED25519_GWORD64(UINT64_C(0xD77832B53A660188)), ED25519_GWORD64(UINT64_C(0x450D81CE906FBA03))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD074D8961CAE743F)), ED25519_GWORD64(UINT64_C(0xF86D18F5EE1C63ED)),
				ED25519_GWORD64(UINT64_C(0x97BDC55BE7F4ED29)), ED25519_GWORD64(UINT64_C(0x4CBAD279663AB108))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6E7BB6A1A6205275)), ED25519_GWORD64(UINT64_C(0xAA4F21D7413C8E83)),
				ED25519_GWORD64(UINT64_C(0x6F56D155E88F5CB2)), ED25519_GWORD64(UINT64_C(0x2DE25D4BA6345BE1))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x80D19024A0D71FCD)), ED25519_GWORD64(UINT64_C(0xC525C20AFB288AF8)),
				ED25519_GWORD64(UINT64_C(0xB1A3974B5F3A6419)), ED25519_GWORD64(UINT64_C(0x7D7FBCEFE2007233))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xCD7C5DC5F3C29094)), ED25519_GWORD64(UINT64_C(0xC781A29A2A9105AB)),
				ED25519_GWORD64(UINT64_C(0x80C61D36421C3058)), ED25519_GWORD64(UINT64_C(0x4F9CD196DCD8D4D7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xFAEF1E6A266B27EE)), ED25519_GWORD64(UINT64_C(0x866C68C4D5739F16)),
				ED25519_GWORD64(UINT64_C(0xF68A2FBC1B03762C)), ED25519_GWORD64(UINT64_C(0xD975435E87B75A8D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x199297D86A7B3768)), ED25519_GWORD64(UINT64_C(0xD0D058241AD17A63)),
				ED25519_GWORD64(UINT64_C(0xBA029CAD5C1C0C17)), ED25519_GWORD64(UINT64_C(0x7CCDD084387A0307))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9B0C84186760CC80)), ED25519_GWORD64(UINT64_C(0xCDAE007A1AB32A99)),
				ED25519_GWORD64(UINT64_C(0xA88DEC86620BDA18)), ED25519_GWORD64(UINT64_C(0xB593CA848190CA44))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDCA6422C6D260404)), ED25519_GWORD64(UINT64_C(0xAE153D50948240BD)),
				ED25519_GWORD64(UINT64_C(0xA9C0C1B4FB68C677)), ED25519_GWORD64(UINT64_C(0xC28BD0ED61D0CF53))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9213189A5E849AA7)), ED25519_GWORD64(UINT64_C(0xD4D8C33565D8FACD)),
				ED25519_GWORD64(UINT64_C(0x8C52545B53FDBBD1)), ED25519_GWORD64(UINT64_C(0x27398308DA2D63E6))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xB9A10E4C0A702453)), ED25519_GWORD64(UINT64_C(0x0FA25866D57D1BDE)),
				ED25519_GWORD64(UINT64_C(0xFFB9D9B5CD27DAF7)), ED25519_GWORD64(UINT64_C(0x572C2945492C33FD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x42C38D28435ED413)), ED25519_GWORD64(UINT64_C(0xBD50F3603278CCC9)),
				ED25519_GWORD64(UINT64_C(0xBB07AB1A79DA03EF)), ED25519_GWORD64(UINT64_C(0x269597AEBE8C3355))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC77FC745D6CD30BE)), ED25519_GWORD64(UINT64_C(0xE4DFE8D3E3BAAEFB)),
				ED25519_GWORD64(UINT64_C(0xA22C8830AA5DDA0C)), ED25519_GWORD64(UINT64_C(0x7F985498C05BCA80))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD35615520FBF6350)), ED25519_GWORD64(UINT64_C(0x08045A45CF4DFBA6)),
				ED25519_GWORD64(UINT64_C(0xEEC24FBC873FA0C2)), ED25519_GWORD64(UINT64_C(0xB0F2653CD69B12E7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3849CE889F0BE104)), ED25519_GWORD64(UINT64_C(0x8005AD1B7B54A288)),
				ED25519_GWORD64(UINT64_C(0x3DA3C39F23FC921C)), ED25519_GWORD64(UINT64_C(0xF6C2EC470A31F304))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8A08C938AAC10C85)), ED25519_GWORD64(UINT64_C(0x46179B60DB276BCB)),
				ED25519_GWORD64(UINT64_C(0xA920C01E0E6FAC70)), ED25519_GWORD64(UINT64_C(0x2F1273F1596473DA))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x30488BD755A70BC0)), ED25519_GWORD64(UINT64_C(0x06D6B5A4F1D442E7)),
				ED25519_GWORD64(UINT64_C(0xEAD1A69EBC596162)), ED25519_GWORD64(UINT64_C(0x38AC1997EDC5F784))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x4739FC7C8AE01DFE)), ED25519_GWORD64(UINT64_C(0xFD5274904A6AAB9F)),
				ED25519_GWORD64(UINT64_C(0x41D98A8287728F2E)), ED25519_GWORD64(UINT64_C(0xDD9E572AD85B69F2))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0666B517A751B13B)), ED25519_GWORD64(UINT64_C(0x747D06867E9B858C)),
				ED25519_GWORD64(UINT64_C(0xACACC011454DDE49)), ED25519_GWORD64(UINT64_C(0x22DFCD9CBFE9E69C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x56EC59B4103BE08E)), ED25519_GWORD64(UINT64_C(0x2EE3BAECD259F969)),
				ED25519_GWORD64(UINT64_C(0x797CB29413F5CD32)), ED25519_GWORD64(UINT64_C(0x8FE9877824CDE472))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8DDBD2E0C30D0CC6)), ED25519_GWORD64(UINT64_C(0xAD8E665FACBB4333)),
				ED25519_GWORD64(UINT64_C(0x8F6B258C322A961F)), ED25519_GWORD64(UINT64_C(0xEB2916C05448C1C7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7EDB34D10ABA913B)), ED25519_GWORD64(UINT64_C(0x4EA3CD822E6DAC0E)),
				ED25519_GWORD64(UINT64_C(0x66083DFF6578F815)), ED25519_GWORD64(UINT64_C(0x4C303F307FF00A17))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x29FC03580DD944ED)), ED25519_GWORD64(UINT64_C(0xECD27AA46FBBEC93)),
				ED25519_GWORD64(UINT64_C(0x130A155FC2E2A7F8)), ED25519_GWORD64(UINT64_C(0xC16B151AB706A1D5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD30A3BD617B28C85)), ED25519_GWORD64(UINT64_C(0xC5D377B739773BEA)),
				ED25519_GWORD64(UINT64_C(0xC6C6E78C1E6A5CBF)), ED25519_GWORD64(UINT64_C(0x0D61B8F78B2AB7C4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x56A8D7EFE9C136B0)), ED25519_GWORD64(UINT64_C(0xBD07E5CD58E44B20)),
				ED25519_GWORD64(UINT64_C(0xAFE62FDA1B57E0AB)), ED25519_GWORD64(UINT64_C(0x191A2AF74277E8D2))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9FE62B434F460EE8)), ED25519_GWORD64(UINT64_C(0xDED303D4A63607D6)),
				ED25519_GWORD64(UINT64_C(0xF052210EB7A0DA24)), ED25519_GWORD64(UINT64_C(0xA37E7DBE00545B93))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xCE16F74BC53C141E)), ED25519_GWORD64(UINT64_C(0x2B9725CE2072EDDE)),
				ED25519_GWORD64(UINT64_C(0xB8B9C36FB5B23EE7)), ED25519_GWORD64(UINT64_C(0xFE2E0E450B5CC908))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x013575ED6701B430)), ED25519_GWORD64(UINT64_C(0x231094E69F0BFD10)),
				ED25519_GWORD64(UINT64_C(0x75320F1583E47F22)), ED25519_GWORD64(UINT64_C(0x71AFA699B11155E3))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xEA423C1C473B50C3)), ED25519_GWORD64(UINT64_C(0x51E87A1F3B38EF10)),
				ED25519_GWORD64(UINT64_C(0x9B84BF5FB2C9BE95)), ED25519_GWORD64(UINT64_C(0x80731FBC78F89A1C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x65CE6F9B3953B61D)), ED25519_GWORD64(UINT64_C(0xC65839EAAFA141E6)),
				ED25519_GWORD64(UINT64_C(0x0F435FFDA9F759FE)), ED25519_GWORD64(UINT64_C(0x021142E9C2B1C28E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE430C71848F81880)), ED25519_GWORD64(UINT64_C(0xBF960C225ECEC119)),
				ED25519_GWORD64(UINT64_C(0xB6DAE0836BBA15E3)), ED25519_GWORD64(UINT64_C(0x4C4D6F3347E15808))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2F0CDDFC988F195D)), ED25519_GWORD64(UINT64_C(0x6B916227B0B9F51B)),
				ED25519_GWORD64(UINT64_C(0x6EC7B6C4779176BE)), ED25519_GWORD64(UINT64_C(0xB8BF9500A88F9FA8))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x18F7ECCFC17D1FC9)), ED25519_GWORD64(UINT64_C(0x6C75F5A651403C14)),
				ED25519_GWORD64(UINT64_C(0xDBDE712BF7EE0CDF)), ED25519_GWORD64(UINT64_C(0x193FDDAAA7E47A22))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1FD2C93C37E8876F)), ED25519_GWORD64(UINT64_C(0xA2F61E5A18D1462C)),
				ED25519_GWORD64(UINT64_C(0x5080F58239241276)), ED25519_GWORD64(UINT64_C(0x6A6FB99EBF0D4969))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xEEB122B5B6E423C6)), ED25519_GWORD64(UINT64_C(0x939D7010F286FF8E)),
				ED25519_GWORD64(UINT64_C(0x90A92A831DCF5D8C)), ED25519_GWORD64(UINT64_C(0x136FDA9F42C5EB10))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6A46C1BB560855D8)), ED25519_GWORD64(UINT64_C(0x2416BB38F893F09D)),
				ED25519_GWORD64(UINT64_C(0xD71D11378F71ACC1)), ED25519_GWORD64(UINT64_C(0xF5F76914A31896EA))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF94CDFB1A305BDD1)), ED25519_GWORD64(UINT64_C(0x0F364B9D9FF82C08)),
				ED25519_GWORD64(UINT64_C(0x2A87D8A5C3BB588A)), ED25519_GWORD64(UINT64_C(0x022183510BE8DCBA))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9D5A710143307A6C)), ED25519_GWORD64(UINT64_C(0xB063DE9EC47DA45F)),
				ED25519_GWORD64(UINT64_C(0x22BBFE52BE927AD3)), ED25519_GWORD64(UINT64_C(0x9387C441FD40426C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x4AF766385EAD2D14)), ED25519_GWORD64(UINT64_C(0xA08ED880CA7C5830)),
				ED25519_GWORD64(UINT64_C(0x0D13A6E610211E3D)), ED25519_GWORD64(UINT64_C(0x6A071CE17B806C03))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB5D3C3D187978AF8)), ED25519_GWORD64(UINT64_C(0x722B5A3D7F0E4413)),
				ED25519_GWORD64(UINT64_C(0x0D7B4848BB477CA0)), ED25519_GWORD64(UINT64_C(0x3171B26AAF1EDC92))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA60DB7D8B28A47D1)), ED25519_GWORD64(UINT64_C(0xA6BF14D61770A4F1)),
				ED25519_GWORD64(UINT64_C(0xD4A1F89353DDBD58)), ED25519_GWORD64(UINT64_C(0x6C514A63344243E9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA92F319097564C95)), ED25519_GWORD64(UINT64_C(0xFF7BB84C2275E119)),
				ED25519_GWORD64(UINT64_C(0x4F55FE37A4875150)), ED25519_GWORD64(UINT64_C(0xA21FD4873CF0835A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2322204F3A156341)), ED25519_GWORD64(UINT64_C(0xFB73E0E9BA0A032D)),
				ED25519_GWORD64(UINT64_C(0xFCE0DD4C410F030E)), ED25519_GWORD64(UINT64_C(0x48DAA596FB924AAA))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x14F61D5DC84C9780)), ED25519_GWORD64(UINT64_C(0x9941F9E3EF418206)),
				ED25519_GWORD64(UINT64_C(0xCDF5B88F346277AC)), ED25519_GWORD64(UINT64_C(0xD8C837FA0E8A79A9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6ECA8E665CA59CB4)), ED25519_GWORD64(UINT64_C(0xA847254B2E38ACA0)),
				ED25519_GWORD64(UINT64_C(0x31AFC708D21E17CE)), ED25519_GWORD64(UINT64_C(0xE76DD6FCCAD84AF7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0CF9688596FC9058)), ED25519_GWORD64(UINT64_C(0x1DDCBBF37B56A01B)),
				ED25519_GWORD64(UINT64_C(0xDCC2E77D4935D66A)), ED25519_GWORD64(UINT64_C(0x1C4F73F2C6A57F0A))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xB36E706EFC7C3484)), ED25519_GWORD64(UINT64_C(0x73DFC9B4C3C1CF61)),
				ED25519_GWORD64(UINT64_C(0xEB1D79C9781CC7E5)), ED25519_GWORD64(UINT64_C(0x70459ADB7DAF675C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0E7A4FBD305FA0A8)), ED25519_GWORD64(UINT64_C(0x829D4CE054C663AD)),
				ED25519_GWORD64(UINT64_C(0xF421C3832FE33848)), ED25519_GWORD64(UINT64_C(0xF95AC80D1BF64C42))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1B91DB4991B42BB3)), ED25519_GWORD64(UINT64_C(0x572696234B02DCCA)),
				ED25519_GWORD64(UINT64_C(0x9FDF9EE51F8C78DC)), ED25519_GWORD64(UINT64_C(0x5FE162848CE21FD3))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2879852D5D7CB1F5)), ED25519_GWORD64(UINT64_C(0xB8DEDD70687DF2E7)),
				ED25519_GWORD64(UINT64_C(0xDC0BFFAB21687891)), ED25519_GWORD64(UINT64_C(0xAB44C043677DAA35))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x4E59214FE1949607)), ED25519_GWORD64(UINT64_C(0x49BE7DC70D71CD4F)),
				ED25519_GWORD64(UINT64_C(0x9300CFD23B50F22D)), ED25519_GWORD64(UINT64_C(0xC789D446FC917232))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1A1C87AB074EB78E)), ED25519_GWORD64(UINT64_C(0xFAC6D18E99DAF467)),
				ED25519_GWORD64(UINT64_C(0x3EACBBCD484F9067)), ED25519_GWORD64(UINT64_C(0x60C52EEF2BB9A4E4))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x702BC5C27CAE6D11)), ED25519_GWORD64(UINT64_C(0x44C7699B54A48CAB)),
				ED25519_GWORD64(UINT64_C(0xEFBC4056BA492EB2)), ED25519_GWORD64(UINT64_C(0x70D77248D9B6676D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0B5D89BC3BFD8BF1)), ED25519_GWORD64(UINT64_C(0xB06B9237C9F3551A)),
				ED25519_GWORD64(UINT64_C(0x0E4C16B0D53028F5)), ED25519_GWORD64(UINT64_C(0x10BC9C312CCFCAAB))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xAA8AE84B3EC2A05B)), ED25519_GWORD64(UINT64_C(0x98699EF4ED1781E0)),
				ED25519_GWORD64(UINT64_C(0x794513E4708E85D1)), ED25519_GWORD64(UINT64_C(0x63755BD3A976F413))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3DC7101897F1ACB7)), ED25519_GWORD64(UINT64_C(0x5DDA7D5EC165BBD8)),
				ED25519_GWORD64(UINT64_C(0x508E5B9C0FA1020F)), ED25519_GWORD64(UINT64_C(0x2763751737C52A56))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB55FA03E2AD10853)), ED25519_GWORD64(UINT64_C(0x356F75909EE63569)),
				ED25519_GWORD64(UINT64_C(0x9FF9F1FDBE69B890)), ED25519_GWORD64(UINT64_C(0x0D8CC1C48BC16F84))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x029402D36EB419A9)), ED25519_GWORD64(UINT64_C(0xF0B44E7E77B460A5)),
				ED25519_GWORD64(UINT64_C(0xCFA86230D43C4956)), ED25519_GWORD64(UINT64_C(0x70C2DD8A7AD166E7))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x91D4967DB8ED7E00)), ED25519_GWORD64(UINT64_C(0x74252F0AD776817A)),
				ED25519_GWORD64(UINT64_C(0xE40982E00D852564)), ED25519_GWORD64(UINT64_C(0xB2B8613816A53CE5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x656194509F6FEC0E)), ED25519_GWORD64(UINT64_C(0xEE2E7EA946C6518D)),
				ED25519_GWORD64(UINT64_C(0x9733C1F367E09B5C)), ED25519_GWORD64(UINT64_C(0x2E0FAC6363948495))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x79E7F7BEE448CD64)), ED25519_GWORD64(UINT64_C(0x6AC83A67087886D0)),
				ED25519_GWORD64(UINT64_C(0xF89FD4D9A0E4DB2E)), ED25519_GWORD64(UINT64_C(0x4179215C735A4F41))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE4AE33B9286BCD21)), ED25519_GWORD64(UINT64_C(0xB7EF7EB6559DD6DC)),
				ED25519_GWORD64(UINT64_C(0x278B141FB3D38E1F)), ED25519_GWORD64(UINT64_C(0xB1FA85662241C286))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8C7094E7D7DCED17)), ED25519_GWORD64(UINT64_C(0x97FB8AC347D39C70)),
				ED25519_GWORD64(UINT64_C(0xE13BE033A906D902)), ED25519_GWORD64(UINT64_C(0xF00344A30CD99D76))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xAF826C422E3622F4)), ED25519_GWORD64(UINT64_C(0xC12029879833502D)),
				ED25519_GWORD64(UINT64_C(0x9BC1B7E12B389123)), ED25519_GWORD64(UINT64_C(0x24BB2312A9952489))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x41F80C2AF5F85C58)), ED25519_GWORD64(UINT64_C(0x687284C304FA6794)),
				ED25519_GWORD64(UINT64_C(0x8945DF99A3BA1BAD)), ED25519_GWORD64(UINT64_C(0x8D1D2AF9FFEB5D16))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB1A8ED1732DE67B0)), ED25519_GWORD64(UINT64_C(0x3CB49418461B4948)),
				ED25519_GWORD64(UINT64_C(0x8EBD434376CFBCD2)), ED25519_GWORD64(UINT64_C(0x8FEE3E871E188008))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA9DA8AA132621EDF)), ED25519_GWORD64(UINT64_C(0x30B822A159226579)),
				ED25519_GWORD64(UINT64_C(0x4004197BA79AC193)), ED25519_GWORD64(UINT64_C(0x16ACD79718531D76))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xC959C6C57887B6AD)), ED25519_GWORD64(UINT64_C(0x94E19EAD5F90FEBA)),
				ED25519_GWORD64(UINT64_C(0x16E24E62A342F504)), ED25519_GWORD64(UINT64_C(0x164ED34B18161700))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x72DF72AF2D9B1D3D)), ED25519_GWORD64(UINT64_C(0x63462A36A432245A)),
				ED25519_GWORD64(UINT64_C(0x3ECEA07916B39637)), ED25519_GWORD64(UINT64_C(0x123E0EF6B9302309))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x487ED94C192FE69A)), ED25519_GWORD64(UINT64_C(0x61AE2CEA3A911513)),
				ED25519_GWORD64(UINT64_C(0x877BF6D3B9A4DE27)), ED25519_GWORD64(UINT64_C(0x78DA0FC61073F3EB))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA29F80F1680C3A81)), ED25519_GWORD64(UINT64_C(0x71F77E151AE9E7E6)),
				ED25519_GWORD64(UINT64_C(0x1100F15848017973)), ED25519_GWORD64(UINT64_C(0x854AA4B316B38DDD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5BF15D28E52BC657)), ED25519_GWORD64(UINT64_C(0x2C47E31870F01A8E)),
				ED25519_GWORD64(UINT64_C(0x2419AFBC06C28BDD)), ED25519_GWORD64(UINT64_C(0xAD25DEEB256B173A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDFC8468D19267CB8)), ED25519_GWORD64(UINT64_C(0x0B28789C66E54DAF)),
				ED25519_GWORD64(UINT64_C(0x2AEB1D2A666EEC17)), ED25519_GWORD64(UINT64_C(0x134610A6AB7DA760))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xCD2A65E777D1F515)), ED25519_GWORD64(UINT64_C(0x548991878FAA60F1)),
				ED25519_GWORD64(UINT64_C(0xB1B73BBCDABC06E5)), ED25519_GWORD64(UINT64_C(0x654878CBA97CC9FB))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x51138EC78DF6B0EB)), ED25519_GWORD64(UINT64_C(0x5397DA89E575F51B)),
				ED25519_GWORD64(UINT64_C(0x09207A1D717AF1B9)), ED25519_GWORD64(UINT64_C(0xA102FDBA2B20D650))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x969EE405055CE6A1)), ED25519_GWORD64(UINT64_C(0x36BCA7681251AD29)),
				ED25519_GWORD64(UINT64_C(0x3A1AF517AA7DA415)), ED25519_GWORD64(UINT64_C(0x0AD725DB29ECB2BA))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xFEC7BC0C9B056F85)), ED25519_GWORD64(UINT64_C(0x537D5268E7F5FFD7)),
				ED25519_GWORD64(UINT64_C(0x77AFC6624312AEFA)), ED25519_GWORD64(UINT64_C(0x4F675F5302399FD9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDC4267B1834E2457)), ED25519_GWORD64(UINT64_C(0xB67544B570CE1BC5)),
				ED25519_GWORD64(UINT64_C(0x1AF07A0BF7D15ED7)), ED25519_GWORD64(UINT64_C(0x4AEFCFFB71A03650))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC32D36360415171E)), ED25519_GWORD64(UINT64_C(0xCD2BEF118998483B)),
				ED25519_GWORD64(UINT64_C(0x870A6EADD0945110)), ED25519_GWORD64(UINT64_C(0x0BCCBB72A2A86561))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x186D5E4C50FE1296)), ED25519_GWORD64(UINT64_C(0xE0397B82FEE89F7E)),
				ED25519_GWORD64(UINT64_C(0x3BC7F6C5507031B0)), ED25519_GWORD64(UINT64_C(0x6678FD69108F37C2))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x185E962FEAB1A9C8)), ED25519_GWORD64(UINT64_C(0x86E7E63565147DCD)),
				ED25519_GWORD64(UINT64_C(0xB092E031BB5B6DF2)), ED25519_GWORD64(UINT64_C(0x4024F0AB59D6B73E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1586FA31636863C2)), ED25519_GWORD64(UINT64_C(0x07F68C48572D33F2)),
				ED25519_GWORD64(UINT64_C(0x4F73CC9F789EAEFC)), ED25519_GWORD64(UINT64_C(0x2D42E2108EAD4701))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x21717B0D0F537580)), ED25519_GWORD64(UINT64_C(0x914E690B131E064C)),
				ED25519_GWORD64(UINT64_C(0x1BB687AE752AE09F)), ED25519_GWORD64(UINT64_C(0xC20BF3A79B423C6E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x97F5131594DFD288)), ED25519_GWORD64(UINT64_C(0x6155985D313F4C6A)),
				ED25519_GWORD64(UINT64_C(0xEBA13F0708455010)), ED25519_GWORD64(UINT64_C(0xE76B2608B8D2D322))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8138BA651C5B2B47)), ED25519_GWORD64(UINT64_C(0x8671B6EC311B1B80)),
				ED25519_GWORD64(UINT64_C(0x7BFF0CB1BC3135B0)), ED25519_GWORD64(UINT64_C(0x745D2FFA9C0CF1E0))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6036DF5721D34E57)), ED25519_GWORD64(UINT64_C(0xB1DB8827997BB3D0)),
				ED25519_GWORD64(UINT64_C(0xD3C209C3C8756AFA)), ED25519_GWORD64(UINT64_C(0x86E15BE54C1DC839))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xBF525A1E2BC9C8BD)), ED25519_GWORD64(UINT64_C(0xEA5B260826479D81)),
				ED25519_GWORD64(UINT64_C(0xD511C70EDF0155DB)), ED25519_GWORD64(UINT64_C(0x1AE23CEB960CF5D0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5B725D871932994A)), ED25519_GWORD64(UINT64_C(0x32351CB5CEB1DAB0)),
				ED25519_GWORD64(UINT64_C(0x7DC41549DAB7CA05)), ED25519_GWORD64(UINT64_C(0x58DED861278EC1F7))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2DFB5BA8B6C2C995)), ED25519_GWORD64(UINT64_C(0x48EEEF8EF52C598C)),
				ED25519_GWORD64(UINT64_C(0x33809107F12D1573)), ED25519_GWORD64(UINT64_C(0x88BA696B531D5BD8))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD8173793F266C549)), ED25519_GWORD64(UINT64_C(0xC8C976C5CC454E49)),
				ED25519_GWORD64(UINT64_C(0x5CE382F8BC26C3A8)), ED25519_GWORD64(UINT64_C(0xAFF39DE85485F6F9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x77ED3EEEC3EFC57A)), ED25519_GWORD64(UINT64_C(0x04E05517D4FF4811)),
				ED25519_GWORD64(UINT64_C(0xEA3D7A3FF1A671CB)), ED25519_GWORD64(UINT64_C(0x120633B4947CFE54))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x82BD314749120FF7)), ED25519_GWORD64(UINT64_C(0xDE237B6D7E6FBE06)),
				ED25519_GWORD64(UINT64_C(0xE11E761911EA79C6)), ED25519_GWORD64(UINT64_C(0x87433BE3CB393BDE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0B9498789161002F)), ED25519_GWORD64(UINT64_C(0x4EE7B13CECEBFAE8)),
				ED25519_GWORD64(UINT64_C(0x70BE739594F0A4C0)), ED25519_GWORD64(UINT64_C(0xB5D30A99B4D59185))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xFF7944C05CE997F4)), ED25519_GWORD64(UINT64_C(0x575D3DE4B05C51A3)),
				ED25519_GWORD64(UINT64_C(0x583381FD5A76847C)), ED25519_GWORD64(UINT64_C(0x2D873EDE7AF6DA9F))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xAA6202E14E5DF96E)), ED25519_GWORD64(UINT64_C(0xA20D59175015E1F5)),
				ED25519_GWORD64(UINT64_C(0x18A275D3BAE21D6C)), ED25519_GWORD64(UINT64_C(0x8543618A01600253))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x157A3164433733F6)), ED25519_GWORD64(UINT64_C(0xFAB8B7EEF4AA81D9)),
				ED25519_GWORD64(UINT64_C(0xB093FEE6F5A64806)), ED25519_GWORD64(UINT64_C(0xAE773654707FA7B6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0DEABDF4974C23C1)), ED25519_GWORD64(UINT64_C(0xAA6F0A259DCE4693)),
				ED25519_GWORD64(UINT64_C(0x04202CB8A29ABA2C)), ED25519_GWORD64(UINT64_C(0x4B1443362D07960D))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x967C54E91C529CB8)), ED25519_GWORD64(UINT64_C(0x30F6269264C635FB)),
				ED25519_GWORD64(UINT64_C(0x2747AFF478121965)), ED25519_GWORD64(UINT64_C(0x97038418EAF66F5C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xCCC4B7C7B66E1F7A)), ED25519_GWORD64(UINT64_C(0x44157E25F50C2F7E)),
				ED25519_GWORD64(UINT64_C(0x3EF06DFC713EAF1C)), ED25519_GWORD64(UINT64_C(0x582F446752DA63F7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC6317BD320324CE4)), ED25519_GWORD64(UINT64_C(0xA81042E8A4488BC4)),
				ED25519_GWORD64(UINT64_C(0xB21EF18B4E5A1364)), ED25519_GWORD64(UINT64_C(0x0C2A1C4BCDA28DC9))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xEDC4814869BD6932)), ED25519_GWORD64(UINT64_C(0x0D6D907DBE1C8D22)),
				ED25519_GWORD64(UINT64_C(0xC63BD212D55CC5AB)), ED25519_GWORD64(UINT64_C(0xDA6A9B30A314DC83))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD24DC7D06F1F0434)), ED25519_GWORD64(UINT64_C(0xB2269E3EDB87C059)),
				ED25519_GWORD64(UINT64_C(0xD15B0272FBB2D28F)), ED25519_GWORD64(UINT64_C(0xFC558BD1C6F64877))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD0EC1524D396463D)), ED25519_GWORD64(UINT64_C(0x12BB628AC35A24F0)),
				ED25519_GWORD64(UINT64_C(0xA50C3A791CBC5FA4)), ED25519_GWORD64(UINT64_C(0x0404A5CA0AFBAFC3))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x62BC9E1B2A416FBE)), ED25519_GWORD64(UINT64_C(0xB5C6F728E350598B)),
				ED25519_GWORD64(UINT64_C(0x04343FD83D5D6967)), ED25519_GWORD64(UINT64_C(0xB9527516E7F8EE98))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8C1F40070AA743D6)), ED25519_GWORD64(UINT64_C(0xCCBAD0CB5B265EE8)),
				ED25519_GWORD64(UINT64_C(0x574B046B668FD2DE)), ED25519_GWORD64(UINT64_C(0x46395BFDCADD9633))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x117FDB2D1A5D9A9C)), ED25519_GWORD64(UINT64_C(0x9C7745BCD1005C2A)),
				ED25519_GWORD64(UINT64_C(0xEFD4BEF154D56FEA)), ED25519_GWORD64(UINT64_C(0x76579A29E822D016))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x333CB51352B434DF)), ED25519_GWORD64(UINT64_C(0xD832284993DE80E1)),
				ED25519_GWORD64(UINT64_C(0xB5512887750D35CE)), ED25519_GWORD64(UINT64_C(0x82C514BB2A2777C1))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x45B68E7E49C02A17)), ED25519_GWORD64(UINT64_C(0x23CD51A2BCA9A37F)),
				ED25519_GWORD64(UINT64_C(0x3ED65F11EC224C1B)), ED25519_GWORD64(UINT64_C(0x43A384DC9E05BDB1))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x684BD5DA8BF1B645)), ED25519_GWORD64(UINT64_C(0xFB8BD37EF6B54B53)),
				ED25519_GWORD64(UINT64_C(0x313916D7A9B0D253)), ED25519_GWORD64(UINT64_C(0x1160920961548059))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x7A385616369B4DBA)), ED25519_GWORD64(UINT64_C(0x75C02CA7655C3563)),
				ED25519_GWORD64(UINT64_C(0x7DC21BF9D4F18021)), ED25519_GWORD64(UINT64_C(0xAF637D7491E6E042))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB44D166929DACFAA)), ED25519_GWORD64(UINT64_C(0xDA529F4C8413598F)),
				ED25519_GWORD64(UINT64_C(0xE9EF63CA453D5559)), ED25519_GWORD64(UINT64_C(0x351E125BC5698E0B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD4B49B461AF67BBE)), ED25519_GWORD64(UINT64_C(0xD603037AC8AB8961)),
				ED25519_GWORD64(UINT64_C(0x71DEE19FF9A699FB)), ED25519_GWORD64(UINT64_C(0x7F182D06E7CE2A9A))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x09454B728E21750F)), ED25519_GWORD64(UINT64_C(0xAA58E8F4D484B8D8)),
				ED25519_GWORD64(UINT64_C(0xD358254D7F46903C)), ED25519_GWORD64(UINT64_C(0xC4ACC043241C5217))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7A7C8E64AB0168D9)), ED25519_GWORD64(UINT64_C(0xCB5A4A5515EDC543)),
				ED25519_GWORD64(UINT64_C(0x095519D347CD0EDA)), ED25519_GWORD64(UINT64_C(0xE7D4AC8C343E93B0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1C7D6BBB4F7A5777)), ED25519_GWORD64(UINT64_C(0x8B35FED4918313E1)),
				ED25519_GWORD64(UINT64_C(0x4ADCA1C6C96B4684)), ED25519_GWORD64(UINT64_C(0x556D1C8312AD71BD))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x81F06756B11BE80E)), ED25519_GWORD64(UINT64_C(0x0FAFF82310A3F3DD)),
				ED25519_GWORD64(UINT64_C(0xF8B2D0556A99465D)), ED25519_GWORD64(UINT64_C(0x897ABE38CC8C7F05))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x17EF40E30C8D3982)), ED25519_GWORD64(UINT64_C(0x31F7073E15A3FA34)),
				ED25519_GWORD64(UINT64_C(0x4F21F3CB0773646E)), ED25519_GWORD64(UINT64_C(0x746C6C6D1D824EFF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0C49C9877EA52DA4)), ED25519_GWORD64(UINT64_C(0x4C4369559BDC1D43)),
				ED25519_GWORD64(UINT64_C(0x022C3809F7CCEBD2)), ED25519_GWORD64(UINT64_C(0x577E14A34BEE84BD))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x94FECEBEBD4DD72B)), ED25519_GWORD64(UINT64_C(0xF46A4FDA060F2211)),
				ED25519_GWORD64(UINT64_C(0x124A5977C0C8D1FF)), ED25519_GWORD64(UINT64_C(0x705304B8FB009295))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF0E268AC61A73AF7)), ED25519_GWORD64(UINT64_C(0xF2FAFA103791A5F5)),
				ED25519_GWORD64(UINT64_C(0xC1E13E826B6D00E9)), ED25519_GWORD64(UINT64_C(0xE0FA7EE96FD78F42))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB63D1D354D296EC6)), ED25519_GWORD64(UINT64_C(0xF3C3053E5FAD31D8)),
				ED25519_GWORD64(UINT64_C(0x670B958CB4BD42EC)), ED25519_GWORD64(UINT64_C(0x21398E0CA16353FD))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2798AAF9B4B755EE)), ED25519_GWORD64(UINT64_C(0x5EAC72135C8DAD72)),
				ED25519_GWORD64(UINT64_C(0xD2CEAA6161B7A023)), ED25519_GWORD64(UINT64_C(0x9BBFB284E98F7D4E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x89F5058A382B33E0)), ED25519_GWORD64(UINT64_C(0x5AE2BA0BAD48C0B4)),
				ED25519_GWORD64(UINT64_C(0x8F93B503A53DB36E)), ED25519_GWORD64(UINT64_C(0xDAA3ED9D95A232E6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x656777E9C7D96561)), ED25519_GWORD64(UINT64_C(0xCB2B125472C78036)),
				ED25519_GWORD64(UINT64_C(0x65053299D9506EEE)), ED25519_GWORD64(UINT64_C(0x4A07E14E5E8957CC))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x240B58CDC477A49B)), ED25519_GWORD64(UINT64_C(0xFD38DADE6447F017)),
				ED25519_GWORD64(UINT64_C(0x19928D32A7C86AAD)), ED25519_GWORD64(UINT64_C(0x50AF7AED84AFA081))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x4EE412CB980DF999)), ED25519_GWORD64(UINT64_C(0xA315D76F3C6EC771)),
				ED25519_GWORD64(UINT64_C(0xBBA5EDDE925C77FD)), ED25519_GWORD64(UINT64_C(0x3F0BAC391D313402))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6E4FDE0115F65BE5)), ED25519_GWORD64(UINT64_C(0x29982621216109B2)),
				ED25519_GWORD64(UINT64_C(0x780205810BADD6D9)), ED25519_GWORD64(UINT64_C(0x1921A316BAEBD006))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD75AAD9AD9F3C18B)), ED25519_GWORD64(UINT64_C(0x566A0EEF60B1C19C)),
				ED25519_GWORD64(UINT64_C(0x3E9A0BAC255C0ED9)), ED25519_GWORD64(UINT64_C(0x7B049DECA062C7F5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x89422F7EDFB870E9)), ED25519_GWORD64(UINT64_C(0x2C296BEB4F76B3BD)),
				ED25519_GWORD64(UINT64_C(0x0738F1D436C24DF7)), ED25519_GWORD64(UINT64_C(0xE458DF41E273AEB0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDCCBE37A35444483)), ED25519_GWORD64(UINT64_C(0x758879330FEDBE93)),
				ED25519_GWORD64(UINT64_C(0x786004C312C5DD87)), ED25519_GWORD64(UINT64_C(0x6093DCCBC2950E64))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6BDEEEBE6084034B)), ED25519_GWORD64(UINT64_C(0x3199C2B6780FB854)),
				ED25519_GWORD64(UINT64_C(0x973376ABB62D0695)), ED25519_GWORD64(UINT64_C(0x6E3180C98B647D90))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1FF39A8585E0706D)), ED25519_GWORD64(UINT64_C(0x36D0A5D8B3E73933)),
				ED25519_GWORD64(UINT64_C(0x43B9F2E1718F453B)), ED25519_GWORD64(UINT64_C(0x57D1EA084827A97C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xEE7AB6E7A128B071)), ED25519_GWORD64(UINT64_C(0xA4C1596D93A88BAA)),
				ED25519_GWORD64(UINT64_C(0xF7B4DE82B2216130)), ED25519_GWORD64(UINT64_C(0x363E999DDD97BD18))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2F1848DCE24BAEB3)), ED25519_GWORD64(UINT64_C(0x769B7255BABCAF60)),
				ED25519_GWORD64(UINT64_C(0x90CB3C6E3CEFE931)), ED25519_GWORD64(UINT64_C(0xA31F979BC6F9B355))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x96A843C135EE1FB1)), ED25519_GWORD64(UINT64_C(0x976EB35508E4C8CF)),
				ED25519_GWORD64(UINT64_C(0xB42F6801B58CD330)), ED25519_GWORD64(UINT64_C(0xC8EE9B78693A052B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5C31DE4BCC2AF3C6)), ED25519_GWORD64(UINT64_C(0xB04BB030FE208D1F)),
				ED25519_GWORD64(UINT64_C(0xB78D7009C14FB466)), ED25519_GWORD64(UINT64_C(0x079BFA9B08792413))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xF3C9ED80A2D54232)), ED25519_GWORD64(UINT64_C(0x0AA08B7877F63952)),
				ED25519_GWORD64(UINT64_C(0xD76DAC63D1085475)), ED25519_GWORD64(UINT64_C(0x9EF4FB159470636B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE3903A51DA300DF4)), ED25519_GWORD64(UINT64_C(0x843964233DA95AB0)),
				ED25519_GWORD64(UINT64_C(0xED3CF12D0B356480)), ED25519_GWORD64(UINT64_C(0x038C77F684817194))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x854E5EE65B167BEC)), ED25519_GWORD64(UINT64_C(0x59590A4296D0CDC2)),
				ED25519_GWORD64(UINT64_C(0x72B2DF3498102199)), ED25519_GWORD64(UINT64_C(0x575EE92A4A0BFF56))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x5D46BC450AA4D7EE)), ED25519_GWORD64(UINT64_C(0xC3AF1227A533B9D8)),
				ED25519_GWORD64(UINT64_C(0x389E3B262B8906C2)), ED25519_GWORD64(UINT64_C(0xA00A1E7E382F581B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD4C080908A182FBC)), ED25519_GWORD64(UINT64_C(0x30E170C299489DBD)),
				ED25519_GWORD64(UINT64_C(0x05BABD5752F733DE)), ED25519_GWORD64(UINT64_C(0xC3D4E7112CD3FD00))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x518DB967EAF93AC5)), ED25519_GWORD64(UINT64_C(0x71BC989B056652C0)),
				ED25519_GWORD64(UINT64_C(0xFE2B85D9567197F5)), ED25519_GWORD64(UINT64_C(0x050ECA52651E4E38))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x97AC397660E668EA)), ED25519_GWORD64(UINT64_C(0x9B19BBFE153AB497)),
				ED25519_GWORD64(UINT64_C(0x4CB179B534ECA79F)), ED25519_GWORD64(UINT64_C(0x6151C09FA131AE57))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC3431ADE453F0C9C)), ED25519_GWORD64(UINT64_C(0xE9F5045EFF703B9B)),
				ED25519_GWORD64(UINT64_C(0xFCD97AC9ED847B3D)), ED25519_GWORD64(UINT64_C(0x4B0EE6C21C58F4C6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3AF55C0DFDF05D96)), ED25519_GWORD64(UINT64_C(0xDD262EE02AB4EE7A)),
				ED25519_GWORD64(UINT64_C(0x11B2BB8712171709)), ED25519_GWORD64(UINT64_C(0x1FEF24FA800F030B))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x22D2AFF530976B73)), ED25519_GWORD64(UINT64_C(0x8D90B806C2D24604)),
				ED25519_GWORD64(UINT64_C(0xDCA1896C4DE5BAE5)), ED25519_GWORD64(UINT64_C(0xA8005FE6C8340C17))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x37D653FB1AA73183)), ED25519_GWORD64(UINT64_C(0x0F9495303FD76418)),
				ED25519_GWORD64(UINT64_C(0xAD200B09FB3A17B2)), ED25519_GWORD64(UINT64_C(0xD44D49292FC8613E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6AEFBA9F34528688)), ED25519_GWORD64(UINT64_C(0x5C1BFF9425107DA1)),
				ED25519_GWORD64(UINT64_C(0xF75BBBCD66D94B36)), ED25519_GWORD64(UINT64_C(0x72E472930F316DFA))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x07F3F635D32A7614)), ED25519_GWORD64(UINT64_C(0x7AAA4D865F6566F0)),
				ED25519_GWORD64(UINT64_C(0x3C85E79728D04450)), ED25519_GWORD64(UINT64_C(0x9FEE7F000FE06438))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2695208C9781083C)), ED25519_GWORD64(UINT64_C(0xB1502A0B23450EE1)),
				ED25519_GWORD64(UINT64_C(0xFD9DAEA603EFDE02)), ED25519_GWORD64(UINT64_C(0xDA9D2E8C2733A34C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x765305DA03DBF7E5)), ED25519_GWORD64(UINT64_C(0xA4DAF2491434CDBD)),
				ED25519_GWORD64(UINT64_C(0x7B4AD5CDD24A88EC)), ED25519_GWORD64(UINT64_C(0x00F94051EE040543))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD7EF93BB07AF9740)), ED25519_GWORD64(UINT64_C(0x583ED0CF3DB766A7)),
				ED25519_GWORD64(UINT64_C(0xCE6998BF6E0B1EC5)), ED25519_GWORD64(UINT64_C(0xC7B7FFD25DD40452))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8D356B23C3D330B2)), ED25519_GWORD64(UINT64_C(0xF21C8B9BB0471B06)),
				ED25519_GWORD64(UINT64_C(0xB36C316C6E42B83C)), ED25519_GWORD64(UINT64_C(0x07D79C7E8BEAB10D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x87FBFB9CBC08DD12)), ED25519_GWORD64(UINT64_C(0x8A066B3AE1EEC29B)),
				ED25519_GWORD64(UINT64_C(0x0D57242BDB1FC1BF)), ED25519_GWORD64(UINT64_C(0x1C3520A35EA64BB6))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xCDA86F40216BC046)), ED25519_GWORD64(UINT64_C(0x1FBB231D12BCD87E)),
				ED25519_GWORD64(UINT64_C(0xB4956A9E17C70990)), ED25519_GWORD64(UINT64_C(0xB8750C3B66D12E55))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x80D253A6BCCBA34A)), ED25519_GWORD64(UINT64_C(0x3E61C3A13838219B)),
				ED25519_GWORD64(UINT64_C(0x90C3B6019882E396)), ED25519_GWORD64(UINT64_C(0x1C3D05775D0EE66F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x692EF1409422E51A)), ED25519_GWORD64(UINT64_C(0xCBC0C73C2B5DF671)),
				ED25519_GWORD64(UINT64_C(0x21014FE7744CE029)), ED25519_GWORD64(UINT64_C(0x0621E2C7D330487C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xB7AE1796B0DBF0F3)), ED25519_GWORD64(UINT64_C(0x54DFAFB9E17CE196)),
				ED25519_GWORD64(UINT64_C(0x25923071E9AAA3B4)), ED25519_GWORD64(UINT64_C(0x5D8E589CA1002E9D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xAF9860CC8259838D)), ED25519_GWORD64(UINT64_C(0x90EA48C1C69F9ADC)),
				ED25519_GWORD64(UINT64_C(0x6526483765581E30)), ED25519_GWORD64(UINT64_C(0x0007D6097BD3A5BC))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC0BF1D950842A94B)), ED25519_GWORD64(UINT64_C(0xB2D3C363588F2E3E)),
				ED25519_GWORD64(UINT64_C(0x0A961438BB51E2EF)), ED25519_GWORD64(UINT64_C(0x1583D7783C1CBF86))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x90034704CC9D28C7)), ED25519_GWORD64(UINT64_C(0x1D1B679EF72CC58F)),
				ED25519_GWORD64(UINT64_C(0x16E12B5FBE5B8726)), ED25519_GWORD64(UINT64_C(0x4958064E83C5580A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xECEEA2EF5DA27AE1)), ED25519_GWORD64(UINT64_C(0x597C3A1455670174)),
				ED25519_GWORD64(UINT64_C(0xC9A62A126609167A)), ED25519_GWORD64(UINT64_C(0x252A5F2E81ED8F70))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0D2894265066E80D)), ED25519_GWORD64(UINT64_C(0xFCC3F785307C8C6B)),
				ED25519_GWORD64(UINT64_C(0x1B53DA780C1112FD)), ED25519_GWORD64(UINT64_C(0x079C170BD843B388))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xCDD6CD50C0D5D056)), ED25519_GWORD64(UINT64_C(0x9AF7686DBB03573B)),
				ED25519_GWORD64(UINT64_C(0x3CA6723FF3C3EF48)), ED25519_GWORD64(UINT64_C(0x6768C0D7317B8ACC))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0506ECE464FA6FEC)), ED25519_GWORD64(UINT64_C(0xBEE3431E6205E523)),
				ED25519_GWORD64(UINT64_C(0x3579422451B8EA42)), ED25519_GWORD64(UINT64_C(0xEDEC05E34AC9FB00))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x94B625E5F155C1B3)), ED25519_GWORD64(UINT64_C(0x417BF3A7997B7B91)),
				ED25519_GWORD64(UINT64_C(0xC22CBDDC6D6B2600)), ED25519_GWORD64(UINT64_C(0x51445E14DDCD52F4))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x893147AB2BBEA442)), ED25519_GWORD64(UINT64_C(0x8C53A24F92079129)),
				ED25519_GWORD64(UINT64_C(0x4B49F948BE30F7A7)), ED25519_GWORD64(UINT64_C(0x92E990086E4FD43D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x57502B4B3B14493E)), ED25519_GWORD64(UINT64_C(0x8E67FF6B444BBCB3)),
				ED25519_GWORD64(UINT64_C(0xB8BD6927166385DB)), ED25519_GWORD64(UINT64_C(0x93186F31E39295C8))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF10C96B37FDFBB2E)), ED25519_GWORD64(UINT64_C(0x9F9A935E121CEAF9)),
				ED25519_GWORD64(UINT64_C(0xDF1136C43A5B983F)), ED25519_GWORD64(UINT64_C(0x77B2E3F05D3E99AF))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD598639C12DDB091)), ED25519_GWORD64(UINT64_C(0xA5D19F30C024866B)),
				ED25519_GWORD64(UINT64_C(0xD17C2F0358FCE460)), ED25519_GWORD64(UINT64_C(0x87A195152E095E8A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x296FA9C59C2EC4CB)), ED25519_GWORD64(UINT64_C(0xBC8B61BF4F84F3CB)),
				ED25519_GWORD64(UINT64_C(0x1C7706D917A8F908)), ED25519_GWORD64(UINT64_C(0xE3B795FC7AD3255D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA8368F02389E5FC8)), ED25519_GWORD64(UINT64_C(0x90433B02CF8DE43B)),
				ED25519_GWORD64(UINT64_C(0xAFA1FD5DC5412643)), ED25519_GWORD64(UINT64_C(0x3E8FE83D032F0137))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x08704C8DE8EFD129)), ED25519_GWORD64(UINT64_C(0xDFC51A8E33E03731)),
				ED25519_GWORD64(UINT64_C(0xA59D5DA51260CDE3)), ED25519_GWORD64(UINT64_C(0xA2D60899A6258C86))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2F8B15B90570A281)), ED25519_GWORD64(UINT64_C(0x94F2427067084549)),
				ED25519_GWORD64(UINT64_C(0xDE1C5AE161BBFD84)), ED25519_GWORD64(UINT64_C(0xF5BA3B797FAC4007))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6239DBC070CDD196)), ED25519_GWORD64(UINT64_C(0x60FE8A8B6C7D8A9A)),
				ED25519_GWORD64(UINT64_C(0xB38847BCEB401260)), ED25519_GWORD64(UINT64_C(0x0904D07B87779E5E))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xF4322D6648F940B9)), ED25519_GWORD64(UINT64_C(0x06952F0CBD2D0C39)),
				ED25519_GWORD64(UINT64_C(0x167697ADA081F931)), ED25519_GWORD64(UINT64_C(0x6240AACEBAF72A6C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB4CE1FD4DDBA9189)), ED25519_GWORD64(UINT64_C(0xCF31DB3EC74C8DAA)),
				ED25519_GWORD64(UINT64_C(0x2C63CC63AD86CC51)), ED25519_GWORD64(UINT64_C(0xC3E2143FBC1DDE07))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF834749C5BA295A0)), ED25519_GWORD64(UINT64_C(0xD6947C5BCA37D25A)),
				ED25519_GWORD64(UINT64_C(0x66F13BA7E7C9316A)), ED25519_GWORD64(UINT64_C(0x56BDAF238DB40CAC))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x1310D36CC19D3B9F)), ED25519_GWORD64(UINT64_C(0x062A6BB7622386B9)),
				ED25519_GWORD64(UINT64_C(0x7C9B8591D7A14F5C)), ED25519_GWORD64(UINT64_C(0x83AA31507E1E5754))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x362AB9E3F53533EB)), ED25519_GWORD64(UINT64_C(0x338568D56EB93D40)),
				ED25519_GWORD64(UINT64_C(0x9E0E14521D5A5572)), ED25519_GWORD64(UINT64_C(0x1D24A86D83741318))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF4EC7648FFD4CE1F)), ED25519_GWORD64(UINT64_C(0xE045EAF054AC8C1C)),
				ED25519_GWORD64(UINT64_C(0x88D225821D09357C)), ED25519_GWORD64(UINT64_C(0x43B261DC9AEB4859))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x19513D8B6C951351)), ED25519_GWORD64(UINT64_C(0x94FE7126000BF47B)),
				ED25519_GWORD64(UINT64_C(0x028D10DDD54F9567)), ED25519_GWORD64(UINT64_C(0x82B4D5E242940964))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE55B1E1988BB79BB)), ED25519_GWORD64(UINT64_C(0xA09ED07DC17A359D)),
				ED25519_GWORD64(UINT64_C(0xB02C2EE2603DEA33)), ED25519_GWORD64(UINT64_C(0x326055CF5B276BC2))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB4A155CB28D18DF2)), ED25519_GWORD64(UINT64_C(0xEACC4646186CE508)),
				ED25519_GWORD64(UINT64_C(0xC49CF4936C824389)), ED25519_GWORD64(UINT64_C(0x27A6C809AE5D3410))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xCD2C270AC43D6941)), ED25519_GWORD64(UINT64_C(0xDD4A3E576A66CAB2)),
				ED25519_GWORD64(UINT64_C(0x79FA592469D7036C)), ED25519_GWORD64(UINT64_C(0xA21503603D8C2599))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8BA6EBCD1F0DB175)), ED25519_GWORD64(UINT64_C(0x37D3D73A675A5BE8)),
				ED25519_GWORD64(UINT64_C(0xF22EDFA315F5585A)), ED25519_GWORD64(UINT64_C(0xACB67174FF60A17E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x59EECDF9390BE1D0)), ED25519_GWORD64(UINT64_C(0xA9422044728CE3F1)),
				ED25519_GWORD64(UINT64_C(0x82891C667A94F0F4)), ED25519_GWORD64(UINT64_C(0x7B1DF4B73890F436))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x5F2E221807F8F58C)), ED25519_GWORD64(UINT64_C(0xE3555C9FD49409D4)),
				ED25519_GWORD64(UINT64_C(0xB2AAA88D1FB6A630)), ED25519_GWORD64(UINT64_C(0x68698245D352E03D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE492F2E0B3B2A224)), ED25519_GWORD64(UINT64_C(0x7C6C9E062B551160)),
				ED25519_GWORD64(UINT64_C(0x15EB8FE20D7F7B0E)), ED25519_GWORD64(UINT64_C(0x61FCEF2658FC5992))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDBB15D852A18187A)), ED25519_GWORD64(UINT64_C(0xF3E4AAD386DDACD7)),
				ED25519_GWORD64(UINT64_C(0x44BAE2810FF6C482)), ED25519_GWORD64(UINT64_C(0x46CF4C473DAF01CF))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x213C6EA7F149812D)), ED25519_GWORD64(UINT64_C(0x7C1E7EF8392B4854)),
				ED25519_GWORD64(UINT64_C(0x2488C38C5629CEBA)), ED25519_GWORD64(UINT64_C(0x9065AAE50D8CC5BB))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x426525ED9EC4E5F9)), ED25519_GWORD64(UINT64_C(0x0E5EDA0116903303)),
				ED25519_GWORD64(UINT64_C(0x72B1A7F2CBE5CADC)), ED25519_GWORD64(UINT64_C(0x29387BCD14EB5F40))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1C2C4525DF200D57)), ED25519_GWORD64(UINT64_C(0x5C3B2DD6BFCA674A)),
				ED25519_GWORD64(UINT64_C(0x0A07E7B1E1834030)), ED25519_GWORD64(UINT64_C(0x69A198E64F1CE716))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE1014434DCC5CAED)), ED25519_GWORD64(UINT64_C(0x47ED5D963C84FB33)),
				ED25519_GWORD64(UINT64_C(0x70019576ED86A0E7)), ED25519_GWORD64(UINT64_C(0x25B2697BD267F9E4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9062B2E0D91A78A9)), ED25519_GWORD64(UINT64_C(0x47C9889CC8509667)),
				ED25519_GWORD64(UINT64_C(0x9DF54A66405070B8)), ED25519_GWORD64(UINT64_C(0xF369E6A92493A1BF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9D673FFB13986864)), ED25519_GWORD64(UINT64_C(0x3CA5FBD9415DC7B8)),
				ED25519_GWORD64(UINT64_C(0xE04ECC3BDF273B5E)), ED25519_GWORD64(UINT64_C(0x1420683DB54E4CD2))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x34EEBB6FC1CC5AD0)), ED25519_GWORD64(UINT64_C(0x6A1B0CE99646AC8B)),
				ED25519_GWORD64(UINT64_C(0xD3B0DA49A66BDE53)), ED25519_GWORD64(UINT64_C(0x31E83B4161D081C1))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB478BD1E249DD184)), ED25519_GWORD64(UINT64_C(0x620C35005E58C102)),
				ED25519_GWORD64(UINT64_C(0xFB02D32FCCBAAC5C)), ED25519_GWORD64(UINT64_C(0xE0B63BEBF508A72D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x97E8C7129E062B4F)), ED25519_GWORD64(UINT64_C(0x49E48F4F29320AD8)),
				ED25519_GWORD64(UINT64_C(0x5BECE14B6F18683F)), ED25519_GWORD64(UINT64_C(0x55CF1EB62D550317))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3076B5E37DF58C3F)), ED25519_GWORD64(UINT64_C(0xD73AB9DDE799CC36)),
				ED25519_GWORD64(UINT64_C(0xBD831CE34913EE20)), ED25519_GWORD64(UINT64_C(0x9A56FBAA62BA0133))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5879101065C23D45)), ED25519_GWORD64(UINT64_C(0x8B9D086D5094819C)),
				ED25519_GWORD64(UINT64_C(0xE2402FA912C55FA7)), ED25519_GWORD64(UINT64_C(0xE69A6564570891D4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x943E6B505C9DC9EC)), ED25519_GWORD64(UINT64_C(0x302557BBA77C371A)),
				ED25519_GWORD64(UINT64_C(0x9873AE5641347651)), ED25519_GWORD64(UINT64_C(0x13C4836799C58A5C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xC4DCFB6A5D8BD080)), ED25519_GWORD64(UINT64_C(0xDEEBC4EC571A4842)),
				ED25519_GWORD64(UINT64_C(0xD4B2E883B8E55365)), ED25519_GWORD64(UINT64_C(0x50BDC87DC8E5B827))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x423A5D465AB3E1A6)), ED25519_GWORD64(UINT64_C(0xFC13C187C7F13F61)),
				ED25519_GWORD64(UINT64_C(0x19F83664ECB5B9B6)), ED25519_GWORD64(UINT64_C(0xE6F80C93A637B607))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x606D37836EDFE111)), ED25519_GWORD64(UINT64_C(0x32353E15F011ABD9)),
				ED25519_GWORD64(UINT64_C(0x64B03AC325B73B96)), ED25519_GWORD64(UINT64_C(0x1DD56444725FD5AE))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xC297E60008BAC887)), ED25519_GWORD64(UINT64_C(0x7D4CEA11EAE1C3E0)),
				ED25519_GWORD64(UINT64_C(0xF3E38BE19FE7977C)), ED25519_GWORD64(UINT64_C(0xBA3A450F63A305CD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8FA47FF83362127D)), ED25519_GWORD64(UINT64_C(0xBC9F6AC471CD7C15)),
				ED25519_GWORD64(UINT64_C(0x6E71454349220C8B)), ED25519_GWORD64(UINT64_C(0x0E645912219F732E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x078F2F31D8394627)), ED25519_GWORD64(UINT64_C(0x389D3183DE94A510)),
				ED25519_GWORD64(UINT64_C(0xD1E36C6D17996F80)), ED25519_GWORD64(UINT64_C(0x318C8D9393A9A87B))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x5D669E29AB1DD385)), ED25519_GWORD64(UINT64_C(0xFC921658342D9E3B)),
				ED25519_GWORD64(UINT64_C(0x55851DFDF35973CD)), ED25519_GWORD64(UINT64_C(0xD09A41C325950AF6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF2745D032AFFFE19)), ED25519_GWORD64(UINT64_C(0x0C9F3C497F24DB66)),
				ED25519_GWORD64(UINT64_C(0xBC98D3E3BA8598EF)), ED25519_GWORD64(UINT64_C(0x224C7C679A1D5314))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xBDC06EDCA6F925E9)), ED25519_GWORD64(UINT64_C(0x793EF3F4641B1F33)),
				ED25519_GWORD64(UINT64_C(0x82EC12809D833E89)), ED25519_GWORD64(UINT64_C(0x05BFF02328A11389))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6881A0DD0DC512E4)), ED25519_GWORD64(UINT64_C(0x4FE70DC844A5FAFE)),
				ED25519_GWORD64(UINT64_C(0x1F748E6B8F4A5240)), ED25519_GWORD64(UINT64_C(0x576277CDEE01A3EA))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3632137023CADFF8)), ED25519_GWORD64(UINT64_C(0x544ACF0AD1ACCF59)),
				ED25519_GWORD64(UINT64_C(0x96741049D21A1C88)), ED25519_GWORD64(UINT64_C(0xF80B8CC3FA2A44A7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1EF38ABC234F305F)), ED25519_GWORD64(UINT64_C(0x9A577FBD1405DE08)),
				ED25519_GWORD64(UINT64_C(0x5E82A51434E62A0D)), ED25519_GWORD64(UINT64_C(0x5FF418726271B7A1))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE5DB47E813B6952D)), ED25519_GWORD64(UINT64_C(0xF35D2A3B432610E1)),
				ED25519_GWORD64(UINT64_C(0xAC1F26E938781276)), ED25519_GWORD64(UINT64_C(0xA9D4DB8CA0A0CB69))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x398E080C1789DB9D)), ED25519_GWORD64(UINT64_C(0xA7602025F3E778F5)),
				ED25519_GWORD64(UINT64_C(0xFA98894C06BD035D)), ED25519_GWORD64(UINT64_C(0x106A03DC25A966BE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD9AD0AAF333353D0)), ED25519_GWORD64(UINT64_C(0x38669DA5ACD309E5)),
				ED25519_GWORD64(UINT64_C(0x3C57658AC888F7F0)), ED25519_GWORD64(UINT64_C(0x4AB38A51052CBEFA))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD6CFD1EF5FDDC089)), ED25519_GWORD64(UINT64_C(0xE82B3EFDF7575DCE)),
				ED25519_GWORD64(UINT64_C(0x25D56B5D201634C2)), ED25519_GWORD64(UINT64_C(0xB041C6BB04ED2B9B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDA7C2B256768D593)), ED25519_GWORD64(UINT64_C(0x98C1C0574422CA13)),
				ED25519_GWORD64(UINT64_C(0xF1A80BD5CA0ACE1D)), ED25519_GWORD64(UINT64_C(0x29CDD1ADC088A690))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0FF2F2F9D956E148)), ED25519_GWORD64(UINT64_C(0xADE797759F356B2E)),
				ED25519_GWORD64(UINT64_C(0x1A4698BB5F6C025C)), ED25519_GWORD64(UINT64_C(0x104BBD6814049A7B))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA95D9A5FD67FF150)), ED25519_GWORD64(UINT64_C(0xE92BE69D4CC75681)),
				ED25519_GWORD64(UINT64_C(0xB7F8024CDE20F257)), ED25519_GWORD64(UINT64_C(0xA04F2A20FB072DF5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x51F0FD3168F1ED54)), ED25519_GWORD64(UINT64_C(0x2C811DCDD86F3BC2)),
				ED25519_GWORD64(UINT64_C(0x44DC5C4304D2F2DE)), ED25519_GWORD64(UINT64_C(0xDBE8CC57092A7149))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC8143B3D30EBB079)), ED25519_GWORD64(UINT64_C(0x7589155ABD652E30)),
				ED25519_GWORD64(UINT64_C(0x653C3C318F6D5C31)), ED25519_GWORD64(UINT64_C(0x2570FB17C279161F))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x192EA9550BB82447)), ED25519_GWORD64(UINT64_C(0xC8E6FBA88F9050D1)),
				ED25519_GWORD64(UINT64_C(0x7986EA2D88A4C935)), ED25519_GWORD64(UINT64_C(0xA41C5F91DE018668))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3EFA367F2CB61575)), ED25519_GWORD64(UINT64_C(0xF5F96F761CD6026C)),
				ED25519_GWORD64(UINT64_C(0xE8C7142A65B52562)), ED25519_GWORD64(UINT64_C(0x3DCB65EA53030ACD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x28D8172940DE6CAA)), ED25519_GWORD64(UINT64_C(0x8FBF2CF022D9733A)),
				ED25519_GWORD64(UINT64_C(0x16D7FCDD235B01D1)), ED25519_GWORD64(UINT64_C(0x08420EDD5FCDF0E5))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x0358C34E04F410BB)), ED25519_GWORD64(UINT64_C(0xB6135B5A276E0685)),
				ED25519_GWORD64(UINT64_C(0x5D9670C7EBB91521)), ED25519_GWORD64(UINT64_C(0x84D654F321DB889C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xCDFF20AB8362FA37)), ED25519_GWORD64(UINT64_C(0x57E118D4E21A3E6E)),
				ED25519_GWORD64(UINT64_C(0xE3179617FC39E62B)), ED25519_GWORD64(UINT64_C(0x8D9A53EFBC1769FD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5E7DC116DDBDB5D5)), ED25519_GWORD64(UINT64_C(0x2954DEB68DA5DD2D)),
				ED25519_GWORD64(UINT64_C(0x1CB608173334A292)), ED25519_GWORD64(UINT64_C(0x4A7A4F2618991AD7))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x24C3B291AF372A4B)), ED25519_GWORD64(UINT64_C(0x93DA8270718147F2)),
				ED25519_GWORD64(UINT64_C(0xDD84856486899EF2)), ED25519_GWORD64(UINT64_C(0x4A96314223E0EE33))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF4A718025FB15F95)), ED25519_GWORD64(UINT64_C(0x3DF65F346B5C1B8F)),
				ED25519_GWORD64(UINT64_C(0xCDFCF08500E01112)), ED25519_GWORD64(UINT64_C(0x11B50C4CDDD31848))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA6E8274408A4FFD6)), ED25519_GWORD64(UINT64_C(0x738E177E9C1576D9)),
				ED25519_GWORD64(UINT64_C(0x773348B63D02B3F2)), ED25519_GWORD64(UINT64_C(0x4F4BCE4DCE6BCC51))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x30E2616EC49D0B6F)), ED25519_GWORD64(UINT64_C(0xE456718FCAEC2317)),
				ED25519_GWORD64(UINT64_C(0x48EB409BF26B4FA6)), ED25519_GWORD64(UINT64_C(0x3042CEE561595F37))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA71FCE5AE2242571)), ED25519_GWORD64(UINT64_C(0x26EA725692F58A9E)),
				ED25519_GWORD64(UINT64_C(0xD21A09D71CEA3CF4)), ED25519_GWORD64(UINT64_C(0xF3FCDD14B71C01E6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x427E7079449BAC41)), ED25519_GWORD64(UINT64_C(0x855AE36DBCE2310A)),
				ED25519_GWORD64(UINT64_C(0x4CAE76215F841A7C)), ED25519_GWORD64(UINT64_C(0x389E740C9A9CE1D6))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xC9BD78F6570EAC15)), ED25519_GWORD64(UINT64_C(0xE55B0B3227919CE1)),
				ED25519_GWORD64(UINT64_C(0x65FC3EABA19B91ED)), ED25519_GWORD64(UINT64_C(0xA5C425E5D6263690))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x64FCB3AE34DCB9BB)), ED25519_GWORD64(UINT64_C(0x97500323E348D0AD)),
				ED25519_GWORD64(UINT64_C(0x45B3F07D62C6381B)), ED25519_GWORD64(UINT64_C(0xE1545379465A6788))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3F3E06A6F1D7DE6E)), ED25519_GWORD64(UINT64_C(0x3EF976278E062308)),
				ED25519_GWORD64(UINT64_C(0x8C14F6264E8A6C77)), ED25519_GWORD64(UINT64_C(0x6539A08915484759))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xDDC4DBD414BB4A06)), ED25519_GWORD64(UINT64_C(0x19B2BC3C98424F8E)),
				ED25519_GWORD64(UINT64_C(0x48A89FD736CA7169)), ED25519_GWORD64(UINT64_C(0x8F65320EF019BD90))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE9D21F74C3D2F760)), ED25519_GWORD64(UINT64_C(0xC150544125C46845)),
				ED25519_GWORD64(UINT64_C(0x624E5CE8F9B99E33)), ED25519_GWORD64(UINT64_C(0x91C5E4AAC5CD186C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD486D1B1CAFDE0C6)), ED25519_GWORD64(UINT64_C(0x4F3FE6E3163B5181)),
				ED25519_GWORD64(UINT64_C(0x59A8AF0DFAF2939A)), ED25519_GWORD64(UINT64_C(0x4CABC7BDEC33072A))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xC08F788F3F78D289)), ED25519_GWORD64(UINT64_C(0xFE30A72CA1404D9F)),
				ED25519_GWORD64(UINT64_C(0xF2778BFCCF65CC9D)), ED25519_GWORD64(UINT64_C(0x7EE498165ACB2021))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x239E9624089C0A1B)), ED25519_GWORD64(UINT64_C(0xC748C4C03AFE4738)),
				ED25519_GWORD64(UINT64_C(0x17DBED2A764FA12A)), ED25519_GWORD64(UINT64_C(0xE39B93F0321C8582))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7BD508E39111A1C3)), ED25519_GWORD64(UINT64_C(0x2B2B90D480907489)),
				ED25519_GWORD64(UINT64_C(0xE7D2AEC2AE72FD19)), ED25519_GWORD64(UINT64_C(0x0EDF493C85B602A6))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6767C4D284764100)), ED25519_GWORD64(UINT64_C(0xA090403FF7F5F835)),
				ED25519_GWORD64(UINT64_C(0x1C8FCFFACAE6BEDE)), ED25519_GWORD64(UINT64_C(0x84C00C54D1DFA369))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xAECC8158599B5A68)), ED25519_GWORD64(UINT64_C(0xEA574F0FEBADE20E)),
				ED25519_GWORD64(UINT64_C(0x4FE41D7422B67F07)), ED25519_GWORD64(UINT64_C(0x403B92E3019D4FB4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x4DC22F818B465CF8)), ED25519_GWORD64(UINT64_C(0x71A0F35A1480EFF8)),
				ED25519_GWORD64(UINT64_C(0xAEE8BFAD04C7D657)), ED25519_GWORD64(UINT64_C(0x355BB12AB26176F4))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA301DAC75A8C7318)), ED25519_GWORD64(UINT64_C(0xED90039DB3CEAA11)),
				ED25519_GWORD64(UINT64_C(0x6F077CBF3BAE3F2D)), ED25519_GWORD64(UINT64_C(0x7518EAF8E052AD8E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA71E64CC7493BBF4)), ED25519_GWORD64(UINT64_C(0xE5BD84D9ECA3B0C3)),
				ED25519_GWORD64(UINT64_C(0x0A6BC50CFA05E785)), ED25519_GWORD64(UINT64_C(0x0F9B8132182EC312))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA48859C41B7F6C32)), ED25519_GWORD64(UINT64_C(0x0F2D60BCF4383298)),
				ED25519_GWORD64(UINT64_C(0x1815A929C9B1D1D9)), ED25519_GWORD64(UINT64_C(0x47C3871BBB1755C4))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xFBE65D50C85066B0)), ED25519_GWORD64(UINT64_C(0x62ECC4B0B3A299B0)),
				ED25519_GWORD64(UINT64_C(0xE53754EA441AE8E0)), ED25519_GWORD64(UINT64_C(0x08FEA02CE8D48D5F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5144539771EC4F48)), ED25519_GWORD64(UINT64_C(0xF805B17DC98C5D6E)),
				ED25519_GWORD64(UINT64_C(0xF762C11A47C3C66B)), ED25519_GWORD64(UINT64_C(0x00B89B85764699DC))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x824DDD7668DEEAD0)), ED25519_GWORD64(UINT64_C(0xC86445204B685D23)),
				ED25519_GWORD64(UINT64_C(0xB514CFCD5D89D665)), ED25519_GWORD64(UINT64_C(0x473829A74F75D537))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x23D9533AAD3902C9)), ED25519_GWORD64(UINT64_C(0x64C2DDCEEF03588F)),
				ED25519_GWORD64(UINT64_C(0x15257390CFE12FB4)), ED25519_GWORD64(UINT64_C(0x6C668B4D44E4D390))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x82D2DA754679C405)), ED25519_GWORD64(UINT64_C(0xE63BD7D8B2618DF0)),
				ED25519_GWORD64(UINT64_C(0x355EEF24AC47EB0A)), ED25519_GWORD64(UINT64_C(0xA078684C4833C6B4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3B48CF217A78820C)), ED25519_GWORD64(UINT64_C(0xF76A0AB281273E97)),
				ED25519_GWORD64(UINT64_C(0xA96C65A78C8EED7B)), ED25519_GWORD64(UINT64_C(0x7411A6054F8A433F))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x579AE53D18B175B4)), ED25519_GWORD64(UINT64_C(0x68713159F392A102)),
				ED25519_GWORD64(UINT64_C(0x8455ECBA1EEF35F5)), ED25519_GWORD64(UINT64_C(0x1EC9A872458C398F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x4D659D32B99DC85A)), ED25519_GWORD64(UINT64_C(0x044CDC75603AF115)),
				ED25519_GWORD64(UINT64_C(0xB34C712CDCC2E488)), ED25519_GWORD64(UINT64_C(0xFC136574FB8134FF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB8E6A4D400A2509B)), ED25519_GWORD64(UINT64_C(0x9B81D7020BC882B4)),
				ED25519_GWORD64(UINT64_C(0x57E7CC9BF1957561)), ED25519_GWORD64(UINT64_C(0x3ADD88A5C7CD6460))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x85C298D459393046)), ED25519_GWORD64(UINT64_C(0x8F7E35985FF659EC)),
				ED25519_GWORD64(UINT64_C(0x1D2CA22AF2F66E3A)), ED25519_GWORD64(UINT64_C(0x61BA1131A406A720))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xAB895770B635DCF2)), ED25519_GWORD64(UINT64_C(0x02DFEF6CF66C1FBC)),
				ED25519_GWORD64(UINT64_C(0x85530268BEB6D187)), ED25519_GWORD64(UINT64_C(0x249929FCCC879E74))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA3D0A0F116959029)), ED25519_GWORD64(UINT64_C(0x023B6B6CBA7EBD89)),
				ED25519_GWORD64(UINT64_C(0x7BF15A3E26783307)), ED25519_GWORD64(UINT64_C(0x5620310CBBD8ECE7))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6646B5F477E285D6)), ED25519_GWORD64(UINT64_C(0x40E8FF676C8F6193)),
				ED25519_GWORD64(UINT64_C(0xA6EC7311ABB594DD)), ED25519_GWORD64(UINT64_C(0x7EC846F3658CEC4D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x528993434934D630)), ED25519_GWORD64(UINT64_C(0xB9DBF806A51222F5)),
				ED25519_GWORD64(UINT64_C(0x8F6D878FC3F41C22)), ED25519_GWORD64(UINT64_C(0xB7676A2A4D9D9730))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9B5E8F3F1DA22EC7)), ED25519_GWORD64(UINT64_C(0x130F1D776C01CD13)),
				ED25519_GWORD64(UINT64_C(0x214C8FCFA2989FB8)), ED25519_GWORD64(UINT64_C(0x6DAAF723399B9DD5))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x583B04BFACAD8E8F)), ED25519_GWORD64(UINT64_C(0x29B743E8148BE884)),
				ED25519_GWORD64(UINT64_C(0x2B1E583B0810C5DB)), ED25519_GWORD64(UINT64_C(0xAB5449E58EB3BBAA))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5F3A7562EB3DBE47)), ED25519_GWORD64(UINT64_C(0xF7EA38548EBDA0B8)),
				ED25519_GWORD64(UINT64_C(0x00C3E53145747299)), ED25519_GWORD64(UINT64_C(0x1304E9E71627D551))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x789814D26ADC9CFE)), ED25519_GWORD64(UINT64_C(0x3C1BAB3F8B48DD0B)),
				ED25519_GWORD64(UINT64_C(0xDA0FE1FFF979C60A)), ED25519_GWORD64(UINT64_C(0x4468DE2D7C2DD693))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x4B9AD8C6F86307BB)), ED25519_GWORD64(UINT64_C(0x21113531435D0C28)),
				ED25519_GWORD64(UINT64_C(0xD4A866C5657A772C)), ED25519_GWORD64(UINT64_C(0xDDA6427E63247352))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x51BB355E9419468B)), ED25519_GWORD64(UINT64_C(0x33E6DC4C23DDC754)),
				ED25519_GWORD64(UINT64_C(0x93A5B6D6447F9962)), ED25519_GWORD64(UINT64_C(0xECCE7C6FFB44BD63))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1A94C688DEAC22CA)), ED25519_GWORD64(UINT64_C(0xB9066EF7BBAE1FF8)),
				ED25519_GWORD64(UINT64_C(0x88AD8C388D59580F)), ED25519_GWORD64(UINT64_C(0x58F29ABFE79F2CA8))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x4B5A64BF710ECDF6)), ED25519_GWORD64(UINT64_C(0xB14CE538462C293C)),
				ED25519_GWORD64(UINT64_C(0x3643D056D50B3AB9)), ED25519_GWORD64(UINT64_C(0x6AF93724185B4870))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE90ECFAB8DE73E68)), ED25519_GWORD64(UINT64_C(0x54036F9F377E76A5)),
				ED25519_GWORD64(UINT64_C(0xF0495B0BBE015982)), ED25519_GWORD64(UINT64_C(0x577629C4A7F41E36))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3220024509C6A888)), ED25519_GWORD64(UINT64_C(0xD2E036134B558973)),
				ED25519_GWORD64(UINT64_C(0x83E236233C33289F)), ED25519_GWORD64(UINT64_C(0x701F25BB0CAEC18F))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9D18F6D97CBEC113)), ED25519_GWORD64(UINT64_C(0x844A06E674BFDBE4)),
				ED25519_GWORD64(UINT64_C(0x20F5B522AC4E60D6)), ED25519_GWORD64(UINT64_C(0x720A5BC050955E51))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC3A8B0F8E4616CED)), ED25519_GWORD64(UINT64_C(0xF700660E9E25A87D)),
				ED25519_GWORD64(UINT64_C(0x61E3061FF4BCA59C)), ED25519_GWORD64(UINT64_C(0x2E0C92BFBDC40BE9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0C3F09439B805A35)), ED25519_GWORD64(UINT64_C(0xE84E8B376242ABFC)),
				ED25519_GWORD64(UINT64_C(0x691417F35C229346)), ED25519_GWORD64(UINT64_C(0x0E9B9CBB144EF0EC))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x8DEE9BD55DB1BEDB)), ED25519_GWORD64(UINT64_C(0xC9C3AB370A723FB9)),
				ED25519_GWORD64(UINT64_C(0x44A8F1BF1C68D791)), ED25519_GWORD64(UINT64_C(0xB66D44191CFD3CDE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xFBBAD48FFB5720AD)), ED25519_GWORD64(UINT64_C(0xEE81916BDBF90D0E)),
				ED25519_GWORD64(UINT64_C(0xD4813152635543BF)), ED25519_GWORD64(UINT64_C(0x221104EB3F337BD8))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9E3C1743F2BC8C14)), ED25519_GWORD64(UINT64_C(0x2EDA26FCB5856C3B)),
				ED25519_GWORD64(UINT64_C(0xCCB82F0E68A7FB97)), ED25519_GWORD64(UINT64_C(0x4167A4E6BC593244))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xC2BE2665F8CE8FDB)), ED25519_GWORD64(UINT64_C(0xE967FF14E880D62C)),
				ED25519_GWORD64(UINT64_C(0xF12E6E7E2F364EEE)), ED25519_GWORD64(UINT64_C(0xB4B33370CB7ED2F6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x643B9D2876F626ED)), ED25519_GWORD64(UINT64_C(0x5D1D9D400E7668EB)),
				ED25519_GWORD64(UINT64_C(0x1B4B430321FC0684)), ED25519_GWORD64(UINT64_C(0xF938BB7E2255246A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xCDC591EE8681D6CC)), ED25519_GWORD64(UINT64_C(0xCE02109CED85A753)),
				ED25519_GWORD64(UINT64_C(0xED7485C158808883)), ED25519_GWORD64(UINT64_C(0x1176FC6E2DFE65E4))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xDB90E28949770EA5)), ED25519_GWORD64(UINT64_C(0x98FBCC2AACF440A3)),
				ED25519_GWORD64(UINT64_C(0x21354FFEDED7879B)), ED25519_GWORD64(UINT64_C(0x9F6A3E54F26906B6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB4AF6CD05B9C619B)), ED25519_GWORD64(UINT64_C(0x2DDFC9F4B2A58480)),
				ED25519_GWORD64(UINT64_C(0x3D4FA502EBE94DC4)), ED25519_GWORD64(UINT64_C(0x08FC3A4C677D5F34))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x60A4C199D30734EA)), ED25519_GWORD64(UINT64_C(0x40C085B631165CD6)),
				ED25519_GWORD64(UINT64_C(0xE2333E23F7598295)), ED25519_GWORD64(UINT64_C(0x4F2FAD0116B900D1))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x962CD91DB73BB625)), ED25519_GWORD64(UINT64_C(0xE60577AAFC129C08)),
				ED25519_GWORD64(UINT64_C(0x6F619B39F3B61689)), ED25519_GWORD64(UINT64_C(0xB451995F2944EE81))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x44BEB24194AE4E41)), ED25519_GWORD64(UINT64_C(0x5F541C511857EF6C)),
				ED25519_GWORD64(UINT64_C(0xA61E6B2D368D0498)), ED25519_GWORD64(UINT64_C(0xC45484A4972EF7AB))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9152FCD09FEA7D7C)), ED25519_GWORD64(UINT64_C(0x4A816C94B0935CF6)),
				ED25519_GWORD64(UINT64_C(0x258E9AAA47285C40)), ED25519_GWORD64(UINT64_C(0x10B89CA6042893B7))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x753941BE5A45F05B)), ED25519_GWORD64(UINT64_C(0xD07CAEED6D9C5F65)),
				ED25519_GWORD64(UINT64_C(0x11776B9C72FF51B6)), ED25519_GWORD64(UINT64_C(0x97D2D1D9EF0D4DA9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3D59474997182889)), ED25519_GWORD64(UINT64_C(0x12EBF8C524533F26)),
				ED25519_GWORD64(UINT64_C(0x0262BFCB14C3EF15)), ED25519_GWORD64(UINT64_C(0xA0B878D577B7518E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x27F2AF18073F3E6A)), ED25519_GWORD64(UINT64_C(0xFD3FE519D7521069)),
				ED25519_GWORD64(UINT64_C(0x22E3B72C3CA60022)), ED25519_GWORD64(UINT64_C(0x72214F63CC65C6A7))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x1D9DB7B9F43B29B6)), ED25519_GWORD64(UINT64_C(0xD605824A4F518F75)),
				ED25519_GWORD64(UINT64_C(0xF2C072BD312F9DC4)), ED25519_GWORD64(UINT64_C(0x9F24AC855A1545B0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB4E37F405307A680)), ED25519_GWORD64(UINT64_C(0xABA714D72F336795)),
				ED25519_GWORD64(UINT64_C(0xD6FBD0A773761099)), ED25519_GWORD64(UINT64_C(0xDFDF48C58171CBC9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x24D608328E9505AA)), ED25519_GWORD64(UINT64_C(0x4748C1D10C1420EE)),
				ED25519_GWORD64(UINT64_C(0xC7FFE45C06FB25A2)), ED25519_GWORD64(UINT64_C(0x00BA739E2AE395E6))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xAE4426F5EA88BB26)), ED25519_GWORD64(UINT64_C(0x360679D984973BFB)),
				ED25519_GWORD64(UINT64_C(0x5C9F030C26694E50)), ED25519_GWORD64(UINT64_C(0x72297DE7D518D226))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x592E98DE5C8790D6)), ED25519_GWORD64(UINT64_C(0xE5BFB7D345C2A2DF)),
				ED25519_GWORD64(UINT64_C(0x115A3B60F9B49922)), ED25519_GWORD64(UINT64_C(0x03283A3E67AD78F3))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x48241DC7BE0CB939)), ED25519_GWORD64(UINT64_C(0x32F19B4D8B633080)),
				ED25519_GWORD64(UINT64_C(0xD3DFC90D02289308)), ED25519_GWORD64(UINT64_C(0x05E1296846271945))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xADBFBBC8242C4550)), ED25519_GWORD64(UINT64_C(0xBCC80CECD03081D9)),
				ED25519_GWORD64(UINT64_C(0x843566A6F5C8DF92)), ED25519_GWORD64(UINT64_C(0x78CF25D38258CE4C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xBA82EEB32D9C495A)), ED25519_GWORD64(UINT64_C(0xCEEFC8FCF12BB97C)),
				ED25519_GWORD64(UINT64_C(0xB02DABAE93B5D1E0)), ED25519_GWORD64(UINT64_C(0x39C00C9C13698D9B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x15AE6B8E31489D68)), ED25519_GWORD64(UINT64_C(0xAA851CAB9C2BF087)),
				ED25519_GWORD64(UINT64_C(0xC9A75A97F04EFA05)), ED25519_GWORD64(UINT64_C(0x006B52076B3FF832))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xF5CB7E16B9CE082D)), ED25519_GWORD64(UINT64_C(0x3407F14C417ABC29)),
				ED25519_GWORD64(UINT64_C(0xD4B36BCE2BF4A7AB)), ED25519_GWORD64(UINT64_C(0x7DE2E9561A9F75CE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x29E0CFE19D957809)), ED25519_GWORD64(UINT64_C(0xB681DF18966310E2)),
				ED25519_GWORD64(UINT64_C(0x57DF39D370516B39)), ED25519_GWORD64(UINT64_C(0xCD57E3443BC76122))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDE70D4F4B6A55ECB)), ED25519_GWORD64(UINT64_C(0x4801527F5D85DB99)),
				ED25519_GWORD64(UINT64_C(0xDBC9C440D3EE9A81)), ED25519_GWORD64(UINT64_C(0x6B2A90AF1A6029ED))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x77EBF3245BB2D80A)), ED25519_GWORD64(UINT64_C(0xD8301B472FB9079B)),
				ED25519_GWORD64(UINT64_C(0xC647E6F24CEE7333)), ED25519_GWORD64(UINT64_C(0x465812C8276C2109))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6923F4FC9AE61E84)), ED25519_GWORD64(UINT64_C(0x5735281DE03F5FD1)),
				ED25519_GWORD64(UINT64_C(0xA764AE43E6EDD12D)), ED25519_GWORD64(UINT64_C(0xDFD8F4E9D12D3E4A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x4D43BEB22A1062D9)), ED25519_GWORD64(UINT64_C(0x7065FB753831DC16)),
				ED25519_GWORD64(UINT64_C(0x180D4A7BDE2968D7)), ED25519_GWORD64(UINT64_C(0x05B32C2B1CB16790))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xF7FCA42C7AD58182)), ED25519_GWORD64(UINT64_C(0x3214286E4333F3CC)),
				ED25519_GWORD64(UINT64_C(0xB6C29D0D340B979D)), ED25519_GWORD64(UINT64_C(0xB1771A48567307E1))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC8C05ECCD24DA8EA)), ED25519_GWORD64(UINT64_C(0xA1CF1AAC05DFEF83)),
				ED25519_GWORD64(UINT64_C(0xDBBEEFF27DF9CD61)), ED25519_GWORD64(UINT64_C(0xBB5556A37B471E99))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x32B0C524E14DD482)), ED25519_GWORD64(UINT64_C(0xEDB351541A2BA4B6)),
				ED25519_GWORD64(UINT64_C(0xA3D16048282B5AF3)), ED25519_GWORD64(UINT64_C(0x4FC079D27A7336EB))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xDC348B440C86C50D)), ED25519_GWORD64(UINT64_C(0x1337CBC9CC94E651)),
				ED25519_GWORD64(UINT64_C(0x6422F74D643E3CB9)), ED25519_GWORD64(UINT64_C(0x241170C2BAE3CD08))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x51C938B089BF2F7F)), ED25519_GWORD64(UINT64_C(0x2497BD6502DFE9A7)),
				ED25519_GWORD64(UINT64_C(0xFFFFC09C7880E453)), ED25519_GWORD64(UINT64_C(0x124567CECAF98E92))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3FF9AB860AC473B4)), ED25519_GWORD64(UINT64_C(0xF0911DEE0113E435)),
				ED25519_GWORD64(UINT64_C(0x4AE75060EBC6C4AF)), ED25519_GWORD64(UINT64_C(0x3F8612966C87000D))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9C18FCFA36048D00)), ED25519_GWORD64(UINT64_C(0x29159DB373899DDD)),
				ED25519_GWORD64(UINT64_C(0xDC9F350B9F92D0AA)), ED25519_GWORD64(UINT64_C(0xA6F57EEE878A19D4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x559A0CC9782A0DDE)), ED25519_GWORD64(UINT64_C(0x551DCDB2EA718385)),
				ED25519_GWORD64(UINT64_C(0x7F62865B31EF238C)), ED25519_GWORD64(UINT64_C(0x504AA7767973613D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0CAB2CD55687EFB1)), ED25519_GWORD64(UINT64_C(0x5180D162247AF17B)),
				ED25519_GWORD64(UINT64_C(0x85C15A344F5A2467)), ED25519_GWORD64(UINT64_C(0x4041943D9DBA3069))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x4B217743A26CAACA)), ED25519_GWORD64(UINT64_C(0x47A6B424648AB7CE)),
				ED25519_GWORD64(UINT64_C(0xCB1D4F7A03FBC9E3)), ED25519_GWORD64(UINT64_C(0x92D931429800D019))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC3C0EEBA43EBCC96)), ED25519_GWORD64(UINT64_C(0x8D749C9C26EA9CAF)),
				ED25519_GWORD64(UINT64_C(0xD9FA95EE1C77CCC6)), ED25519_GWORD64(UINT64_C(0x1420A1D97684340F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x00C67799D337594F)), ED25519_GWORD64(UINT64_C(0x5E3C5140B23AA47B)),
				ED25519_GWORD64(UINT64_C(0x44182854E35FF395)), ED25519_GWORD64(UINT64_C(0x1B4F92314359A012))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x33CF3030A49866B1)), ED25519_GWORD64(UINT64_C(0x251F73D2215F4859)),
				ED25519_GWORD64(UINT64_C(0xAB82AA4051DEF4F6)), ED25519_GWORD64(UINT64_C(0x5FF191D56F9A23F6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3E5C109D89150951)), ED25519_GWORD64(UINT64_C(0x39CEFA912DE9696A)),
				ED25519_GWORD64(UINT64_C(0x20EAE43F975F3020)), ED25519_GWORD64(UINT64_C(0x239B572A7F132DAE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x819ED433AC2D9068)), ED25519_GWORD64(UINT64_C(0x2883AB795FC98523)),
				ED25519_GWORD64(UINT64_C(0xEF4572805593EB3D)), ED25519_GWORD64(UINT64_C(0x020C526A758F36CB))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE931EF59F042CC76)), ED25519_GWORD64(UINT64_C(0x2C589C9D8E124BB6)),
				ED25519_GWORD64(UINT64_C(0xADC8E18AAEC75997)), ED25519_GWORD64(UINT64_C(0xC52CFE0A5602C50C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x779834F89ED8DBBC)), ED25519_GWORD64(UINT64_C(0xC8F2AAF9DC7CA46C)),
				ED25519_GWORD64(UINT64_C(0xA9524CDCA3E1B074)), ED25519_GWORD64(UINT64_C(0x02AACC4615313877))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x86A0F7A0647877DF)), ED25519_GWORD64(UINT64_C(0xBBC464270E607C9F)),
				ED25519_GWORD64(UINT64_C(0xAB17EA25F1FB11C9)), ED25519_GWORD64(UINT64_C(0x4CFB7D7B304B877B))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE28699C29789EF12)), ED25519_GWORD64(UINT64_C(0x2B6ECD71DF57190D)),
				ED25519_GWORD64(UINT64_C(0xC343C857ECC970D0)), ED25519_GWORD64(UINT64_C(0x5B1D4CBC434D3AC5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x72B43D6CB89B75FE)), ED25519_GWORD64(UINT64_C(0x54C694D99C6ADC80)),
				ED25519_GWORD64(UINT64_C(0xB8C3AA373EE34C9F)), ED25519_GWORD64(UINT64_C(0x14B4622B39075364))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB6FB2615CC0A9F26)), ED25519_GWORD64(UINT64_C(0x3A4F0E2BB88DCCE5)),
				ED25519_GWORD64(UINT64_C(0x1301498B3369A705)), ED25519_GWORD64(UINT64_C(0x2F98F71258592DD1))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2E12AE444F54A6EE)), ED25519_GWORD64(UINT64_C(0xFCFE3EF0A9CBD7DE)),
				ED25519_GWORD64(UINT64_C(0xCEBF890D75835DE0)), ED25519_GWORD64(UINT64_C(0x9D8062E9E7614554))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0C94A74CB50F9E56)), ED25519_GWORD64(UINT64_C(0x5B1FF4A98E8E1320)),
				ED25519_GWORD64(UINT64_C(0x9A2ACC2182300F67)), ED25519_GWORD64(UINT64_C(0x3A6AE249D806AAF9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x657ADA85A9907C5A)), ED25519_GWORD64(UINT64_C(0x1A0EA8B591B90F62)),
				ED25519_GWORD64(UINT64_C(0x8D0E1DFBDF34B4E9)), ED25519_GWORD64(UINT64_C(0x298B8CE8AEF25FF3))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x837A72EA0A2165DE)), ED25519_GWORD64(UINT64_C(0x3FAB07B40BCF79F6)),
				ED25519_GWORD64(UINT64_C(0x521636C77738AE70)), ED25519_GWORD64(UINT64_C(0x6BA6271803A7D7DC))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2A927953EFF70CB2)), ED25519_GWORD64(UINT64_C(0x4B89C92A79157076)),
				ED25519_GWORD64(UINT64_C(0x9418457A30A7CF6A)), ED25519_GWORD64(UINT64_C(0x34B8A8404D5CE485))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC26EECB583693335)), ED25519_GWORD64(UINT64_C(0xD5A813DF63B5FEFD)),
				ED25519_GWORD64(UINT64_C(0xA293AA9AA4B22573)), ED25519_GWORD64(UINT64_C(0x71D62BDD465E1C6A))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xCD2DB5DAB1F75EF5)), ED25519_GWORD64(UINT64_C(0xD77F95CF16B065F5)),
				ED25519_GWORD64(UINT64_C(0x14571FEA3F49F085)), ED25519_GWORD64(UINT64_C(0x1C333621262B2B3D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6533CC28D378DF6D)), ED25519_GWORD64(UINT64_C(0xF6DB43790A0FA4B4)),
				ED25519_GWORD64(UINT64_C(0xE3645FF9F701DA5A)), ED25519_GWORD64(UINT64_C(0xF4D5F317F3172BA4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA86FE55467D9CA81)), ED25519_GWORD64(UINT64_C(0x398B7C752B298C37)),
				ED25519_GWORD64(UINT64_C(0xDA6D0892E3AC623B)), ED25519_GWORD64(UINT64_C(0x4AEBCC4547E9D98C))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x0B408D9E7354B5FD)), ED25519_GWORD64(UINT64_C(0x806B32535BA85B6E)),
				ED25519_GWORD64(UINT64_C(0xDBE63A034A58A207)), ED25519_GWORD64(UINT64_C(0x973BD9DDC9A1DF2C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x12F0071B276D01C9)), ED25519_GWORD64(UINT64_C(0xE7B8BAC586C48C70)),
				ED25519_GWORD64(UINT64_C(0x5308129B71D6FBA9)), ED25519_GWORD64(UINT64_C(0x5D88FBF95A3DB792))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2B500F1EFE5872DF)), ED25519_GWORD64(UINT64_C(0x58D6582ED43918C1)),
				ED25519_GWORD64(UINT64_C(0xE6ED278EC9673AE0)), ED25519_GWORD64(UINT64_C(0x06E1CD13B19EA319))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x472BAF629E5B0353)), ED25519_GWORD64(UINT64_C(0x3BAA0B90278D0447)),
				ED25519_GWORD64(UINT64_C(0x0C785F469643BF27)), ED25519_GWORD64(UINT64_C(0x7F3A6A1A8D837B13))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x40D0AD516F166F23)), ED25519_GWORD64(UINT64_C(0x118E32931FAB6ABE)),
				ED25519_GWORD64(UINT64_C(0x3FE35E14A04D088E)), ED25519_GWORD64(UINT64_C(0x3080603526E16266))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF7E644395D3D800B)), ED25519_GWORD64(UINT64_C(0x95A8D555C901EDF6)),
				ED25519_GWORD64(UINT64_C(0x68CD7830592C6339)), ED25519_GWORD64(UINT64_C(0x30D0FDED2E51307E))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9CB4971E68B8473D)), ED25519_GWORD64(UINT64_C(0xA09572296664BBCF)),
				ED25519_GWORD64(UINT64_C(0x5C8DE72672FA412B)), ED25519_GWORD64(UINT64_C(0xC615084351C589D9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE0594D1AF21233B3)), ED25519_GWORD64(UINT64_C(0x1BDBE78EF0CC4D9C)),
				ED25519_GWORD64(UINT64_C(0x6965187F8F499A77)), ED25519_GWORD64(UINT64_C(0x0A9214202C099868))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xBC9019C0AEB9A02E)), ED25519_GWORD64(UINT64_C(0x55C7110D16034CAE)),
				ED25519_GWORD64(UINT64_C(0x0E6DF501659932EC)), ED25519_GWORD64(UINT64_C(0x3BCA0D2895CA5DFE))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9C688EB69ECC01BF)), ED25519_GWORD64(UINT64_C(0xF0BC83ADA644896F)),
				ED25519_GWORD64(UINT64_C(0xCA2D955F5F7A9FE2)), ED25519_GWORD64(UINT64_C(0x4EA8B4038DF28241))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x40F031BC3C5D6291)), ED25519_GWORD64(UINT64_C(0x19FC8B3ECFF07A60)),
				ED25519_GWORD64(UINT64_C(0x98183DA2130FB545)), ED25519_GWORD64(UINT64_C(0xD631DEDDAE8F13CD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2AED460AF1CAD202)), ED25519_GWORD64(UINT64_C(0x46305305A48CEE83)),
				ED25519_GWORD64(UINT64_C(0x9121774549F11A5F)), ED25519_GWORD64(UINT64_C(0x24CE0930542CA463))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3FCFA155FDF30B85)), ED25519_GWORD64(UINT64_C(0xD2F7168E36372EA4)),
				ED25519_GWORD64(UINT64_C(0xB2E064DE6492F844)), ED25519_GWORD64(UINT64_C(0x549928A7324F4280))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1FE890F5FD06C0F3)), ED25519_GWORD64(UINT64_C(0xB5C468355D8810F2)),
				ED25519_GWORD64(UINT64_C(0x827808FE6E8CAF3E)), ED25519_GWORD64(UINT64_C(0xC1D4E3C28A06D74B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF26E32A763EE1A2E)), ED25519_GWORD64(UINT64_C(0xAE91E4B7D25FFDEA)),
				ED25519_GWORD64(UINT64_C(0xBC3BD33BD17F4D69)), ED25519_GWORD64(UINT64_C(0x491B66DEC0DCFF6A))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x75F04A8ED0DA64A1)), ED25519_GWORD64(UINT64_C(0xED222CAF67E2284B)),
				ED25519_GWORD64(UINT64_C(0x8234A3791F7B7BA4)), ED25519_GWORD64(UINT64_C(0x4CF6B8B0B7018B67))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x98F5B13DC7EA32A7)), ED25519_GWORD64(UINT64_C(0xE3D5F8CC7E16DB98)),
				ED25519_GWORD64(UINT64_C(0xAC0ABF52CBF8D947)), ED25519_GWORD64(UINT64_C(0x08F338D0C85EE4AC))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC383A821991A73BD)), ED25519_GWORD64(UINT64_C(0xAB27BC01DF320C7A)),
				ED25519_GWORD64(UINT64_C(0xC13D331B84777063)), ED25519_GWORD64(UINT64_C(0x530D4A82EB078A99))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6D6973456C9ABF8B)), ED25519_GWORD64(UINT64_C(0x257FB2FC4900A880)),
				ED25519_GWORD64(UINT64_C(0x2BACF412C8CFB850)), ED25519_GWORD64(UINT64_C(0x8DB3E7E00CBFBD5B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x004C3630E1F94825)), ED25519_GWORD64(UINT64_C(0x7E2D78268CAB535A)),
				ED25519_GWORD64(UINT64_C(0xC7482323CC84FF8B)), ED25519_GWORD64(UINT64_C(0x65EA753F101770B9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3D66FC3EE2096363)), ED25519_GWORD64(UINT64_C(0x81D62C7F61B5CB6B)),
				ED25519_GWORD64(UINT64_C(0x0FBE044213443B1A)), ED25519_GWORD64(UINT64_C(0x02A4EC1921E1A1DB))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xF5C86162F1CF794C)), ED25519_GWORD64(UINT64_C(0x118C861926EE57F2)),
				ED25519_GWORD64(UINT64_C(0x172124851C063578)), ED25519_GWORD64(UINT64_C(0xB6D12B5DEC067FCF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5CE6259A3B24B8A2)), ED25519_GWORD64(UINT64_C(0xB8577ACC45AFA0B8)),
				ED25519_GWORD64(UINT64_C(0xCCCBE6E88BA07037)), ED25519_GWORD64(UINT64_C(0x3D143C51127809BF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x126D279179154557)), ED25519_GWORD64(UINT64_C(0xD5E48F5CFC783A0A)),
				ED25519_GWORD64(UINT64_C(0x36BDB6E8DF179BAC)), ED25519_GWORD64(UINT64_C(0x2EF517885BA82859))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x96EEBFFB305B2F51)), ED25519_GWORD64(UINT64_C(0xD3F938AD889596B8)),
				ED25519_GWORD64(UINT64_C(0xF0F52DC746D5DD25)), ED25519_GWORD64(UINT64_C(0x57968290BB3A0095))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x4637974E8C58AEC9)), ED25519_GWORD64(UINT64_C(0xB9EF22FBABF041A4)),
				ED25519_GWORD64(UINT64_C(0xE185D956E980718A)), ED25519_GWORD64(UINT64_C(0xAF1B78FAB143A8A6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF71AB8430A20E101)), ED25519_GWORD64(UINT64_C(0xF393658D24F0EC47)),
				ED25519_GWORD64(UINT64_C(0xCF7509A86EE2EED1)), ED25519_GWORD64(UINT64_C(0x7DC43E35DC2AA3E1))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x5A782A5C273E9718)), ED25519_GWORD64(UINT64_C(0x3576C6995E4EFD94)),
				ED25519_GWORD64(UINT64_C(0x0F2ED8051F237D3E)), ED25519_GWORD64(UINT64_C(0x044FB81D82D50A99))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x85966665887DD9B0)), ED25519_GWORD64(UINT64_C(0xC90F9B314BB05355)),
				ED25519_GWORD64(UINT64_C(0xC6E08DF8EF2079B1)), ED25519_GWORD64(UINT64_C(0xFEF72016758CC12F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC1DF18C5A907E3D9)), ED25519_GWORD64(UINT64_C(0x57B3371DCE4C6359)),
				ED25519_GWORD64(UINT64_C(0xCA704534B201BB49)), ED25519_GWORD64(UINT64_C(0x7F79823F9C30DD2E))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6A9C1FF068F587BA)), ED25519_GWORD64(UINT64_C(0x0827894E0050C8DE)),
				ED25519_GWORD64(UINT64_C(0x3CBF99557DED5BE7)), ED25519_GWORD64(UINT64_C(0x64A9B0431C06D6F0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8334D239A3B513E8)), ED25519_GWORD64(UINT64_C(0xC13670D4B91FA8D8)),
				ED25519_GWORD64(UINT64_C(0x12B54136F590BD33)), ED25519_GWORD64(UINT64_C(0x0A4E0373D784D9B4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2EB3D6A15B7D2919)), ED25519_GWORD64(UINT64_C(0xB0B4F6A0D53A8235)),
				ED25519_GWORD64(UINT64_C(0x7156CE4389A45D47)), ED25519_GWORD64(UINT64_C(0x071A7D0ACE18346C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xCC0C355220E14431)), ED25519_GWORD64(UINT64_C(0x0D65950709B15141)),
				ED25519_GWORD64(UINT64_C(0x9AF5621B209D5F36)), ED25519_GWORD64(UINT64_C(0x7C69BCF7617755D3))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD3072DAAC887BA0B)), ED25519_GWORD64(UINT64_C(0x01262905BFA562EE)),
				ED25519_GWORD64(UINT64_C(0xCF543002C0EF768B)), ED25519_GWORD64(UINT64_C(0x2C3BCC7146EA7E9C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x07F0D7EB04E8295F)), ED25519_GWORD64(UINT64_C(0x10DB18252F50F37D)),
				ED25519_GWORD64(UINT64_C(0xE951A9A3171798D7)), ED25519_GWORD64(UINT64_C(0x6F5A9A7322ACA51D))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE729D4EBA3D944AB)), ED25519_GWORD64(UINT64_C(0x8D9E09408078AF9E)),
				ED25519_GWORD64(UINT64_C(0x4525567A47869C03)), ED25519_GWORD64(UINT64_C(0x82AB9680EE8D3B24))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8BA1000C2F41C6C5)), ED25519_GWORD64(UINT64_C(0xC49F79C10CFEFB9B)),
				ED25519_GWORD64(UINT64_C(0x4EFA47703CC51C9F)), ED25519_GWORD64(UINT64_C(0x494E21A2E147AFCA))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xEFA48A85DDE50D9A)), ED25519_GWORD64(UINT64_C(0x219A224E0FB9A249)),
				ED25519_GWORD64(UINT64_C(0xFA091F1DD91EF6D9)), ED25519_GWORD64(UINT64_C(0x6B5D76CBEA46BB34))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE0F941171E782522)), ED25519_GWORD64(UINT64_C(0xF1E6AE74036936D3)),
				ED25519_GWORD64(UINT64_C(0x408B3EA2D0FCC746)), ED25519_GWORD64(UINT64_C(0x16FB869C03DD313E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8857556CEC0CD994)), ED25519_GWORD64(UINT64_C(0x6472DC6F5CD01DBA)),
				ED25519_GWORD64(UINT64_C(0xAF0169148F42B477)), ED25519_GWORD64(UINT64_C(0x0AE333F685277354))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x288E199733B60962)), ED25519_GWORD64(UINT64_C(0x24FC72B4D8ABE133)),
				ED25519_GWORD64(UINT64_C(0x4811F7ED0991D03E)), ED25519_GWORD64(UINT64_C(0x3F81E38B8F70D075))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x0ADB7F355F17C811)), ED25519_GWORD64(UINT64_C(0x74B923C3D74299A4)),
				ED25519_GWORD64(UINT64_C(0xD57C3E8BCBF8EAF7)), ED25519_GWORD64(UINT64_C(0x8AD3E2D34CDEDC3D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7F910FCC7ED9AFEB)), ED25519_GWORD64(UINT64_C(0x545CB8A12465874B)),
				ED25519_GWORD64(UINT64_C(0xA8397ED24B0C4704)), ED25519_GWORD64(UINT64_C(0xD0510FC104F50993))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6F0C0FC5336E249D)), ED25519_GWORD64(UINT64_C(0x745EDE19C331CFD9)),
				ED25519_GWORD64(UINT64_C(0xF2D6FD0009EEFE1C)), ED25519_GWORD64(UINT64_C(0x127C158BF0FA1EBE))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xDEA28FC4AE51B974)), ED25519_GWORD64(UINT64_C(0x1D9973D3744DFE96)),
				ED25519_GWORD64(UINT64_C(0x6240680B873848A8)), ED25519_GWORD64(UINT64_C(0x4ED82479D167DF95))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF6197C422E9879A2)), ED25519_GWORD64(UINT64_C(0xA44ADDD452CA3647)),
				ED25519_GWORD64(UINT64_C(0x9B413FC14B4EACCB)), ED25519_GWORD64(UINT64_C(0x354EF87D07EF4F68))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xFEE3B52260C5D975)), ED25519_GWORD64(UINT64_C(0x50352EFCEB41B0B8)),
				ED25519_GWORD64(UINT64_C(0x8808AC30A9F6653C)), ED25519_GWORD64(UINT64_C(0x302D92D20539236D))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2DBC6FB6E4E0F164)), ED25519_GWORD64(UINT64_C(0x04E1BF29A4BD6A93)),
				ED25519_GWORD64(UINT64_C(0x5E1966D4787AF6E8)), ED25519_GWORD64(UINT64_C(0x8EDC5F5EB426D060))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7813C1A2BCA4282A)), ED25519_GWORD64(UINT64_C(0xED62F091A1863DD9)),
				ED25519_GWORD64(UINT64_C(0xAEC7BCB8C268FA86)), ED25519_GWORD64(UINT64_C(0x90E5D3B76F1CAE4C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5453BFD653DA8E67)), ED25519_GWORD64(UINT64_C(0xE9DC1EEC24A9F641)),
				ED25519_GWORD64(UINT64_C(0xBF87263B03578A23)), ED25519_GWORD64(UINT64_C(0x45B46C51361CBA72))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xCE9D4DDD8A7FE3D1)), ED25519_GWORD64(UINT64_C(0xAB13645676620E30)),
				ED25519_GWORD64(UINT64_C(0x4B594F7BB30E9958)), ED25519_GWORD64(UINT64_C(0xDC1C0AEF321229DF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA9402ABF314F7FA1)), ED25519_GWORD64(UINT64_C(0xE257F1DC8E8CF450)),
				ED25519_GWORD64(UINT64_C(0x1DBBD54B23A8BE84)), ED25519_GWORD64(UINT64_C(0x2177BFA36DCB713B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x37081BBCFA79DB8F)), ED25519_GWORD64(UINT64_C(0x6048811EC25F59B3)),
				ED25519_GWORD64(UINT64_C(0x087A76659C832487)), ED25519_GWORD64(UINT64_C(0x4AE619387D8AB5BB))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x61117E44985BFB83)), ED25519_GWORD64(UINT64_C(0xFCE0462A71963136)),
				ED25519_GWORD64(UINT64_C(0x83AC3448D425904B)), ED25519_GWORD64(UINT64_C(0x75685ABE5BA43D64))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8DDBF6AA5344A31B)), ED25519_GWORD64(UINT64_C(0x7D88EAB4B41B4078)),
				ED25519_GWORD64(UINT64_C(0x5EB0EB974A130D60)), ED25519_GWORD64(UINT64_C(0x9A00D91B17BF3E03))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6E960933EB61F2B2)), ED25519_GWORD64(UINT64_C(0x543D0FA8C9FF4952)),
				ED25519_GWORD64(UINT64_C(0xDF7275107AF66569)), ED25519_GWORD64(UINT64_C(0x135529B623B0E6AA))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xF5C716BCE22E83EB)), ED25519_GWORD64(UINT64_C(0xB42BEB19E80985C1)),
				ED25519_GWORD64(UINT64_C(0xEC9DA63714254AAE)), ED25519_GWORD64(UINT64_C(0xD972EA051590A613))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x18F0DBD7ADD1D505)), ED25519_GWORD64(UINT64_C(0x979F7888CFC11F11)),
				ED25519_GWORD64(UINT64_C(0x8732E1F07114759B)), ED25519_GWORD64(UINT64_C(0xF9B5B81A65CA3A01))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0FD4AC20DC8F7811)), ED25519_GWORD64(UINT64_C(0x9A9AD294AC4D4FA8)),
				ED25519_GWORD64(UINT64_C(0xC01B2D64B3360434)), ED25519_GWORD64(UINT64_C(0x4F7E9C95905F3BDB))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x71C8443D355299EB)), ED25519_GWORD64(UINT64_C(0x8BCD3B1CDBEBEAD7)),
				ED25519_GWORD64(UINT64_C(0x8092499EF1A49466)), ED25519_GWORD64(UINT64_C(0x9942EEC4A144ADC8))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x62674BBC5781301B)), ED25519_GWORD64(UINT64_C(0xD8520F3989ADDC0F)),
				ED25519_GWORD64(UINT64_C(0x8C2999AE53FBD9C6)), ED25519_GWORD64(UINT64_C(0xB1993AD92E638E4C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7DAC5319AE234992)), ED25519_GWORD64(UINT64_C(0x2C1B3D910CEA3E92)),
				ED25519_GWORD64(UINT64_C(0x553CE494253C1122)), ED25519_GWORD64(UINT64_C(0x2A0A65314EF9CA75))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xCF361ACD3C1C7927)), ED25519_GWORD64(UINT64_C(0x2F9EBCAC5A35BC3B)),
				ED25519_GWORD64(UINT64_C(0x60E860E9A8CDA6AB)), ED25519_GWORD64(UINT64_C(0x855DC39B6DEA1A13))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2DB7937FF7F927AF)), ED25519_GWORD64(UINT64_C(0xDB741F0617D0A635)),
				ED25519_GWORD64(UINT64_C(0x5982F3A21155AF76)), ED25519_GWORD64(UINT64_C(0xCCF6E218647C2DED))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB119227CC28D5BB6)), ED25519_GWORD64(UINT64_C(0x07E24EBC774DFFAB)),
				ED25519_GWORD64(UINT64_C(0xA83C78CEE4A32C89)), ED25519_GWORD64(UINT64_C(0x121A307710AA24B6))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD659713EC77483C9)), ED25519_GWORD64(UINT64_C(0x88BFE077B82B96AF)),
				ED25519_GWORD64(UINT64_C(0x289E28231097BCD3)), ED25519_GWORD64(UINT64_C(0x527BB94A6CED3A9B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE4DB5D5E9F034A97)), ED25519_GWORD64(UINT64_C(0xE153FC093034BC2D)),
				ED25519_GWORD64(UINT64_C(0x460546919551D3B1)), ED25519_GWORD64(UINT64_C(0x333FC76C7A40E52D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x563D992A995B482E)), ED25519_GWORD64(UINT64_C(0x3405D07C6E383801)),
				ED25519_GWORD64(UINT64_C(0x485035DE2F64D8E5)), ED25519_GWORD64(UINT64_C(0x6B89069B20A7A9F7))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x4082FA8CB5C7DB64)), ED25519_GWORD64(UINT64_C(0x068686F8C734C155)),
				ED25519_GWORD64(UINT64_C(0x29E6C8D9F6E7A57E)), ED25519_GWORD64(UINT64_C(0x8473D308A7639BCF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x812AA041627021FA)), ED25519_GWORD64(UINT64_C(0x995A89FAF9245B4E)),
				ED25519_GWORD64(UINT64_C(0xFFADC4CE5072EF05)), ED25519_GWORD64(UINT64_C(0xA3BC2103AA73EB73))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xCAEE792603589E05)), ED25519_GWORD64(UINT64_C(0x2B4B421246DCC492)),
				ED25519_GWORD64(UINT64_C(0x02A1EF74E601A94F)), ED25519_GWORD64(UINT64_C(0x102F73BFDE04341A))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA2B4DAE0B5511C9A)), ED25519_GWORD64(UINT64_C(0x7AC860292BFFFF06)),
				ED25519_GWORD64(UINT64_C(0x981F375DF5504234)), ED25519_GWORD64(UINT64_C(0x3F6BD725DA4EA12D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xEB18B9AB7F5745C6)), ED25519_GWORD64(UINT64_C(0x023A8AEE5787C690)),
				ED25519_GWORD64(UINT64_C(0xB72712DA2DF7AFA9)), ED25519_GWORD64(UINT64_C(0x36597D25EA5C013D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x734D8D7B106058AC)), ED25519_GWORD64(UINT64_C(0xD940579E6FC6905F)),
				ED25519_GWORD64(UINT64_C(0x6466F8F99202932D)), ED25519_GWORD64(UINT64_C(0x7B7ECC19DA60D6D0))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6DAE4A51A77CFA88)), ED25519_GWORD64(UINT64_C(0x82263654E7A38650)),
				ED25519_GWORD64(UINT64_C(0x09BBFFCD8F2D82DB)), ED25519_GWORD64(UINT64_C(0x83BEDC661BF5CABA))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x78C2373C695C68FA)), ED25519_GWORD64(UINT64_C(0xDD252E660642906E)),
				ED25519_GWORD64(UINT64_C(0x951D44444AE12BD2)), ED25519_GWORD64(UINT64_C(0xC235AD7601743956))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6258CB0D078975F5)), ED25519_GWORD64(UINT64_C(0x492942549189F298)),
				ED25519_GWORD64(UINT64_C(0xA0CAB423E2E36EE4)), ED25519_GWORD64(UINT64_C(0x0E7CE2B0CDF066A1))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xFEA6FEDFD94B70E6)), ED25519_GWORD64(UINT64_C(0xF130C051C1FCBA2D)),
				ED25519_GWORD64(UINT64_C(0x4882D47E7F2FAB89)), ED25519_GWORD64(UINT64_C(0xE15256138AECEEB5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC494643AC48C8590)), ED25519_GWORD64(UINT64_C(0xFD361DF43C6139AD)),
				ED25519_GWORD64(UINT64_C(0x09DB17DD3AE94D48)), ED25519_GWORD64(UINT64_C(0xE66E0A5D8FB4674A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2ABBF64E4870CB0D)), ED25519_GWORD64(UINT64_C(0xCD65BCF0AA458B6B)),
				ED25519_GWORD64(UINT64_C(0x9ABE4EBA75E8985D)), ED25519_GWORD64(UINT64_C(0x7F0BC810D514DEE4))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x83AC9DAD7372138D)), ED25519_GWORD64(UINT64_C(0x9FF6F8BA2EF72E98)),
				ED25519_GWORD64(UINT64_C(0x311E2EDD43EC6957)), ED25519_GWORD64(UINT64_C(0x9D3A907DDEC5AB75))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB9006BA426F4136F)), ED25519_GWORD64(UINT64_C(0x8D67369E57E03035)),
				ED25519_GWORD64(UINT64_C(0xCBC8DFD94F463C28)), ED25519_GWORD64(UINT64_C(0x0D1F8DBCF8EEDBF5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xBA1693313ED081DC)), ED25519_GWORD64(UINT64_C(0x29329FAD851B3480)),
				ED25519_GWORD64(UINT64_C(0x0128013C030321CB)), ED25519_GWORD64(UINT64_C(0x00011B44A31BFDE3))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x16561F696A0AA75C)), ED25519_GWORD64(UINT64_C(0xC1BF725C5852BD6A)),
				ED25519_GWORD64(UINT64_C(0x11A8DD7F9A7966AD)), ED25519_GWORD64(UINT64_C(0x63D988A2D2851026))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3FDFA06C3FC66C0C)), ED25519_GWORD64(UINT64_C(0x5D40E38E4DD60DD2)),
				ED25519_GWORD64(UINT64_C(0x7AE38B38268E4D71)), ED25519_GWORD64(UINT64_C(0x3AC48D916E8357E1))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x00120753AFBD232E)), ED25519_GWORD64(UINT64_C(0xE92BCEB8FDD8F683)),
				ED25519_GWORD64(UINT64_C(0xF81669B384E72B91)), ED25519_GWORD64(UINT64_C(0x33FAD52B2368A066))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x8D2CC8D0C422CFE8)), ED25519_GWORD64(UINT64_C(0x072B4F7B05A13ACB)),
				ED25519_GWORD64(UINT64_C(0xA3FEB6E6ECF6A56F)), ED25519_GWORD64(UINT64_C(0x3CC355CCB90A71E2))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x540649C6C5E41E16)), ED25519_GWORD64(UINT64_C(0x0AF86430333F7735)),
				ED25519_GWORD64(UINT64_C(0xB2ACFCD2F305E746)), ED25519_GWORD64(UINT64_C(0x16C0F429A256DCA7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE9B69443903E9131)), ED25519_GWORD64(UINT64_C(0xB8A494CB7A5637CE)),
				ED25519_GWORD64(UINT64_C(0xC87CD1A4BABA9244)), ED25519_GWORD64(UINT64_C(0x631EAF426BAE7568))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x47D975B9A3700DE8)), ED25519_GWORD64(UINT64_C(0x7280C5FBE2F80552)),
				ED25519_GWORD64(UINT64_C(0x53658F2732E45DE1)), ED25519_GWORD64(UINT64_C(0x431F2C7F665F80B5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB3E90410DA66FE8C)), ED25519_GWORD64(UINT64_C(0x85DD4B526C16E5A6)),
				ED25519_GWORD64(UINT64_C(0xBC3D97611EF9BF83)), ED25519_GWORD64(UINT64_C(0xD599648B1EA919B5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD6026344858F7B19)), ED25519_GWORD64(UINT64_C(0x14AB352FA1EA514A)),
				ED25519_GWORD64(UINT64_C(0x8900441A2090A9D7)), ED25519_GWORD64(UINT64_C(0x7B04715F91253B26))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xB376C280C4E6BAC6)), ED25519_GWORD64(UINT64_C(0x970ED3DD6D1D9B0B)),
				ED25519_GWORD64(UINT64_C(0xB09A9558450BF944)), ED25519_GWORD64(UINT64_C(0x48D0ACFA57CDE223))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x83EDBD28ACF6AE30)), ED25519_GWORD64(UINT64_C(0x86357C8B7D5C7AB4)),
				ED25519_GWORD64(UINT64_C(0xC0404769B7EB2C44)), ED25519_GWORD64(UINT64_C(0xD9B37BF5C2F6583F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB60F26E47DABE671)), ED25519_GWORD64(UINT64_C(0xF1D1A197622F3A37)),
				ED25519_GWORD64(UINT64_C(0x4208CE7EE9960394)), ED25519_GWORD64(UINT64_C(0x16234191336D3BDB))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xDD499CD61FF38640)), ED25519_GWORD64(UINT64_C(0x29CD9BC3063625A0)),
				ED25519_GWORD64(UINT64_C(0x51E2D8023DD73DC3)), ED25519_GWORD64(UINT64_C(0x4A25707A203B9231))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB9E499DEF6267FF6)), ED25519_GWORD64(UINT64_C(0x7772CA7B742C0843)),
				ED25519_GWORD64(UINT64_C(0x23A0153FE9A4F2B1)), ED25519_GWORD64(UINT64_C(0x2CDFDFECD5D05006))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2AB7668A53F6ED6A)), ED25519_GWORD64(UINT64_C(0x304242581DD170A1)),
				ED25519_GWORD64(UINT64_C(0x4000144C3AE20161)), ED25519_GWORD64(UINT64_C(0x5721896D248E49FC))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x285D5091A1D0DA3B)), ED25519_GWORD64(UINT64_C(0x4BAA6FA7B5FE3E08)),
				ED25519_GWORD64(UINT64_C(0x63E5177CE19393B3)), ED25519_GWORD64(UINT64_C(0x83C935AFC4B030FD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0B6E5517FD181B9B)), ED25519_GWORD64(UINT64_C(0x9022629F2BB963B4)),
				ED25519_GWORD64(UINT64_C(0x5509BCE932064625)), ED25519_GWORD64(UINT64_C(0xD78EDD74F63C13DA))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x997276C6492B0C3D)), ED25519_GWORD64(UINT64_C(0x47CCC2C4DFE205FC)),
				ED25519_GWORD64(UINT64_C(0xDCD29B84DD623A3C)), ED25519_GWORD64(UINT64_C(0x3EC2AB590288C7A2))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA7213A09AE32D1B8)), ED25519_GWORD64(UINT64_C(0x0F2B87DF40F5C2D5)),
				ED25519_GWORD64(UINT64_C(0x0BAEA4C6E81EAB29)), ED25519_GWORD64(UINT64_C(0x8E1BF66C6ADBAC5E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA1A0D27BE4D87BA6)), ED25519_GWORD64(UINT64_C(0xA98B4DEB61391AED)),
				ED25519_GWORD64(UINT64_C(0x99A0DDD073CB9B83)), ED25519_GWORD64(UINT64_C(0xADD5C25A200FCACE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE2ABD5E9792C887E)), ED25519_GWORD64(UINT64_C(0x1A020018CB926D5D)),
				ED25519_GWORD64(UINT64_C(0xBFBA69CDBAAE5F1E)), ED25519_GWORD64(UINT64_C(0x730548B35AE88F5F))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x805B094BA1D6E334)), ED25519_GWORD64(UINT64_C(0xBF3EF17709353F19)),
				ED25519_GWORD64(UINT64_C(0x423F06CB0622702B)), ED25519_GWORD64(UINT64_C(0x585A2277D87845DD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC43551A3CBA8B8EE)), ED25519_GWORD64(UINT64_C(0x65A26F1DB2115F16)),
				ED25519_GWORD64(UINT64_C(0x760F4F52AB8C3850)), ED25519_GWORD64(UINT64_C(0x3043443B411DB8CA))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA18A5F8233D48962)), ED25519_GWORD64(UINT64_C(0x6698C4B5EC78257F)),
				ED25519_GWORD64(UINT64_C(0xA78E6FA5373E41FF)), ED25519_GWORD64(UINT64_C(0x7656278950EF981F))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE17073A3EA86CF8A)), ED25519_GWORD64(UINT64_C(0x3A8CFBB707155FDC)),
				ED25519_GWORD64(UINT64_C(0x4853E7FC31838A8E)), ED25519_GWORD64(UINT64_C(0xA8BBF484B613F616))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x38C3CF59D51FC8C0)), ED25519_GWORD64(UINT64_C(0x9BEDD2FD0506B6F2)),
				ED25519_GWORD64(UINT64_C(0x26BF109FAB570E8F)), ED25519_GWORD64(UINT64_C(0x3F4160A8C1B846A6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF2612F5C6F136C7C)), ED25519_GWORD64(UINT64_C(0xAFEAD107F6DD11BE)),
				ED25519_GWORD64(UINT64_C(0x527E9AD213DE6F33)), ED25519_GWORD64(UINT64_C(0x1E79CB358188F75D))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x77E953D8F5E0816E)), ED25519_GWORD64(UINT64_C(0x84A50C44299DDED9)),
				ED25519_GWORD64(UINT64_C(0xDC6C2D0C864525E5)), ED25519_GWORD64(UINT64_C(0xC78AB52D39D1F2F4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x013436C3EEF7E3DE)), ED25519_GWORD64(UINT64_C(0x828B6A7FFE9E10F8)),
				ED25519_GWORD64(UINT64_C(0x7FF908E5BCF9DEFC)), ED25519_GWORD64(UINT64_C(0xE5D7951B3A3B3831))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x66A6A4D39252D159)), ED25519_GWORD64(UINT64_C(0xE5DDE1BC871AC807)),
				ED25519_GWORD64(UINT64_C(0xB82C6B40A6C1C96F)), ED25519_GWORD64(UINT64_C(0x16D87A411A212214))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xFBA4D5E2D54E0570)), ED25519_GWORD64(UINT64_C(0xE21FAFD72EBD99FA)),
				ED25519_GWORD64(UINT64_C(0x497AC2736EE9778F)), ED25519_GWORD64(UINT64_C(0x9F990B577A5A6DDE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB3BD7E5A42066202)), ED25519_GWORD64(UINT64_C(0x879BE3CD0C5A24C1)),
				ED25519_GWORD64(UINT64_C(0x57C05DB1D6F994B7)), ED25519_GWORD64(UINT64_C(0xA8F87C8165F38CA6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA3344EAD1BE8F7D6)), ED25519_GWORD64(UINT64_C(0x7D1E50EBACEA798F)),
				ED25519_GWORD64(UINT64_C(0x77C6569E520DE052)), ED25519_GWORD64(UINT64_C(0x45882FE1534D6D3E))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD8AC9929943C6FE4)), ED25519_GWORD64(UINT64_C(0xB5F9F161A38392A2)),
				ED25519_GWORD64(UINT64_C(0x2699DB13BEC89AF3)), ED25519_GWORD64(UINT64_C(0x7DCF843CE405F074))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6669345D757983D6)), ED25519_GWORD64(UINT64_C(0x62B6ED1117AA11A6)),
				ED25519_GWORD64(UINT64_C(0x7DDD1857985E128F)), ED25519_GWORD64(UINT64_C(0x688FE5B8F626F6DD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6C90D6484A4732C0)), ED25519_GWORD64(UINT64_C(0xD52143FDCA563299)),
				ED25519_GWORD64(UINT64_C(0xB3BE28C3915DC6E1)), ED25519_GWORD64(UINT64_C(0x6739687E7327191B))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA66DCC9DC80C1AC0)), ED25519_GWORD64(UINT64_C(0x97A05CF41B38A436)),
				ED25519_GWORD64(UINT64_C(0xA7EBF3BE95DBD7C6)), ED25519_GWORD64(UINT64_C(0x7DA0B8F68D7E7DAB))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xEF782014385675A6)), ED25519_GWORD64(UINT64_C(0xA2649F30AAFDA9E8)),
				ED25519_GWORD64(UINT64_C(0x4CD1EB505CDFA8CB)), ED25519_GWORD64(UINT64_C(0x46115ABA1D4DC0B3))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD40F1953C3B5DA76)), ED25519_GWORD64(UINT64_C(0x1DAC6F7321119E9B)),
				ED25519_GWORD64(UINT64_C(0x03CC6021FEB25960)), ED25519_GWORD64(UINT64_C(0x5A5F887E83674B4B))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9E9628D3A0A643B9)), ED25519_GWORD64(UINT64_C(0xB5C3CB00E6C32064)),
				ED25519_GWORD64(UINT64_C(0x9B5302897C2DEC32)), ED25519_GWORD64(UINT64_C(0x43E37AE2D5D1C70C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x8F6301CF70A13D11)), ED25519_GWORD64(UINT64_C(0xCFCEB815350DD0C4)),
				ED25519_GWORD64(UINT64_C(0xF70297D4A4BCA47E)), ED25519_GWORD64(UINT64_C(0x3669B656E44D1434))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x387E3F06EDA6E133)), ED25519_GWORD64(UINT64_C(0x67301D5199A13AC0)),
				ED25519_GWORD64(UINT64_C(0xBD5AD8F836263811)), ED25519_GWORD64(UINT64_C(0x6A21E6CD4FD5E9BE))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xEF4129126699B2D0)), ED25519_GWORD64(UINT64_C(0x71D30847708D1301)),
				ED25519_GWORD64(UINT64_C(0x325432D01182B0BD)), ED25519_GWORD64(UINT64_C(0xC5371B07001E8B36))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF1C6170A3046E64C)), ED25519_GWORD64(UINT64_C(0x58712A2A00D23524)),
				ED25519_GWORD64(UINT64_C(0x69DBBD3C8C82B755)), ED25519_GWORD64(UINT64_C(0xD86BF9F1A195FF57))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA6DB088D5EF8790B)), ED25519_GWORD64(UINT64_C(0x5278F0DC610937E5)),
				ED25519_GWORD64(UINT64_C(0xAC0349D261A16EB8)), ED25519_GWORD64(UINT64_C(0x0EAFB03790E52179))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x5140805E0F75AE1D)), ED25519_GWORD64(UINT64_C(0xEC02FBE32662CC30)),
				ED25519_GWORD64(UINT64_C(0x2CEBDF1EEA92396D)), ED25519_GWORD64(UINT64_C(0x44AE3344C5435BB3))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x960555C13748042F)), ED25519_GWORD64(UINT64_C(0x219A41E6820BAA11)),
				ED25519_GWORD64(UINT64_C(0x1C81F73873486D0C)), ED25519_GWORD64(UINT64_C(0x309ACC675A02C661))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9CF289B9BBA543EE)), ED25519_GWORD64(UINT64_C(0xF3760E9D5AC97142)),
				ED25519_GWORD64(UINT64_C(0x1D82E5C64F9360AA)), ED25519_GWORD64(UINT64_C(0x62D5221B7F94678F))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x7585D4263AF77A29)), ED25519_GWORD64(UINT64_C(0xDFAE7B11FEE9144D)),
				ED25519_GWORD64(UINT64_C(0xA506708059F7193D)), ED25519_GWORD64(UINT64_C(0x94F29A5383922037))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x524C299C18D0936D)), ED25519_GWORD64(UINT64_C(0xC86BB56C8A0C1A0C)),
				ED25519_GWORD64(UINT64_C(0xA375052EDB4A8631)), ED25519_GWORD64(UINT64_C(0x5C0EFDE4BC754562))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDF717EDC25B2D7F5)), ED25519_GWORD64(UINT64_C(0x21F970DB99B53040)),
				ED25519_GWORD64(UINT64_C(0xDA9234B7C3ED4C62)), ED25519_GWORD64(UINT64_C(0x5E72365C7BEE093E))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x7D9339062F08B33E)), ED25519_GWORD64(UINT64_C(0x5B9659E5DF9F32BE)),
				ED25519_GWORD64(UINT64_C(0xACFF3DAD1F9EBDFD)), ED25519_GWORD64(UINT64_C(0x70B20555CB7349B7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x575BFC074571216C)), ED25519_GWORD64(UINT64_C(0x3779675D0694D95B)),
				ED25519_GWORD64(UINT64_C(0x9A0A37BBF4191E33)), ED25519_GWORD64(UINT64_C(0xF7F1104C47B4EABC))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xBE5113C555112C4C)), ED25519_GWORD64(UINT64_C(0x6688423A9A881FCD)),
				ED25519_GWORD64(UINT64_C(0x446677855E503B47)), ED25519_GWORD64(UINT64_C(0x0E34398F4A06404A))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x18930B093E4B1928)), ED25519_GWORD64(UINT64_C(0x7DE3E10E73F3F640)),
				ED25519_GWORD64(UINT64_C(0xF43217DA73395D6F)), ED25519_GWORD64(UINT64_C(0x6F8ADED6CA379C3E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB67D22D93ECEBDE8)), ED25519_GWORD64(UINT64_C(0x09B3E84127822F07)),
				ED25519_GWORD64(UINT64_C(0x743FA61FB05B6D8D)), ED25519_GWORD64(UINT64_C(0x5E5405368A362372))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE340123DFDB7B29A)), ED25519_GWORD64(UINT64_C(0x487B97E1A21AB291)),
				ED25519_GWORD64(UINT64_C(0xF9967D02FDE6949E)), ED25519_GWORD64(UINT64_C(0x780DE72EC8D3DE97))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x671FEAF300F42772)), ED25519_GWORD64(UINT64_C(0x8F72EB2A2A8C41AA)),
				ED25519_GWORD64(UINT64_C(0x29A17FD797373292)), ED25519_GWORD64(UINT64_C(0x1DEFC6AD32B587A6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0AE28545089AE7BC)), ED25519_GWORD64(UINT64_C(0x388DDECF1C7F4D06)),
				ED25519_GWORD64(UINT64_C(0x38AC15510A4811B8)), ED25519_GWORD64(UINT64_C(0x0EB28BF671928CE4))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xAF5BBE1AEF5195A7)), ED25519_GWORD64(UINT64_C(0x148C1277917B15ED)),
				ED25519_GWORD64(UINT64_C(0x2991F7FB7AE5DA2E)), ED25519_GWORD64(UINT64_C(0x467D201BF8DD2867))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xBC1EF4BD567AE796)), ED25519_GWORD64(UINT64_C(0x3F624CB2D64498BD)),
				ED25519_GWORD64(UINT64_C(0xE41064D22C1F4EC8)), ED25519_GWORD64(UINT64_C(0xAEF9C5A5BA384001))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x95FE919A74EF4F9A)), ED25519_GWORD64(UINT64_C(0x3A827BECF6A308A2)),
				ED25519_GWORD64(UINT64_C(0x964E01D309A47B01)), ED25519_GWORD64(UINT64_C(0xF1C43C4F5BA3C797))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB6FD6DF6FA9E74CD)), ED25519_GWORD64(UINT64_C(0xF18278BCE4AF267A)),
				ED25519_GWORD64(UINT64_C(0x8255B3D0F1EF990E)), ED25519_GWORD64(UINT64_C(0x5A758CA390C5F293))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x8CE0918B1D61DC81)), ED25519_GWORD64(UINT64_C(0x8DED36469A813066)),
				ED25519_GWORD64(UINT64_C(0xD4E6A829AFE8AAD3)), ED25519_GWORD64(UINT64_C(0x8A738027F639D43F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA2B72710D9462495)), ED25519_GWORD64(UINT64_C(0x3AA8C6D2D57D5003)),
				ED25519_GWORD64(UINT64_C(0xE3D400BFA0B487CA)), ED25519_GWORD64(UINT64_C(0x2DBAE244B3EB72EC))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x980F4A2F57FFE1CC)), ED25519_GWORD64(UINT64_C(0x00670D0DE1839843)),
				ED25519_GWORD64(UINT64_C(0x105C3F4A49FB15FD)), ED25519_GWORD64(UINT64_C(0x2698CA635126A69C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2E3D702F5E3DD90E)), ED25519_GWORD64(UINT64_C(0x9E3F0918E4D25386)),
				ED25519_GWORD64(UINT64_C(0x5E773EF6024DA96A)), ED25519_GWORD64(UINT64_C(0x3C004B0C4AFA3332))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE765318832B0BA78)), ED25519_GWORD64(UINT64_C(0x381831F7925CFF8B)),
				ED25519_GWORD64(UINT64_C(0x08A81B91A0291FCC)), ED25519_GWORD64(UINT64_C(0x1FB43DCC49CAEB07))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9AA946AC06F4B82B)), ED25519_GWORD64(UINT64_C(0x1CA284A5A806C4F3)),
				ED25519_GWORD64(UINT64_C(0x3ED3265FC6CD4787)), ED25519_GWORD64(UINT64_C(0x6B43FD01CD1FD217))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xB5C742583E760EF3)), ED25519_GWORD64(UINT64_C(0x75DC52B9EE0AB990)),
				ED25519_GWORD64(UINT64_C(0xBF1427C2072B923F)), ED25519_GWORD64(UINT64_C(0x73420B2D6FF0D9F0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC7A75D4B4697C531)), ED25519_GWORD64(UINT64_C(0x15FDF848DF0FFFBF)),
				ED25519_GWORD64(UINT64_C(0x2868B9EBAA46785A)), ED25519_GWORD64(UINT64_C(0xDA68D7105B52F714))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xAF2CF6CB9E851E06)), ED25519_GWORD64(UINT64_C(0x8F593913C62238C4)),
				ED25519_GWORD64(UINT64_C(0xDA8AB89699FBF373)), ED25519_GWORD64(UINT64_C(0x3DB5632FEA34BC9E))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2E4990B1829825C2)), ED25519_GWORD64(UINT64_C(0xEDEAEB873E9A8991)),
				ED25519_GWORD64(UINT64_C(0xEEF03D394C704AF8)), ED25519_GWORD64(UINT64_C(0xD9197EA495DF2B0E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF46EEE2BF75DD9D8)), ED25519_GWORD64(UINT64_C(0x0D17B1F6396759A5)),
				ED25519_GWORD64(UINT64_C(0x1BF2D131499E7273)), ED25519_GWORD64(UINT64_C(0x04321ADF49D75F13))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x04E16019E4E55AAE)), ED25519_GWORD64(UINT64_C(0xE77B437A7E2F92E9)),
				ED25519_GWORD64(UINT64_C(0xC7CE2DC16F159AA4)), ED25519_GWORD64(UINT64_C(0x45EAFDC1F4D70CC0))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xB60E4624CFCCB1DA)), ED25519_GWORD64(UINT64_C(0x59DBC292BD5C0395)),
				ED25519_GWORD64(UINT64_C(0x31A09D1DDC0481C9)), ED25519_GWORD64(UINT64_C(0xBF73CEEA5D56D940))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x698401858045D718)), ED25519_GWORD64(UINT64_C(0x4C22FAA2CF2F0651)),
				ED25519_GWORD64(UINT64_C(0x941A36656B222DC6)), ED25519_GWORD64(UINT64_C(0xDA5EEBC80362DADE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB7A7BFD10A4E8DC6)), ED25519_GWORD64(UINT64_C(0xBE57007E44C9B339)),
				ED25519_GWORD64(UINT64_C(0x60C1207F1557AEFA)), ED25519_GWORD64(UINT64_C(0x26058891266218DB))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x4C818E3CC676E52F)), ED25519_GWORD64(UINT64_C(0x5E422C9303CECCAD)),
				ED25519_GWORD64(UINT64_C(0xEC07CCCAB4129F08)), ED25519_GWORD64(UINT64_C(0x8DEDFA10B24443B8))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x59F704A68360FEF1)), ED25519_GWORD64(UINT64_C(0xC3D93FDE7661E6F4)),
				ED25519_GWORD64(UINT64_C(0x831B2A7312873551)), ED25519_GWORD64(UINT64_C(0xD4AD0C2E4E615D57))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xEE3B67D5B82B522A)), ED25519_GWORD64(UINT64_C(0x36F163469FA5C1EB)),
				ED25519_GWORD64(UINT64_C(0xA5B4D2F26EC19FD3)), ED25519_GWORD64(UINT64_C(0x62ECB2BAA77A9408))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x92072836AFB62874)), ED25519_GWORD64(UINT64_C(0x5FCD5E8579E104A5)),
				ED25519_GWORD64(UINT64_C(0x5AAD01ADC630A14A)), ED25519_GWORD64(UINT64_C(0x61913D5075663F98))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE5ED795261152B2A)), ED25519_GWORD64(UINT64_C(0x4962357D0EDDD7D1)),
				ED25519_GWORD64(UINT64_C(0x7482C8D0B96B4C71)), ED25519_GWORD64(UINT64_C(0xAE59F919A966D8BE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0DC62D361A3231DA)), ED25519_GWORD64(UINT64_C(0xFA47583294200270)),
				ED25519_GWORD64(UINT64_C(0x02D801513F9594CE)), ED25519_GWORD64(UINT64_C(0x3DDBC2A131C05D5C))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xF3AA57A22796BB14)), ED25519_GWORD64(UINT64_C(0x883ABAB79B07DA21)),
				ED25519_GWORD64(UINT64_C(0xE54BE21831A0391C)), ED25519_GWORD64(UINT64_C(0x5EE7FB38D83205F9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9ADC0FF9CE5EC538)), ED25519_GWORD64(UINT64_C(0x039C2A6B8C2F130D)),
				ED25519_GWORD64(UINT64_C(0x028007C7F0F89515)), ED25519_GWORD64(UINT64_C(0xF8968314AC04B36B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x538DFDCB41446A8E)), ED25519_GWORD64(UINT64_C(0xA5ACFDA9434937F9)),
				ED25519_GWORD64(UINT64_C(0x46AF908D263C8C78)), ED25519_GWORD64(UINT64_C(0x61D0633C9BCA0D09))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xADA328BCF8FC73DF)), ED25519_GWORD64(UINT64_C(0xEE84695DA6F037FC)),
				ED25519_GWORD64(UINT64_C(0x637FB4DB38C2A909)), ED25519_GWORD64(UINT64_C(0x5B23AC2DF8067BDC))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x63744935FFDB2553)), ED25519_GWORD64(UINT64_C(0xC5BD6B89780B68BB)),
				ED25519_GWORD64(UINT64_C(0x6F1B3280553EEC03)), ED25519_GWORD64(UINT64_C(0xEE965FD847AED7F5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9AD2B953EE80527B)), ED25519_GWORD64(UINT64_C(0xE88F19AAFADE6D8D)),
				ED25519_GWORD64(UINT64_C(0x0E711704150E82CF)), ED25519_GWORD64(UINT64_C(0x79B9BBB9DD95DEDC))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD1997DAE8E9F7361)), ED25519_GWORD64(UINT64_C(0xA032A2F8CFBB0816)),
				ED25519_GWORD64(UINT64_C(0xCD6CBA126D445F0A)), ED25519_GWORD64(UINT64_C(0x9BA811460ACCB834))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xEBB355406A3126AF)), ED25519_GWORD64(UINT64_C(0xD26383A868C8C393)),
				ED25519_GWORD64(UINT64_C(0x6C0C6429E5B97A82)), ED25519_GWORD64(UINT64_C(0xD065F158C9FD2147))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x708169FB0C429954)), ED25519_GWORD64(UINT64_C(0xE14600ACD76ECF67)),
				ED25519_GWORD64(UINT64_C(0x2EAAB98A70E645BA)), ED25519_GWORD64(UINT64_C(0x3981F39E58A4FAF2))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xC845DFA56DE66FCB)), ED25519_GWORD64(UINT64_C(0xE152A5002C40483A)),
				ED25519_GWORD64(UINT64_C(0xE9D2E163C7B4F632)), ED25519_GWORD64(UINT64_C(0xB0F4452EDCBC1B65))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x18FB8A7559230A93)), ED25519_GWORD64(UINT64_C(0x1D168F6960E6F45D)),
				ED25519_GWORD64(UINT64_C(0x3A85A94514A93CB5)), ED25519_GWORD64(UINT64_C(0x38DC083705ACD0FD))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x856D2782C5759740)), ED25519_GWORD64(UINT64_C(0xFA134569F99CBECC)),
				ED25519_GWORD64(UINT64_C(0x8844FC73C0EA4E71)), ED25519_GWORD64(UINT64_C(0x632D9A1A593F2469))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xBF09FD11ED0C8494)), ED25519_GWORD64(UINT64_C(0x63F071810D9F693A)),
				ED25519_GWORD64(UINT64_C(0x21908C2D57CF8779)), ED25519_GWORD64(UINT64_C(0xBA5A7DF28AF64BA2))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF6BB6B15B807CBA6)), ED25519_GWORD64(UINT64_C(0x1823C7DFBC54F0D7)),
				ED25519_GWORD64(UINT64_C(0xBB1D97036E29670B)), ED25519_GWORD64(UINT64_C(0x0B24F48847ED4A57))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDCDAD4BE511BEAC7)), ED25519_GWORD64(UINT64_C(0xA4538075ED26CCF2)),
				ED25519_GWORD64(UINT64_C(0xE19CFF9F005F9A65)), ED25519_GWORD64(UINT64_C(0x34FCF74475481F63))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA5BB1DAB78CFAA85)), ED25519_GWORD64(UINT64_C(0x5CEDA267190B72F2)),
				ED25519_GWORD64(UINT64_C(0x9309C9110A92608E)), ED25519_GWORD64(UINT64_C(0x8119A3042FB374B0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC197E04C789767B7)), ED25519_GWORD64(UINT64_C(0xB8714DCB38D9467D)),
				ED25519_GWORD64(UINT64_C(0x55DE888283F95FA8)), ED25519_GWORD64(UINT64_C(0xBD3BDC164DFA63F7))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x67A2D89CE8C2177D)), ED25519_GWORD64(UINT64_C(0x669DA5F66895D0C1)),
				ED25519_GWORD64(UINT64_C(0xF56598E5B282A2B0)), ED25519_GWORD64(UINT64_C(0x56C088F1EDE20A73))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x581B5FAC24F38EEF)), ED25519_GWORD64(UINT64_C(0xA90BE9FEBAE30CBD)),
				ED25519_GWORD64(UINT64_C(0x9A2169028ACF92F0)), ED25519_GWORD64(UINT64_C(0x838B7EA48359038F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x336D3D1110A86E17)), ED25519_GWORD64(UINT64_C(0xD7F388320B75B2FA)),
				ED25519_GWORD64(UINT64_C(0xF915337625072988)), ED25519_GWORD64(UINT64_C(0x09674C6B99108B87))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9F4EF82199316FF8)), ED25519_GWORD64(UINT64_C(0x2F49D282EAA78D4F)),
				ED25519_GWORD64(UINT64_C(0x0971A5AB5AEF3174)), ED25519_GWORD64(UINT64_C(0x6E5E31025969EB65))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3304FB0E6306620F)), ED25519_GWORD64(UINT64_C(0xFB35068987ACBA3F)),
				ED25519_GWORD64(UINT64_C(0xBD1924778C1061A3)), ED25519_GWORD64(UINT64_C(0xB058AD43D1838620))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB16C62F587E593FB)), ED25519_GWORD64(UINT64_C(0x4999EDDECA5D3E71)),
				ED25519_GWORD64(UINT64_C(0xB491C1E014CC3E6D)), ED25519_GWORD64(UINT64_C(0x08F5114789A8DBA8))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x323C0FFDE57663D0)), ED25519_GWORD64(UINT64_C(0x05C3DF38A22EA610)),
				ED25519_GWORD64(UINT64_C(0xBDC78ABDAC994F9A)), ED25519_GWORD64(UINT64_C(0x26549FA4EFE3DC99))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xDB468549AF3F666E)), ED25519_GWORD64(UINT64_C(0xD77FCF04F14A0EA5)),
				ED25519_GWORD64(UINT64_C(0x3DF23FF7A4BA0C47)), ED25519_GWORD64(UINT64_C(0x3A10DFE132CE3C85))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x741D5A461E6BF9D6)), ED25519_GWORD64(UINT64_C(0x2305B3FC7777A581)),
				ED25519_GWORD64(UINT64_C(0xD45574A26474D3D9)), ED25519_GWORD64(UINT64_C(0x1926E1DC6401E0FF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE07F4E8AEA17CEA0)), ED25519_GWORD64(UINT64_C(0x2FD515463A1FC1FD)),
				ED25519_GWORD64(UINT64_C(0x175322FD31F2C0F1)), ED25519_GWORD64(UINT64_C(0x1FA1D01D861E5D15))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x38DCAC00D1DF94AB)), ED25519_GWORD64(UINT64_C(0x2E712BDDD1080DE9)),
				ED25519_GWORD64(UINT64_C(0x7F13E93EFDD5E262)), ED25519_GWORD64(UINT64_C(0x73FCED18EE9A01E5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xCC8055947D59981F)), ED25519_GWORD64(UINT64_C(0x1E4656DA37F15520)),
				ED25519_GWORD64(UINT64_C(0x99F6F7744E059320)), ED25519_GWORD64(UINT64_C(0xF73563BC6A75CF33))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x06B1E90863139CB3)), ED25519_GWORD64(UINT64_C(0xA493DA67C5A03ECD)),
				ED25519_GWORD64(UINT64_C(0x8D77CEC8AD638932)), ED25519_GWORD64(UINT64_C(0x1F426B701B864F44))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xF17E35C891A1253F)), ED25519_GWORD64(UINT64_C(0xB76B8153575E9C76)),
				ED25519_GWORD64(UINT64_C(0xFA83406F0D9B723E)), ED25519_GWORD64(UINT64_C(0x8B76BB1B3FA7E438))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xEFC9264C41911C01)), ED25519_GWORD64(UINT64_C(0xF1A3B7B817A22C25)),
				ED25519_GWORD64(UINT64_C(0x5875DA6BF30F1447)), ED25519_GWORD64(UINT64_C(0x4E1AF5271D31B090))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x08B8C1F97F92939B)), ED25519_GWORD64(UINT64_C(0xBE6771CBD444AB6E)),
				ED25519_GWORD64(UINT64_C(0x22E5646399BB8017)), ED25519_GWORD64(UINT64_C(0x7B6DD61EB772A955))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x5730ABF9AB01D2C7)), ED25519_GWORD64(UINT64_C(0x16FB76DC40143B18)),
				ED25519_GWORD64(UINT64_C(0x866CBE65A0CBB281)), ED25519_GWORD64(UINT64_C(0x53FA9B659BFF6AFE))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB7ADC1E850F33D7F)), ED25519_GWORD64(UINT64_C(0x7998FA4F608CD5CF)),
				ED25519_GWORD64(UINT64_C(0xAD962DBD8DFC5BDB)), ED25519_GWORD64(UINT64_C(0xF03E9BCEAF1D2F4F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6C14C8E994885455)), ED25519_GWORD64(UINT64_C(0x843A5D6665AED4E5)),
				ED25519_GWORD64(UINT64_C(0x181BB73EBCD65AF1)), ED25519_GWORD64(UINT64_C(0x398D93E5C4C61F50))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xC3877C60D2E7E3F2)), ED25519_GWORD64(UINT64_C(0x3B34AAA030828BB1)),
				ED25519_GWORD64(UINT64_C(0x283E26E7739EF138)), ED25519_GWORD64(UINT64_C(0x699C9C9002C30577))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1C4BD16733E248E0)), ED25519_GWORD64(UINT64_C(0xBD9E128715BF0A5F)),
				ED25519_GWORD64(UINT64_C(0xD43F8CF0A10B0376)), ED25519_GWORD64(UINT64_C(0xD3B09B5DDF191B13))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF306A7235946F1CC)), ED25519_GWORD64(UINT64_C(0x921718B5CCE5D97D)),
				ED25519_GWORD64(UINT64_C(0x28CDD24781B4E975)), ED25519_GWORD64(UINT64_C(0x51CAF30C6FCDD907))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x737AF99A18AC54B4)), ED25519_GWORD64(UINT64_C(0x903378DCC51CB30F)),
				ED25519_GWORD64(UINT64_C(0x2B89BC334CE10CC7)), ED25519_GWORD64(UINT64_C(0x92AE29C189F8E99A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA60BA7427674E00A)), ED25519_GWORD64(UINT64_C(0x630E8570A17A7BF3)),
				ED25519_GWORD64(UINT64_C(0x3758563DCF3324CC)), ED25519_GWORD64(UINT64_C(0x5504AA292383FDAA))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA99EC0CB1F0D01CF)), ED25519_GWORD64(UINT64_C(0x0DD1EFCC3A34F7AE)),
				ED25519_GWORD64(UINT64_C(0x55CA7521D09C4E22)), ED25519_GWORD64(UINT64_C(0x5FD14FE958EBA5EA))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3C42FE5EBF93CB8E)), ED25519_GWORD64(UINT64_C(0xBEDFA85136D4565F)),
				ED25519_GWORD64(UINT64_C(0xE0F0859E884220E8)), ED25519_GWORD64(UINT64_C(0x7DD73F960725D128))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB5DC2DDF2845AB2C)), ED25519_GWORD64(UINT64_C(0x069491B10A7FE993)),
				ED25519_GWORD64(UINT64_C(0x4DAAF3D64002E346)), ED25519_GWORD64(UINT64_C(0x093FF26E586474D1))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB10D24FE68059829)), ED25519_GWORD64(UINT64_C(0x75730672DBAF23E5)),
				ED25519_GWORD64(UINT64_C(0x1367253AB457AC29)), ED25519_GWORD64(UINT64_C(0x2F59BCBC86B470A4))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x7041D560B691C2EE)), ED25519_GWORD64(UINT64_C(0x85201B3FADD7E71E)),
				ED25519_GWORD64(UINT64_C(0x16C2E16311335585)), ED25519_GWORD64(UINT64_C(0xAAA55E3D010828B1))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x83847D429917134C)), ED25519_GWORD64(UINT64_C(0xAD1B911F567D03D7)),
				ED25519_GWORD64(UINT64_C(0x7E7748D9BE77AAD1)), ED25519_GWORD64(UINT64_C(0xD458B42E2E51AF4A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xED5192E60C07444F)), ED25519_GWORD64(UINT64_C(0x42C54E2D74421D10)),
				ED25519_GWORD64(UINT64_C(0x352B4C82FDB5C864)), ED25519_GWORD64(UINT64_C(0x13E9004A8A768664))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xBB2E00C9193B876C)), ED25519_GWORD64(UINT64_C(0xECE3A890E0DC506B)),
				ED25519_GWORD64(UINT64_C(0xECF3B7C036DE649F)), ED25519_GWORD64(UINT64_C(0xDF46040898DE9E1A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x739D8845832FCEC8)), ED25519_GWORD64(UINT64_C(0xFA38D6C9AE6BF863)),
				ED25519_GWORD64(UINT64_C(0x32BC0DCAB74FFEF7)), ED25519_GWORD64(UINT64_C(0xF3937E8814BCE45E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB9037116297BF48D)), ED25519_GWORD64(UINT64_C(0xA9D13B22D4F06834)),
				ED25519_GWORD64(UINT64_C(0xE19715574696BDC6)), ED25519_GWORD64(UINT64_C(0x2CF8A4E891D5E835))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2CB5487E17D06BA2)), ED25519_GWORD64(UINT64_C(0x24D2381C3950196B)),
				ED25519_GWORD64(UINT64_C(0xD7659C8185978A30)), ED25519_GWORD64(UINT64_C(0x7A6F7F2891D6A4F6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6D93FD8707110F54)), ED25519_GWORD64(UINT64_C(0xDD4C09D37C38B549)),
				ED25519_GWORD64(UINT64_C(0x7CB16A4CC2736A86)), ED25519_GWORD64(UINT64_C(0xA049BD6E58252A09))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7D09FD8D6A9AEF49)), ED25519_GWORD64(UINT64_C(0xF0EE60BE5B3DB90B)),
				ED25519_GWORD64(UINT64_C(0x4C21B52C519EBFD4)), ED25519_GWORD64(UINT64_C(0x6011AADFC545941D))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x63DED0C802CBF87D)), ED25519_GWORD64(UINT64_C(0xFBD098CA0DFF6AAA)),
				ED25519_GWORD64(UINT64_C(0x624D0AFDB9B6ED99)), ED25519_GWORD64(UINT64_C(0xE9CE18B779340B1E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5F67926DCF95F829)), ED25519_GWORD64(UINT64_C(0x7C7E856171289071)),
				ED25519_GWORD64(UINT64_C(0xD6A1E7F3998F7A5B)), ED25519_GWORD64(UINT64_C(0xEFC5CC1B0B62F9E0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD1EF5528B29879CB)), ED25519_GWORD64(UINT64_C(0xDD1AAE3CD47E9092)),
				ED25519_GWORD64(UINT64_C(0x127E0442189F2352)), ED25519_GWORD64(UINT64_C(0x15596B3AE57101F1))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x09FF31167E5124CA)), ED25519_GWORD64(UINT64_C(0x0BE4158BD9C745DF)),
				ED25519_GWORD64(UINT64_C(0x292B7D227EF556E5)), ED25519_GWORD64(UINT64_C(0x3AA4E241AFB6D138))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x462739D23F9179A2)), ED25519_GWORD64(UINT64_C(0xFF83123197D6DDCF)),
				ED25519_GWORD64(UINT64_C(0x1307DEB553F2148A)), ED25519_GWORD64(UINT64_C(0x0D2237687B5F4DDA))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2CC138BF2A3305F5)), ED25519_GWORD64(UINT64_C(0x48583F8FA2E926C3)),
				ED25519_GWORD64(UINT64_C(0x083AB1A25549D2EB)), ED25519_GWORD64(UINT64_C(0x32FCAA6E4687A36C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x3207A4732787CCDF)), ED25519_GWORD64(UINT64_C(0x17E31908F213E3F8)),
				ED25519_GWORD64(UINT64_C(0xD5B2ECD7F60D964E)), ED25519_GWORD64(UINT64_C(0x746F6336C2600BE9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7BC56E8DC57D9AF5)), ED25519_GWORD64(UINT64_C(0x3E0BD2ED9DF0BDF2)),
				ED25519_GWORD64(UINT64_C(0xAAC014DE22EFE4A3)), ED25519_GWORD64(UINT64_C(0x4627E9CEFEBD6A5C))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x3F4AF345AB6C971C)), ED25519_GWORD64(UINT64_C(0xE288EB729943731F)),
				ED25519_GWORD64(UINT64_C(0x33596A8A0344186D)), ED25519_GWORD64(UINT64_C(0x7B4917007ED66293))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x54341B28DD53A2CA)), ED25519_GWORD64(UINT64_C(0xAA17905BDF42FC3F)),
				ED25519_GWORD64(UINT64_C(0x0FF592D94DD2F8F4)), ED25519_GWORD64(UINT64_C(0x9D03620FE08CD37D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2D85FB5CAB84B064)), ED25519_GWORD64(UINT64_C(0x497810D289F3BC14)),
				ED25519_GWORD64(UINT64_C(0x476ADC447B15CE0C)), ED25519_GWORD64(UINT64_C(0x122BA376F844FD7B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC20232CDA2B4E554)), ED25519_GWORD64(UINT64_C(0x9ED0FD42115D187F)),
				ED25519_GWORD64(UINT64_C(0x2EABB4BE7DD479D9)), ED25519_GWORD64(UINT64_C(0x02C70BF52B68EC4C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xACE532BF458D72E1)), ED25519_GWORD64(UINT64_C(0x5BE768E07CB73CB5)),
				ED25519_GWORD64(UINT64_C(0x56CF7D94EE8BBDE7)), ED25519_GWORD64(UINT64_C(0x6B0697E3FEB43A03))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA287EC4B5D0B2FBB)), ED25519_GWORD64(UINT64_C(0x415C5790074882CA)),
				ED25519_GWORD64(UINT64_C(0xE044A61EC1D0815C)), ED25519_GWORD64(UINT64_C(0x26334F0A409EF5E0))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB6C8F04ADF62A3C0)), ED25519_GWORD64(UINT64_C(0x3EF000EF076DA45D)),
				ED25519_GWORD64(UINT64_C(0x9C9CB95849F0D2A9)), ED25519_GWORD64(UINT64_C(0x1CC37F43441B2FAE))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xD76656F1C9CEAEA6)), ED25519_GWORD64(UINT64_C(0x1C5B15F818E5656A)),
				ED25519_GWORD64(UINT64_C(0x26E72832844C2334)), ED25519_GWORD64(UINT64_C(0xBA346F772F196838))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x508F565A5CC7323C)), ED25519_GWORD64(UINT64_C(0xD061C4C0E506A922)),
				ED25519_GWORD64(UINT64_C(0xFB18ABDB5C45AC19)), ED25519_GWORD64(UINT64_C(0xEC6809C10380314A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD2D55112E2DA6AC8)), ED25519_GWORD64(UINT64_C(0xE9BD0331B1E851ED)),
				ED25519_GWORD64(UINT64_C(0x960746DD8EC67262)), ED25519_GWORD64(UINT64_C(0x05911B9F6EF7C5D0))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x5349ACF3512EEADC)), ED25519_GWORD64(UINT64_C(0x20C141D31CC1CB49)),
				ED25519_GWORD64(UINT64_C(0x24180C07A99A688D)), ED25519_GWORD64(UINT64_C(0xD55EF9D1C64B2D17))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xC1339983F5DF0EA8)), ED25519_GWORD64(UINT64_C(0xC0F3758F512C4CAC)),
				ED25519_GWORD64(UINT64_C(0x2CF1130A0BB398E1)), ED25519_GWORD64(UINT64_C(0xEB3CECF9AA270C62))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x36A770BA3B73BD08)), ED25519_GWORD64(UINT64_C(0x624AEF08A3AFBF0C)),
				ED25519_GWORD64(UINT64_C(0x5737FF98B40946F2)), ED25519_GWORD64(UINT64_C(0x675F4DE13381749D))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xA12FF6D93BDAB30A)), ED25519_GWORD64(UINT64_C(0x0725D80F9D652DFE)),
				ED25519_GWORD64(UINT64_C(0x019C4FF39ABE9487)), ED25519_GWORD64(UINT64_C(0xE0F450B882CD3C43))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0E2C52036B1782FC)), ED25519_GWORD64(UINT64_C(0x64816C816CAD83B4)),
				ED25519_GWORD64(UINT64_C(0xD0DCBDD96964073E)), ED25519_GWORD64(UINT64_C(0x13D99DF70164C520))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x014B5EC321E5C0CA)), ED25519_GWORD64(UINT64_C(0x4FCB69C9D719BFA2)),
				ED25519_GWORD64(UINT64_C(0x4E5F1C18750023A0)), ED25519_GWORD64(UINT64_C(0x1C06DE9E55EDAC80))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xFFD52B40FF6D69AA)), ED25519_GWORD64(UINT64_C(0x34530B18DC4049BB)),
				ED25519_GWORD64(UINT64_C(0x5E4A5C2FA34D9897)), ED25519_GWORD64(UINT64_C(0x78096F8E7D32BA2D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x990F7AD6A33EC4E2)), ED25519_GWORD64(UINT64_C(0x6608F938BE2EE08E)),
				ED25519_GWORD64(UINT64_C(0x9CA143C563284515)), ED25519_GWORD64(UINT64_C(0x4CF38A1FEC2DB60D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA0AAAA650DFA5CE7)), ED25519_GWORD64(UINT64_C(0xF9C49E2A48B5478C)),
				ED25519_GWORD64(UINT64_C(0x4F09CC7D7003725B)), ED25519_GWORD64(UINT64_C(0x373CAD3A26091ABE))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xF1BEA8FB89DDBB9A)), ED25519_GWORD64(UINT64_C(0x3BCB2CBC61AEAECB)),
				ED25519_GWORD64(UINT64_C(0x8F58A7BB1F9B8D9D)), ED25519_GWORD64(UINT64_C(0xA1547EDA5112A686))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB294634D82C9F57C)), ED25519_GWORD64(UINT64_C(0x1FCBFDE124934536)),
				ED25519_GWORD64(UINT64_C(0x9E9C4DB3418CDB5A)), ED25519_GWORD64(UINT64_C(0x0040F3D9454419FC))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xDEFDE939FD5986D3)), ED25519_GWORD64(UINT64_C(0xF4272C89510A380C)),
				ED25519_GWORD64(UINT64_C(0xB72BA407BB3119B9)), ED25519_GWORD64(UINT64_C(0x63550A334A254DF4))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9BBA584572547B36)), ED25519_GWORD64(UINT64_C(0xF305C6FAE2C408E0)),
				ED25519_GWORD64(UINT64_C(0x60E8FA69C734F18D)), ED25519_GWORD64(UINT64_C(0xB9A92BAFAA7D767A))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6507D6EDB569CF24)), ED25519_GWORD64(UINT64_C(0x178429B00CA52EE1)),
				ED25519_GWORD64(UINT64_C(0xEA7C0090EB6BD65D)), ED25519_GWORD64(UINT64_C(0xBEEA62C7DAF78F51))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x9D24C713E693274E)), ED25519_GWORD64(UINT64_C(0x5F63857768DBD375)),
				ED25519_GWORD64(UINT64_C(0x70525560EB8AB39A)), ED25519_GWORD64(UINT64_C(0x68436A0665C9C4CD))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x1E56D317E8201069)), ED25519_GWORD64(UINT64_C(0xC5266844840AE965)),
				ED25519_GWORD64(UINT64_C(0xC1E0A1C6320FFC7A)), ED25519_GWORD64(UINT64_C(0xD373669C91611472))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xBC0235E8202F3F27)), ED25519_GWORD64(UINT64_C(0xC75C00E264F975B0)),
				ED25519_GWORD64(UINT64_C(0x91A4E9D5A38C2416)), ED25519_GWORD64(UINT64_C(0x17B6E7F68AB789F9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x5D2814AB9A0E5257)), ED25519_GWORD64(UINT64_C(0x908F2084C9CAB3FC)),
				ED25519_GWORD64(UINT64_C(0xAFCAF5885B2D1ECA)), ED25519_GWORD64(UINT64_C(0x1CB4B5A678F87D11))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6B74AA62A2A007D4)), ED25519_GWORD64(UINT64_C(0xF311E0B0F071C7B1)),
				ED25519_GWORD64(UINT64_C(0x5707E438000BE223)), ED25519_GWORD64(UINT64_C(0xADC0FD2D82EF6EAC))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB664C06B394AFC6C)), ED25519_GWORD64(UINT64_C(0x0C88DE2498DA5FB1)),
				ED25519_GWORD64(UINT64_C(0x4F8D03164BCAD834)), ED25519_GWORD64(UINT64_C(0x330BCA78DE7434A2))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x982EFF841119744E)), ED25519_GWORD64(UINT64_C(0xF9695E962B074724)),
				ED25519_GWORD64(UINT64_C(0xC58AC14FBFC953FB)), ED25519_GWORD64(UINT64_C(0x3C31BE1B369F1CF5))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xC168BC93F9CB4272)), ED25519_GWORD64(UINT64_C(0xAEB8711FC7CEDB98)),
				ED25519_GWORD64(UINT64_C(0x7F0E52AA34AC8D7A)), ED25519_GWORD64(UINT64_C(0x41CEC1097E7D55BB))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xB0F4864D08948AEE)), ED25519_GWORD64(UINT64_C(0x07DC19EE91BA1C6F)),
				ED25519_GWORD64(UINT64_C(0x7975CDAEA6ACA158)), ED25519_GWORD64(UINT64_C(0x330B61134262D4BB))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF79619D7A26D808A)), ED25519_GWORD64(UINT64_C(0xBB1FD49E1D9E156D)),
				ED25519_GWORD64(UINT64_C(0x73D7C36CDBA1DF27)), ED25519_GWORD64(UINT64_C(0x26B44CD91F28777D))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE1B7F29362730383)), ED25519_GWORD64(UINT64_C(0x4B5279FFEBCA8A2C)),
				ED25519_GWORD64(UINT64_C(0xDAFC778ABFD41314)), ED25519_GWORD64(UINT64_C(0x7DEB10149C72610F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x51F048478F387475)), ED25519_GWORD64(UINT64_C(0xB25DBCF49CBECB3C)),
				ED25519_GWORD64(UINT64_C(0x9AAB1244D99F2055)), ED25519_GWORD64(UINT64_C(0x2C709E6C1C10A5D6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xCB62AF6A8766EE7A)), ED25519_GWORD64(UINT64_C(0x66CBEC045553CD0E)),
				ED25519_GWORD64(UINT64_C(0x588001380F0BE4B5)), ED25519_GWORD64(UINT64_C(0x08E68E9FF62CE2EA))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2F2D09D50AB8F2F9)), ED25519_GWORD64(UINT64_C(0xACB9218DC55923DF)),
				ED25519_GWORD64(UINT64_C(0x4A8F342673766CB9)), ED25519_GWORD64(UINT64_C(0x4CB13BD738F719F5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x34AD500A4BC130AD)), ED25519_GWORD64(UINT64_C(0x8D38DB493D0BD49C)),
				ED25519_GWORD64(UINT64_C(0xA25C3D98500A89BE)), ED25519_GWORD64(UINT64_C(0x2F1F3F87EEBA3B09))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF7848C75E515B64A)), ED25519_GWORD64(UINT64_C(0xA59501BADB4A9038)),
				ED25519_GWORD64(UINT64_C(0xC20D313F3F751B50)), ED25519_GWORD64(UINT64_C(0x19A1E353C0AE2EE8))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xB42172CDD596BDBD)), ED25519_GWORD64(UINT64_C(0x93E0454398EEFC40)),
				ED25519_GWORD64(UINT64_C(0x9FB15347B44109B5)), ED25519_GWORD64(UINT64_C(0x736BD3990266AE34))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x7D1C7560BAFA05C3)), ED25519_GWORD64(UINT64_C(0xB3E1A0A0C6E55E61)),
				ED25519_GWORD64(UINT64_C(0xE3529718C0D66473)), ED25519_GWORD64(UINT64_C(0x41546B11C20C3486))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x85532D509334B3B4)), ED25519_GWORD64(UINT64_C(0x46FD114B60816573)),
				ED25519_GWORD64(UINT64_C(0xCC5F5F30425C8375)), ED25519_GWORD64(UINT64_C(0x412295A2B87FAB5C))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2E655261E293EAB3)), ED25519_GWORD64(UINT64_C(0x845A92032133ACDB)),
				ED25519_GWORD64(UINT64_C(0x460975CB7900996B)), ED25519_GWORD64(UINT64_C(0x8760BB8D195ADD80))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x19C99B88F57ED6E9)), ED25519_GWORD64(UINT64_C(0x5393CB266DF8C825)),
				ED25519_GWORD64(UINT64_C(0x5CEE3213B30AD273)), ED25519_GWORD64(UINT64_C(0x14E153EBB52D2E34))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x413E1A17CDE6818A)), ED25519_GWORD64(UINT64_C(0x57156DA9ED69A084)),
				ED25519_GWORD64(UINT64_C(0x2CBF268F46CACCB1)), ED25519_GWORD64(UINT64_C(0x6B34BE9BC33AC5F2))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x11FC69656571F2C0)), ED25519_GWORD64(UINT64_C(0xC6C9E845530E737A)),
				ED25519_GWORD64(UINT64_C(0xE33AE7A2D4FE5035)), ED25519_GWORD64(UINT64_C(0x81B9C7B62E6DD30B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xF3DF2F643A78C0B2)), ED25519_GWORD64(UINT64_C(0x4C3E971EF22E027C)),
				ED25519_GWORD64(UINT64_C(0xEC7D1C5E49C1B5A3)), ED25519_GWORD64(UINT64_C(0x2012C18F0922DD2D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x880B55E55AC89D29)), ED25519_GWORD64(UINT64_C(0x1483241F45A0A763)),
				ED25519_GWORD64(UINT64_C(0x3D36EFDFC2E76C1F)), ED25519_GWORD64(UINT64_C(0x08AF5B784E4BADE8))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xE27314D289CC2C4B)), ED25519_GWORD64(UINT64_C(0x4BE4BD11A287178D)),
				ED25519_GWORD64(UINT64_C(0x18D528D6FA3364CE)), ED25519_GWORD64(UINT64_C(0x6423C1D5AFD9826E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x283499DC881F2533)), ED25519_GWORD64(UINT64_C(0x9D0525DA779323B6)),
				ED25519_GWORD64(UINT64_C(0x897ADDFB673441F4)), ED25519_GWORD64(UINT64_C(0x32B79D71163A168D))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xCC85F8D9EDFCB36A)), ED25519_GWORD64(UINT64_C(0x22BCC28F3746E5F9)),
				ED25519_GWORD64(UINT64_C(0xE49DE338F9E5D3CD)), ED25519_GWORD64(UINT64_C(0x480A5EFBC13E2DCC))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xB6614CE442CE220C)), ED25519_GWORD64(UINT64_C(0x6E199DCC4C053928)),
				ED25519_GWORD64(UINT64_C(0x663FB4A4DC1CBE03)), ED25519_GWORD64(UINT64_C(0xA4B31D47691C8E06))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0B51E70B0162205E)), ED25519_GWORD64(UINT64_C(0x06B505CF8B1DAFC5)),
				ED25519_GWORD64(UINT64_C(0x2C6BB061EF5AABCD)), ED25519_GWORD64(UINT64_C(0xC7AA27600CB7BF31))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x2A541EEDC015F8C3)), ED25519_GWORD64(UINT64_C(0x11A4FE7E7C693F7C)),
				ED25519_GWORD64(UINT64_C(0xF0AF66134EA278D6)), ED25519_GWORD64(UINT64_C(0x545B585D14DDA094))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x6204E4D0E3B321E1)), ED25519_GWORD64(UINT64_C(0x3BAA637A28FF1E95)),
				ED25519_GWORD64(UINT64_C(0x0B0CCFFD5B99BD9E)), ED25519_GWORD64(UINT64_C(0x4D22DC3E64C8D071))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x67BF275EA0D43A0F)), ED25519_GWORD64(UINT64_C(0xADE68E34089BEEBE)),
				ED25519_GWORD64(UINT64_C(0x4289134CD479E72E)), ED25519_GWORD64(UINT64_C(0x0F62F9C332BA5454))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xFCB46589D63B5F39)), ED25519_GWORD64(UINT64_C(0x5CAE6A3F57CBCF61)),
				ED25519_GWORD64(UINT64_C(0xFEBAC2D2953AFA05)), ED25519_GWORD64(UINT64_C(0x1C0FA01A36371436))
			}}
		}

	},
	{
		{
			{{
				ED25519_GWORD64(UINT64_C(0x69082B0E8C936A3D)), ED25519_GWORD64(UINT64_C(0xF9C9A035C1DAC5B6)),
				ED25519_GWORD64(UINT64_C(0x6FB73E54C4DFB634)), ED25519_GWORD64(UINT64_C(0xC005419B1D2BC140))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xD2C604B622943DFF)), ED25519_GWORD64(UINT64_C(0xBC8CBECE44CFB3A0)),
				ED25519_GWORD64(UINT64_C(0x5D254FF397808678)), ED25519_GWORD64(UINT64_C(0x0FA3614F3B1CA6BF))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA003FEBDB9BE82F0)), ED25519_GWORD64(UINT64_C(0x2089C1AF3A44AC90)),
				ED25519_GWORD64(UINT64_C(0xF8499F911954FA8E)), ED25519_GWORD64(UINT64_C(0x1FBA218AEF40AB42))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x4F3E57043E7B0194)), ED25519_GWORD64(UINT64_C(0xA81D3EEE08DAAF7F)),
				ED25519_GWORD64(UINT64_C(0xC839C6AB99DCDEF1)), ED25519_GWORD64(UINT64_C(0x6C535D13FF7761D5))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xAB549448FAC8F53E)), ED25519_GWORD64(UINT64_C(0x81F6E89A7BA63741)),
				ED25519_GWORD64(UINT64_C(0x74FD6C7D6C2B5E01)), ED25519_GWORD64(UINT64_C(0x392E3ACAA8C86E42))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x4CBD34E93E8A35AF)), ED25519_GWORD64(UINT64_C(0x2E0781445887E816)),
				ED25519_GWORD64(UINT64_C(0x19319C76F29AB0AB)), ED25519_GWORD64(UINT64_C(0x25E17FE4D50AC13B))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x915F7FF576F121A7)), ED25519_GWORD64(UINT64_C(0xC34A32272FCD87E3)),
				ED25519_GWORD64(UINT64_C(0xCCBA2FDE4D1BE526)), ED25519_GWORD64(UINT64_C(0x6BBA828F8969899B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x0A289BD71E04F663)), ED25519_GWORD64(UINT64_C(0x208E1C52D6420F95)),
				ED25519_GWORD64(UINT64_C(0x5186D8B034691FAB)), ED25519_GWORD64(UINT64_C(0xA55751442A9FB351))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE2D1BC6690FE3901)), ED25519_GWORD64(UINT64_C(0x4CB54A18A0997AD5)),
				ED25519_GWORD64(UINT64_C(0x971D6914AF8460D4)), ED25519_GWORD64(UINT64_C(0x559D504F7F6B7BE4))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x9C4891E7F6D266FD)), ED25519_GWORD64(UINT64_C(0x0744A19B0307781B)),
				ED25519_GWORD64(UINT64_C(0x88388F1D6061E23B)), ED25519_GWORD64(UINT64_C(0x123EA6A3354BD50E))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xA7738378B3EB54D5)), ED25519_GWORD64(UINT64_C(0x1D69D366A5553C7C)),
				ED25519_GWORD64(UINT64_C(0x0A26CF62F92800BA)), ED25519_GWORD64(UINT64_C(0x01AB12D5807E3217))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x118D189041E32D96)), ED25519_GWORD64(UINT64_C(0xB9EDE3C2D8315848)),
				ED25519_GWORD64(UINT64_C(0x1EAB4271D83245D9)), ED25519_GWORD64(UINT64_C(0x4A3961E2C918A154))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x0327D644F3233F1E)), ED25519_GWORD64(UINT64_C(0x499A260E34FCF016)),
				ED25519_GWORD64(UINT64_C(0x83B5A716F2DAB979)), ED25519_GWORD64(UINT64_C(0x68ACEEAD9BD4111F))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x71DC3BE0F8E6BBA0)), ED25519_GWORD64(UINT64_C(0xD6CEF8347EFFE30A)),
				ED25519_GWORD64(UINT64_C(0xA992425FE13A476A)), ED25519_GWORD64(UINT64_C(0x2CD6BCE3FB1DB763))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x38B4C90EF3D7C210)), ED25519_GWORD64(UINT64_C(0x308E6E24B7AD040C)),
				ED25519_GWORD64(UINT64_C(0x3860D9F1B7E73E23)), ED25519_GWORD64(UINT64_C(0x595760D5B508F597))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x882ACBEBFD022790)), ED25519_GWORD64(UINT64_C(0x89AF3305C4115760)),
				ED25519_GWORD64(UINT64_C(0x65F492E37D3473F4)), ED25519_GWORD64(UINT64_C(0x2CB2C5DF54515A2B))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x6129BFE104AA6384)), ED25519_GWORD64(UINT64_C(0x8F960008A4A7FCCB)),
				ED25519_GWORD64(UINT64_C(0x3F8BC0897D909458)), ED25519_GWORD64(UINT64_C(0xF09FA43EDCB291A9))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xEB0A5D8C63FD2ACA)), ED25519_GWORD64(UINT64_C(0xD22BC1662E694EFF)),
				ED25519_GWORD64(UINT64_C(0x2723F36EF8CBB03A)), ED25519_GWORD64(UINT64_C(0x70F029ECF0C8131F))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0x2A6AAFAA5E10B0B9)), ED25519_GWORD64(UINT64_C(0x78F0A370EF041AA9)),
				ED25519_GWORD64(UINT64_C(0x773EFB77AA3AD61F)), ED25519_GWORD64(UINT64_C(0x44ECA5A2A74BD9E1))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x461307B32EED3E33)), ED25519_GWORD64(UINT64_C(0xAE042F33A45581E7)),
				ED25519_GWORD64(UINT64_C(0xC94449D3195F0366)), ED25519_GWORD64(UINT64_C(0x0B7D5D8A6C314858))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x25D448327B95D543)), ED25519_GWORD64(UINT64_C(0x70D38300A3340F1D)),
				ED25519_GWORD64(UINT64_C(0xDE1C531C60E1C52B)), ED25519_GWORD64(UINT64_C(0x272224512C7DE9E4))
			}}
		},
		{
			{{
				ED25519_GWORD64(UINT64_C(0xBF7BBB8A42A975FC)), ED25519_GWORD64(UINT64_C(0x8C5C397796ADA358)),
				ED25519_GWORD64(UINT64_C(0xE27FC76FCDEDAA48)), ED25519_GWORD64(UINT64_C(0x19735FD7F6BC20A6))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0x1ABC92AF49C5342E)), ED25519_GWORD64(UINT64_C(0xFFEED811B2E6FAD0)),
				ED25519_GWORD64(UINT64_C(0xEFA28C8DFCC84E29)), ED25519_GWORD64(UINT64_C(0x11B5DF18A44CC543))
			}},
			{{
				ED25519_GWORD64(UINT64_C(0xE3AB90D042C84266)), ED25519_GWORD64(UINT64_C(0xEB848E0F7F19547E)),
				ED25519_GWORD64(UINT64_C(0x2503A1D065A497B9)), ED25519_GWORD64(UINT64_C(0x0FEF911191DF895F))
			}}
		}
	}
};

/*!
 * \brief Derives a 32-byte X25519 public key using a read-only Edwards table.
 * \param out: Caller-owned output; capacity is given by the array extent or result type.
 * \param scalar: Caller-owned 32-byte little-endian scalar; not modified.
 * \details All buffers contain 32 bytes and must be non-null. No allocation or shared mutable state.
 * The scalar copies and selected fixed-base field intermediates are securely erased.
 * Low-order/all-zero rejection belongs to the public wrapper.
 */
void qsc_ed25519_x25519_generate(uint8_t out[32U], const uint8_t scalar[32U])
{
	uint8_t k[32U] = { 0 };
	uint8_t s[32U];

	ed25519_xclamp(k, scalar);
	ed25519_gscalar(s, k);
	ed25519_gpublic(out, s, ed25519_gbase_table);
	qsc_memutils_secure_erase(s, sizeof(s));
	qsc_memutils_secure_erase(k, sizeof(k));
}

static qsc_ed25519_gfe ed25519_gload(const uint8_t bytes[32U])
{
	qsc_ed25519_gfe value;
	size_t i;

	for (i = 0U; i < ED25519_GWORDS; ++i)
	{
		value.v[i] = ed25519_gloadword(bytes + sizeof(qsc_ed25519_gword) * i);
	}

	value.v[ED25519_GWORDS - 1U] &= ED25519_GMAX >> 1;

	return value;
}

static qsc_ed25519_gfe ed25519_gimport(const qsc_fe25519 input)
{
	int64_t words[10U];
	int64_t low;
	int64_t carry;
	uint8_t bytes[32U] = { 0U };
	uint64_t word;
	size_t i;
	size_t j;
	size_t pass;
	size_t width;
	size_t bit;
	qsc_ed25519_gfe result;

	for (i = 0U; i < 10U; ++i)
	{
		words[i] = input[i];
	}

	for (pass = 0U; pass < 4U; ++pass)
	{
		for (i = 0U; i < 9U; ++i)
		{
			width = 26U - (i & 1U);
			low = (int64_t)((uint64_t)words[i] & ((UINT64_C(1) << width) - 1U));
			carry = (words[i] - low) / (INT64_C(1) << width);
			words[i] = low;
			words[i + 1U] += carry;
		}

		low = (int64_t)((uint64_t)words[9U] & UINT64_C(0x1FFFFFF));
		carry = (words[9U] - low) / INT64_C(33554432);
		words[9U] = low;
		words[0U] += 19 * carry;
	}

	bit = 0U;

	for (i = 0U; i < 10U; ++i)
	{
		word = (uint64_t)words[i] << (bit % 8U);

		for (j = 0U; j < 4U; ++j)
		{
			bytes[bit / 8U + j] |= (uint8_t)(word >> (8U * j));
		}

		bit += 26U - (i & 1U);
	}

	result = ed25519_gload(bytes);
	qsc_memutils_secure_erase(words, sizeof(words));
	qsc_memutils_secure_erase(bytes, sizeof(bytes));

	return result;
}

static void ed25519_gexport(qsc_fe25519 out, qsc_ed25519_gfe input)
{
	uint8_t bytes[32U];
	uint32_t word;
	size_t i;
	size_t j;
	size_t bit;
	size_t width;

	ed25519_gserialize(bytes, input);
	bit = 0U;

	for (i = 0U; i < 10U; ++i)
	{
		word = 0U;

		for (j = 0U; j < 4U; ++j)
		{
			word |= (uint32_t)bytes[bit / 8U + j] << (8U * j);
		}

		width = 26U - (i & 1U);
		out[i] = (int32_t)((word >> (bit % 8U)) & ((UINT32_C(1) << width) - 1U));
		bit += width;
	}

	qsc_memutils_secure_erase(bytes, sizeof(bytes));
}

void qsc_ge25519_scalarmult_base(qsc_ge25519_p3* h, const uint8_t* a)
{
	uint8_t scalar[32U];
	qsc_ed25519_gextended point;

	ed25519_gscalar(scalar, a);
	point = ed25519_gbasepoint(scalar, ed25519_gbase_table);
	ed25519_gexport(h->x, point.x);
	ed25519_gexport(h->y, point.y);
	ed25519_gexport(h->z, point.z);
	ed25519_gexport(h->t, point.t);
	qsc_memutils_secure_erase(scalar, sizeof(scalar));
	qsc_memutils_secure_erase(&point, sizeof(point));
}

static void ed25519_gencode(uint8_t out[32U], const qsc_ed25519_gprojective* point)
{
	qsc_ed25519_gfe inverse;
	qsc_ed25519_gfe x;
	qsc_ed25519_gfe y;
	uint8_t xb[32U];

	inverse = ed25519_ginvert(point->z);
	x = ed25519_gmul(point->x, inverse);
	y = ed25519_gmul(point->y, inverse);
	ed25519_gserialize(out, y);
	ed25519_gserialize(xb, x);
	out[31U] |= (uint8_t)((xb[0U] & 1U) << 7);
	qsc_memutils_secure_erase(&inverse, sizeof(inverse));
	qsc_memutils_secure_erase(&x, sizeof(x));
	qsc_memutils_secure_erase(&y, sizeof(y));
	qsc_memutils_secure_erase(xb, sizeof(xb));
}

void qsc_ge25519_p3_to_bytes(uint8_t* s, const qsc_ge25519_p3* h)
{
	qsc_ed25519_gprojective point;

	point.x = ed25519_gimport(h->x);
	point.y = ed25519_gimport(h->y);
	point.z = ed25519_gimport(h->z);
	ed25519_gencode(s, &point);
	qsc_memutils_secure_erase(&point, sizeof(point));
}

void qsc_ge25519_to_bytes(uint8_t* s, const qsc_ge25519_p2* h)
{
	qsc_ed25519_gprojective point;

	point.x = ed25519_gimport(h->x);
	point.y = ed25519_gimport(h->y);
	point.z = ed25519_gimport(h->z);
	ed25519_gencode(s, &point);
	qsc_memutils_secure_erase(&point, sizeof(point));
}

/*! \brief Twice the Edwards parameter d, modulo 2^255 - 19. */
static const qsc_ed25519_gfe ed25519_gd2 = 
{
	{
		ED25519_GWORD64(UINT64_C(0xEBD69B9426B2F159)), 
		ED25519_GWORD64(UINT64_C(0x00E0149A8283B156)),
		ED25519_GWORD64(UINT64_C(0x198E80F2EEF3D130)), 
		ED25519_GWORD64(UINT64_C(0x2406D9DC56DFFCE7))
	}
};

static qsc_ed25519_gextended ed25519_gadd_point(qsc_ed25519_gextended p, qsc_ed25519_gextended q)
{

	qsc_ed25519_gfe a;
	qsc_ed25519_gfe b;
	qsc_ed25519_gfe c;
	qsc_ed25519_gfe d;
	qsc_ed25519_gcompleted r;

	a = ed25519_gmul(ed25519_gsub(p.y, p.x), ed25519_gsub(q.y, q.x));
	b = ed25519_gmul(ed25519_gadd(p.y, p.x), ed25519_gadd(q.y, q.x));
	c = ed25519_gmul(ed25519_gmul(p.t, q.t), ed25519_gd2);
	d = ed25519_gmul(p.z, q.z);
	d = ed25519_gadd(d, d);
	r.x = ed25519_gsub(b, a);
	r.y = ed25519_gadd(b, a);
	r.z = ed25519_gadd(d, c);
	r.t = ed25519_gsub(d, c);

	return ed25519_gextended_from(r);
}

/*! \brief Cached projective point for public-input joint multiplication. */
typedef struct
{
	qsc_ed25519_gfe yplusx;	 /*!< Y + X. */
	qsc_ed25519_gfe yminusx; /*!< Y - X. */
	qsc_ed25519_gfe z;		 /*!< Projective denominator. */
	qsc_ed25519_gfe t2d;	 /*!< 2*d*T. */
} qsc_ed25519_gcached;

static qsc_ed25519_gcached ed25519_gcache(qsc_ed25519_gextended p)
{
	qsc_ed25519_gcached result;

	result.yplusx = ed25519_gadd(p.y, p.x);
	result.yminusx = ed25519_gsub(p.y, p.x);
	result.z = p.z;
	result.t2d = ed25519_gmul(p.t, ed25519_gd2);

	return result;
}

static qsc_ed25519_gextended ed25519_gadd_cached(qsc_ed25519_gextended p, qsc_ed25519_gcached q)
{
	qsc_ed25519_gfe a;
	qsc_ed25519_gfe b;
	qsc_ed25519_gfe c;
	qsc_ed25519_gfe d;
	qsc_ed25519_gcompleted r;

	a = ed25519_gmul(ed25519_gsub(p.y, p.x), q.yminusx);
	b = ed25519_gmul(ed25519_gadd(p.y, p.x), q.yplusx);
	c = ed25519_gmul(p.t, q.t2d);
	d = ed25519_gmul(p.z, q.z);
	d = ed25519_gadd(d, d);
	r.x = ed25519_gsub(b, a);
	r.y = ed25519_gadd(b, a);
	r.z = ed25519_gadd(d, c);
	r.t = ed25519_gsub(d, c);

	return ed25519_gextended_from(r);
}

/*! \brief Immutable odd multiples B, 3B, ..., 15B for public-input verification. */
static const qsc_ed25519_gniels ed25519_verify_base[8U] = 
{
	{{{ED25519_GWORD64(UINT64_C(0x2FBC93C6F58C3B85)), ED25519_GWORD64(UINT64_C(0xCF932DC6FB8C0E19)), ED25519_GWORD64(UINT64_C(0x270B4898643D42C2)), ED25519_GWORD64(UINT64_C(0x07CF9D3A33D4BA65))}}, 
	{{ED25519_GWORD64(UINT64_C(0x9D103905D740913E)), ED25519_GWORD64(UINT64_C(0xFD399F05D140BEB3)), ED25519_GWORD64(UINT64_C(0xA5C18434688F8A09)), ED25519_GWORD64(UINT64_C(0x44FD2F9298F81267))}},
	{{ED25519_GWORD64(UINT64_C(0xABC91205877AAA68)), ED25519_GWORD64(UINT64_C(0x26D9E823CCAAC49E)), ED25519_GWORD64(UINT64_C(0x5A1B7DCBDD43598C)), ED25519_GWORD64(UINT64_C(0x6F117B689F0C65A8))}}},
	{{{ED25519_GWORD64(UINT64_C(0xAF25B0A84CEE9730)), ED25519_GWORD64(UINT64_C(0x025A8430E8864B8A)), ED25519_GWORD64(UINT64_C(0xC11B50029F016732)), ED25519_GWORD64(UINT64_C(0x7A164E1B9A80F8F4))}},
	{{ED25519_GWORD64(UINT64_C(0x56611FE8A4FCD265)), ED25519_GWORD64(UINT64_C(0x3BD353FDE5C1BA7D)), ED25519_GWORD64(UINT64_C(0x8131F31A214BD6BD)), ED25519_GWORD64(UINT64_C(0x2AB91587555BDA62))}},
	{{ED25519_GWORD64(UINT64_C(0x14AE933F0DD0D889)), ED25519_GWORD64(UINT64_C(0x589423221C35DA62)), ED25519_GWORD64(UINT64_C(0xD170E5458CF2DB4C)), ED25519_GWORD64(UINT64_C(0x5A2826AF12B9B4C6))}}},
	{{{ED25519_GWORD64(UINT64_C(0xA212BC4408A5BB33)), ED25519_GWORD64(UINT64_C(0x8D5048C3C75EED02)), ED25519_GWORD64(UINT64_C(0xDD1BEB0C5ABFEC44)), ED25519_GWORD64(UINT64_C(0x2945CCF146E206EB))}},
	{{ED25519_GWORD64(UINT64_C(0x7F9182C3A447D6BA)), ED25519_GWORD64(UINT64_C(0xD50014D14B2729B7)), ED25519_GWORD64(UINT64_C(0xE33CF11CB864A087)), ED25519_GWORD64(UINT64_C(0x154A7E73EB1B55F3))}}, 
	{{ED25519_GWORD64(UINT64_C(0xBCBBDBF1812A8285)), ED25519_GWORD64(UINT64_C(0x270E0807D0BDD1FC)), ED25519_GWORD64(UINT64_C(0xB41B670B1BBDA72D)), ED25519_GWORD64(UINT64_C(0x43AABE696B3BB69A))}}},
	{{{ED25519_GWORD64(UINT64_C(0x6B1A5CD0944EA3BF)), ED25519_GWORD64(UINT64_C(0x7470353AB39DC0D2)), ED25519_GWORD64(UINT64_C(0x71B2528228542E49)), ED25519_GWORD64(UINT64_C(0x461BEA69283C927E))}}, 
	{{ED25519_GWORD64(UINT64_C(0xBA6F2C9AAA3221B1)), ED25519_GWORD64(UINT64_C(0x6CA021533BBA23A7)), ED25519_GWORD64(UINT64_C(0x9DEA764F92192C3A)), ED25519_GWORD64(UINT64_C(0x1D6EDD5D2E5317E0))}}, 
	{{ED25519_GWORD64(UINT64_C(0xF1836DC801B8B3A2)), ED25519_GWORD64(UINT64_C(0xB3035F47053EA49A)), ED25519_GWORD64(UINT64_C(0x529C41BA5877ADF3)), ED25519_GWORD64(UINT64_C(0x7A9FBB1C6A0F90A7))}}},
	{{{ED25519_GWORD64(UINT64_C(0x9B2E678AA6A8632F)), ED25519_GWORD64(UINT64_C(0xA6509E6F51BC46C5)), ED25519_GWORD64(UINT64_C(0xCEB233C9C686F5B5)), ED25519_GWORD64(UINT64_C(0x34B9ED338ADD7F59))}},
	{{ED25519_GWORD64(UINT64_C(0xF36E217E039D8064)), ED25519_GWORD64(UINT64_C(0x98A081B6F520419B)), ED25519_GWORD64(UINT64_C(0x96CBC608E75EB044)), ED25519_GWORD64(UINT64_C(0x49C05A51FADC9C8F))}},
	{{ED25519_GWORD64(UINT64_C(0x06B4E8BF9045AF1B)), ED25519_GWORD64(UINT64_C(0xE2FF83E8A719D22F)), ED25519_GWORD64(UINT64_C(0xAAF6FC2993D4CF16)), ED25519_GWORD64(UINT64_C(0x73C172021B008B06))}}},
	{{{ED25519_GWORD64(UINT64_C(0x2FBF00848A802ADE)), ED25519_GWORD64(UINT64_C(0xE5D9FECF02302E27)), ED25519_GWORD64(UINT64_C(0x113E847117703406)), ED25519_GWORD64(UINT64_C(0x4275AAE2546D8FAF))}}, 
	{{ED25519_GWORD64(UINT64_C(0x315F5B0249864348)), ED25519_GWORD64(UINT64_C(0x3ED6B36977088381)), ED25519_GWORD64(UINT64_C(0xA3A075556A8DEB95)), ED25519_GWORD64(UINT64_C(0x18AB598029D5C77F))}}, 
	{{ED25519_GWORD64(UINT64_C(0xD82B2CC5FD6089E9)), ED25519_GWORD64(UINT64_C(0x031EB4A13282E4A4)), ED25519_GWORD64(UINT64_C(0x44311199B51A8622)), ED25519_GWORD64(UINT64_C(0x3DC65522B53DF948))}}},
	{{{ED25519_GWORD64(UINT64_C(0xBF70C222A2007F6D)), ED25519_GWORD64(UINT64_C(0xBF84B39AB5BCDEDB)), ED25519_GWORD64(UINT64_C(0x537A0E12FB07BA07)), ED25519_GWORD64(UINT64_C(0x234FD7EEC346F241))}}, 
	{{ED25519_GWORD64(UINT64_C(0x506F013B327FBF93)), ED25519_GWORD64(UINT64_C(0xAEFCEBC99B776F6B)), ED25519_GWORD64(UINT64_C(0x9D12B232AAAD5968)), ED25519_GWORD64(UINT64_C(0x0267882D176024A7))}}, 
	{{ED25519_GWORD64(UINT64_C(0x5360A119732EA378)), ED25519_GWORD64(UINT64_C(0x2437E6B1DF8DD471)), ED25519_GWORD64(UINT64_C(0xA2EF37F891A7E533)), ED25519_GWORD64(UINT64_C(0x497BA6FDAA097863))}}},
	{{{ED25519_GWORD64(UINT64_C(0x24CECC0313CFEAA0)), ED25519_GWORD64(UINT64_C(0x8648C28D189C246D)), ED25519_GWORD64(UINT64_C(0x2DBDBDFAC1F2D4D0)), ED25519_GWORD64(UINT64_C(0x61E22917F12DE72B))}},
	{{ED25519_GWORD64(UINT64_C(0x040BCD86468CCF0B)), ED25519_GWORD64(UINT64_C(0xD3829BA42A9910D6)), ED25519_GWORD64(UINT64_C(0x7508300807B25192)), ED25519_GWORD64(UINT64_C(0x43B5CD4218D05EBF))}}, 
	{{ED25519_GWORD64(UINT64_C(0x5D9A762F9BD0B516)), ED25519_GWORD64(UINT64_C(0xEB38AF4E373FDEEE)), ED25519_GWORD64(UINT64_C(0x032E5A7D93D64270)), ED25519_GWORD64(UINT64_C(0x511D61210AE4D842))}}}
};

void qsc_ge25519_double_scalarmult_vartime(qsc_ge25519_p2* r, const uint8_t* a, const qsc_ge25519_p3* A, const uint8_t* b)
{
	qsc_ed25519_gextended table[8U];
	qsc_ed25519_gcached cached[8U];
	qsc_ed25519_gcached selected;
	qsc_ed25519_gniels base;
	qsc_ed25519_gfe swap;
	qsc_ed25519_gextended twice;
	qsc_ed25519_gextended sum;
	int8_t adigits[257U];
	int8_t bdigits[257U];
	int32_t digit;
	size_t i;

	table[0U].x = ed25519_gimport(A->x);
	table[0U].y = ed25519_gimport(A->y);
	table[0U].z = ed25519_gimport(A->z);
	table[0U].t = ed25519_gimport(A->t);
	twice = ed25519_gextended_from(ed25519_gextended_dbl(table[0U]));

	for (i = 1U; i < 8U; ++i)
	{
		table[i] = ed25519_gadd_point(table[i - 1U], twice);
	}

	for (i = 0U; i < 8U; ++i)
	{
		cached[i] = ed25519_gcache(table[i]);
	}

	ed25518_slide_vartime(adigits, a);
	ed25518_slide_vartime(bdigits, b);
	sum = ed25519_gextended_identity();
	i = 257U;

	while (i > 0U && adigits[i - 1U] == 0 && bdigits[i - 1U] == 0)
	{
		--i;
	}

	for (; i > 0U; --i)
	{
		sum = ed25519_gextended_from(ed25519_gextended_dbl(sum));
		digit = adigits[i - 1U];

		if (digit != 0)
		{
			selected = cached[(size_t)(digit < 0 ? -digit : digit) / 2U];

			if (digit < 0)
			{
				swap = selected.yplusx;
				selected.yplusx = selected.yminusx;
				selected.yminusx = swap;
				selected.t2d = ed25519_gnegate(selected.t2d);
			}

			sum = ed25519_gadd_cached(sum, selected);
		}

		digit = bdigits[i - 1U];

		if (digit != 0)
		{
			base = ed25519_verify_base[(size_t)(digit < 0 ? -digit : digit) / 2U];

			if (digit < 0)
			{
				swap = base.yplusx;
				base.yplusx = base.yminusx;
				base.yminusx = swap;
				base.xy2d = ed25519_gnegate(base.xy2d);
			}

			sum = ed25519_gextended_from(ed25519_gadd_niels(sum, base));
		}
	}

	ed25519_gexport(r->x, sum.x);
	ed25519_gexport(r->y, sum.y);
	ed25519_gexport(r->z, sum.z);
}

void qsc_ge25519_basepoint_to_bytes(uint8_t* out, const uint8_t* scalar)
{
	uint8_t reduced[32U];
	qsc_ed25519_gextended point;
	qsc_ed25519_gprojective projective;

	ed25519_gscalar(reduced, scalar);
	point = ed25519_gbasepoint(reduced, ed25519_gbase_table);
	projective.x = point.x;
	projective.y = point.y;
	projective.z = point.z;
	ed25519_gencode(out, &projective);
	qsc_memutils_secure_erase(reduced, sizeof(reduced));
	qsc_memutils_secure_erase(&point, sizeof(point));
	qsc_memutils_secure_erase(&projective, sizeof(projective));
}

/* \endcond DOXYGEN_NO_DOCUMENT */
