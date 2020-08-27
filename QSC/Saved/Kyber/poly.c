#include "poly.h"
#include "ntt.h"
#include "sha3.h"
#include "intutils.h"

void cbd(poly* r, const uint8_t* buf)
{
	uint32_t d;
	uint32_t t;
	int16_t a;
	int16_t b;
	size_t i;
	size_t j;

	for (i = 0; i < KYBER_N / 8; ++i)
	{
		t = qsc_le8to32(buf + 4 * i);
		d = t & 0x55555555UL;
		d += (t >> 1) & 0x55555555UL;

		for (j = 0; j < 8; j++)
		{
			a = (d >> (4 * j)) & 0x03U;
			b = (d >> ((4 * j) + 2)) & 0x03U;
			r->coeffs[(8 * i) + j] = (uint16_t)(a - b);
		}
	}
}

void poly_compress(uint8_t* r, poly* a)
{
	uint8_t t[8];
	size_t i;
	size_t j;
	size_t k;

	k = 0;
	poly_csubq(a);

#if (KYBER_POLYCOMPRESSEDBYTES == 96)
	for (i = 0; i < KYBER_N; i += 8)
	{
		for (j = 0; j < 8; ++j)
		{
			t[j] = ((((uint32_t)a->coeffs[i + j] << 3U) + KYBER_Q / 2) / KYBER_Q) & 7U;
		}

		r[k] = t[0] | (t[1] << 3U) | (t[2] << 6U);
		r[k + 1] = (t[2] >> 2U) | (t[3] << 1U) | (t[4] << 4U) | (t[5] << 7U);
		r[k + 2] = (t[5] >> 1U) | (t[6] << 2U) | (t[7] << 5U);
		k += 3;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 128)
	for (i = 0; i < KYBER_N; i += 8)
	{
		for (j = 0; j < 8; ++j)
		{
			/* jgu -false possible overflow */
			/*lint -e661 -e662 */
			t[j] = ((((uint32_t)a->coeffs[i + j] << 4U) + KYBER_Q / 2) / KYBER_Q) & 15U;
		}

		r[k] = (uint8_t)(t[0] | (t[1] << 4U));
		r[k + 1] = (uint8_t)(t[2] | (t[3] << 4U));
		r[k + 2] = (uint8_t)(t[4] | (t[5] << 4U));
		r[k + 3] = (uint8_t)(t[6] | (t[7] << 4U));
		k += 4;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
	for (i = 0; i < KYBER_N; i += 8)
	{
		for (j = 0; j < 8; ++j)
		{
			t[j] = ((((uint32_t)a->coeffs[i + j] << 5U) + KYBER_Q / 2) / KYBER_Q) & 31U;
		}

		r[k] = (uint8_t)(t[0] | (t[1] << 5U));
		r[k + 1] = (uint8_t)((t[1] >> 3U) | (t[2] << 2U) | (t[3] << 7U));
		r[k + 2] = (uint8_t)((t[3] >> 1U) | (t[4] << 4U));
		r[k + 3] = (uint8_t)((t[4] >> 4U) | (t[5] << 1U) | (t[6] << 6U));
		r[k + 4] = (uint8_t)((t[6] >> 2U) | (t[7] << 3U));
		k += 5;
	}
#endif
}

void poly_decompress(poly* r, const uint8_t* a)
{
	size_t i;

#if (KYBER_POLYCOMPRESSEDBYTES == 96)
	for (i = 0; i < KYBER_N; i += 8)
	{
		r->coeffs[i] = (((a[0] & 7U) * KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 1] = ((((a[0] >> 3U) & 7U) * KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 2] = ((((a[0] >> 6U) | ((a[1] << 2U) & 4U)) * KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 3] = ((((a[1] >> 1U) & 7U) * KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 4] = ((((a[1] >> 4U) & 7U) * KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 5] = ((((a[1] >> 7U) | ((a[2] << 1U) & 6U)) * KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 6] = ((((a[2] >> 2U) & 7U) * KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 7] = ((((a[2] >> 5U)) * KYBER_Q) + 4) >> 3U;
		a += 3;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 128)
	for (i = 0; i < KYBER_N; i += 8)
	{
		r->coeffs[i] = (((a[0] & 15U) * KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 1] = (((a[0] >> 4U) * KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 2] = (((a[1] & 15U) * KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 3] = (((a[1] >> 4U) * KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 4] = (((a[2] & 15U) * KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 5] = (((a[2] >> 4U) * KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 6] = (((a[3] & 15U) * KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 7] = (((a[3] >> 4U) * KYBER_Q) + 8) >> 4U;
		a += 4;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
	for (i = 0; i < KYBER_N; i += 8)
	{
		r->coeffs[i] = (((a[0] & 31U) * KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 1] = ((((a[0] >> 5U) | ((a[1] & 3U) << 3U)) * KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 2] = ((((a[1] >> 2U) & 31U) * KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 3] = ((((a[1] >> 7U) | ((a[2] & 15U) << 1U)) * KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 4] = ((((a[2] >> 4U) | ((a[3] & 1U) << 4U)) * KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 5] = ((((a[3] >> 1U) & 31U) * KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 6] = ((((a[3] >> 6U) | ((a[4] & 7U) << 2U)) * KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 7] = (((a[4] >> 3U) * KYBER_Q) + 16) >> 5U;
		a += 5;
	}
#endif
}

void poly_tobytes(uint8_t* r, poly* a)
{
	size_t i;
	uint16_t t0;
	uint16_t t1;

	poly_csubq(a);

	for (i = 0; i < KYBER_N / 2; ++i) 
	{
		t0 = a->coeffs[2 * i];
		t1 = a->coeffs[2 * i + 1];
		r[3 * i] = t0 & 0xFFU;
		r[3 * i + 1] = (t0 >> 8U) | ((t1 & 0x0FU) << 4U);
		r[3 * i + 2] = (uint8_t)(t1 >> 4U);
	}
}

void poly_frombytes(poly* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < KYBER_N / 2; ++i) 
	{
		r->coeffs[2 * i] = a[3 * i] | ((uint16_t)a[3 * i + 1] & 0x0FU) << 8;
		r->coeffs[2 * i + 1] = a[3 * i + 1] >> 4U | ((uint16_t)a[3 * i + 2] & 0xFFU) << 4U;
	}
}

void poly_getnoise(poly* r, const uint8_t* seed, uint8_t nonce)
{
	uint8_t buf[KYBER_ETA * KYBER_N / 4];
	uint8_t extkey[KYBER_SYMBYTES + 1];
	size_t i;

	for (i = 0; i < KYBER_SYMBYTES; ++i)
	{
		extkey[i] = seed[i];
	}

	extkey[i] = nonce;
	qsc_shake256_compute(buf, KYBER_ETA*KYBER_N / 4, extkey, KYBER_SYMBYTES + 1);

	cbd(r, buf);
}

void poly_ntt(poly* r)
{
	ntt(r->coeffs);
	poly_reduce(r);
}

void poly_invntt(poly* r)
{
	invntt(r->coeffs);
}

void poly_basemul(poly* r, const poly* a, const poly* b)
{
	size_t i;

	for (i = 0; i < KYBER_N / 4; ++i) 
	{
		basemul(r->coeffs + (4 * i), a->coeffs + (4 * i), b->coeffs + (4 * i), zetas[64 + i]);
		basemul(r->coeffs + (4 * i) + 2, a->coeffs + (4U * i) + 2, b->coeffs + (4U * i) + 2, -zetas[64 + i]);
	}
}

void poly_frommont(poly* r)
{
	const int16_t f = (1ULL << 32) % KYBER_Q;
	size_t i;

	for (i = 0; i < KYBER_N; ++i)
	{
		r->coeffs[i] = (uint16_t)montgomery_reduce((int32_t)r->coeffs[i] * f);
	}
}

void poly_reduce(poly* r)
{
	size_t i;

	for (i = 0; i < KYBER_N; ++i)
	{
		r->coeffs[i] = (uint16_t)barrett_reduce((int16_t)r->coeffs[i]);
	}
}

void poly_csubq(poly* r)
{
	size_t i;

	for (i = 0; i < KYBER_N; ++i)
	{
		r->coeffs[i] = (uint16_t)csubq((int16_t)r->coeffs[i]);
	}
}

void poly_add(poly* r, const poly* a, const poly* b)
{
	size_t i;

	for (i = 0; i < KYBER_N; ++i)
	{
		r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
	}
}

void poly_sub(poly* r, const poly* a, const poly* b)
{
	size_t i;

	for (i = 0; i < KYBER_N; ++i)
	{
		r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
	}
}

void poly_frommsg(poly* r, const uint8_t msg[KYBER_SYMBYTES])
{
	size_t i;
	size_t j;
	uint16_t mask;

	for (i = 0; i < KYBER_SYMBYTES; ++i)
	{
		for (j = 0; j < 8; ++j)
		{
			mask = ~((msg[i] >> j) & 1U) + 1;
			r->coeffs[(8 * i) + j] = mask & ((KYBER_Q + 1) / 2);
		}
	}
}

void poly_tomsg(uint8_t msg[KYBER_SYMBYTES], poly* a)
{
	size_t i;
	size_t j;
	uint16_t t;

	poly_csubq(a);

	for (i = 0; i < KYBER_SYMBYTES; ++i)
	{
		msg[i] = 0;

		for (j = 0; j < 8; ++j)
		{
			t = (((a->coeffs[(8 * i) + j] << 1U) + KYBER_Q / 2) / KYBER_Q) & 1U;
			/* jgu -suprressed false signed shift info */
			/*lint -e701 */
			msg[i] |= (uint8_t)(t << j);
		}
	}
}
