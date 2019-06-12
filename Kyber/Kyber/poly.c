#include "poly.h"
#include "ntt.h"
#include "sha3.h"
#include "util.h"

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
		t = le8to32(buf + 4 * i);
		d = t & 0x55555555UL;
		d += (t >> 1) & 0x55555555UL;

		for (j = 0; j < 8; j++)
		{
			a = (d >> (4 * j)) & 0x3;
			b = (d >> ((4 * j) + 2)) & 0x3;
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
			t[j] = ((((uint32_t)a->coeffs[i + j] << 3) + KYBER_Q / 2) / KYBER_Q) & 7;
		}

		r[k] = t[0] | (t[1] << 3) | (t[2] << 6);
		r[k + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[k + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
		k += 3;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 128)
	for (i = 0; i < KYBER_N; i += 8)
	{
		for (j = 0; j < 8; ++j)
		{
			/* jgu -false possible overflow */
			/*lint -e661 -e662 */
			t[j] = ((((uint32_t)a->coeffs[i + j] << 4) + KYBER_Q / 2) / KYBER_Q) & 15;
		}

		r[k] = (uint8_t)(t[0] | (t[1] << 4));
		r[k + 1] = (uint8_t)(t[2] | (t[3] << 4));
		r[k + 2] = (uint8_t)(t[4] | (t[5] << 4));
		r[k + 3] = (uint8_t)(t[6] | (t[7] << 4));
		k += 4;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
	for (i = 0; i < KYBER_N; i += 8)
	{
		for (j = 0; j < 8; ++j)
		{
			t[j] = ((((uint32_t)a->coeffs[i + j] << 5) + KYBER_Q / 2) / KYBER_Q) & 31;
		}

		r[k] = (uint8_t)(t[0] | (t[1] << 5));
		r[k + 1] = (uint8_t)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
		r[k + 2] = (uint8_t)((t[3] >> 1) | (t[4] << 4));
		r[k + 3] = (uint8_t)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
		r[k + 4] = (uint8_t)((t[6] >> 2) | (t[7] << 3));
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
		r->coeffs[i] = (((a[0] & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 1] = ((((a[0] >> 3) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 2] = ((((a[0] >> 6) | ((a[1] << 2) & 4)) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 3] = ((((a[1] >> 1) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 4] = ((((a[1] >> 4) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 5] = ((((a[1] >> 7) | ((a[2] << 1) & 6)) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 6] = ((((a[2] >> 2) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 7] = ((((a[2] >> 5)) * KYBER_Q) + 4) >> 3;
		a += 3;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 128)
	for (i = 0; i < KYBER_N; i += 8)
	{
		r->coeffs[i] = (((a[0] & 15) * KYBER_Q) + 8) >> 4;
		r->coeffs[i + 1] = (((a[0] >> 4) * KYBER_Q) + 8) >> 4;
		r->coeffs[i + 2] = (((a[1] & 15) * KYBER_Q) + 8) >> 4;
		r->coeffs[i + 3] = (((a[1] >> 4) * KYBER_Q) + 8) >> 4;
		r->coeffs[i + 4] = (((a[2] & 15) * KYBER_Q) + 8) >> 4;
		r->coeffs[i + 5] = (((a[2] >> 4) * KYBER_Q) + 8) >> 4;
		r->coeffs[i + 6] = (((a[3] & 15) * KYBER_Q) + 8) >> 4;
		r->coeffs[i + 7] = (((a[3] >> 4) * KYBER_Q) + 8) >> 4;
		a += 4;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
	for (i = 0; i < KYBER_N; i += 8)
	{
		r->coeffs[i] = (((a[0] & 31) * KYBER_Q) + 16) >> 5;
		r->coeffs[i + 1] = ((((a[0] >> 5) | ((a[1] & 3) << 3)) * KYBER_Q) + 16) >> 5;
		r->coeffs[i + 2] = ((((a[1] >> 2) & 31) * KYBER_Q) + 16) >> 5;
		r->coeffs[i + 3] = ((((a[1] >> 7) | ((a[2] & 15) << 1)) * KYBER_Q) + 16) >> 5;
		r->coeffs[i + 4] = ((((a[2] >> 4) | ((a[3] & 1) << 4)) * KYBER_Q) + 16) >> 5;
		r->coeffs[i + 5] = ((((a[3] >> 1) & 31) * KYBER_Q) + 16) >> 5;
		r->coeffs[i + 6] = ((((a[3] >> 6) | ((a[4] & 7) << 2)) * KYBER_Q) + 16) >> 5;
		r->coeffs[i + 7] = (((a[4] >> 3) * KYBER_Q) + 16) >> 5;
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
		r[3 * i] = t0 & 0xFF;
		r[3 * i + 1] = (t0 >> 8) | ((t1 & 0x0F) << 4);
		r[3 * i + 2] = (uint8_t)(t1 >> 4);
	}
}

void poly_frombytes(poly* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < KYBER_N / 2; ++i) 
	{
		r->coeffs[2 * i] = a[3 * i] | ((uint16_t)a[3 * i + 1] & 0x0F) << 8;
		r->coeffs[2 * i + 1] = a[3 * i + 1] >> 4 | ((uint16_t)a[3 * i + 2] & 0xFF) << 4;
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
	shake256(buf, KYBER_ETA*KYBER_N / 4, extkey, KYBER_SYMBYTES + 1);

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
			mask = ~((msg[i] >> j) & 1) + 1;
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
			t = (((a->coeffs[(8 * i) + j] << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
			/* jgu -suprressed false signed shift info */
			/*lint -e701 */
			msg[i] |= (uint8_t)(t << j);
		}
	}
}
