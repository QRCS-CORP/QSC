#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "sha3.h"

static uint16_t coeff_freeze(uint16_t x)
{
	/* Fully reduces an integer modulo q in constant time */

	uint16_t m;
	uint16_t r;
	int16_t c;

	r = x % NEWHOPE_Q;
	m = r - NEWHOPE_Q;
	c = m;
	c >>= 15;
	r = m ^ ((r ^ m) & c);

	return r;
}

static uint16_t flipabs(uint16_t x)
{
	/* Computes |(x mod q) - Q/2| */
	int16_t r;
	int16_t m;

	r = coeff_freeze(x);
	r = r - (NEWHOPE_Q / 2);
	m = r >> 15;

	return (r + m) ^ m;
}

void poly_frombytes(poly* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < NEWHOPE_N / 4; i++)
	{
		r->coeffs[4 * i + 0] = a[7 * i + 0] | (((uint16_t)a[7 * i + 1] & 0x3f) << 8);
		r->coeffs[4 * i + 1] = (a[7 * i + 1] >> 6) | (((uint16_t)a[7 * i + 2]) << 2) | (((uint16_t)a[7 * i + 3] & 0x0f) << 10);
		r->coeffs[4 * i + 2] = (a[7 * i + 3] >> 4) | (((uint16_t)a[7 * i + 4]) << 4) | (((uint16_t)a[7 * i + 5] & 0x03) << 12);
		r->coeffs[4 * i + 3] = (a[7 * i + 5] >> 2) | (((uint16_t)a[7 * i + 6]) << 6);
	}
}

void poly_tobytes(uint8_t* r, const poly* p)
{
	size_t i;
	uint16_t t0;
	uint16_t t1;
	uint16_t t2;
	uint16_t t3;

	for (i = 0; i < NEWHOPE_N / 4; i++)
	{
		t0 = coeff_freeze(p->coeffs[4 * i + 0]);
		t1 = coeff_freeze(p->coeffs[4 * i + 1]);
		t2 = coeff_freeze(p->coeffs[4 * i + 2]);
		t3 = coeff_freeze(p->coeffs[4 * i + 3]);

		r[7 * i + 0] = t0 & 0xff;
		r[7 * i + 1] = (t0 >> 8) | (t1 << 6);
		r[7 * i + 2] = (t1 >> 2);
		r[7 * i + 3] = (t1 >> 10) | (t2 << 4);
		r[7 * i + 4] = (t2 >> 4);
		r[7 * i + 5] = (t2 >> 12) | (t3 << 2);
		r[7 * i + 6] = (t3 >> 6);
	}
}

void poly_compress(uint8_t* r, const poly* p)
{
	uint32_t t[8];
	size_t i;
	size_t j;
	size_t k;

	k = 0;

	for (i = 0; i < NEWHOPE_N; i += 8)
	{
		for (j = 0; j < 8; j++)
		{
			t[j] = coeff_freeze(p->coeffs[i + j]);
			t[j] = (((t[j] << 3) + NEWHOPE_Q / 2) / NEWHOPE_Q) & 0x7;
		}

		r[k] = t[0] | (t[1] << 3) | (t[2] << 6);
		r[k + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[k + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
		k += 3;
	}
}

void poly_decompress(poly* r, const uint8_t* a)
{
	size_t i;
	size_t j;

	for (i = 0; i < NEWHOPE_N; i += 8)
	{
		r->coeffs[i + 0] = a[0] & 7;
		r->coeffs[i + 1] = (a[0] >> 3) & 7;
		r->coeffs[i + 2] = (a[0] >> 6) | ((a[1] << 2) & 4);
		r->coeffs[i + 3] = (a[1] >> 1) & 7;
		r->coeffs[i + 4] = (a[1] >> 4) & 7;
		r->coeffs[i + 5] = (a[1] >> 7) | ((a[2] << 1) & 6);
		r->coeffs[i + 6] = (a[2] >> 2) & 7;
		r->coeffs[i + 7] = (a[2] >> 5);
		a += 3;

		for (j = 0; j < 8; j++)
		{
			r->coeffs[i + j] = ((uint32_t)r->coeffs[i + j] * NEWHOPE_Q + 4) >> 3;
		}
	}
}

void poly_frommsg(poly* r, const uint8_t* msg)
{
	uint32_t mask;
	size_t i;
	size_t j;

	for (i = 0; i < 32; i++)
	{
		for (j = 0; j < 8; j++)
		{
			mask = -((msg[i] >> j) & 1);
			r->coeffs[8 * i + j + 0] = mask & (NEWHOPE_Q / 2);
			r->coeffs[8 * i + j + 256] = mask & (NEWHOPE_Q / 2);
#if (NEWHOPE_N == 1024)
			r->coeffs[8 * i + j + 512] = mask & (NEWHOPE_Q / 2);
			r->coeffs[8 * i + j + 768] = mask & (NEWHOPE_Q / 2);
#endif
		}
	}
}

void poly_tomsg(uint8_t* msg, const poly* x)
{
	size_t i;
	uint16_t t;

	for (i = 0; i < 32; i++)
	{
		msg[i] = 0;
	}

	for (i = 0; i < 256; i++)
	{
		t = flipabs(x->coeffs[i + 0]);
		t += flipabs(x->coeffs[i + 256]);
#if (NEWHOPE_N == 1024)
		t += flipabs(x->coeffs[i + 512]);
		t += flipabs(x->coeffs[i + 768]);
		t = ((t - NEWHOPE_Q));
#else
		t = ((t - NEWHOPE_Q / 2));
#endif
		t >>= 15;
		msg[i >> 3] |= t << (i & 7);
	}
}

void poly_uniform(poly* a, const uint8_t* seed)
{
	uint64_t state[25];
	uint8_t buf[SHAKE128_RATE];
	uint8_t extseed[NEWHOPE_SYMBYTES + 1];
	size_t ctr;
	size_t i;
	size_t j;
	uint16_t val;

	for (i = 0; i < NEWHOPE_SYMBYTES; i++)
	{
		extseed[i] = seed[i];
	}

	ctr = 0;
	/* generate a in blocks of 64 coefficients */
	for (i = 0; i < NEWHOPE_N / 64; i++)
	{
		ctr = 0;
		/* domain-separate the 16 independent calls */
		extseed[NEWHOPE_SYMBYTES] = (uint8_t)i;
		shake128_initialize(state, extseed, NEWHOPE_SYMBYTES + 1);
		/* Very unlikely to run more than once */
		while (ctr < 64)
		{
			shake128_squeezeblocks(state, buf, 1);
			for (j = 0; j < SHAKE128_RATE && ctr < 64; j += 2)
			{
				val = (buf[j] | ((uint16_t)buf[j + 1] << 8));
				if (val < 5 * NEWHOPE_Q)
				{
					a->coeffs[i * 64 + ctr] = val;
					ctr++;
				}
			}
		}
	}
}

static uint8_t hw(uint8_t a)
{
	/* Compute the Hamming weight of a byte */

	uint8_t i;
	uint8_t r;

	r = 0;
	for (i = 0; i < 8; i++)
	{
		r += (a >> i) & 1;
	}

	return r;
}

void poly_sample(poly* r, const uint8_t* seed, uint8_t nonce)
{
	uint8_t buf[128];
	uint8_t extseed[NEWHOPE_SYMBYTES + 2];
	size_t i;
	size_t j;
	uint8_t a;
	uint8_t b;

	for (i = 0; i < NEWHOPE_SYMBYTES; i++)
	{
		extseed[i] = seed[i];
	}

	extseed[NEWHOPE_SYMBYTES] = nonce;

	/* Generate noise in blocks of 64 coefficients */
	for (i = 0; i < NEWHOPE_N / 64; i++)
	{
		extseed[NEWHOPE_SYMBYTES + 1] = (uint8_t)i;
		shake256(buf, 128, extseed, NEWHOPE_SYMBYTES + 2);

		for (j = 0; j < 64; j++)
		{
			a = buf[2 * j];
			b = buf[(2 * j) + 1];
			r->coeffs[(64 * i) + j] = hw(a) + (NEWHOPE_Q - hw(b));
		}
	}
}

void poly_mul_pointwise(poly* r, const poly* a, const poly* b)
{
	size_t i;
	uint16_t t;

	for (i = 0; i < NEWHOPE_N; i++)
	{
		/* t is now in Montgomery domain */
		t = montgomery_reduce(3186 * b->coeffs[i]);
		/* r->coeffs[i] is back in normal domain */
		r->coeffs[i] = montgomery_reduce(a->coeffs[i] * t);
	}
}

void poly_add(poly* r, const poly* a, const poly* b)
{
	size_t i;

	for (i = 0; i < NEWHOPE_N; i++)
	{
		r->coeffs[i] = (a->coeffs[i] + b->coeffs[i]) % NEWHOPE_Q;
	}
}

void poly_sub(poly* r, const poly* a, const poly* b)
{
	size_t i;

	for (i = 0; i < NEWHOPE_N; i++)
	{
		r->coeffs[i] = (a->coeffs[i] + 3 * NEWHOPE_Q - b->coeffs[i]) % NEWHOPE_Q;
	}
}

void poly_ntt(poly* r)
{
	mul_coefficients(r->coeffs, psis_bitrev_montgomery);
	ntt((uint16_t *)r->coeffs, omegas_bitrev_montgomery);
}

void poly_invntt(poly *r)
{
	bitrev_vector(r->coeffs);
	ntt((uint16_t*)r->coeffs, omegas_inv_bitrev_montgomery);
	mul_coefficients(r->coeffs, psis_inv_montgomery);
}

