#include "poly.h"
#include "params.h"
#include "ntt.h"
#include "reduce.h"
#include "rounding.h"
#include "sha3.h"

void poly_reduce(poly* a)
{
	size_t i;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		a->coeffs[i] = reduce32(a->coeffs[i]);
	}
}

void poly_csubq(poly* a) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		a->coeffs[i] = csubq(a->coeffs[i]);
	}
}

void poly_freeze(poly* a) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		a->coeffs[i] = freeze(a->coeffs[i]);
	}
}

void poly_add(poly* c, const poly* a, const poly* b) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
	}
}

void poly_sub(poly* c, const poly* a, const poly* b) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		c->coeffs[i] = a->coeffs[i] + (2 * DILITHIUM_Q) - b->coeffs[i];
	}
}

void poly_shiftl(poly* a) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		a->coeffs[i] <<= DILITHIUM_D;
	}
}

void poly_ntt(poly* a)
{
	ntt(a->coeffs);
}

void poly_invntt_montgomery(poly* a) 
{
	invntt_frominvmont(a->coeffs);
}

void poly_pointwise_invmontgomery(poly* c, const poly* a, const poly* b) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		c->coeffs[i] = montgomery_reduce((uint64_t)a->coeffs[i] * b->coeffs[i]);
	}
}

void poly_power2round(poly* a1, poly* a0, const poly* a) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		a1->coeffs[i] = power2round(a->coeffs[i], &a0->coeffs[i]);
	}
}

void poly_decompose(poly* a1, poly* a0, const poly* a) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		a1->coeffs[i] = decompose(a->coeffs[i], &a0->coeffs[i]);
	}
}

uint32_t poly_make_hint(poly* h, const poly* a0, const poly* a1) 
{
	size_t i;
	uint32_t s;

	s = 0;

	for (i = 0; i < DILITHIUM_N; ++i) 
	{
		h->coeffs[i] = make_hint(a0->coeffs[i], a1->coeffs[i]);
		s += h->coeffs[i];
	}

	return s;
}

void poly_use_hint(poly* a, const poly* b, const poly* h) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		a->coeffs[i] = use_hint(b->coeffs[i], h->coeffs[i]);
	}
}

int32_t poly_chknorm(const poly* a, uint32_t B) 
{
	size_t i;
	int32_t s;
	int32_t t;

	/* It is ok to leak which coefficient violates the bound since
	   the probability for each coefficient is independent of secret
	   data but we must not leak the sign of the centralized representative. */

	s = 0;

	for (i = 0; i < DILITHIUM_N; ++i) 
	{
		/* Absolute value of centralized representative */
		t = ((DILITHIUM_Q - 1) / 2) - a->coeffs[i];
		t ^= (t >> 31U);
		t = ((DILITHIUM_Q - 1) / 2) - t;

		if ((uint32_t)t >= B) 
		{
			s = 1;
			break;
		}
	}

	return s;
}

/*************************************************
* Name:        rej_uniform
*
* Description: Sample uniformly random coefficients in [0, DILITHIUM_Q-1] by
*              performing rejection sampling using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - uint32_t len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - uint32_t buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static uint32_t rej_uniform(uint32_t* a, uint32_t len, const uint8_t* buf, size_t buflen)
{
	size_t pos;
	size_t ctr;
	uint32_t t;

	ctr = 0;
	pos = 0;

	while (ctr < len && pos + 3 <= buflen) 
	{
		t = buf[pos];
		++pos;
		t |= (uint32_t)buf[pos] << 8;
		++pos;
		t |= (uint32_t)buf[pos] << 16;
		++pos;
		t &= 0x007FFFFFUL;

		if (t < DILITHIUM_Q)
		{
			a[ctr] = t;
			++ctr;
		}
	}

	return (uint32_t)ctr;
}

void poly_uniform(poly* a, const uint8_t seed[DILITHIUM_SEED_SIZE], uint16_t nonce)
{
	const size_t NBLKS = (769 + QSC_SHAKE_128_RATE) / QSC_SHAKE_128_RATE;
	uint8_t buf[(((769 + QSC_SHAKE_128_RATE) / QSC_SHAKE_128_RATE) * QSC_SHAKE_128_RATE) + 2];
	keccak_state kstate;
	uint8_t tmps[DILITHIUM_SEED_SIZE + 2];
	size_t buflen;
	size_t i;
	size_t off;
	uint32_t ctr;

	for (i = 0; i < QSC_SHA3_STATE_SIZE; ++i)
	{
		kstate.state[i] = 0;
	}

	buflen = NBLKS * QSC_SHAKE_128_RATE;

	for (i = 0; i < DILITHIUM_SEED_SIZE; ++i)
	{
		tmps[i] = seed[i];
	}

	tmps[DILITHIUM_SEED_SIZE] = (uint8_t)nonce;
	tmps[DILITHIUM_SEED_SIZE + 1] = nonce >> 8;
	qsc_shake128_initialize(&kstate, tmps, DILITHIUM_SEED_SIZE + 2);
	qsc_shake128_squeezeblocks(&kstate, buf, NBLKS);

	ctr = rej_uniform(a->coeffs, DILITHIUM_N, buf, buflen);

	while (ctr < DILITHIUM_N) 
	{
		off = buflen % 3;

		for (i = 0; i < off; ++i)
		{
			buf[i] = buf[buflen - off + i];
		}

		buflen = QSC_SHAKE_128_RATE + off;
		qsc_shake128_squeezeblocks(&kstate, buf + off, 1);
		ctr += rej_uniform(a->coeffs + ctr, DILITHIUM_N - ctr, buf, buflen);
	}
}

/*************************************************
* Name:        rej_eta
*
* Description: Sample uniformly random coefficients in [-DILITHIUM_ETA, DILITHIUM_ETA] by
*              performing rejection sampling using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - uint32_t len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - uint32_t buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static uint32_t rej_eta(uint32_t* a, uint32_t len, const uint8_t *buf, size_t buflen)
{
#if DILITHIUM_ETA > 7
#error "rej_eta() assumes DILITHIUM_ETA <= 7"
#endif

	size_t ctr;
	size_t pos;
	uint32_t t0;
	uint32_t t1;

	ctr = 0;
	pos = 0;

	while (ctr < len && pos < buflen)
	{
#if DILITHIUM_ETA <= 3
		t0 = buf[pos] & 0x07;
		t1 = buf[pos] >> 5;
		++pos;
#else
		t0 = buf[pos] & 0x0FU;
		t1 = buf[pos] >> 4;
		++pos;
#endif

		if (t0 <= 2 * DILITHIUM_ETA)
		{
			a[ctr] = DILITHIUM_Q + DILITHIUM_ETA - t0;
			++ctr;
		}

		if (t1 <= 2 * DILITHIUM_ETA && ctr < len)
		{
			a[ctr] = DILITHIUM_Q + DILITHIUM_ETA - t1;
			++ctr;
		}
	}

	return (uint32_t)ctr;
}

void poly_uniform_eta(poly* a, const uint8_t seed[DILITHIUM_SEED_SIZE], uint16_t nonce)
{
	const size_t NBLKS = ((DILITHIUM_N / 2 * (1U << DILITHIUM_SETABITS)) / (2 * DILITHIUM_ETA + 1) + QSC_SHAKE_128_RATE) / QSC_SHAKE_128_RATE;
	uint8_t buf[(((DILITHIUM_N / 2 * (1U << DILITHIUM_SETABITS)) / (2 * DILITHIUM_ETA + 1) + QSC_SHAKE_128_RATE) / QSC_SHAKE_128_RATE) * QSC_SHAKE_128_RATE];
	keccak_state kstate;
	uint8_t tmps[DILITHIUM_SEED_SIZE + 2];
	size_t buflen;
	size_t i;
	uint32_t ctr;

	buflen = NBLKS * QSC_SHAKE_128_RATE;

	for (i = 0; i < QSC_SHA3_STATE_SIZE; ++i)
	{
		kstate.state[i] = 0;
	}

	for (i = 0; i < DILITHIUM_SEED_SIZE; ++i)
	{
		tmps[i] = seed[i];
	}

	tmps[DILITHIUM_SEED_SIZE] = (uint8_t)nonce;
	tmps[DILITHIUM_SEED_SIZE + 1] = nonce >> 8;
	qsc_shake128_initialize(&kstate, tmps, DILITHIUM_SEED_SIZE + 2);
	qsc_shake128_squeezeblocks(&kstate, buf, NBLKS);

	ctr = rej_eta(a->coeffs, DILITHIUM_N, buf, buflen);

	while (ctr < DILITHIUM_N) 
	{
		qsc_shake128_squeezeblocks(&kstate, buf, 1);
		ctr += rej_eta(a->coeffs + ctr, DILITHIUM_N - ctr, buf, QSC_SHAKE_128_RATE);
	}
}

/*************************************************
* Name:        rej_gamma1m1
*
* Description: Sample uniformly random coefficients
*              in [-(DILITHIUM_GAMMA1 - 1), DILITHIUM_GAMMA1 - 1] by performing rejection sampling
*              using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - uint32_t len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - uint32_t buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static uint32_t rej_gamma1m1(uint32_t* a, uint32_t len, const uint8_t* buf, size_t buflen)
{
#if DILITHIUM_GAMMA1 > (1 << 19)
#error "rej_gamma1m1() assumes DILITHIUM_GAMMA1 - 1 fits in 19 bits"
#endif

	size_t ctr;
	size_t pos;
	uint32_t t0;
	uint32_t t1;

	ctr = 0;
	pos = 0;

	while (ctr < len && pos + 5 <= buflen) 
	{
		t0 = buf[pos];
		t0 |= (uint32_t)buf[pos + 1] << 8;
		t0 |= (uint32_t)buf[pos + 2] << 16;
		t0 &= 0x000FFFFFUL;

		t1 = buf[pos + 2] >> 4;
		t1 |= (uint32_t)buf[pos + 3] << 4;
		t1 |= (uint32_t)buf[pos + 4] << 12;

		pos += 5;

		if (t0 <= (2 * DILITHIUM_GAMMA1) - 2)
		{
			a[ctr] = DILITHIUM_Q + DILITHIUM_GAMMA1 - 1 - t0;
			++ctr;
		}

		if (t1 <= (2 * DILITHIUM_GAMMA1) - 2 && ctr < len)
		{
			a[ctr] = DILITHIUM_Q + DILITHIUM_GAMMA1 - 1 - t1;
			++ctr;
		}
	}

	return (uint32_t)ctr;
}

void poly_uniform_gamma1m1(poly* a, const uint8_t seed[DILITHIUM_CRH_SIZE], uint16_t nonce)
{
	const size_t NBLKS = (641 + QSC_SHAKE_256_RATE) / QSC_SHAKE_256_RATE;
	uint8_t buf[(((641 + QSC_SHAKE_256_RATE) / QSC_SHAKE_256_RATE) * QSC_SHAKE_256_RATE) + 4];
	keccak_state kstate;
	uint8_t tmps[DILITHIUM_CRH_SIZE + 2];
	size_t buflen;
	size_t i;
	size_t off;
	uint32_t ctr;

	for (i = 0; i < QSC_SHA3_STATE_SIZE; ++i)
	{
		kstate.state[i] = 0;
	}

	for (i = 0; i < DILITHIUM_CRH_SIZE; ++i)
	{
		tmps[i] = seed[i];
	}

	tmps[DILITHIUM_CRH_SIZE] = (uint8_t)nonce;
	tmps[DILITHIUM_CRH_SIZE + 1] = nonce >> 8;
	qsc_shake256_initialize(&kstate, tmps, DILITHIUM_CRH_SIZE + 2);
	qsc_shake256_squeezeblocks(&kstate, buf, NBLKS);
	buflen = NBLKS * QSC_SHAKE_256_RATE;

	ctr = rej_gamma1m1(a->coeffs, DILITHIUM_N, buf, buflen);

	while (ctr < DILITHIUM_N) 
	{
		off = buflen % 5;

		for (i = 0; i < off; ++i)
		{
			buf[i] = buf[buflen - off + i];
		}

		buflen = QSC_SHAKE_256_RATE + off;
		qsc_shake256_squeezeblocks(&kstate, buf + off, 1);
		ctr += rej_gamma1m1(a->coeffs + ctr, DILITHIUM_N - ctr, buf, buflen);
	}
}

void polyeta_pack(uint8_t* r, const poly* a) 
{
#if 2 * DILITHIUM_ETA >= 16
#	error "polyeta_pack() assumes 2*DILITHIUM_ETA < 16"
#endif
	size_t i;
	uint8_t t[8];

#if (2 * DILITHIUM_ETA) <= 7

	for (i = 0; i < DILITHIUM_N / 8; ++i) 
	{
		t[0] = DILITHIUM_Q + DILITHIUM_ETA - a->coeffs[(8 * i)];
		t[1] = DILITHIUM_Q + DILITHIUM_ETA - a->coeffs[(8 * i) + 1];
		t[2] = DILITHIUM_Q + DILITHIUM_ETA - a->coeffs[(8 * i) + 2];
		t[3] = DILITHIUM_Q + DILITHIUM_ETA - a->coeffs[(8 * i) + 3];
		t[4] = DILITHIUM_Q + DILITHIUM_ETA - a->coeffs[(8 * i) + 4];
		t[5] = DILITHIUM_Q + DILITHIUM_ETA - a->coeffs[(8 * i) + 5];
		t[6] = DILITHIUM_Q + DILITHIUM_ETA - a->coeffs[(8 * i) + 6];
		t[7] = DILITHIUM_Q + DILITHIUM_ETA - a->coeffs[(8 * i) + 7];

		r[(3 * i)] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
		r[(3 * i) + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[(3 * i) + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
	}

#else

	for (i = 0; i < DILITHIUM_N / 2; ++i) 
	{
		t[0] = DILITHIUM_Q + DILITHIUM_ETA - a->coeffs[(2 * i)];
		t[1] = DILITHIUM_Q + DILITHIUM_ETA - a->coeffs[(2 * i) + 1];
		r[i] = t[0] | (uint8_t)(t[1] << 4);
	}

#endif
}

void polyeta_unpack(poly* r, const uint8_t* a) 
{
	size_t i;

#if (2 * DILITHIUM_ETA) <= 7

	for (i = 0; i < DILITHIUM_N / 8; ++i) 
	{
		r->coeffs[(8 * i)] = a[3 * i] & 0x07;
		r->coeffs[(8 * i) + 1] = (a[3 * i] >> 3) & 0x07;
		r->coeffs[(8 * i) + 2] = ((a[3 * i] >> 6) | (a[(3 * i) + 1] << 2)) & 0x07;
		r->coeffs[(8 * i) + 3] = (a[(3 * i) + 1] >> 1) & 0x07;
		r->coeffs[(8 * i) + 4] = (a[(3 * i) + 1] >> 4) & 0x07;
		r->coeffs[(8 * i) + 5] = ((a[(3 * i) + 1] >> 7) | (a[(3 * i) + 2] << 1)) & 0x07;
		r->coeffs[(8 * i) + 6] = (a[(3 * i) + 2] >> 2) & 0x07;
		r->coeffs[(8 * i) + 7] = (a[(3 * i) + 2] >> 5) & 0x07;

		r->coeffs[(8 * i)] = DILITHIUM_Q + DILITHIUM_ETA - r->coeffs[(8 * i)];
		r->coeffs[(8 * i) + 1] = DILITHIUM_Q + DILITHIUM_ETA - r->coeffs[(8 * i) + 1];
		r->coeffs[(8 * i) + 2] = DILITHIUM_Q + DILITHIUM_ETA - r->coeffs[(8 * i) + 2];
		r->coeffs[(8 * i) + 3] = DILITHIUM_Q + DILITHIUM_ETA - r->coeffs[(8 * i) + 3];
		r->coeffs[(8 * i) + 4] = DILITHIUM_Q + DILITHIUM_ETA - r->coeffs[(8 * i) + 4];
		r->coeffs[(8 * i) + 5] = DILITHIUM_Q + DILITHIUM_ETA - r->coeffs[(8 * i) + 5];
		r->coeffs[(8 * i) + 6] = DILITHIUM_Q + DILITHIUM_ETA - r->coeffs[(8 * i) + 6];
		r->coeffs[(8 * i) + 7] = DILITHIUM_Q + DILITHIUM_ETA - r->coeffs[(8 * i) + 7];
	}

#else

	for (i = 0; i < DILITHIUM_N / 2; ++i) 
	{
		r->coeffs[(2 * i)] = a[i] & 0x0Fu;
		r->coeffs[(2 * i) + 1] = a[i] >> 4;
		r->coeffs[(2 * i)] = DILITHIUM_Q + DILITHIUM_ETA - r->coeffs[2 * i];
		r->coeffs[(2 * i) + 1] = DILITHIUM_Q + DILITHIUM_ETA - r->coeffs[(2 * i) + 1];
	}

#endif
}

void polyt1_pack(uint8_t* r, const poly* a) 
{
#if DILITHIUM_D != 14
#error "polyt1_pack() assumes DILITHIUM_D == 14"
#endif

	size_t i;

	for (i = 0; i < DILITHIUM_N / 8; ++i) 
	{
		r[(9 * i)] = (a->coeffs[(8 * i)] >> 0);
		r[(9 * i) + 1] = (a->coeffs[(8 * i)] >> 8) | (a->coeffs[(8 * i) + 1] << 1);
		r[(9 * i) + 2] = (a->coeffs[(8 * i) + 1] >> 7) | (a->coeffs[(8 * i) + 2] << 2);
		r[(9 * i) + 3] = (a->coeffs[(8 * i) + 2] >> 6) | (a->coeffs[(8 * i) + 3] << 3);
		r[(9 * i) + 4] = (a->coeffs[(8 * i) + 3] >> 5) | (a->coeffs[(8 * i) + 4] << 4);
		r[(9 * i) + 5] = (a->coeffs[(8 * i) + 4] >> 4) | (a->coeffs[(8 * i) + 5] << 5);
		r[(9 * i) + 6] = (a->coeffs[(8 * i) + 5] >> 3) | (a->coeffs[(8 * i) + 6] << 6);
		r[(9 * i) + 7] = (a->coeffs[(8 * i) + 6] >> 2) | (a->coeffs[(8 * i) + 7] << 7);
		r[(9 * i) + 8] = (a->coeffs[(8 * i) + 7] >> 1);
	}
}

void polyt1_unpack(poly* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < DILITHIUM_N / 8; ++i) 
	{
		r->coeffs[(8 * i)] = (((uint32_t)a[(9 * i)]) | ((uint32_t)a[(9 * i) + 1] << 8)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 1] = (((uint32_t)a[(9 * i) + 1] >> 1) | ((uint32_t)a[(9 * i) + 2] << 7)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 2] = (((uint32_t)a[(9 * i) + 2] >> 2) | ((uint32_t)a[(9 * i) + 3] << 6)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 3] = (((uint32_t)a[(9 * i) + 3] >> 3) | ((uint32_t)a[(9 * i) + 4] << 5)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 4] = (((uint32_t)a[(9 * i) + 4] >> 4) | ((uint32_t)a[(9 * i) + 5] << 4)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 5] = (((uint32_t)a[(9 * i) + 5] >> 5) | ((uint32_t)a[(9 * i) + 6] << 3)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 6] = (((uint32_t)a[(9 * i) + 6] >> 6) | ((uint32_t)a[(9 * i) + 7] << 2)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 7] = (((uint32_t)a[(9 * i) + 7] >> 7) | ((uint32_t)a[(9 * i) + 8] << 1)) & 0x000001FFUL;
	}
}

void polyt0_pack(uint8_t* r, const poly* a)
{
	size_t i;
	uint32_t t[4];

	for (i = 0; i < DILITHIUM_N / 4; ++i) 
	{
		t[0] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - a->coeffs[(4 * i)];
		t[1] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - a->coeffs[(4 * i) + 1];
		t[2] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - a->coeffs[(4 * i) + 2];
		t[3] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - a->coeffs[(4 * i) + 3];

		r[(7 * i)] = t[0];
		r[(7 * i) + 1] = t[0] >> 8;
		r[(7 * i) + 1] |= t[1] << 6;
		r[(7 * i) + 2] = t[1] >> 2;
		r[(7 * i) + 3] = t[1] >> 10;
		r[(7 * i) + 3] |= t[2] << 4;
		r[(7 * i) + 4] = t[2] >> 4;
		r[(7 * i) + 5] = t[2] >> 12;
		r[(7 * i) + 5] |= t[3] << 2;
		r[(7 * i) + 6] = t[3] >> 6;
	}
}

void polyt0_unpack(poly* r, const uint8_t* a) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_N / 4; ++i) 
	{
		r->coeffs[(4 * i)] = a[(7 * i)];
		r->coeffs[(4 * i)] |= (uint32_t)(a[(7 * i) + 1] & 0x3FU) << 8;

		r->coeffs[(4 * i) + 1] = a[(7 * i) + 1] >> 6;
		r->coeffs[(4 * i) + 1] |= (uint32_t)a[(7 * i) + 2] << 2;
		r->coeffs[(4 * i) + 1] |= (uint32_t)(a[(7 * i) + 3] & 0x0FU) << 10;

		r->coeffs[(4 * i) + 2] = a[(7 * i) + 3] >> 4;
		r->coeffs[(4 * i) + 2] |= (uint32_t)a[(7 * i) + 4] << 4;
		r->coeffs[(4 * i) + 2] |= (uint32_t)(a[(7 * i) + 5] & 0x03U) << 12;

		r->coeffs[(4 * i) + 3] = a[(7 * i) + 5] >> 2;
		r->coeffs[(4 * i) + 3] |= (uint32_t)a[(7 * i) + 6] << 6;

		r->coeffs[(4 * i)] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - r->coeffs[(4 * i)];
		r->coeffs[(4 * i) + 1] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - r->coeffs[(4 * i) + 1];
		r->coeffs[(4 * i) + 2] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - r->coeffs[(4 * i) + 2];
		r->coeffs[(4 * i) + 3] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - r->coeffs[(4 * i) + 3];
	}
}

void polyz_pack(uint8_t* r, const poly* a) 
{
#if DILITHIUM_GAMMA1 > (1 << 19)
#error "polyz_pack() assumes DILITHIUM_GAMMA1 <= 2^{19}"
#endif

	size_t i;
	uint32_t t[2];

	for (i = 0; i < DILITHIUM_N / 2; ++i) 
	{
		/* Map to {0,...,2*DILITHIUM_GAMMA1 - 2} */
		t[0] = DILITHIUM_GAMMA1 - 1 - a->coeffs[(2 * i)];
		t[0] += ((int32_t)t[0] >> 31) & DILITHIUM_Q;
		t[1] = DILITHIUM_GAMMA1 - 1 - a->coeffs[(2 * i) + 1];
		t[1] += ((int32_t)t[1] >> 31) & DILITHIUM_Q;

		r[(5 * i)] = t[0];
		r[(5 * i) + 1] = t[0] >> 8;
		r[(5 * i) + 2] = t[0] >> 16;
		r[(5 * i) + 2] |= t[1] << 4;
		r[(5 * i) + 3] = t[1] >> 4;
		r[(5 * i) + 4] = t[1] >> 12;
	}
}

void polyz_unpack(poly* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < DILITHIUM_N / 2; ++i)
	{
		r->coeffs[(2 * i)] = a[(5 * i)];
		r->coeffs[(2 * i)] |= (uint32_t)a[(5 * i) + 1] << 8;
		r->coeffs[(2 * i)] |= (uint32_t)(a[(5 * i) + 2] & 0x0FU) << 16;

		r->coeffs[(2 * i) + 1] = a[(5 * i) + 2] >> 4;
		r->coeffs[(2 * i) + 1] |= (uint32_t)a[(5 * i) + 3] << 4;
		r->coeffs[(2 * i) + 1] |= (uint32_t)a[(5 * i) + 4] << 12;

		r->coeffs[(2 * i)] = DILITHIUM_GAMMA1 - 1 - r->coeffs[(2 * i)];
		r->coeffs[(2 * i)] += ((int32_t)r->coeffs[(2 * i)] >> 31) & DILITHIUM_Q;
		r->coeffs[(2 * i) + 1] = DILITHIUM_GAMMA1 - 1 - r->coeffs[(2 * i) + 1];
		r->coeffs[(2 * i) + 1] += ((int32_t)r->coeffs[(2 * i) + 1] >> 31) & DILITHIUM_Q;
	}
}

void polyw1_pack(uint8_t* r, const poly* a)
{
	size_t i;

	for (i = 0; i < DILITHIUM_N / 2; ++i)
	{
		r[i] = a->coeffs[(2 * i)] | (a->coeffs[(2 * i) + 1] << 4);
	}
}
