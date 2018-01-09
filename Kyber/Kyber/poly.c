#include "poly.h"
#include "cbd.h"
#include "ntt.h"
#include "reduce.h"
#include "sha3.h"

/* Note: compress, decompress, tobytes, frombytes, frommsg, tomsg, unit tested against original, 01/08/2018 */

void poly_compress(uint8_t* r, const poly* a)
{
	uint32_t t[8];
	size_t i; 
	size_t j;
	size_t k;

	k = 0;

	for (i = 0; i < KYBER_N; i += 8)
	{
		for (j = 0; j < 8; j++)
		{
			/* checked: lint-misra 661-662 'possible out-of-bounds', this is a false positive */
			t[j] = ((((freeze(a->coeffs[i + j]) << 3) + (KYBER_Q / 2)) / KYBER_Q) & 7); /*lint !e662 !e661 */
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

	for (i = 0; i < KYBER_N; i += 8)
	{
		/* checked: lint-misra 661-662 errors are all 'possible out-of-bounds' false positives */
		r->coeffs[i] = ((((a[0] & 7) * KYBER_Q) + 4) >> 3);
		r->coeffs[i + 1] = (((((a[0] >> 3) & 7) * KYBER_Q) + 4) >> 3); /*lint !e661 */
		r->coeffs[i + 2] = (((((a[0] >> 6) | ((a[1] << 2) & 4)) * KYBER_Q) + 4) >> 3); /*lint !e662 !e661 */
		r->coeffs[i + 3] = (((((a[1] >> 1) & 7) * KYBER_Q) + 4) >> 3); /*lint !e662 !e661 */
		r->coeffs[i + 4] = (((((a[1] >> 4) & 7) * KYBER_Q) + 4) >> 3); /*lint !e662 !e661 */
		r->coeffs[i + 5] = (((((a[1] >> 7) | ((a[2] << 1) & 6)) * KYBER_Q) + 4) >> 3); /*lint !e662 !e661 */
		r->coeffs[i + 6] = (((((a[2] >> 2) & 7) * KYBER_Q) + 4) >> 3); /*lint !e662 !e661 */
		r->coeffs[i + 7] = (((((a[2] >> 5)) * KYBER_Q) + 4) >> 3); /*lint !e662 !e661 */
		a += 3; /*lint !e662 !e661 */
	}
}

void poly_tobytes(uint8_t* r, const poly* a)
{
	uint16_t t[8];
	size_t i;
	size_t j;

	for (i = 0; i < KYBER_N / 8; i++)
	{
		for (j = 0; j < 8; j++)
		{
			t[j] = freeze(a->coeffs[(8 * i) + j]);
		}

		r[13 * i] = (t[0] & 0xFF);
		r[(13 * i) + 1] = ((t[0] >> 8) | ((t[1] & 0x07) << 5));
		r[(13 * i) + 2] = ((t[1] >> 3) & 0xFF);
		r[(13 * i) + 3] = ((t[1] >> 11) | ((t[2] & 0x3F) << 2));
		r[(13 * i) + 4] = ((t[2] >> 6) | ((t[3] & 0x01) << 7));
		r[(13 * i) + 5] = ((t[3] >> 1) & 0xFF);
		r[(13 * i) + 6] = ((t[3] >> 9) | ((t[4] & 0x0F) << 4));
		r[(13 * i) + 7] = ((t[4] >> 4) & 0xFF);
		r[(13 * i) + 8] = ((t[4] >> 12) | ((t[5] & 0x7F) << 1));
		r[(13 * i) + 9] = ((t[5] >> 7) | ((t[6] & 0x03) << 6));
		r[(13 * i) + 10] = ((t[6] >> 2) & 0xFF);
		r[(13 * i) + 11] = ((t[6] >> 10) | ((t[7] & 0x1F) << 3));
		r[(13 * i) + 12] = (t[7] >> 5);
	}
}

void poly_frombytes(poly* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < KYBER_N / 8; i++)
	{
		r->coeffs[8 * i] = (a[13 * i] | (((uint16_t)a[(13 * i) + 1] & 0x1F) << 8));
		r->coeffs[(8 * i) + 1] = ((a[(13 * i) + 1] >> 5) | (((uint16_t)a[(13 * i) + 2]) << 3) | (((uint16_t)a[(13 * i) + 3] & 0x03) << 11));
		r->coeffs[(8 * i) + 2] = ((a[(13 * i) + 3] >> 2) | (((uint16_t)a[(13 * i) + 4] & 0x7F) << 6));
		r->coeffs[(8 * i) + 3] = ((a[(13 * i) + 4] >> 7) | (((uint16_t)a[(13 * i) + 5]) << 1) | (((uint16_t)a[(13 * i) + 6] & 0x0F) << 9));
		r->coeffs[(8 * i) + 4] = ((a[(13 * i) + 6] >> 4) | (((uint16_t)a[(13 * i) + 7]) << 4) | (((uint16_t)a[(13 * i) + 8] & 0x01) << 12));
		r->coeffs[(8 * i) + 5] = ((a[(13 * i) + 8] >> 1) | (((uint16_t)a[(13 * i) + 9] & 0x3F) << 7));
		r->coeffs[(8 * i) + 6] = ((a[(13 * i) + 9] >> 6) | (((uint16_t)a[(13 * i) + 10]) << 2) | (((uint16_t)a[(13 * i) + 11] & 0x07) << 10));
		r->coeffs[(8 * i) + 7] = ((a[(13 * i) + 11] >> 3) | (((uint16_t)a[(13 * i) + 12]) << 5));
	}
}

void poly_getnoise(poly* r, const uint8_t* seed, uint8_t nonce)
{
	uint8_t buf[(KYBER_ETA * KYBER_N) / 4];

#ifdef MATRIX_GENERATOR_CSHAKE

	cshake256_simple(buf, (KYBER_ETA * KYBER_N) / 4, nonce, seed, KYBER_SYMBYTES);

#else

	uint8_t extseed[KYBER_SYMBYTES + 1];
	size_t i;

	for (i = 0; i < KYBER_SYMBYTES; i++)
	{
		extseed[i] = seed[i];
	}

	extseed[KYBER_SYMBYTES] = nonce;
	shake256(buf, (KYBER_ETA * KYBER_N) / 4, extseed, KYBER_SYMBYTES + 1);

#endif

	cbd(r, buf);
}

void poly_ntt(poly* r)
{
	ntt(r->coeffs);
}

void poly_invntt(poly* r)
{
	invntt(r->coeffs);
}

void poly_add(poly* r, const poly* a, const poly* b)
{
	size_t i;

	for (i = 0; i < KYBER_N; i++)
	{
		r->coeffs[i] = barrett_reduce(a->coeffs[i] + b->coeffs[i]);
	}
}

void poly_sub(poly* r, const poly* a, const poly* b)
{
	size_t i;

	for (i = 0; i < KYBER_N; i++)
	{
		r->coeffs[i] = barrett_reduce(a->coeffs[i] + ((3 * KYBER_Q) - b->coeffs[i]));
	}
}

void poly_frommsg(poly* r, const uint8_t msg[KYBER_SYMBYTES])
{
	size_t i;
	size_t j;
	uint16_t mask;

	for (i = 0; i < KYBER_SYMBYTES; i++)
	{
		for (j = 0; j < 8; j++)
		{
			mask = ~((msg[i] >> j) & 1) + 1;
			r->coeffs[(8 * i) + j] = (mask & ((KYBER_Q + 1) / 2));
		}
	}
}

void poly_tomsg(uint8_t msg[KYBER_SYMBYTES], const poly* a)
{
	size_t i;
	size_t j;
	uint16_t t;

	for (i = 0; i < KYBER_SYMBYTES; i++)
	{
		msg[i] = 0;

		for (j = 0; j < 8; j++)
		{
			t = ((((freeze(a->coeffs[(8 * i) + j]) << 1) + KYBER_Q / 2) / KYBER_Q) & 1);
			msg[i] |= (t << j);
		}
	}
}
