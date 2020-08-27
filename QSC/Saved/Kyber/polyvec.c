#include "polyvec.h"

void polyvec_compress(uint8_t* r, polyvec* a)
{
	size_t i;
	size_t j;
	size_t k;

	polyvec_csubq(a);

#if (KYBER_POLYVECBASEBYTES == 352)

	uint16_t t[8];

	for (i = 0; i < KYBER_K; ++i)
	{
		for (j = 0; j < KYBER_N / 8; ++j)
		{
			for (k = 0; k < 8; ++k)
			{
				t[k] = ((((uint32_t)a->vec[i].coeffs[(8 * j) + k] << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7FF;
			}

			r[11 * j] = t[0] & 0xFF;
			r[(11 * j) + 1] = (t[0] >> 8) | ((t[1] & 0x1F) << 3);
			r[(11 * j) + 2] = (t[1] >> 5) | ((t[2] & 0x03) << 6);
			r[(11 * j) + 3] = (t[2] >> 2) & 0xFF;
			r[(11 * j) + 4] = (t[2] >> 10) | ((t[3] & 0x7F) << 1);
			r[(11 * j) + 5] = (t[3] >> 7) | ((t[4] & 0x0F) << 4);
			r[(11 * j) + 6] = (t[4] >> 4) | ((t[5] & 0x01) << 7);
			r[(11 * j) + 7] = (t[5] >> 1) & 0xff;
			r[(11 * j) + 8] = (t[5] >> 9) | ((t[6] & 0x3F) << 2);
			r[(11 * j) + 9] = (t[6] >> 6) | ((t[7] & 0x07) << 5);
			r[(11 * j) + 10] = (t[7] >> 3);
		}

		r += KYBER_POLYVECBASEBYTES;
	}

#elif (KYBER_POLYVECBASEBYTES == 320)

	uint16_t t[4];

	for (i = 0; i < KYBER_K; ++i)
	{
		for (j = 0; j < KYBER_N / 4; ++j)
		{
			for (k = 0; k < 4; ++k)
			{
				t[k] = ((((uint32_t)a->vec[i].coeffs[(4 * j) + k] << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3FFU;
			}

			r[5 * j] = (uint8_t)(t[0] & 0xFFU);
			r[(5 * j) + 1] = (uint8_t)((t[0] >> 8U) | ((t[1] & 0x3FU) << 2U));
			r[(5 * j) + 2] = (uint8_t)((t[1] >> 6U) | ((t[2] & 0x0FU) << 4U));
			r[(5 * j) + 3] = (uint8_t)((t[2] >> 4U) | ((t[3] & 0x03U) << 6U));
			r[(5 * j) + 4] = (uint8_t)((t[3] >> 2U));
		}

		r += KYBER_POLYVECBASEBYTES;
	}

#endif
}

void polyvec_decompress(polyvec* r, const uint8_t* a)
{
	size_t i;
	size_t j;

#if (KYBER_POLYVECBASEBYTES == 352)

	for (i = 0; i < KYBER_K; i++)
	{
		for (j = 0; j < KYBER_N / 8; j++)
		{
			r->vec[i].coeffs[(8 * j)] = (((a[(11 * j)] | (((uint32_t)a[(11 * j) + 1] & 0x07) << 8)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 1] = ((((a[(11 * j) + 1] >> 3) | (((uint32_t)a[(11 * j) + 2] & 0x3F) << 5)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 2] = ((((a[(11 * j) + 2] >> 6) | (((uint32_t)a[(11 * j) + 3] & 0xFF) << 2) | (((uint32_t)a[(11 * j) + 4] & 0x01) << 10)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 3] = ((((a[(11 * j) + 4] >> 1) | (((uint32_t)a[(11 * j) + 5] & 0x0F) << 7)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 4] = ((((a[(11 * j) + 5] >> 4) | (((uint32_t)a[(11 * j) + 6] & 0x7F) << 4)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 5] = ((((a[(11 * j) + 6] >> 7) | (((uint32_t)a[(11 * j) + 7] & 0xFF) << 1) | (((uint32_t)a[(11 * j) + 8] & 0x03) << 9)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 6] = ((((a[(11 * j) + 8] >> 2) | (((uint32_t)a[(11 * j) + 9] & 0x1F) << 6)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 7] = ((((a[(11 * j) + 9] >> 5) | (((uint32_t)a[(11 * j) + 10] & 0xFF) << 3)) * KYBER_Q) + 1024) >> 11;
		}

		a += KYBER_POLYVECBASEBYTES;
	}

#elif (KYBER_POLYVECBASEBYTES == 320)

	for (i = 0; i < KYBER_K; ++i)
	{
		for (j = 0; j < KYBER_N / 4; ++j)
		{
			r->vec[i].coeffs[4 * j] = (((a[5 * j] | (((uint32_t)a[(5 * j) + 1] & 0x03U) << 8U)) * KYBER_Q) + 512) >> 10U;
			r->vec[i].coeffs[(4 * j) + 1] = ((((a[(5 * j) + 1] >> 2U) | (((uint32_t)a[(5 * j) + 2] & 0x0FU) << 6U)) * KYBER_Q) + 512) >> 10U;
			r->vec[i].coeffs[(4 * j) + 2] = ((((a[(5 * j) + 2] >> 4U) | (((uint32_t)a[(5 * j) + 3] & 0x3FU) << 4U)) * KYBER_Q) + 512) >> 10U;
			r->vec[i].coeffs[(4 * j) + 3] = ((((a[(5 * j) + 3] >> 6U) | (((uint32_t)a[(5 * j) + 4] & 0xFFU) << 2U)) * KYBER_Q) + 512) >> 10U;
		}

		a += KYBER_POLYVECBASEBYTES;
	}

#endif
}

void polyvec_tobytes(uint8_t* r, polyvec* a)
{
	size_t i;

	for (i = 0; i < KYBER_K; ++i)
	{
		poly_tobytes(r + (i * KYBER_POLYBYTES), &a->vec[i]);
	}
}

void polyvec_frombytes(polyvec* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < KYBER_K; ++i)
	{
		poly_frombytes(&r->vec[i], a + (i * KYBER_POLYBYTES));
	}
}

void polyvec_ntt(polyvec* r)
{
	size_t i;

	for (i = 0; i < KYBER_K; ++i)
	{
		poly_ntt(&r->vec[i]);
	}
}

void polyvec_invntt(polyvec* r)
{
	size_t i;

	for (i = 0; i < KYBER_K; ++i)
	{
		poly_invntt(&r->vec[i]);
	}
}

void polyvec_pointwise_acc(poly* r, const polyvec* a, const polyvec* b)
{
	poly t;
	size_t i;

	poly_basemul(r, &a->vec[0], &b->vec[0]);

	for (i = 1; i < KYBER_K; ++i) 
	{
		poly_basemul(&t, &a->vec[i], &b->vec[i]);
		poly_add(r, r, &t);
	}

	poly_reduce(r);
}

void polyvec_reduce(polyvec* r)
{
	size_t i;

	for (i = 0; i < KYBER_K; ++i)
	{
		poly_reduce(&r->vec[i]);
	}
}

void polyvec_csubq(polyvec* r)
{
	size_t i;

	for (i = 0; i < KYBER_K; ++i)
	{
		poly_csubq(&r->vec[i]);
	}
}

void polyvec_add(polyvec* r, const polyvec* a, const polyvec* b)
{
	size_t i;

	for (i = 0; i < KYBER_K; ++i)
	{
		poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
	}
}
