#include "polyvec.h"
#include "cbd.h"
#include "reduce.h"
#include "sha3.h"

/* Note: compress, decompress, in K{2,3,4} unit tested against original, 01/08/2018 */

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))

	void polyvec_compress(uint8_t* r, const polyvec* a)
	{
		uint16_t t[8];
		size_t i;
		size_t j;
		size_t k;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 8; j++)
			{
				for (k = 0; k < 8; k++)
				{
					t[k] = ((((uint32_t)freeze(a->vec[i].coeffs[(8 * j) + k]) << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7FF;
				}

				r[11 * j] = (t[0] & 0xFF);
				r[(11 * j) + 1] = ((t[0] >> 8) | ((t[1] & 0x1F) << 3));
				r[(11 * j) + 2] = ((t[1] >> 5) | ((t[2] & 0x03) << 6));
				r[(11 * j) + 3] = ((t[2] >> 2) & 0xFF);
				r[(11 * j) + 4] = ((t[2] >> 10) | ((t[3] & 0x7F) << 1));
				r[(11 * j) + 5] = ((t[3] >> 7) | ((t[4] & 0x0F) << 4));
				r[(11 * j) + 6] = ((t[4] >> 4) | ((t[5] & 0x01) << 7));
				r[(11 * j) + 7] = ((t[5] >> 1) & 0xFF);
				r[(11 * j) + 8] = ((t[5] >> 9) | ((t[6] & 0x3F) << 2));
				r[(11 * j) + 9] = ((t[6] >> 6) | ((t[7] & 0x07) << 5));
				r[(11 * j) + 10] = (t[7] >> 3);
			}
			r += 352;
		}
	}

	void polyvec_decompress(polyvec* r, const uint8_t* a)
	{
		size_t i;
		size_t j;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 8; j++)
			{
				r->vec[i].coeffs[8 * j] = ((((a[11 * j] | (((uint32_t)a[(11 * j) + 1] & 0x07) << 8)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 1] = (((((a[(11 * j) + 1] >> 3) | (((uint32_t)a[(11 * j) + 2] & 0x3F) << 5)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 2] = (((((a[(11 * j) + 2] >> 6) | (((uint32_t)a[(11 * j) + 3] & 0xFF) << 2) | (((uint32_t)a[(11 * j) + 4] & 0x01) << 10)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 3] = (((((a[(11 * j) + 4] >> 1) | (((uint32_t)a[(11 * j) + 5] & 0x0F) << 7)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 4] = (((((a[(11 * j) + 5] >> 4) | (((uint32_t)a[(11 * j) + 6] & 0x7F) << 4)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 5] = (((((a[(11 * j) + 6] >> 7) | (((uint32_t)a[(11 * j) + 7] & 0xFF) << 1) | (((uint32_t)a[(11 * j) + 8] & 0x03) << 9)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 6] = (((((a[(11 * j) + 8] >> 2) | (((uint32_t)a[(11 * j) + 9] & 0x1F) << 6)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 7] = (((((a[(11 * j) + 9] >> 5) | (((uint32_t)a[(11 * j) + 10] & 0xFF) << 3)) * KYBER_Q) + 1024) >> 11);
			}
			a += 352;
		}
	}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))

	void polyvec_compress(uint8_t* r, const polyvec* a)
	{
		uint16_t t[4];
		size_t i;
		size_t j;
		size_t k;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 4; j++)
			{
				for (k = 0; k < 4; k++)
				{
					t[k] = (((((uint32_t)freeze(a->vec[i].coeffs[(4 * j) + k]) << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3FF);
				}

				r[5 * j] = (t[0] & 0xFF);
				r[(5 * j) + 1] = (t[0] >> 8) | ((t[1] & 0x3F) << 2);
				r[(5 * j) + 2] = (t[1] >> 6) | ((t[2] & 0x0F) << 4);
				r[(5 * j) + 3] = (t[2] >> 4) | ((t[3] & 0x03) << 6);
				r[(5 * j) + 4] = (t[3] >> 2);
			}
			r += 320;
		}
	}

	void polyvec_decompress(polyvec* r, const uint8_t* a)
	{
		size_t i;
		size_t j;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 4; j++)
			{
				r->vec[i].coeffs[4 * j] = ((((a[5 * j] | (((uint32_t)a[(5 * j) + 1] & 0x03) << 8)) * KYBER_Q) + 512) >> 10);
				r->vec[i].coeffs[(4 * j) + 1] = (((((a[(5 * j) + 1] >> 2) | (((uint32_t)a[(5 * j) + 2] & 0x0F) << 6)) * KYBER_Q) + 512) >> 10);
				r->vec[i].coeffs[(4 * j) + 2] = (((((a[(5 * j) + 2] >> 4) | (((uint32_t)a[(5 * j) + 3] & 0x3F) << 4)) * KYBER_Q) + 512) >> 10);
				r->vec[i].coeffs[(4 * j) + 3] = (((((a[(5 * j) + 3] >> 6) | (((uint32_t)a[(5 * j) + 4] & 0xFF) << 2)) * KYBER_Q) + 512) >> 10);
			}
			a += 320;
		}
	}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 288))

	void polyvec_compress(uint8_t* r, const polyvec* a)
	{
		uint16_t t[8];
		size_t i;
		size_t j;
		size_t k;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 8; j++)
			{
				for (k = 0; k < 8; k++)
				{
					t[k] = (((((uint32_t)freeze(a->vec[i].coeffs[(8 * j) + k]) << 9) + KYBER_Q / 2) / KYBER_Q) & 0x1FF);
				}

				r[9 * j] = (t[0] & 0xFF);
				r[(9 * j) + 1] = ((t[0] >> 8) | ((t[1] & 0x7F) << 1));
				r[(9 * j) + 2] = ((t[1] >> 7) | ((t[2] & 0x3F) << 2));
				r[(9 * j) + 3] = ((t[2] >> 6) | ((t[3] & 0x1F) << 3));
				r[(9 * j) + 4] = ((t[3] >> 5) | ((t[4] & 0x0F) << 4));
				r[(9 * j) + 5] = ((t[4] >> 4) | ((t[5] & 0x07) << 5));
				r[(9 * j) + 6] = ((t[5] >> 3) | ((t[6] & 0x03) << 6));
				r[(9 * j) + 7] = ((t[6] >> 2) | ((t[7] & 0x01) << 7));
				r[(9 * j) + 8] = ((t[7] >> 1);
			}
			r += 288;
		}
	}

	void polyvec_decompress(polyvec* r, const uint8_t* a)
	{
		size_t i;
		size_t j;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 8; j++)
			{
				r->vec[i].coeffs[8 * j] = ((((a[9 * j] | (((uint32_t)a[(9 * j) + 1] & 0x01) << 8)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 1] = (((((a[(9 * j) + 1] >> 1) | (((uint32_t)a[(9 * j) + 2] & 0x03) << 7)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 2] = (((((a[(9 * j) + 2] >> 2) | (((uint32_t)a[(9 * j) + 3] & 0x07) << 6)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 3] = (((((a[(9 * j) + 3] >> 3) | (((uint32_t)a[(9 * j) + 4] & 0x0F) << 5)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 4] = (((((a[(9 * j) + 4] >> 4) | (((uint32_t)a[(9 * j) + 5] & 0x1F) << 4)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 5] = (((((a[(9 * j) + 5] >> 5) | (((uint32_t)a[(9 * j) + 6] & 0x3F) << 3)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 6] = (((((a[(9 * j) + 6] >> 6) | (((uint32_t)a[(9 * j) + 7] & 0x7F) << 2)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 7] = (((((a[(9 * j) + 7] >> 7) | (((uint32_t)a[(9 * j) + 8] & 0xFF) << 1)) * KYBER_Q) + 256) >> 9);
			}
			a += 288;
		}
	}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 256))

	void polyvec_compress(uint8_t* r, const polyvec* a)
	{
		size_t i;
		size_t j;
		size_t k;
		uint16_t t;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N; j++)
			{
				r[j] = (((((uint32_t)freeze(a->vec[i].coeffs[j]) << 8) + KYBER_Q / 2) / KYBER_Q) & 0xFF);
			}
			r += 256;
		}
	}

	void polyvec_decompress(polyvec* r, const uint8_t* a)
	{
		size_t i;
		size_t j;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N; j++)
			{
				r->vec[i].coeffs[j] = (((a[j] * KYBER_Q) + 128) >> 8);
			}
			a += 256;
		}
	}

#else 
  #error "Unsupported compression of polyvec"
#endif

void polyvec_tobytes(uint8_t* r, const polyvec* a)
{
	size_t i;

	for (i = 0; i < KYBER_K; i++)
	{
		poly_tobytes(r + (i * KYBER_POLYBYTES), &a->vec[i]);
	}
}

void polyvec_frombytes(polyvec* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < KYBER_K; i++)
	{
		poly_frombytes(&r->vec[i], a + (i * KYBER_POLYBYTES));
	}
}

void polyvec_ntt(polyvec* r)
{
	size_t i;

	for (i = 0; i < KYBER_K; i++)
	{
		poly_ntt(&r->vec[i]);
	}
}

void polyvec_invntt(polyvec* r)
{
	size_t i;

	for (i = 0; i < KYBER_K; i++)
	{
		poly_invntt(&r->vec[i]);
	}
}

void polyvec_pointwise_acc(poly* r, const polyvec* a, const polyvec* b)
{
	size_t i;
	size_t j;
	uint16_t t;

	for (j = 0; j < KYBER_N; j++)
	{
		/* 4613(0x1205UL) = 2^{2*18} % q */
		t = montgomery_reduce(0x1205UL * (uint32_t)b->vec[0].coeffs[j]);
		r->coeffs[j] = montgomery_reduce(a->vec[0].coeffs[j] * t);

		for (i = 1; i < KYBER_K; i++)
		{
			t = montgomery_reduce(0x1205UL * (uint32_t)b->vec[i].coeffs[j]);
			r->coeffs[j] += montgomery_reduce(a->vec[i].coeffs[j] * t);
		}

		r->coeffs[j] = barrett_reduce(r->coeffs[j]);
	}
}

void polyvec_add(polyvec* r, const polyvec* a, const polyvec* b)
{
	size_t i;

	for (i = 0; i < KYBER_K; i++)
	{
		poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
	}
}
