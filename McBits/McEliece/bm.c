/*
  This file is for the Berlekamp-Massey algorithm
*/

#include "bm.h"
#include "gf.h"
#include "vec.h"

static void into_vec(uint64_t* out, uint16_t in) 
{
	size_t i;

	for (i = 0; i < MCELIECE_GFBITS; i++) 
	{
		out[i] = (in >> i) & 1;
		out[i] = ~out[i] + 1;
	}
}

static uint16_t vec_reduce(uint64_t* prod) 
{
	uint64_t tmp[MCELIECE_GFBITS];
	uint16_t ret = 0;
	int32_t i;

	for (i = 0; i < MCELIECE_GFBITS; i++) 
	{
		tmp[i] = prod[i];
	}

	for (i = MCELIECE_GFBITS - 1; i >= 0; i--)
	{
		tmp[i] ^= (tmp[i] >> 32);
	}
	for (i = MCELIECE_GFBITS - 1; i >= 0; i--)
	{
		tmp[i] ^= (tmp[i] >> 16);
	}
	for (i = MCELIECE_GFBITS - 1; i >= 0; i--)
	{
		tmp[i] ^= (tmp[i] >> 8);
	}
	for (i = MCELIECE_GFBITS - 1; i >= 0; i--)
	{
		tmp[i] ^= (tmp[i] >> 4);
	}
	for (i = MCELIECE_GFBITS - 1; i >= 0; i--) 
	{
		ret <<= 1;
		ret |= (0x6996 >> (tmp[i] & 0xF)) & 1;
	};

	return ret;
}

static uint64_t mask_nonzero_64bit(uint16_t a) 
{
	uint64_t ret;

	ret = a;
	ret -= 1;
	ret >>= 63;
	ret -= 1;

	return ret;
}

static uint64_t mask_leq_64bit(uint16_t a, uint16_t b) 
{
	uint64_t tmpa;
	uint64_t tmpb;
	uint64_t ret;

	tmpa = a;
	tmpb = b;
	ret = tmpb - tmpa;
	ret >>= 63;
	ret -= 1;

	return ret;
}

static void vec_cmov(uint64_t* out, uint64_t* in, uint64_t mask) 
{
	size_t i;

	for (i = 0; i < MCELIECE_GFBITS; i++)
	{
		out[i] = (in[i] & mask) | (out[i] & ~mask);
	}
}

void bm(uint64_t out[MCELIECE_GFBITS], uint64_t in[][MCELIECE_GFBITS]) 
{
	uint64_t B[MCELIECE_GFBITS];
	uint64_t C[MCELIECE_GFBITS];
	uint64_t prod[MCELIECE_GFBITS];
	uint64_t rvec[MCELIECE_GFBITS];
	uint64_t tmpC[MCELIECE_GFBITS];
	uint64_t tmpin[MCELIECE_GFBITS];
	uint16_t mask16b;
	uint64_t maskleq;
	uint64_t masknz;
	uint16_t b;
	uint16_t binv;
	uint16_t d;
	uint16_t i;
	uint16_t L;
	uint16_t N;
	uint16_t r;

	/* init */

	C[0] = 1;
	C[0] <<= 63;
	B[0] = 1;
	B[0] <<= 62;

	for (i = 1; i < MCELIECE_GFBITS; i++)
	{
		B[i] = C[i] = 0;
	}

	b = 1;
	L = 0;

	for (N = 0; N < MCELIECE_SYST * 2; N++) 
	{
		/* computing d */

		if (N < 64)
		{
			for (i = 0; i < MCELIECE_GFBITS; i++)
			{
				tmpin[i] = in[0][i] << (63 - N);
			}
		}
		else
		{
			for (i = 0; i < MCELIECE_GFBITS; i++)
			{
				tmpin[i] = (in[0][i] >> (N - 63)) | (in[1][i] << (127 - N));
			}
		}

		vec_mul(prod, C, tmpin);
		d = vec_reduce(prod);

		/* 3 cases */
		binv = gf_inv(b);
		r = gf_mul(d, binv);
		into_vec(rvec, r);
		vec_mul(tmpC, rvec, B);

		for (i = 0; i < MCELIECE_GFBITS; i++)
		{
			tmpC[i] ^= C[i];
		}

		masknz = mask_nonzero_64bit(d);
		maskleq = mask_leq_64bit(L * 2, N);
		mask16b = (masknz & maskleq) & 0xFFFF;
		vec_cmov(B, C, masknz & maskleq);
		vec_copy(C, tmpC);
		b = (d & mask16b) | (b & ~mask16b);
		L = ((N + 1 - L) & mask16b) | (L & ~mask16b);

		for (i = 0; i < MCELIECE_GFBITS; i++)
		{
			B[i] >>= 1;
		}
	}

	vec_copy(out, C);

	for (i = 0; i < MCELIECE_GFBITS; i++)
	{
		out[i] >>= 64 - (MCELIECE_SYST + 1);
	}
}
