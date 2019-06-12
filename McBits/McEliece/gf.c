/*
  This file is for functions for field arithmetic
*/

#include "gf.h"

uint16_t gf_diff(uint16_t a, uint16_t b) 
{
	uint32_t t = (uint32_t)(a ^ b);

	t = ((t - 1) >> 20) ^ 0xFFFUL;

	return (uint16_t) t;
}

uint16_t gf_inv(uint16_t in)
{
	uint16_t out;
	uint16_t tmp_11;
	uint16_t tmp_1111;

	out = in;
	out = gf_sq(out);
	tmp_11 = gf_mul(out, in);
	out = gf_sq(tmp_11);
	out = gf_sq(out);
	tmp_1111 = gf_mul(out, tmp_11);
	out = gf_sq(tmp_1111);
	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_mul(out, tmp_1111);
	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_mul(out, tmp_11);
	out = gf_sq(out);
	out = gf_mul(out, in);

	return gf_sq(out);
}

uint16_t gf_mul(uint16_t in0, uint16_t in1)
{
	uint32_t t;
	uint32_t t0;
	uint32_t t1;
	uint32_t tmp;
	size_t i;

	t0 = in0;
	t1 = in1;

	tmp = t0 * (t1 & 1);

	for (i = 1; i < MCELIECE_GFBITS; i++)
	{
		tmp ^= (t0 * (t1 & (1 << i)));
	}

	t = tmp & 0x7FC000;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	t = tmp & 0x3000;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	return tmp & ((1 << MCELIECE_GFBITS) - 1);
}

void gf_mulm(uint16_t* out, uint16_t* in0, uint16_t* in1) 
{
	uint16_t tmp[123];
	size_t i;
	size_t j;

	for (i = 0; i < 123; i++)
	{
		tmp[i] = 0;
	}

	for (i = 0; i < 62; i++)
	{
		for (j = 0; j < 62; j++)
		{
			tmp[i + j] ^= gf_mul(in0[i], in1[j]);
		}
	}

	for (i = 122; i >= 62; i--) 
	{
		tmp[i - 55] ^= gf_mul(tmp[i], (uint16_t)1763);
		tmp[i - 61] ^= gf_mul(tmp[i], (uint16_t)1722);
		tmp[i - 62] ^= gf_mul(tmp[i], (uint16_t)4033);
	}

	for (i = 0; i < 62; i++)
	{
		out[i] = tmp[i];
	}
}

uint16_t gf_sq(uint16_t in) 
{
	uint32_t t;
	uint32_t x;

	x = in;
	x = (x | (x << 8)) & 0x00FF00FFUL;
	x = (x | (x << 4)) & 0x0F0F0F0FUL;
	x = (x | (x << 2)) & 0x33333333UL;
	x = (x | (x << 1)) & 0x55555555UL;

	t = x & 0x7FC000;
	x ^= t >> 9;
	x ^= t >> 12;

	t = x & 0x3000;
	x ^= t >> 9;
	x ^= t >> 12;

	return x & ((1 << MCELIECE_GFBITS) - 1);
}
