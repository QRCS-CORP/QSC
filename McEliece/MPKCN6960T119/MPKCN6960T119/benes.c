/*
  This file is for Benes network related functions
*/

#include "transpose.h"
#include "params.h"
#include "util.h"
#include "gf.h"

/* middle layers of the benes network */
static void layer_in(uint64_t data[2][64], const uint64_t* bits, uint32_t lgs)
{
	uint64_t d;
	size_t i;
	size_t j;
	size_t k;
	uint32_t s;

	k = 0;
	s = 1UL << lgs;

	for (i = 0; i < 64; i += s * 2)
	{
		for (j = i; j < i + s; j++)
		{
			d = (data[0][j] ^ data[0][j + s]);
			d &= bits[k];
			++k;
			data[0][j] ^= d;
			data[0][j + s] ^= d;

			d = (data[1][j] ^ data[1][j + s]);
			d &= bits[k];
			++k;
			data[1][j] ^= d;
			data[1][j + s] ^= d;
		}
	}
}

/* first and last layers of the benes network */
static void layer_ex(uint64_t* data, const uint64_t* bits, uint32_t lgs)
{
	uint64_t d;
	size_t i;
	size_t j;
	size_t k;
	uint32_t s;

	k = 0;
	s = 1UL << lgs;

	for (i = 0; i < 128; i += s * 2)
	{
		for (j = i; j < i + s; j++)
		{
			d = (data[j] ^ data[j + s]);
			d &= bits[k];
			++k;
			data[j] ^= d;
			data[j + s] ^= d;
		}
	}
}

/* input: r, sequence of bits to be permuted */
/* bits, condition bits of the Benes network */
/* rev, 0 for normal application; !0 for inverse */
/* output: r, permuted bits */
void apply_benes(uint8_t* r, const uint8_t* bits, int32_t rev)
{
	uint64_t riv[2][64];
	uint64_t rih[2][64];
	uint64_t biv[64];
	uint64_t bih[64];
	size_t i;
	int32_t inc;
	uint32_t iter;
	const uint8_t* bptr;
	uint8_t* rptr;

	rptr = r;

	if (rev) 
	{ 
		bptr = bits + 12288; 
		inc = -1024; 
	}
	else 
	{ 
		bptr = bits;         
		inc = 0; 
	}

	for (i = 0; i < 64; ++i)
	{
		riv[0][i] = load8(rptr + i * 16);
		riv[1][i] = load8(rptr + i * 16 + 8);
	}

	transpose_64x64(rih[0], riv[0]);
	transpose_64x64(rih[1], riv[1]);

	for (iter = 0; iter <= 6; iter++)
	{
		for (i = 0; i < 64; ++i)
		{
			biv[i] = load8(bptr);
			bptr += 8;
		}

		bptr += inc;
		transpose_64x64(bih, biv);
		layer_ex(rih[0], bih, iter);
	}

	transpose_64x64(riv[0], rih[0]);
	transpose_64x64(riv[1], rih[1]);

	for (iter = 0; iter <= 5; iter++)
	{
		for (i = 0; i < 64; ++i)
		{
			biv[i] = load8(bptr);
			bptr += 8;
		}

		bptr += inc;
		layer_in(riv, biv, iter);
	}

	iter = 5;

	do
	{
		--iter;
		for (i = 0; i < 64; ++i)
		{
			biv[i] = load8(bptr);
			bptr += 8;
		}

		bptr += inc;
		layer_in(riv, biv, iter);
	} 
	while (iter != 0);

	transpose_64x64(rih[0], riv[0]);
	transpose_64x64(rih[1], riv[1]);

	iter = 7;

	do
	{
		--iter;
		for (i = 0; i < 64; ++i)
		{
			biv[i] = load8(bptr);
			bptr += 8;
		}

		bptr += inc;
		transpose_64x64(bih, biv);
		layer_ex(rih[0], bih, iter);
	} 
	while (iter != 0);

	transpose_64x64(riv[0], rih[0]);
	transpose_64x64(riv[1], rih[1]);

	for (i = 0; i < 64; ++i)
	{
		store8(rptr + i * 16 + 0, riv[0][i]);
		store8(rptr + i * 16 + 8, riv[1][i]);
	}
}

/* input: condition bits c */
/* output: support s */
void support_gen(gf* s, const uint8_t* c)
{
	uint8_t L[GFBITS][(1 << GFBITS) / 8];
	size_t i;
	size_t j;
	gf a;

	for (i = 0; i < GFBITS; ++i)
	{
		for (j = 0; j < (1 << GFBITS) / 8; ++j)
		{
			L[i][j] = 0;
		}
	}

	for (i = 0; i < (1 << GFBITS); ++i)
	{
		a = gf_bitrev((gf)i);

		for (j = 0; j < GFBITS; ++j)
		{
			L[j][i / 8] |= ((a >> j) & 1) << (i % 8);
		}
	}

	for (j = 0; j < GFBITS; ++j)
	{
		apply_benes(L[j], c, 0);
	}

	for (i = 0; i < SYS_N; ++i)
	{
		s[i] = 0;

		j = GFBITS;

		do
		{
			--j;
			s[i] <<= 1;
			s[i] |= (L[j][i / 8] >> (i % 8)) & 1;
		} 
		while (j > 0);
	}
}

