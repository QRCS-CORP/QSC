/*
  This file is for functions for field arithmetic
*/

#include "gf.h"
#include "params.h"

gf bitrev(gf a)
{
	a = ((a & 0x00FFU) << 8) | ((a & 0xFF00U) >> 8);
	a = ((a & 0x0F0FU) << 4) | ((a & 0xF0F0U) >> 4);
	a = ((a & 0x3333U) << 2) | ((a & 0xCCCCU) >> 2);
	a = ((a & 0x5555U) << 1) | ((a & 0xAAAAU) >> 1);

	return a >> 3;
}

gf gf_iszero(gf a)
{
	uint32_t t;

	t = a;
	t -= 1;
	t >>= 19;

	return (gf)t;
}

gf gf_add(gf in0, gf in1)
{
	return in0 ^ in1;
}

gf gf_mul(gf in0, gf in1)
{
	uint64_t t;
	uint64_t t0;
	uint64_t t1;
	uint64_t tmp;
	size_t i;

	t0 = in0;
	t1 = in1;
	tmp = t0 * (t1 & 1);

	for (i = 1; i < GFBITS; i++)
	{
		tmp ^= (t0 * (t1 & (1 << i)));
	}

	t = tmp & 0x0000000001FF0000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	t = tmp & 0x000000000000E000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

	return (gf)(tmp & GFMASK);
}

/* input: field element in */
/* return: (in^2)^2 */
static inline gf gf_sq2(gf in)
{
	uint64_t x; 
	uint64_t t;
	size_t i;

	const uint64_t B[] = 
	{
		0x1111111111111111ULL, 
	    0x0303030303030303ULL,
	    0x000F000F000F000FULL,
	    0x000000FF000000FFULL
	};

	const uint64_t M[] = 
	{
		0x0001FF0000000000ULL,
	    0x000000FF80000000ULL,
	    0x000000007FC00000ULL,
	    0x00000000003FE000ULL
	};

	x = in;
	x = (x | (x << 24)) & B[3];
	x = (x | (x << 12)) & B[2];
	x = (x | (x << 6)) & B[1];
	x = (x | (x << 3)) & B[0];

	for (i = 0; i < 4; i++)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (gf)(x & GFMASK);
}

/* input: field element in, m */
/* return: (in^2)*m */
static inline gf gf_sqmul(gf in, gf m)
{
	uint64_t x;
	uint64_t t0;
	uint64_t t1;
	uint64_t t;
	size_t i;

	const uint64_t M[] = 
	{
		0x0000001FF0000000ULL,
	    0x000000000FF80000ULL,
	    0x000000000007E000ULL
	}; 

	t0 = in;
	t1 = m;
	x = (t1 << 6) * (t0 & (1 << 6));
	t0 ^= (t0 << 7);

	x ^= (t1 * (t0 & (0x04001)));
	x ^= (t1 * (t0 & (0x08002))) << 1;
	x ^= (t1 * (t0 & (0x10004))) << 2;
	x ^= (t1 * (t0 & (0x20008))) << 3;
	x ^= (t1 * (t0 & (0x40010))) << 4;
	x ^= (t1 * (t0 & (0x80020))) << 5;

	for (i = 0; i < 3; i++)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (gf)(x & GFMASK);
}

/* input: field element in, m */
/* return: ((in^2)^2)*m */
static inline gf gf_sq2mul(gf in, gf m)
{
	uint64_t x;
	uint64_t t0;
	uint64_t t1;
	uint64_t t;
	size_t i;

	const uint64_t M[] = 
	{
		0x1FF0000000000000ULL,
		0x000FF80000000000ULL,
		0x000007FC00000000ULL,
	    0x00000003FE000000ULL,
	    0x0000000001FE0000ULL,
	    0x000000000001E000ULL
	};

	t0 = in;
	t1 = m;
	x = (t1 << 18) * (t0 & (1 << 6));
	t0 ^= (t0 << 21);

	x ^= (t1 * (t0 & (0x010000001)));
	x ^= (t1 * (t0 & (0x020000002))) << 3;
	x ^= (t1 * (t0 & (0x040000004))) << 6;
	x ^= (t1 * (t0 & (0x080000008))) << 9;
	x ^= (t1 * (t0 & (0x100000010))) << 12;
	x ^= (t1 * (t0 & (0x200000020))) << 15;

	for (i = 0; i < 6; i++)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (gf)(x & GFMASK);
}

/* input: field element den, num */
/* return: (num/den) */
gf gf_frac(gf den, gf num)
{
	gf tmp_11;
	gf tmp_1111;
	gf out;

	// ^11
	tmp_11 = gf_sqmul(den, den);
	// ^1111
	tmp_1111 = gf_sq2mul(tmp_11, tmp_11);
	out = gf_sq2(tmp_1111);
	// ^11111111
	out = gf_sq2mul(out, tmp_1111);
	out = gf_sq2(out);
	// ^111111111111
	out = gf_sq2mul(out, tmp_1111);
	// ^1111111111110 = ^-1
	return gf_sqmul(out, num);
}

gf gf_inv(gf den)
{
	return gf_frac(den, (gf)1);
}

/* input: in0, in1 in GF((2^m)^t)*/
/* output: out = in0*in1 */
void GF_mul(gf* out, gf* in0, gf* in1)
{
	gf prod[255];
	size_t i;
	size_t j;

	for (i = 0; i < 255; i++)
	{
		prod[i] = 0;
	}

	for (i = 0; i < 128; i++)
	{
		for (j = 0; j < 128; j++)
		{
			prod[i + j] ^= gf_mul(in0[i], in1[j]);
		}
	}

	for (i = 254; i >= 128; i--)
	{
		prod[i - 123] ^= gf_mul(prod[i], (gf)7682);
		prod[i - 125] ^= gf_mul(prod[i], (gf)2159);
		prod[i - 128] ^= gf_mul(prod[i], (gf)3597);
	}

	for (i = 0; i < 128; i++)
	{
		out[i] = prod[i];
	}
}

