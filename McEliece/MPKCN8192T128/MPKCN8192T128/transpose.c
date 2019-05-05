/*
  This file is for matrix transposition
*/

#include "transpose.h"

/* input: in, a 64x64 matrix over GF(2) */
/* output: out, transpose of in */
void transpose_64x64(uint64_t* out, const uint64_t* in)
{
	uint64_t x;
	uint64_t y;
	size_t i;
	size_t j;
	size_t d;
	size_t s;

	const uint64_t masks[6][2] =
	{
		{0x5555555555555555ULL, 0xAAAAAAAAAAAAAAAAULL},
		{0x3333333333333333ULL, 0xCCCCCCCCCCCCCCCCULL},
		{0x0F0F0F0F0F0F0F0FULL, 0xF0F0F0F0F0F0F0F0ULL},
		{0x00FF00FF00FF00FFULL, 0xFF00FF00FF00FF00ULL},
		{0x0000FFFF0000FFFFULL, 0xFFFF0000FFFF0000ULL},
		{0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL}
	};

	for (i = 0; i < 64; i++)
	{
		out[i] = in[i];
	}

	d = 6;

	do
	{
		--d;

		s = 1ULL << d;

		for (i = 0; i < 64; i += s * 2)
		{
			for (j = i; j < i + s; j++)
			{
				x = (out[j] & masks[d][0]) | ((out[j + s] & masks[d][0]) << s);
				y = ((out[j] & masks[d][1]) >> s) | (out[j + s] & masks[d][1]);
				out[j] = x;
				out[j + s] = y;
			}
		}
	} 
	while (d != 0);
}
