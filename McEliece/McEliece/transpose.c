#include "transpose.h"

void transpose_64x64_compact(uint64_t* out, uint64_t* in) 
{
	uint64_t x;
	uint64_t y;
	int32_t i;
	int32_t idx0;
	int32_t idx1;
	int32_t j;
	int32_t p;
	int32_t s;

	const uint64_t mask[6][2] = 
	{
		{ 0x5555555555555555ULL, 0xAAAAAAAAAAAAAAAAULL },
		{ 0x3333333333333333ULL, 0xCCCCCCCCCCCCCCCCULL },
		{ 0x0F0F0F0F0F0F0F0FULL, 0xF0F0F0F0F0F0F0F0ULL },
		{ 0x00FF00FF00FF00FFULL, 0xFF00FF00FF00FF00ULL },
		{ 0x0000FFFF0000FFFFULL, 0xFFFF0000FFFF0000ULL },
		{ 0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL }
	};

	for (i = 0; i < 64; i++)
	{
		out[i] = in[i];
	}

	for (j = 5; j >= 0; j--) 
	{
		s = 1 << j;

		for (p = 0; p < 32 / s; p++) 
		{
			for (i = 0; i < s; i++) 
			{
				idx0 = p * 2 * s + i;
				idx1 = p * 2 * s + i + s;
				x = (out[idx0] & mask[j][0]) | ((out[idx1] & mask[j][0]) << s);
				y = ((out[idx0] & mask[j][1]) >> s) | (out[idx1] & mask[j][1]);
				out[idx0] = x;
				out[idx1] = y;
			}
		}
	}
}

void transpose_8x64(uint64_t* in) 
{
	uint64_t x;
	uint64_t y;

	const uint64_t mask[3][2] = 
	{
		{ 0x5555555555555555ULL, 0xAAAAAAAAAAAAAAAAULL },
		{ 0x3333333333333333ULL, 0xCCCCCCCCCCCCCCCCULL },
		{ 0x0F0F0F0F0F0F0F0FULL, 0xF0F0F0F0F0F0F0F0ULL },
	};

	x = (in[0] & mask[2][0]) | ((in[4] & mask[2][0]) << 4);
	y = ((in[0] & mask[2][1]) >> 4) | (in[4] & mask[2][1]);
	in[0] = x;
	in[4] = y;
	x = (in[1] & mask[2][0]) | ((in[5] & mask[2][0]) << 4);
	y = ((in[1] & mask[2][1]) >> 4) | (in[5] & mask[2][1]);
	in[1] = x;
	in[5] = y;
	x = (in[2] & mask[2][0]) | ((in[6] & mask[2][0]) << 4);
	y = ((in[2] & mask[2][1]) >> 4) | (in[6] & mask[2][1]);
	in[2] = x;
	in[6] = y;
	x = (in[3] & mask[2][0]) | ((in[7] & mask[2][0]) << 4);
	y = ((in[3] & mask[2][1]) >> 4) | (in[7] & mask[2][1]);
	in[3] = x;
	in[7] = y;
	x = (in[0] & mask[1][0]) | ((in[2] & mask[1][0]) << 2);
	y = ((in[0] & mask[1][1]) >> 2) | (in[2] & mask[1][1]);
	in[0] = x;
	in[2] = y;
	x = (in[1] & mask[1][0]) | ((in[3] & mask[1][0]) << 2);
	y = ((in[1] & mask[1][1]) >> 2) | (in[3] & mask[1][1]);
	in[1] = x;
	in[3] = y;
	x = (in[4] & mask[1][0]) | ((in[6] & mask[1][0]) << 2);
	y = ((in[4] & mask[1][1]) >> 2) | (in[6] & mask[1][1]);
	in[4] = x;
	in[6] = y;
	x = (in[5] & mask[1][0]) | ((in[7] & mask[1][0]) << 2);
	y = ((in[5] & mask[1][1]) >> 2) | (in[7] & mask[1][1]);
	in[5] = x;
	in[7] = y;
	x = (in[0] & mask[0][0]) | ((in[1] & mask[0][0]) << 1);
	y = ((in[0] & mask[0][1]) >> 1) | (in[1] & mask[0][1]);
	in[0] = x;
	in[1] = y;
	x = (in[2] & mask[0][0]) | ((in[3] & mask[0][0]) << 1);
	y = ((in[2] & mask[0][1]) >> 1) | (in[3] & mask[0][1]);
	in[2] = x;
	in[3] = y;
	x = (in[4] & mask[0][0]) | ((in[5] & mask[0][0]) << 1);
	y = ((in[4] & mask[0][1]) >> 1) | (in[5] & mask[0][1]);
	in[4] = x;
	in[5] = y;
	x = (in[6] & mask[0][0]) | ((in[7] & mask[0][0]) << 1);
	y = ((in[6] & mask[0][1]) >> 1) | (in[7] & mask[0][1]);
	in[6] = x;
	in[7] = y;
}
