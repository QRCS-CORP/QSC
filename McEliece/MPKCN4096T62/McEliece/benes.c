#include "benes.h"
#include "transpose.h"

static void benes_helper(uint64_t* bs, uint64_t* condptr, int32_t low)
{
	int32_t high;
	int32_t i;
	int32_t j;
	int32_t x;
	int32_t y;
	uint64_t diff;

	high = 5 - low;

	for (j = 0; j < (1 << low); j++)
	{
		x = (0 << low) + j;
		y = (1 << low) + j;

		for (i = 0; i < (1 << high); i++)
		{
			diff = bs[x] ^ bs[y];
			diff &= (*condptr++);
			bs[x] ^= diff;
			bs[y] ^= diff;
			x += (1 << (low + 1));
			y += (1 << (low + 1));
		}
	}
}

void benes_compact(uint64_t* bs, uint64_t* cond, int32_t rev)
{
	uint64_t* condptr;
	int32_t inc;
	int32_t low;

	if (rev == 0) 
	{
		inc = 32;
		condptr = cond;
	} 
	else 
	{
		inc = -32;
		condptr = &cond[704];
	}

	for (low = 0; low <= 5; low++) 
	{
		benes_helper(bs, condptr, low);
		condptr += inc;
	}

	transpose_64x64_compact(bs, bs);

	for (low = 0; low <= 5; low++)
	{
		benes_helper(bs, condptr, low);
		condptr += inc;
	}
	for (low = 4; low >= 0; low--) 
	{
		benes_helper(bs, condptr, low);
		condptr += inc;
	}

	transpose_64x64_compact(bs, bs);

	for (low = 5; low >= 0; low--) 
	{
		benes_helper(bs, condptr, low);
		condptr += inc;
	}
}
