/*
  This file is for Nieddereiter encryption
*/

#include "encrypt.h"
#include "params.h"
#include "util.h"
#include "rng.h"
#include <stdio.h>

/* moving the indices in the right range to the beginning of the array */
static int32_t mov_forward(uint16_t* ind)
{
	size_t i;
	size_t j;
	int32_t found;
	uint16_t t;

	for (i = 0; i < SYS_T; i++)
	{
		found = 0;

		for (j = i; j < SYS_T * 2; j++)
		{
			if (ind[j] < SYS_N)
			{
				t = ind[i]; 
				ind[i] = ind[j];
				ind[j] = t;
				found = 1;
				break;
			}
		}

		if (found == 0)
		{
			break;
		}
	}

	return found;
}

/* output: e, an error vector of weight t */
static void gen_e(uint8_t* e)
{
	uint64_t e_int[(SYS_N + 63) / 64];
	uint64_t val[SYS_T];
	uint16_t ind[SYS_T * 2];
	uint64_t mask;
	uint64_t one;
	int32_t eq;
	int32_t i;
	int32_t j;

	one = 1;

	for(;;)
	{
		randombytes((uint8_t*)ind, sizeof(ind));

		for (i = 0; i < SYS_T * 2; i++)
		{
			ind[i] &= GFMASK;
		}

		if (mov_forward(ind) == 0)
		{
			continue;
		}

		// check for repetition
		eq = 0;

		for (i = 1; i < SYS_T; i++)
		{
			for (j = 0; j < i; j++)
			{
				if (ind[i] == ind[j])
				{
					eq = 1;
				}
			}
		}

		if (eq == 0)
		{
			break;
		}
	}

	for (j = 0; j < SYS_T; j++)
	{
		val[j] = one << (ind[j] & 63);
	}

	for (i = 0; i < (SYS_N + 63) / 64; i++)
	{
		e_int[i] = 0;

		for (j = 0; j < SYS_T; j++)
		{
			mask = i ^ (ind[j] >> 6);
			mask -= 1;
			mask >>= 63;
			mask = ~mask + 1;
			e_int[i] |= val[j] & mask;
		}
	}

	for (i = 0; i < (SYS_N + 63) / 64 - 1; i++)
	{
		store8(e, e_int[i]); 
		e += 8;
	}

	for (j = 0; j < (SYS_N % 64); j += 8)
	{
		e[j / 8] = (e_int[i] >> j) & 0xFF;
	}
}

void syndrome(uint8_t* s, const uint8_t* pk, const uint8_t* e)
{
	/* input: public key pk, error vector e */
	/* output: syndrome s */

	const uint8_t* pk_ptr = pk;
	uint8_t row[SYS_N / 8];
	size_t i;
	size_t j;
	uint32_t tail;
	uint8_t b;

	for (i = 0; i < SYND_BYTES; i++)
	{
		s[i] = 0;
	}

	tail = PK_NROWS % 8;

	for (i = 0; i < PK_NROWS; i++)
	{
		for (j = 0; j < SYS_N / 8; j++)
		{
			row[j] = 0;
		}

		for (j = 0; j < PK_ROW_BYTES; j++)
		{
			row[((SYS_N / 8) - PK_ROW_BYTES) + j] = pk_ptr[j];
		}

		for (j = (SYS_N / 8) - 1; j >= (SYS_N / 8) - PK_ROW_BYTES; j--)
		{
			row[j] = (row[j] << tail) | (row[j - 1] >> (8UL - tail));
		}

		row[i / 8] |= 1 << (i % 8);
		b = 0;

		for (j = 0; j < SYS_N / 8; j++)
		{
			b ^= row[j] & e[j];
		}

		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		b &= 1;

		s[i / 8] |= (b << (i % 8));
		pk_ptr += PK_ROW_BYTES;
	}
}

void encrypt(uint8_t* ss, const uint8_t* pk, uint8_t* e)
{
	gen_e(e);
	syndrome(ss, pk, e);
}

