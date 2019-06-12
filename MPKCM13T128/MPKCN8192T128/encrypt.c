/*
  This file is for Nieddereiter encryption
*/

#include "encrypt.h"
#include "gf.h"
#include "params.h"
#include "rng.h"
#include "util.h"
#ifdef MPKCM13T128_KAT
#	include <stdio.h>
#endif

/* output: e, an error vector of weight t */
static void gen_e(uint8_t* e)
{
	uint16_t ind[SYS_T];
	uint64_t e_int[SYS_N / 64];
	uint64_t val[SYS_T];
	uint64_t mask;
	uint64_t one;
	size_t eq;
	size_t i;
	size_t j;

	one = 1;

	for(;;)
	{
		randombytes((uint8_t*)ind, sizeof(ind));

		for (i = 0; i < SYS_T; i++)
		{
			ind[i] &= GFMASK;
		}

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

	for (i = 0; i < SYS_N / 64; i++)
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

	for (i = 0; i < SYS_N / 64; i++)
	{
		store8(e + i * 8, e_int[i]);
	}
}

/* input: public key pk, error vector e */
/* output: syndrome s */
void syndrome(uint8_t* s, const uint8_t* pk, uint8_t* e)
{
	uint8_t row[SYS_N / 8];
	size_t i;
	size_t j;
	size_t poft;
	uint8_t b;

	for (i = 0; i < SYND_BYTES; i++)
	{
		s[i] = 0;
	}

	poft = 0;

	for (i = 0; i < PK_NROWS; i++)
	{
		for (j = 0; j < SYS_N / 8; j++)
		{
			row[j] = 0;
		}

		for (j = 0; j < PK_ROW_BYTES; j++)
		{
			row[SYS_N / 8 - PK_ROW_BYTES + j] = pk[poft + j];
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

		poft += PK_ROW_BYTES;
	}
}

void encrypt(uint8_t* s, const uint8_t* pk, uint8_t* e)
{
	gen_e(e);

#ifdef MPKCM13T128_KAT
	{
		size_t k;
		printf("encrypt e: positions");

		for (k = 0; k < SYS_N; ++k)
		{
			if (e[k / 8] & (1 << (k & 7)))
			{
				printf(" %d", k);
			}
		}

    printf("\n");
  }
#endif

	syndrome(s, pk, e);
}

