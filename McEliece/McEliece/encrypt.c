#include "encrypt.h"
#include "sysrand.h"
#include "util.h"
#include <string.h>

static mqc_status gen_e(uint8_t* e)
{
	uint64_t eint[64];
	uint16_t ind[MCELIECE_SYST];
	uint64_t val[MCELIECE_SYST];
	uint64_t mask;
	uint64_t one;
	size_t eq;
	size_t i; 
	size_t j;
	mqc_status status;

	while (1) 
	{
		status = sysrand_getbytes((uint8_t*)ind, sizeof(ind));

		for (i = 0; i < MCELIECE_SYST; i++)
		{
			ind[i] &= (1 << MCELIECE_GFBITS) - 1;
		}

		eq = 0;

		for (i = 1; i < MCELIECE_SYST; i++)
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

	one = 1;

	for (j = 0; j < MCELIECE_SYST; j++)
	{
		val[j] = one << (ind[j] & 63);
	}

	for (i = 0; i < 64; i++)
	{
		eint[i] = 0;

		for (j = 0; j < MCELIECE_SYST; j++) 
		{
			mask = i ^ (ind[j] >> 6);
			mask -= 1;
			mask >>= 63;
			mask = ~mask + 1;
			eint[i] |= val[j] & mask;
		}
	}

	for (i = 0; i < 64; i++)
	{
		le64to8(e + i * 8, eint[i]);
	}

	return status;
}

static void syndrome(uint8_t* s, const uint8_t* pk, const uint8_t* e) 
{
	uint64_t eint[MCELIECE_COLSIZE];
	uint64_t row_int[MCELIECE_COLSIZE];
	uint64_t tmp[8];
	size_t i;
	size_t j;
	int32_t t;
	uint8_t b;

	memcpy(s, e, MCELIECE_SYNDBYTES);
	eint[MCELIECE_COLSIZE - 1] = 0;
	memcpy(eint, e + MCELIECE_SYNDBYTES, MCELIECE_PKNCOLS / 8);

	for (i = 0; i < MCELIECE_PKNROWS; i += 8) 
	{
		for (t = 0; t < 8; t++) 
		{
			row_int[MCELIECE_COLSIZE - 1] = 0;
			memcpy(row_int, &pk[(i + t) * (MCELIECE_PKNCOLS / 8)], MCELIECE_PKNCOLS / 8);
			tmp[t] = 0;

			for (j = 0; j < MCELIECE_COLSIZE; j++)
			{
				tmp[t] ^= eint[j] & row_int[j];
			}
		}

		b = 0;

		for (t = 7; t >= 0; t--)
		{
			tmp[t] ^= (tmp[t] >> 32);
		}
		for (t = 7; t >= 0; t--)
		{
			tmp[t] ^= (tmp[t] >> 16);
		}
		for (t = 7; t >= 0; t--)
		{
			tmp[t] ^= (tmp[t] >> 8);
		}
		for (t = 7; t >= 0; t--)
		{
			tmp[t] ^= (tmp[t] >> 4);
		}
		for (t = 7; t >= 0; t--) 
		{
			b <<= 1;
			b |= (0x6996 >> (tmp[t] & 0xF)) & 1;
		}

		s[i / 8] ^= b;
	}
}

mqc_status encrypt(uint8_t* s, uint8_t* e, const uint8_t* pk)
{
	mqc_status status;

	status = gen_e(e);
	syndrome(s, pk, e);

	return status;
}
