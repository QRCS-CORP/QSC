#include "sk_gen.h"
#include "gf.h"
#include "sysrand.h"
#include "util.h"

static int32_t irr_gen(uint16_t* out, uint16_t* f) 
{
	uint16_t mat[MCELIECE_SYST + 1][MCELIECE_SYST];
	int32_t c;
	int32_t i;
	int32_t j;
	int32_t k;
	uint16_t inv;
	uint16_t mask;
	uint16_t t;

	/* fill matrix */
	mat[0][0] = 1;

	for (i = 1; i < MCELIECE_SYST; i++)
	{
		mat[0][i] = 0;
	}

	for (i = 0; i < MCELIECE_SYST; i++)
	{
		mat[1][i] = f[i];
	}

	for (j = 2; j <= MCELIECE_SYST; j++)
	{
		gf_mulm(mat[j], mat[j - 1], f);
	}

	/* gaussian */
	for (j = 0; j < MCELIECE_SYST; j++) 
	{
		for (k = j + 1; k < MCELIECE_SYST; k++)
		{
			mask = gf_diff(mat[j][j], mat[j][k]);

			for (c = 0; c < MCELIECE_SYST + 1; c++)
			{
				mat[c][j] ^= mat[c][k] & mask;
			}
		}

		if (mat[j][j] == 0) 
		{ 
			/* return if not invertible */
			return -1;
		}

		/* compute inverse */
		inv = gf_inv(mat[j][j]);

		for (c = 0; c < MCELIECE_SYST + 1; c++)
		{
			mat[c][j] = gf_mul(mat[c][j], inv);
		}

		for (k = 0; k < MCELIECE_SYST; k++) 
		{
			t = mat[j][k];

			if (k != j) 
			{
				for (c = 0; c < MCELIECE_SYST + 1; c++)
				{
					mat[c][k] ^= gf_mul(mat[c][j], t);
				}
			}
		}
	}

	for (i = 0; i < MCELIECE_SYST; i++)
	{
		out[i] = mat[MCELIECE_SYST][i];
	}

	out[MCELIECE_SYST] = 1;

	return 0;
}

mqc_status sk_gen(uint8_t* sk)
{
	uint64_t cond[MCELIECE_CONDBYTES / 8];
	uint16_t f[MCELIECE_SYST];
	uint16_t irr[MCELIECE_SYST + 1];
	uint64_t sk_int[MCELIECE_GFBITS];
	int32_t i;
	int32_t j;
	mqc_status status;

	while (1) 
	{
		status = sysrand_getbytes((uint8_t*)f, sizeof(f));

		for (i = 0; i < MCELIECE_SYST; i++)
		{
			f[i] &= (1 << MCELIECE_GFBITS) - 1;
		}

		if (irr_gen(irr, f) == 0)
		{
			break;
		}
	}

	for (i = 0; i < MCELIECE_GFBITS; i++) 
	{
		sk_int[i] = 0;

		for (j = MCELIECE_SYST; j >= 0; j--)
		{
			sk_int[i] <<= 1;
			sk_int[i] |= (irr[j] >> i) & 1;
		}

		le64to8(sk + i * 8, sk_int[i]);
	}

	if (status == MQC_STATUS_SUCCESS)
	{
		status = sysrand_getbytes((uint8_t*)cond, sizeof(cond));

		for (i = 0; i < MCELIECE_CONDBYTES / 8; i++)
		{
			le64to8(sk + MCELIECE_IRRBYTES + i * 8, cond[i]);
		}
	}

	return status;
}
