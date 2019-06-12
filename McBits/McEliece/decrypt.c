/*
  This file is for Nieddereiter decryption
*/

#include "decrypt.h"
#include "benes.h"
#include "bm.h"
#include "fft.h"
#include "fft_tr.h"
#include "transpose.h"
#include "util.h"
#include "vec.h"

static void scaling(uint64_t out[][MCELIECE_GFBITS], uint64_t inv[][MCELIECE_GFBITS], const uint8_t* sk, uint64_t* recv) 
{
	int32_t i; 
	int32_t j;
	uint64_t eval[64][MCELIECE_GFBITS];
	uint64_t skint[MCELIECE_GFBITS];
	uint64_t tmp[MCELIECE_GFBITS];

	/* computing inverses */
	for (i = 0; i < MCELIECE_GFBITS; i++)
	{
		skint[i] = le8to64(sk + i * 8);
	}

	fft(eval, skint);

	for (i = 0; i < 64; i++)
	{
		vec_sq(eval[i], eval[i]);
	}

	vec_copy(inv[0], eval[0]);

	for (i = 1; i < 64; i++)
	{
		vec_mul(inv[i], inv[i - 1], eval[i]);
	}

	vec_inv(tmp, inv[63]);

	for (i = 62; i >= 0; i--) 
	{
		vec_mul(inv[i + 1], tmp, inv[i]);
		vec_mul(tmp, tmp, eval[i + 1]);
	}

	vec_copy(inv[0], tmp);

	for (i = 0; i < 64; i++)
	{
		for (j = 0; j < MCELIECE_GFBITS; j++)
		{
			out[i][j] = inv[i][j] & recv[i];
		}
	}
}

static void scaling_inv(uint64_t out[][MCELIECE_GFBITS], uint64_t inv[][MCELIECE_GFBITS], uint64_t* recv) 
{
	int32_t i; 
	int32_t j;

	for (i = 0; i < 64; i++)
	{
		for (j = 0; j < MCELIECE_GFBITS; j++)
		{
			out[i][j] = inv[i][j] & recv[i];
		}
	}
}

static void preprocess(uint64_t* recv, const uint8_t* s) 
{
	int32_t i;

	for (i = 0; i < 64; i++)
	{
		recv[i] = 0;
	}

	for (i = 0; i < MCELIECE_SYNDBYTES / 8; i++)
	{
		recv[i] = le8to64(s + i * 8);
	}

	for (i = MCELIECE_SYNDBYTES % 8 - 1; i >= 0; i--) 
	{
		recv[MCELIECE_SYNDBYTES / 8] <<= 8;
		recv[MCELIECE_SYNDBYTES / 8] |= s[MCELIECE_SYNDBYTES / 8 * 8 + i];
	}
}

static void acc(uint64_t* c, uint64_t v)
{
	int32_t i;
	uint64_t carry;
	uint64_t t;

	carry = v;

	for (i = 0; i < 8; i++) 
	{
		t = c[i] ^ carry;
		carry = c[i] & carry;
		c[i] = t;
	}
}

static int32_t weight(uint64_t* v) 
{
	int32_t i;
	int32_t w;

	union 
	{
		uint64_t data_64[8];
		uint8_t data_8[64];
	} counter;

	for (i = 0; i < 8; i++)
	{
		counter.data_64[i] = 0;
	}

	for (i = 0; i < 64; i++)
	{
		acc(counter.data_64, v[i]);
	}

	transpose_8x64(counter.data_64);

	w = 0;

	for (i = 0; i < 64; i++)
	{
		w += counter.data_8[i];
	}

	return w;
}

static void syndrome_adjust(uint64_t in[][MCELIECE_GFBITS])
{
	size_t i;

	for (i = 0; i < MCELIECE_GFBITS; i++) 
	{
		in[1][i] <<= (128 - MCELIECE_SYST * 2);
		in[1][i] >>= (128 - MCELIECE_SYST * 2);
	}
}

mqc_status decrypt(uint8_t* e, const uint8_t* sk, const uint8_t* s)
{
	uint64_t cond[MCELIECE_CONDBYTES / 8];
	uint64_t error[64];
	uint64_t locator[MCELIECE_GFBITS];
	uint64_t recv[64];
	uint64_t eval[64][MCELIECE_GFBITS];
	uint64_t inv[64][MCELIECE_GFBITS];
	uint64_t scaled[64][MCELIECE_GFBITS];
	uint64_t spriv[2][MCELIECE_GFBITS];
	uint64_t sprivcmp[2][MCELIECE_GFBITS];
	uint64_t diff;
	uint64_t t;
	size_t i;
	size_t j;

	for (i = 0; i < MCELIECE_CONDBYTES / 8; i++)
	{
		cond[i] = le8to64(sk + MCELIECE_IRRBYTES + i * 8);
	}

	preprocess(recv, s);
	benes_compact(recv, cond, 1);
	/* scaling */
	scaling(scaled, inv, sk, recv);
    /* transposed FFT */
	fft_tr(spriv, scaled);
	syndrome_adjust(spriv);
	/* Berlekamp Massey */
	bm(locator, spriv);
	/* FFT */
	fft(eval, locator);

	for (i = 0; i < 64; i++) 
	{
		error[i] = vec_or(eval[i]);
		error[i] = ~error[i];
	}

	/* re-encrypt */
	scaling_inv(scaled, inv, error);
	fft_tr(sprivcmp, scaled);
	syndrome_adjust(sprivcmp);
	diff = 0;

	for (i = 0; i < 2; i++)
	{
		for (j = 0; j < MCELIECE_GFBITS; j++)
		{
			diff |= spriv[i][j] ^ sprivcmp[i][j];
		}
	}

	diff |= diff >> 32;
	diff |= diff >> 16;
	diff |= diff >> 8;
	t = diff & 0xFF;

	benes_compact(error, cond, 0);

	for (i = 0; i < 64; i++)
	{
		le64to8(e + i * 8, error[i]);
	}

	t |= weight(error) ^ MCELIECE_SYST;
	t -= 1;
	t >>= 63;

	return (t == 1) ? MQC_STATUS_SUCCESS : MQC_STATUS_FAILURE;
}
