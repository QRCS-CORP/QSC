#include "mpkcn8192t128.h"

#ifdef QSC_MCELIECE_STRONG
#include "intutils.h"
#include <stdlib.h>
#include <string.h>

/* benes.c */

void qsc_mceliece_apply_benes(uint8_t* r, const uint8_t* bits, int32_t rev)
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
		riv[0][i] = le8to64(rptr + i * 16);
		riv[1][i] = le8to64(rptr + i * 16 + 8);
	}

	qsc_mceliece_transpose_64x64(rih[0], riv[0]);
	qsc_mceliece_transpose_64x64(rih[1], riv[1]);

	for (iter = 0; iter <= 6; iter++)
	{
		for (i = 0; i < 64; ++i)
		{
			biv[i] = le8to64(bptr);
			bptr += 8;
		}

		bptr += inc;
		qsc_mceliece_transpose_64x64(bih, biv);
		qsc_mceliece_benes_layer_ex(rih[0], bih, iter);
	}

	qsc_mceliece_transpose_64x64(riv[0], rih[0]);
	qsc_mceliece_transpose_64x64(riv[1], rih[1]);

	for (iter = 0; iter <= 5; iter++)
	{
		for (i = 0; i < 64; ++i)
		{
			biv[i] = le8to64(bptr);
			bptr += 8;
		}

		bptr += inc;
		qsc_mceliece_benes_layer_in(riv, biv, iter);
	}

	iter = 5;

	do
	{
		--iter;
		for (i = 0; i < 64; ++i)
		{
			biv[i] = le8to64(bptr);
			bptr += 8;
		}

		bptr += inc;
		qsc_mceliece_benes_layer_in(riv, biv, iter);
	} 
	while (iter != 0);

	qsc_mceliece_transpose_64x64(rih[0], riv[0]);
	qsc_mceliece_transpose_64x64(rih[1], riv[1]);

	iter = 7;

	do
	{
		--iter;
		for (i = 0; i < 64; ++i)
		{
			biv[i] = le8to64(bptr);
			bptr += 8;
		}

		bptr += inc;
		qsc_mceliece_transpose_64x64(bih, biv);
		qsc_mceliece_benes_layer_ex(rih[0], bih, iter);
	} 
	while (iter != 0);

	qsc_mceliece_transpose_64x64(riv[0], rih[0]);
	qsc_mceliece_transpose_64x64(riv[1], rih[1]);

	for (i = 0; i < 64; ++i)
	{
		le64to8(rptr + i * 16 + 0, riv[0][i]);
		le64to8(rptr + i * 16 + 8, riv[1][i]);
	}
}

void qsc_mceliece_support_gen(gf* s, const uint8_t* c)
{
	uint8_t L[QSC_MCELIECE_GFBITS][(1 << QSC_MCELIECE_GFBITS) / 8];
	size_t i;
	size_t j;
	gf a;

	for (i = 0; i < QSC_MCELIECE_GFBITS; ++i)
	{
		for (j = 0; j < (1 << QSC_MCELIECE_GFBITS) / 8; ++j)
		{
			L[i][j] = 0;
		}
	}

	for (i = 0; i < (1 << QSC_MCELIECE_GFBITS); ++i)
	{
		a = qsc_mceliece_gf_bitrev((gf)i);

		for (j = 0; j < QSC_MCELIECE_GFBITS; ++j)
		{
			L[j][i / 8] |= ((a >> j) & 1) << (i % 8);
		}
	}

	for (j = 0; j < QSC_MCELIECE_GFBITS; ++j)
	{
		qsc_mceliece_apply_benes(L[j], c, 0);
	}

	for (i = 0; i < QSC_MCELIECE_SYS_N; ++i)
	{
		s[i] = 0;

		j = QSC_MCELIECE_GFBITS;

		do
		{
			--j;
			s[i] <<= 1;
			s[i] |= (L[j][i / 8] >> (i % 8)) & 1U;
		} 
		while (j > 0);
	}
}

/* bm.c */

void qsc_mceliece_bm(gf* out, const gf* s)
{
	gf T[QSC_MCELIECE_SYS_T + 1];
	gf C[QSC_MCELIECE_SYS_T + 1];
	gf B[QSC_MCELIECE_SYS_T + 1];
	int32_t i;
	uint16_t N;
	uint16_t L;
	uint16_t mle;
	uint16_t mne;
	gf b;
	gf d;
	gf f;

	b = 1;
	L = 0;

	for (i = 0; i < QSC_MCELIECE_SYS_T + 1; i++)
	{
		C[i] = B[i] = 0;
	}

	B[1] = C[0] = 1;

	for (N = 0; N < 2 * QSC_MCELIECE_SYS_T; N++)
	{
		d = 0;

		for (i = 0; i <= min(N, QSC_MCELIECE_SYS_T); i++)
		{
			d ^= qsc_mceliece_gf_mul(C[i], s[N - i]);
		}

		mne = d;
		mne -= 1;
		mne >>= 15;
		mne -= 1;
		mle = N;
		mle -= 2U * L;
		mle >>= 15;
		mle -= 1;
		mle &= mne;

		for (i = 0; i <= QSC_MCELIECE_SYS_T; i++)
		{
			T[i] = C[i];
		}

		f = qsc_mceliece_gf_frac(b, d);

		for (i = 0; i <= QSC_MCELIECE_SYS_T; i++)
		{
			C[i] ^= qsc_mceliece_gf_mul(f, B[i]) & mne;
		}

		L = (L & ~mle) | ((N + 1 - L) & mle);

		for (i = 0; i <= QSC_MCELIECE_SYS_T; i++)
		{
			B[i] = (B[i] & ~mle) | (T[i] & mle);
		}

		b = (b & ~mle) | (d & mle);
		i = QSC_MCELIECE_SYS_T;

		do
		{

			B[i] = B[i - 1];
			--i;
		} while (i > 0);

		B[0] = 0;
	}

	for (i = 0; i <= QSC_MCELIECE_SYS_T; i++)
	{
		out[i] = C[QSC_MCELIECE_SYS_T - i];
	}
}

/* controlbits.c */

void qsc_mceliece_controlbits(uint8_t* out, const uint32_t* pi)
{
	uint8_t c[(((2 * QSC_MCELIECE_GFBITS) - 1) * (1 << QSC_MCELIECE_GFBITS)) / 16] = { 0 };
	size_t i;

	qsc_mceliece_permutecontrolbits(QSC_MCELIECE_GFBITS, (1UL << QSC_MCELIECE_GFBITS), 1UL, 0UL, c, pi);

	for (i = 0; i < sizeof(c); i++)
	{
		out[i] = c[i];
	}
}

/* decrypt.c */

int32_t qsc_mceliece_decrypt(uint8_t* e, const uint8_t* sk, const uint8_t* c)
{
	gf g[QSC_MCELIECE_SYS_T + 1];
	gf L[QSC_MCELIECE_SYS_N];
	gf s[QSC_MCELIECE_SYS_T * 2];
	gf s_cmp[QSC_MCELIECE_SYS_T * 2];
	gf locator[QSC_MCELIECE_SYS_T + 1];
	gf images[QSC_MCELIECE_SYS_N];
	uint8_t r[QSC_MCELIECE_SYS_N / 8];
	size_t i;
	gf check;
	gf t;
	gf w;

	for (i = 0; i < QSC_MCELIECE_SYND_BYTES; i++)
	{
		r[i] = c[i];
	}

	for (i = QSC_MCELIECE_SYND_BYTES; i < QSC_MCELIECE_SYS_N / 8; i++)
	{
		r[i] = 0;
	}

	for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
	{
		g[i] = le8to16(sk);
		g[i] &= QSC_MCELIECE_GFMASK;
		sk += 2;
	}

	g[QSC_MCELIECE_SYS_T] = 1;
	qsc_mceliece_support_gen(L, sk);
	qsc_mceliece_synd(s, g, L, r);
	qsc_mceliece_bm(locator, s);
	qsc_mceliece_root(images, locator, L);

	for (i = 0; i < QSC_MCELIECE_SYS_N / 8; i++)
	{
		e[i] = 0;
	}

	w = 0;

	for (i = 0; i < QSC_MCELIECE_SYS_N; i++)
	{
		t = qsc_mceliece_gf_iszero(images[i]) & 1;
		e[i / 8] |= t << (i % 8);
		w += t;
	}

	qsc_mceliece_synd(s_cmp, g, L, e);
	check = w;
	check ^= QSC_MCELIECE_SYS_T;

	for (i = 0; i < QSC_MCELIECE_SYS_T * 2; i++)
	{
		check |= s[i] ^ s_cmp[i];
	}

	check -= 1;
	check >>= 15;
	check ^= 1;

	return check;
}

/* encrypt.c */

static void gen_e(uint8_t* e, void (*rng_generate)(uint8_t*, size_t))
{
	uint64_t e_int[QSC_MCELIECE_SYS_N / 64];
	uint64_t val[QSC_MCELIECE_SYS_T];
	uint16_t ind[QSC_MCELIECE_SYS_T];
	uint64_t mask;
	uint64_t one;
	size_t eq;
	size_t i;
	size_t j;

	one = 1;

	for (;;)
	{
		rng_generate((uint8_t*)ind, sizeof(ind));

		for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
		{
			ind[i] &= QSC_MCELIECE_GFMASK;
		}

		eq = 0;

		for (i = 1; i < QSC_MCELIECE_SYS_T; i++)
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

	for (j = 0; j < QSC_MCELIECE_SYS_T; j++)
	{
		val[j] = one << (ind[j] & 63);
	}

	for (i = 0; i < QSC_MCELIECE_SYS_N / 64; i++)
	{
		e_int[i] = 0;

		for (j = 0; j < QSC_MCELIECE_SYS_T; j++)
		{
			mask = i ^ (ind[j] >> 6);
			mask -= 1;
			mask >>= 63;
			mask = ~mask + 1;
			e_int[i] |= val[j] & mask;
		}
	}

	for (i = 0; i < QSC_MCELIECE_SYS_N / 64; i++)
	{
		le64to8(e + i * 8, e_int[i]);
	}
}

void syndrome(uint8_t* s, const uint8_t* pk, uint8_t* e)
{
	uint8_t row[QSC_MCELIECE_SYS_N / 8];
	size_t i;
	size_t j;
	size_t poft;
	uint8_t b;

	for (i = 0; i < QSC_MCELIECE_SYND_BYTES; i++)
	{
		s[i] = 0;
	}

	poft = 0;

	for (i = 0; i < QSC_MCELIECE_PK_NROWS; i++)
	{
		for (j = 0; j < QSC_MCELIECE_SYS_N / 8; j++)
		{
			row[j] = 0;
		}

		for (j = 0; j < QSC_MCELIECE_PK_ROW_BYTES; j++)
		{
			row[QSC_MCELIECE_SYS_N / 8 - QSC_MCELIECE_PK_ROW_BYTES + j] = pk[poft + j];
		}

		row[i / 8] |= 1 << (i % 8);
		b = 0;

		for (j = 0; j < QSC_MCELIECE_SYS_N / 8; j++)
		{
			b ^= row[j] & e[j];
		}

		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		b &= 1U;
		s[i / 8] |= (b << (i % 8));

		poft += QSC_MCELIECE_PK_ROW_BYTES;
	}
}

void qsc_mceliece_encrypt(uint8_t* s, const uint8_t* pk, uint8_t* e, void (*rng_generate)(uint8_t*, size_t))
{
	gen_e(e, rng_generate);
	syndrome(s, pk, e);
}

/* gf.c */

void qsc_mceliece_gf_multiply(gf* out, gf* in0, gf* in1)
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
			prod[i + j] ^= qsc_mceliece_gf_mul(in0[i], in1[j]);
		}
	}

	for (i = 254; i >= 128; i--)
	{
		prod[i - 123] ^= qsc_mceliece_gf_mul(prod[i], (gf)QSC_MCELIECE_GF_MUL_FACTOR1);
		prod[i - 125] ^= qsc_mceliece_gf_mul(prod[i], (gf)QSC_MCELIECE_GF_MUL_FACTOR2);
		prod[i - 128] ^= qsc_mceliece_gf_mul(prod[i], (gf)QSC_MCELIECE_GF_MUL_FACTOR3);
	}

	for (i = 0; i < 128; i++)
	{
		out[i] = prod[i];
	}
}

/* pk_gen.c */

int32_t qsc_mceliece_pk_gen(uint8_t* pk, const uint8_t* sk)
{
	gf g[QSC_MCELIECE_SYS_T + 1];
	gf L[QSC_MCELIECE_SYS_N];
	gf inv[QSC_MCELIECE_SYS_N];
	int32_t ret;
	size_t c;
	size_t i;
	size_t j;
	size_t k;
	size_t row;
	uint8_t b;
	uint8_t mask;

	ret = 1;

#ifdef MQC_COMPILER_GCC
	uint8_t mat[QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T][QSC_MCELIECE_SYS_N / 8];
#else
	uint8_t** mat = malloc(QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T * sizeof(uint8_t*));

	for (i = 0; i < QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T; ++i)
	{
		mat[i] = malloc(QSC_MCELIECE_SYS_N / 8);
		memset(mat[i], 0, QSC_MCELIECE_SYS_N / 8);
	}
#endif

	if (mat != NULL)
	{
		g[QSC_MCELIECE_SYS_T] = 1;

		for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
		{
			g[i] = le8to16(sk);
			g[i] &= QSC_MCELIECE_GFMASK;
			sk += 2;
		}

		qsc_mceliece_support_gen(L, sk);
		qsc_mceliece_root(inv, g, L);

		for (i = 0; i < QSC_MCELIECE_SYS_N; i++)
		{
			inv[i] = qsc_mceliece_gf_inv(inv[i]);
		}

		for (i = 0; i < QSC_MCELIECE_PK_NROWS; i++)
		{
			for (j = 0; j < QSC_MCELIECE_SYS_N / 8; j++)
			{
				mat[i][j] = 0;
			}
		}

		for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
		{
			for (j = 0; j < QSC_MCELIECE_SYS_N; j += 8)
			{
				for (k = 0; k < QSC_MCELIECE_GFBITS; k++)
				{
					b = (inv[j + 7] >> k) & 1; b <<= 1;
					b |= (inv[j + 6] >> k) & 1; b <<= 1;
					b |= (inv[j + 5] >> k) & 1; b <<= 1;
					b |= (inv[j + 4] >> k) & 1; b <<= 1;
					b |= (inv[j + 3] >> k) & 1; b <<= 1;
					b |= (inv[j + 2] >> k) & 1; b <<= 1;
					b |= (inv[j + 1] >> k) & 1; b <<= 1;
					b |= (inv[j + 0] >> k) & 1;

					mat[i * QSC_MCELIECE_GFBITS + k][j / 8] = b;
				}
			}

			for (j = 0; j < QSC_MCELIECE_SYS_N; j++)
			{
				inv[j] = qsc_mceliece_gf_mul(inv[j], L[j]);
			}
		}

		for (i = 0; i < (QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T + 7) / 8; i++)
		{
			for (j = 0; j < 8; j++)
			{
				row = i * 8 + j;

				if (row >= QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T)
				{
					break;
				}

				for (k = row + 1; k < QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T; k++)
				{
					mask = mat[row][i] ^ mat[k][i];
					mask >>= j;
					mask &= 1;
					mask = ~mask + 1;

					for (c = 0; c < QSC_MCELIECE_SYS_N / 8; c++)
					{
						mat[row][c] ^= mat[k][c] & mask;
					}
				}

				// return if not systematic
				if (((mat[row][i] >> j) & 1) == 0)
				{
					return -1;
				}

				for (k = 0; k < QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T; k++)
				{
					if (k != row)
					{
						mask = mat[k][i] >> j;
						mask &= 1;
						mask = ~mask + 1;

						for (c = 0; c < QSC_MCELIECE_SYS_N / 8; c++)
						{
							mat[k][c] ^= mat[row][c] & mask;
						}
					}
				}
			}
		}

		for (i = 0; i < QSC_MCELIECE_PK_NROWS; i++)
		{
			memcpy(pk + i * QSC_MCELIECE_PK_ROW_BYTES, mat[i] + QSC_MCELIECE_PK_NROWS / 8, QSC_MCELIECE_PK_ROW_BYTES);
		}

#ifndef MQC_COMPILER_GCC
		if (mat != NULL)
		{
			for (i = 0; i < QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T; ++i)
			{
				free(mat[i]);
			}

			free(mat);
		}
#endif

		ret = 0;
	}

	return ret;
}

/* root.c */

gf qsc_mceliece_root_eval(const gf* f, gf a)
{
	size_t i;
	gf r;

	r = f[QSC_MCELIECE_SYS_T];
	i = QSC_MCELIECE_SYS_T;

	do
	{
		--i;
		r = qsc_mceliece_gf_mul(r, a);
		r = qsc_mceliece_gf_add(r, f[i]);
	} 
	while (i != 0);

	return r;
}

void qsc_mceliece_root(gf* out, const gf* f, const gf* L)
{
	size_t i;

	for (i = 0; i < QSC_MCELIECE_SYS_N; i++)
	{
		out[i] = qsc_mceliece_root_eval(f, L[i]);
	}
}

/* sk_gen.c */

static int32_t irr_gen(gf* out, const gf* f)
{
	gf mat[QSC_MCELIECE_SYS_T + 1][QSC_MCELIECE_SYS_T];
	size_t c;
	size_t i;
	size_t j;
	size_t k;
	int32_t ret;
	gf mask;
	gf inv;
	gf t;

	ret = 0;
	mat[0][0] = 1;

	for (i = 1; i < QSC_MCELIECE_SYS_T; i++)
	{
		mat[0][i] = 0;
	}

	for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
	{
		mat[1][i] = f[i];
	}

	for (j = 2; j <= QSC_MCELIECE_SYS_T; j++)
	{
		qsc_mceliece_gf_multiply(mat[j], mat[j - 1], f);
	}

	for (j = 0; j < QSC_MCELIECE_SYS_T; j++)
	{
		for (k = j + 1; k < QSC_MCELIECE_SYS_T; k++)
		{
			mask = qsc_mceliece_gf_iszero(mat[j][j]);

			for (c = j; c < QSC_MCELIECE_SYS_T + 1; c++)
			{
				mat[c][j] ^= mat[c][k] & mask;
			}
		}

		if (mat[j][j] == 0)
		{
			ret = -1;
			break;
		}

		inv = qsc_mceliece_gf_inv(mat[j][j]);

		for (c = j; c < QSC_MCELIECE_SYS_T + 1; c++)
		{
			mat[c][j] = qsc_mceliece_gf_mul(mat[c][j], inv);
		}

		for (k = 0; k < QSC_MCELIECE_SYS_T; k++)
		{
			if (k != j)
			{
				t = mat[j][k];

				for (c = j; c < QSC_MCELIECE_SYS_T + 1; c++)
				{
					mat[c][k] ^= qsc_mceliece_gf_mul(mat[c][j], t);
				}
			}
		}
	}

	if (ret == 0)
	{
		for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
		{
			out[i] = mat[QSC_MCELIECE_SYS_T][i];
		}
	}

	return ret;
}

int32_t perm_conversion(uint32_t* perm)
{
	uint64_t L[1 << QSC_MCELIECE_GFBITS];
	size_t i;
	int32_t ret;

	ret = 0;

	for (i = 0; i < (1 << QSC_MCELIECE_GFBITS); i++)
	{
		L[i] = perm[i];
		L[i] <<= 31;
		L[i] |= i;
	}

	qsc_mceliece_sort_63b(1 << QSC_MCELIECE_GFBITS, L);

	for (i = 1; i < (1 << QSC_MCELIECE_GFBITS); i++)
	{
		if ((L[i - 1] >> 31) == (L[i] >> 31))
		{
			ret = -1;
			break;
		}
	}

	if (ret == 0)
	{
		for (i = 0; i < (1 << QSC_MCELIECE_GFBITS); i++)
		{
			perm[i] = L[i] & QSC_MCELIECE_GFMASK;
		}
	}

	return ret;
}

int32_t qsc_mceliece_sk_part_gen(uint8_t* sk, void (*rng_generate)(uint8_t*, size_t))
{
	// random permutation
	uint32_t perm[1 << QSC_MCELIECE_GFBITS];
	// irreducible polynomial
	gf g[QSC_MCELIECE_SYS_T];
	// random element in GF(2^mt)
	gf a[QSC_MCELIECE_SYS_T];
	size_t i;

	for (;;)
	{
		rng_generate((uint8_t*)a, sizeof(a));

		for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
		{
			a[i] &= QSC_MCELIECE_GFMASK;
		}

		if (irr_gen(g, a) == 0)
		{
			break;
		}
	}

	for (;;)
	{
		rng_generate((uint8_t*)perm, sizeof(perm));

		if (perm_conversion(perm) == 0)
		{
			break;
		}
	}

	for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
	{
		le16to8(sk + QSC_MCELIECE_SYS_N / 8 + i * 2, g[i]);
	}

	qsc_mceliece_controlbits(sk + QSC_MCELIECE_SYS_N / 8 + QSC_MCELIECE_IRR_BYTES, perm);

	return 0;
}

/* synd.c */

void qsc_mceliece_synd(gf* out, const gf* f, const gf* L, const uint8_t* r)
{
	size_t i;
	size_t j;
	gf c;
	gf e;
	gf einv;

	for (j = 0; j < 2 * QSC_MCELIECE_SYS_T; j++)
	{
		out[j] = 0;
	}

	for (i = 0; i < QSC_MCELIECE_SYS_N; i++)
	{
		c = (r[i / 8] >> (i % 8)) & 1;
		e = qsc_mceliece_root_eval(f, L[i]);
		einv = qsc_mceliece_gf_inv(qsc_mceliece_gf_mul(e, e));

		for (j = 0; j < 2 * QSC_MCELIECE_SYS_T; j++)
		{
			out[j] = qsc_mceliece_gf_add(out[j], qsc_mceliece_gf_mul(einv, c));
			einv = qsc_mceliece_gf_mul(einv, L[i]);
		}
	}
}

#endif