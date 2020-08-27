#include "mpkcn6960t119.h"

#ifndef QSC_MCELIECE_STRONG
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
	uint8_t L[QSC_MCELIECE_GFBITS][(1U << QSC_MCELIECE_GFBITS) / 8];
	size_t i;
	size_t j;
	gf a;

	for (i = 0; i < QSC_MCELIECE_GFBITS; ++i)
	{
		for (j = 0; j < (1U << QSC_MCELIECE_GFBITS) / 8; ++j)
		{
			L[i][j] = 0;
		}
	}

	for (i = 0; i < (1U << QSC_MCELIECE_GFBITS); ++i)
	{
		a = qsc_mceliece_gf_bitrev((gf)i);

		for (j = 0; j < QSC_MCELIECE_GFBITS; ++j)
		{
			L[j][i / 8] |= ((a >> j) & 1U) << (i % 8);
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

		L = (L & ~mle) | ((uint16_t)(N + 1 - L) & mle);

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
		} 
		while (i > 0);

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
	/* input: pi, a permutation*/
	/* output: out, control bits w.r.t. pi */

	uint8_t c[(((2 * QSC_MCELIECE_GFBITS) - 1) * (1UL << QSC_MCELIECE_GFBITS)) / 16] = { 0 };
	size_t i;

	qsc_mceliece_permutecontrolbits(QSC_MCELIECE_GFBITS, (1UL << QSC_MCELIECE_GFBITS), 1UL, 0UL, c, pi);

	for (i = 0; i < sizeof(c); i++)
	{
		out[i] = c[i];
	}
}

/* decrypt.h */

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
	int32_t w;
	uint16_t check;
	gf t;

	w = 0;

	for (i = 0; i < QSC_MCELIECE_SYND_BYTES; i++)
	{
		r[i] = c[i];
	}

	r[i - 1] &= (1U << ((QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T) % 8)) - 1;

	for (i = QSC_MCELIECE_SYND_BYTES; i < QSC_MCELIECE_SYS_N / 8; i++)
	{
		r[i] = 0;
	}

	for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
	{
		g[i] = le8to16(sk);
		g[i] &= (uint16_t)QSC_MCELIECE_GFMASK;
		sk += 2;
	}

	g[QSC_MCELIECE_SYS_T] = 1;
	qsc_mceliece_support_gen(L, sk);
	qsc_mceliece_synd(s, g, L, r);
	qsc_mceliece_bm(locator, s);
	qsc_mceliece_root(images, locator, L);

	for (i = 0; i < QSC_MCELIECE_SYS_N / 8; i++)
	{
		e[i] = 0x00;
	}

	for (i = 0; i < QSC_MCELIECE_SYS_N; i++)
	{
		t = qsc_mceliece_gf_iszero(images[i]) & 1U;
		e[i / 8] |= (uint8_t)(t << (i % 8));
		w += t;

	}

	qsc_mceliece_synd(s_cmp, g, L, e);
	check = (uint16_t)w;
	check ^= (uint16_t)QSC_MCELIECE_SYS_T;

	for (i = 0; i < QSC_MCELIECE_SYS_T * 2; i++)
	{
		check |= (uint16_t)s[i] ^ s_cmp[i];
	}

	check -= 1;
	check >>= 15U;
	check ^= 1U;

	return check;
}

/* encrypt.h */

static int32_t mov_forward(uint16_t* ind)
{
	size_t i;
	size_t j;
	int32_t found;
	uint16_t t;

	for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
	{
		found = 0;

		for (j = i; j < QSC_MCELIECE_SYS_T * 2; j++)
		{
			if (ind[j] < QSC_MCELIECE_SYS_N)
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

static void gen_e(uint8_t* e, void (*rng_generate)(uint8_t*, size_t))
{
	uint64_t e_int[(QSC_MCELIECE_SYS_N + 63) / 64];
	uint64_t val[QSC_MCELIECE_SYS_T];
	uint16_t ind[QSC_MCELIECE_SYS_T * 2];
	uint64_t mask;
	uint64_t one;
	int32_t eq;
	size_t i;
	size_t j;

	one = 1;

	for (;;)
	{
		rng_generate((uint8_t*)ind, sizeof(ind));

		for (i = 0; i < QSC_MCELIECE_SYS_T * 2; i++)
		{
			ind[i] &= (uint16_t)QSC_MCELIECE_GFMASK;
		}

		if (mov_forward(ind) == 0)
		{
			continue;
		}

		// check for repetition
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
		val[j] = one << (ind[j] & 63U);
	}

	for (i = 0; i < (QSC_MCELIECE_SYS_N + 63) / 64; i++)
	{
		e_int[i] = 0;

		for (j = 0; j < QSC_MCELIECE_SYS_T; j++)
		{
			mask = i ^ (uint64_t)(ind[j] >> 6);
			mask -= 1;
			mask >>= 63;
			mask = ~mask + 1;
			e_int[i] |= val[j] & mask;
		}
	}

	for (i = 0; i < (QSC_MCELIECE_SYS_N + 63) / 64 - 1; i++)
	{
		le64to8(e, e_int[i]);
		e += 8;
	}

	for (j = 0; j < (QSC_MCELIECE_SYS_N % 64); j += 8)
	{
		e[j / 8] = (e_int[i] >> j) & 0xFFU;
	}
}

void syndrome(uint8_t* s, const uint8_t* pk, const uint8_t* e)
{
	/* input: public key pk, error vector e */
	/* output: syndrome s */

	const uint8_t* pk_ptr = pk;
	uint8_t row[QSC_MCELIECE_SYS_N / 8];
	size_t i;
	size_t j;
	uint32_t tail;
	uint8_t b;

	for (i = 0; i < QSC_MCELIECE_SYND_BYTES; i++)
	{
		s[i] = 0;
	}

	tail = QSC_MCELIECE_PK_NROWS % 8;

	for (i = 0; i < QSC_MCELIECE_PK_NROWS; i++)
	{
		for (j = 0; j < QSC_MCELIECE_SYS_N / 8; j++)
		{
			row[j] = 0;
		}

		for (j = 0; j < QSC_MCELIECE_PK_ROW_BYTES; j++)
		{
			row[((QSC_MCELIECE_SYS_N / 8) - QSC_MCELIECE_PK_ROW_BYTES) + j] = pk_ptr[j];
		}

		for (j = (QSC_MCELIECE_SYS_N / 8) - 1; j >= (QSC_MCELIECE_SYS_N / 8) - QSC_MCELIECE_PK_ROW_BYTES; j--)
		{
			row[j] = (row[j] << tail) | (row[j - 1] >> (8UL - tail));
		}

		row[i / 8] |= 1U << (i % 8);
		b = 0;

		for (j = 0; j < QSC_MCELIECE_SYS_N / 8; j++)
		{
			b ^= row[j] & e[j];
		}

		b ^= b >> 4U;
		b ^= b >> 2U;
		b ^= b >> 1U;
		b &= 1U;

		s[i / 8] |= (b << (i % 8));
		pk_ptr += QSC_MCELIECE_PK_ROW_BYTES;
	}
}

void qsc_mceliece_encrypt(uint8_t* ss, const uint8_t* pk, uint8_t* e, void (*rng_generate)(uint8_t*, size_t))
{
	gen_e(e, rng_generate);
	syndrome(ss, pk, e);
}

/* gf.c */

void qsc_mceliece_gf_multiply(gf* out, const gf* in0, const gf* in1)
{
	gf prod[QSC_MCELIECE_IRR_BYTES - 1];
	size_t i;
	size_t j;

	for (i = 0; i < QSC_MCELIECE_IRR_BYTES - 1; i++)
	{
		prod[i] = 0;
	}

	for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
	{
		for (j = 0; j < QSC_MCELIECE_SYS_T; j++)
		{
			prod[i + j] ^= qsc_mceliece_gf_mul(in0[i], in1[j]);
		}
	}

	for (i = QSC_MCELIECE_IRR_BYTES - 2; i >= QSC_MCELIECE_SYS_T; i--)
	{
		prod[i - (QSC_MCELIECE_SYS_T - 2)] ^= qsc_mceliece_gf_mul(prod[i], (gf)QSC_MCELIECE_GF_MUL_FACTOR1);
		prod[i - QSC_MCELIECE_SYS_T] ^= qsc_mceliece_gf_mul(prod[i], (gf)QSC_MCELIECE_GF_MUL_FACTOR2);
	}

	for (i = 0; i < QSC_MCELIECE_SYS_T; i++)
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
	size_t c;
	size_t i;
	size_t j;
	size_t k;
	size_t row;
	uint32_t tail;
	int32_t ret;
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
		ret = 0;

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
					/* jgu: checked */
					/*lint -save -e661, -e662 */
					b = (inv[j + 7] >> k) & 1U;
					b <<= 1;
					b |= (inv[j + 6] >> k) & 1U;
					b <<= 1;
					b |= (inv[j + 5] >> k) & 1U;
					b <<= 1;
					b |= (inv[j + 4] >> k) & 1U;
					b <<= 1;
					b |= (inv[j + 3] >> k) & 1U;
					b <<= 1;
					b |= (inv[j + 2] >> k) & 1U;
					b <<= 1;
					b |= (inv[j + 1] >> k) & 1U;
					b <<= 1;
					b |= (inv[j] >> k) & 1U;
					/*lint -restore */
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
				row = (i * 8) + j;

				if (row >= QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T)
				{
					break;
				}

				for (k = row + 1; k < QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T; k++)
				{
					mask = mat[row][i] ^ mat[k][i];
					mask >>= j;
					mask &= 1U;
					mask = ~mask + 1;

					for (c = 0; c < QSC_MCELIECE_SYS_N / 8; c++)
					{
						mat[row][c] ^= mat[k][c] & mask;
					}
				}

				// return if not systematic
				if (((mat[row][i] >> j) & 1U) == 0)
				{
					ret = -1;
					break;
				}

				for (k = 0; k < QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T; k++)
				{
					if (k != row)
					{
						mask = mat[k][i] >> j;
						mask &= 1U;
						mask = ~mask + 1;

						for (c = 0; c < QSC_MCELIECE_SYS_N / 8; c++)
						{
							mat[k][c] ^= mat[row][c] & mask;
						}
					}
				}
			}

			if (ret != 0)
			{
				break;
			}
		}

		if (ret == 0)
		{
			tail = (QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T) % 8;
			k = 0;

			for (i = 0; i < QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T; i++)
			{
				for (j = ((QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T) - 1) / 8; j < (QSC_MCELIECE_SYS_N / 8) - 1; j++)
				{
					pk[k] = (mat[i][j] >> tail) | (mat[i][j + 1UL] << (8UL - tail));
					++k;
				}

				pk[k] = (mat[i][j] >> tail);
				++k;
			}

			for (i = 0; i < QSC_MCELIECE_GFBITS * QSC_MCELIECE_SYS_T; ++i)
			{
				free(mat[i]);
			}
		}

		free(mat);
	}

	return ret;
}

/* qsc_mceliece_root.c */

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
	/* input: f, an element in GF((2^m)^t) */
	/* output: out, the generating polynomial of f (first t coefficients only) */
	/* return: 0 for success, -1 for failure*/

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

		// return if not systematic
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
	/* input: permutation represented by 32-bit integers */
	/* output: an equivalent permutation represented by integers in {0, ..., 2^m-1} */
	/* return  0 if no repeated intergers in the input */
	/* return -1 if there are repeated intergers in the input */

	uint64_t L[1 << QSC_MCELIECE_GFBITS];
	size_t i;
	int32_t ret;

	ret = 0;

	for (i = 0; i < (1UL << QSC_MCELIECE_GFBITS); i++)
	{
		L[i] = perm[i];
		L[i] <<= 31;
		L[i] |= i;
	}

	qsc_mceliece_sort_63b(1UL << QSC_MCELIECE_GFBITS, L);

	for (i = 1; i < (1UL << QSC_MCELIECE_GFBITS); i++)
	{
		if ((L[i - 1] >> 31) == (L[i] >> 31))
		{
			ret = -1;
			break;
		}
	}

	if (ret == 0)
	{
		for (i = 0; i < (1UL << QSC_MCELIECE_GFBITS); i++)
		{
			perm[i] = L[i] & QSC_MCELIECE_GFMASK;
		}
	}

	return ret;
}

int32_t qsc_mceliece_sk_part_gen(uint8_t* sk, void (*rng_generate)(uint8_t*, size_t))
{
	/* output: sk, the secret key */

	// random permutation
	uint32_t perm[1UL << QSC_MCELIECE_GFBITS];
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
		c = (r[i / 8] >> (i % 8)) & 1U;
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


