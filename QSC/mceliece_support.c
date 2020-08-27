#include "mceliece_support.h"
#include "intutils.h"
#include "sha3.h"
#include <stdlib.h>

/* shared functions */

/* benes.c */

void qsc_mceliece_benes_layer_in(uint64_t data[2][64], const uint64_t* bits, uint32_t lgs)
{
	uint64_t d;
	size_t i;
	size_t j;
	size_t k;
	size_t s;

	k = 0;
	s = (size_t)1UL << lgs;

	for (i = 0; i < 64; i += s * 2)
	{
		for (j = i; j < i + s; j++)
		{
			d = (data[0][j] ^ data[0][j + s]);
			d &= bits[k];
			++k;
			data[0][j] ^= d;
			data[0][j + s] ^= d;

			d = (data[1][j] ^ data[1][j + s]);
			d &= bits[k];
			++k;
			data[1][j] ^= d;
			data[1][j + s] ^= d;
		}
	}
}

void qsc_mceliece_benes_layer_ex(uint64_t* data, const uint64_t* bits, uint32_t lgs)
{
	uint64_t d;
	size_t i;
	size_t j;
	size_t k;
	uint32_t s;

	k = 0;
	s = 1UL << lgs;

	for (i = 0; i < 128; i += s * 2)
	{
		for (j = i; j < i + s; j++)
		{
			d = (data[j] ^ data[j + s]);
			d &= bits[k];
			++k;
			data[j] ^= d;
			data[j + s] ^= d;
		}
	}
}

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
		bptr = bits + QSC_MCELIECE_BENES_BPTR;
		inc = QSC_MCELIECE_BENES_INC;
	}
	else
	{
		bptr = bits;
		inc = 0;
	}

	for (i = 0; i < 64; ++i)
	{
		riv[0][i] = qsc_intutils_le8to64(rptr + i * 16);
		riv[1][i] = qsc_intutils_le8to64(rptr + i * 16 + 8);
	}

	qsc_mceliece_transpose_64x64(rih[0], riv[0]);
	qsc_mceliece_transpose_64x64(rih[1], riv[1]);

	for (iter = 0; iter <= 6; iter++)
	{
		for (i = 0; i < 64; ++i)
		{
			biv[i] = qsc_intutils_le8to64(bptr);
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
			biv[i] = qsc_intutils_le8to64(bptr);
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
			biv[i] = qsc_intutils_le8to64(bptr);
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
			biv[i] = qsc_intutils_le8to64(bptr);
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
		qsc_intutils_le64to8(rptr + i * 16 + 0, riv[0][i]);
		qsc_intutils_le64to8(rptr + i * 16 + 8, riv[1][i]);
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

bit qsc_mceliece_is_smaller(uint32_t a, uint32_t b)
{
	uint32_t ret;

	ret = a - b;
	ret >>= 31;

	return (bit)ret;
}

bit qsc_mceliece_is_smaller_63b(uint64_t a, uint64_t b)
{
	uint64_t ret;

	ret = a - b;
	ret >>= 63;

	return (bit)ret;
}

void qsc_mceliece_cswap(uint32_t* x, uint32_t* y, bit swap)
{
	uint32_t m;
	uint32_t d;

	m = (uint32_t)swap;
	m = 0 - m;
	d = (*x ^ *y);
	d &= m;
	*x ^= d;
	*y ^= d;
}

void qsc_mceliece_cswap_63b(uint64_t* x, uint64_t* y, bit swap)
{
	uint64_t m;
	uint64_t d;

	m = (uint32_t)swap;
	m = 0 - m;
	d = (*x ^ *y);
	d &= m;
	*x ^= d;
	*y ^= d;
}

void qsc_mceliece_minmax(uint32_t* x, uint32_t* y)
{
	bit m;

	m = qsc_mceliece_is_smaller(*y, *x);
	qsc_mceliece_cswap(x, y, m);

}

void qsc_mceliece_minmax_63b(uint64_t* x, uint64_t* y)
{
	bit m;

	m = qsc_mceliece_is_smaller_63b(*y, *x);
	qsc_mceliece_cswap_63b(x, y, m);
}

void qsc_mceliece_merge(uint32_t n, uint32_t* x, uint32_t step)
{
	size_t i;

	if (n == 1)
	{
		qsc_mceliece_minmax(&x[0], &x[step]);
	}
	else
	{
		qsc_mceliece_merge(n / 2, x, step * 2);
		qsc_mceliece_merge(n / 2, x + step, step * 2);

		for (i = 1; i < (2 * n) - 1; i += 2)
		{
			qsc_mceliece_minmax(&x[i * step], &x[(i + 1) * step]);
		}
	}
}

void qsc_mceliece_merge_63b(uint32_t n, uint64_t* x, uint32_t step)
{
	size_t i;

	if (n == 1)
	{
		qsc_mceliece_minmax_63b(&x[0], &x[step]);
	}
	else
	{
		qsc_mceliece_merge_63b(n / 2, x, step * 2);
		qsc_mceliece_merge_63b(n / 2, x + step, step * 2);

		for (i = 1; i < 2 * n - 1; i += 2)
		{
			qsc_mceliece_minmax_63b(&x[i * step], &x[(i + 1) * step]);
		}
	}
}

void qsc_mceliece_sort(uint32_t n, uint32_t* x)
{
	if (n > 1)
	{
		qsc_mceliece_sort(n / 2, x);
		qsc_mceliece_sort(n / 2, x + (n / 2));
		qsc_mceliece_merge(n / 2, x, 1UL);
	}
}

void qsc_mceliece_sort_63b(uint32_t n, uint64_t* x)
{
	if (n > 1)
	{
		qsc_mceliece_sort_63b(n / 2, x);
		qsc_mceliece_sort_63b(n / 2, x + (n / 2));
		qsc_mceliece_merge_63b(n / 2, x, 1UL);
	}
}

void qsc_mceliece_composeinv(uint32_t n, uint32_t* y, const uint32_t* x, const uint32_t* pi)
{
	/* y[pi[i]] = x[i] */
	/* requires n = 2^w */
	/* requires pi to be a permutation */

	size_t i;

#ifdef MQC_COMPILER_GCC
	uint8_t t[n * sizeof(uint32_t)];
#else
	uint32_t* t = malloc(n * sizeof(uint32_t));
#endif

	if (t != NULL)
	{
		for (i = 0; i < n; ++i)
		{
			t[i] = x[i] | (pi[i] << 16);
		}

		qsc_mceliece_sort(n, t);

		for (i = 0; i < n; ++i)
		{
			y[i] = t[i] & 0x0000FFFFUL;
		}

#ifndef MQC_COMPILER_GCC
		free(t);
#endif
	}
}

void qsc_mceliece_invert(uint32_t n, uint32_t* ip, const uint32_t* pi)
{
	/* ip[i] = j iff pi[i] = j */
	/* requires n = 2^w */
	/* requires pi to be a permutation */

	uint32_t i;

	for (i = 0; i < n; i++)
	{
		ip[i] = i;
	}

	qsc_mceliece_composeinv(n, ip, ip, pi);
}

void qsc_mceliece_flow(uint32_t w, uint32_t* x, const uint32_t* y, const uint32_t t)
{
	uint32_t b;
	uint32_t ycopy;
	bit m0;
	bit m1;

	ycopy = *y;
	m0 = qsc_mceliece_is_smaller(*y & ((1UL << w) - 1), *x & ((1UL << w) - 1));
	m1 = qsc_mceliece_is_smaller(0UL, t);

	qsc_mceliece_cswap(x, &ycopy, m0);
	b = (uint32_t)(m0 & m1);
	*x ^= (b << w);
}

void qsc_mceliece_compose(uint32_t w, uint32_t n, const uint32_t* pi, uint32_t* P)
{
	size_t i;
	uint32_t t;

#ifdef MQC_COMPILER_GCC
	uint32_t I[2 * n * sizeof(uint32_t)];
	uint32_t ip[n * sizeof(uint32_t)];
#else
	uint32_t* I = malloc(2 * n * sizeof(uint32_t));
	uint32_t* ip = malloc(n * sizeof(uint32_t));
#endif

	if (I != NULL && ip != NULL)
	{
		qsc_mceliece_invert(n, ip, pi);

		for (i = 0; i < n; ++i)
		{
			I[i] = ip[i] | (1UL << w);
			I[n + i] = pi[i];
		}

		// end ip
		for (i = 0; i < 2 * n; ++i)
		{
			P[i] = (uint32_t)((i >> w) + (i & ((1UL << w) - 2)) + ((i & 1UL) << w));
		}

#ifdef MQC_COMPILER_GCC
		uint32_t PI[2 * n * sizeof(uint32_t)];
		uint32_t T[2 * n * sizeof(uint32_t)];
#else
		uint32_t* PI = malloc(2 * n * sizeof(uint32_t));
		uint32_t* T = malloc(2 * n * sizeof(uint32_t));
#endif

		if (PI != NULL && T != NULL)
		{
			for (t = 0; t < w; ++t)
			{
				qsc_mceliece_composeinv(2 * n, PI, P, I);

				for (i = 0; i < 2 * n; ++i)
				{
					qsc_mceliece_flow(w, &P[i], &PI[i], t);
				}

				for (i = 0; i < 2 * n; ++i)
				{
					T[i] = I[i ^ 1];
				}

				qsc_mceliece_composeinv(2 * n, I, I, T);

				for (i = 0; i < 2 * n; ++i)
				{
					T[i] = P[i ^ 1];
				}

				for (i = 0; i < 2 * n; ++i)
				{
					qsc_mceliece_flow(w, &P[i], &T[i], 1);
				}
			}
		}

#ifndef MQC_COMPILER_GCC
		if (PI != NULL)
		{
			free(PI);
		}
		if (T != NULL)
		{
			free(T);
		}
#endif
	}

#ifndef MQC_COMPILER_GCC
	if (I != NULL)
	{
		free(I);
	}
	if (ip != NULL)
	{
		free(ip);
	}
#endif
}

void qsc_mceliece_permute(uint32_t w, uint32_t n, uint32_t off, uint32_t step, const uint32_t* P, const uint32_t* pi, uint8_t* c, uint32_t* piflip)
{
	size_t i;
	size_t j;

	for (i = 0; i < n; ++i)
	{
		for (j = 0; j < w; ++j)
		{
			piflip[i] = pi[i];
		}
	}

	for (i = 0; i < n / 2; ++i)
	{
		c[(off + i * step) / 8] |= ((P[i * 2] >> w) & 1) << ((off + i * step) % 8);
	}

	for (i = 0; i < n / 2; ++i)
	{
		c[(off + ((w - 1) * n + i) * step) / 8] |= ((P[n + i * 2] >> w) & 1) << ((off + ((w - 1) * n + i) * step) % 8);
	}

	for (i = 0; i < n / 2; ++i)
	{
		qsc_mceliece_cswap(&piflip[i * 2], &piflip[i * 2 + 1], (P[n + i * 2] >> w) & 1);
	}
}

void qsc_mceliece_permutecontrolbits(uint32_t w, uint32_t n, uint32_t step, uint32_t off, uint8_t* c, const uint32_t* pi)
{
	/* input: permutation pi */
	/* output: (2w-1)n/2 (or 0 if n==1) control bits c[0],c[step],c[2*step],... */
	/* requires n = 2^w */

	size_t i;

	if (w == 1)
	{
		c[off / 8] |= (pi[0] & 1U) << (off % 8);
	}

	if (w > 1)
	{
#ifdef MQC_COMPILER_GCC
		uint32_t piflip[n * sizeof(uint32_t)];
#else
		uint32_t* piflip = malloc(n * sizeof(uint32_t));
#endif

		if (piflip != NULL)
		{
#ifdef MQC_COMPILER_GCC
			uint32_t P[2 * n * sizeof(uint32_t)];
#else
			uint32_t* P = malloc(2 * n * sizeof(uint32_t));
#endif

			if (P != NULL)
			{
				qsc_mceliece_compose(w, n, pi, P);
				qsc_mceliece_permute(w, n, off, step, P, pi, c, piflip);
#ifndef MQC_COMPILER_GCC
				free(P);
#endif
			}

#ifdef MQC_COMPILER_GCC
			uint32_t subpi[n * sizeof(uint32_t)];
#else
			uint32_t* subpi = malloc(n * sizeof(uint32_t));
#endif

			if (subpi != NULL)
			{
				for (i = 0; i < n / 2; ++i)
				{
					subpi[i] = piflip[i * 2] >> 1;
				}

				for (i = 0; i < n / 2; ++i)
				{
					subpi[i + n / 2] = piflip[(i * 2) + 1] >> 1;
				}

#ifndef MQC_COMPILER_GCC
				free(piflip);
#endif
				qsc_mceliece_permutecontrolbits(w - 1, n / 2, step * 2, off + step * (n / 2), c, subpi);
				qsc_mceliece_permutecontrolbits(w - 1, n / 2, step * 2, off + step * ((n / 2) + 1), c, &subpi[n / 2]);

#ifndef MQC_COMPILER_GCC
				free(subpi);
#endif
			}
		}
	}
}

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

/* gf.c */

gf qsc_mceliece_gf_bitrev(gf a)
{
	a = ((a & 0x00FFU) << 8) | ((a & 0xFF00U) >> 8);
	a = ((a & 0x0F0FU) << 4) | ((a & 0xF0F0U) >> 4);
	a = ((a & 0x3333U) << 2) | ((a & 0xCCCCU) >> 2);
	a = ((a & 0x5555U) << 1) | ((a & 0xAAAAU) >> 1);

	return a >> 3;
}

gf qsc_mceliece_gf_iszero(gf a)
{
	uint32_t t;

	t = a;
	t -= 1;
	t >>= 19;

	return (gf)t;
}

gf qsc_mceliece_gf_add(gf in0, gf in1)
{
	return in0 ^ in1;
}

gf qsc_mceliece_gf_mul(gf in0, gf in1)
{
	uint64_t t;
	uint64_t t0;
	uint64_t t1;
	uint64_t tmp;
	size_t i;

	t0 = in0;
	t1 = in1;
	tmp = t0 * (t1 & 1ULL);

	for (i = 1; i < GFNBITS; i++)
	{
		tmp ^= (t0 * (t1 & (1ULL << i)));
	}

	t = tmp & 0x0000000001FF0000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	t = tmp & 0x000000000000E000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

	return (gf)(tmp & (uint64_t)GFNMASK);
}

gf qsc_mceliece_gf_sq2(gf in)
{
	uint64_t x;
	uint64_t t;
	size_t i;

	const uint64_t B[] =
	{
		0x1111111111111111ULL,
		0x0303030303030303ULL,
		0x000F000F000F000FULL,
		0x000000FF000000FFULL
	};

	const uint64_t M[] =
	{
		0x0001FF0000000000ULL,
		0x000000FF80000000ULL,
		0x000000007FC00000ULL,
		0x00000000003FE000ULL
	};

	x = in;
	x = (x | (x << 24)) & B[3];
	x = (x | (x << 12)) & B[2];
	x = (x | (x << 6)) & B[1];
	x = (x | (x << 3)) & B[0];

	for (i = 0; i < 4; i++)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (gf)(x & (uint64_t)GFNMASK);
}

gf qsc_mceliece_gf_sqmul(gf in, gf m)
{
	uint64_t x;
	uint64_t t0;
	uint64_t t1;
	uint64_t t;
	size_t i;

	const uint64_t M[] =
	{
		0x0000001FF0000000ULL,
		0x000000000FF80000ULL,
		0x000000000007E000ULL
	};

	t0 = in;
	t1 = m;
	x = (t1 << 6) * (t0 & (1 << 6));
	t0 ^= (t0 << 7);

	x ^= (t1 * (t0 & 0x0000000000004001ULL));
	x ^= (t1 * (t0 & 0x0000000000008002ULL)) << 1U;
	x ^= (t1 * (t0 & 0x0000000000010004ULL)) << 2U;
	x ^= (t1 * (t0 & 0x0000000000020008ULL)) << 3U;
	x ^= (t1 * (t0 & 0x0000000000040010ULL)) << 4U;
	x ^= (t1 * (t0 & 0x0000000000080020ULL)) << 5U;

	for (i = 0; i < 3; i++)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (gf)(x & GFNMASK);
}

gf qsc_mceliece_gf_sq2mul(gf in, gf m)
{
	uint64_t x;
	uint64_t t0;
	uint64_t t1;
	uint64_t t;
	size_t i;

	const uint64_t M[] =
	{
		0x1FF0000000000000ULL,
		0x000FF80000000000ULL,
		0x000007FC00000000ULL,
		0x00000003FE000000ULL,
		0x0000000001FE0000ULL,
		0x000000000001E000ULL
	};

	t0 = in;
	t1 = m;
	x = (t1 << 18) * (t0 & (1 << 6));
	t0 ^= (t0 << 21);

	x ^= (t1 * (t0 & (0x0000000010000001ULL)));
	x ^= (t1 * (t0 & (0x0000000020000002ULL))) << 3;
	x ^= (t1 * (t0 & (0x0000000040000004ULL))) << 6;
	x ^= (t1 * (t0 & (0x0000000080000008ULL))) << 9;
	x ^= (t1 * (t0 & (0x0000000100000010ULL))) << 12;
	x ^= (t1 * (t0 & (0x0000000200000020ULL))) << 15;

	for (i = 0; i < 6; i++)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (gf)(x & GFNMASK);
}

gf qsc_mceliece_gf_frac(gf den, gf num)
{
	gf tmp_11;
	gf tmp_1111;
	gf out;

	// ^11
	tmp_11 = qsc_mceliece_gf_sqmul(den, den);
	// ^1111
	tmp_1111 = qsc_mceliece_gf_sq2mul(tmp_11, tmp_11);
	out = qsc_mceliece_gf_sq2(tmp_1111);
	// ^11111111
	out = qsc_mceliece_gf_sq2mul(out, tmp_1111);
	out = qsc_mceliece_gf_sq2(out);
	// ^111111111111
	out = qsc_mceliece_gf_sq2mul(out, tmp_1111);
	// ^1111111111110 = ^-1
	return qsc_mceliece_gf_sqmul(out, num);
}

gf qsc_mceliece_gf_inv(gf den)
{
	return qsc_mceliece_gf_frac(den, (gf)1);
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

/* transpose.c */

void qsc_mceliece_transpose_64x64(uint64_t* out, const uint64_t* in)
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

/* unique functions */

#if defined(QSC_MCELIECE_N8192T128)

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
		g[i] = qsc_intutils_le8to16(sk);
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
		qsc_intutils_le64to8(e + i * 8, e_int[i]);
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

void qsc_mceliece_gf_multiply(gf* out, gf* in0, const gf* in1)
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
			g[i] = qsc_intutils_le8to16(sk);
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
		qsc_intutils_le16to8(sk + QSC_MCELIECE_SYS_N / 8 + i * 2, g[i]);
	}

	qsc_mceliece_controlbits(sk + QSC_MCELIECE_SYS_N / 8 + QSC_MCELIECE_IRR_BYTES, perm);

	return 0;
}

#elif defined(QSC_MCELIECE_N6960T119)

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
	gf check;
	gf t;
	gf w;

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
		g[i] = qsc_intutils_le8to16(sk);
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
		qsc_intutils_le64to8(e, e_int[i]);
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

void qsc_mceliece_gf_multiply(gf* out, gf* in0, const gf* in1)
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
			g[i] = qsc_intutils_le8to16(sk);
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
		qsc_intutils_le16to8(sk + QSC_MCELIECE_SYS_N / 8 + i * 2, g[i]);
	}

	qsc_mceliece_controlbits(sk + QSC_MCELIECE_SYS_N / 8 + QSC_MCELIECE_IRR_BYTES, perm);

	return 0;
}

#else
#	error No McEliece implementation is defined, check common.h!
#endif

/* kem.c */

bool qsc_mceliece_kem_dec(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	uint8_t conf[32] = { 0 };
	uint8_t e2[1 + (QSC_MCELIECE_SYS_N / 8)] = { 2 };
	uint8_t preimage[1 + (QSC_MCELIECE_SYS_N / 8) + (QSC_MCELIECE_SYND_BYTES + 32)];
	size_t pctr;
	size_t i;
	uint16_t m;
	uint8_t confirm;
	uint8_t derr;

	pctr = 0;
	confirm = 0;
	derr = (uint8_t)qsc_mceliece_decrypt(e2 + 1, privatekey + (QSC_MCELIECE_SYS_N / 8), ciphertext);
	qsc_shake256_compute(conf, QSC_MCELIECE_MAC_SIZE, e2, sizeof(e2));

	for (i = 0; i < 32; i++)
	{
		confirm |= conf[i] ^ ciphertext[QSC_MCELIECE_SYND_BYTES + i];
	}

	m = derr | confirm;
	m -= 1;
	m >>= 8;
	preimage[pctr] = (~m & 0) | (m & 1);
	++pctr;

	for (i = 0; i < QSC_MCELIECE_SYS_N / 8; i++)
	{
		preimage[pctr] = (~m & privatekey[i]) | (m & e2[i + 1]);
		++pctr;
	}

	for (i = 0; i < QSC_MCELIECE_SYND_BYTES + 32; i++)
	{
		preimage[pctr] = ciphertext[i];
		++pctr;
	}

	qsc_shake256_compute(secret, QSC_MCELIECE_MAC_SIZE, preimage, sizeof(preimage));

	return (confirm == 0 && derr == 0);
}

void qsc_mceliece_kem_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, void (*rng_generate)(uint8_t*, size_t))
{
	uint8_t e2[1 + (QSC_MCELIECE_SYS_N / 8)] = { 2 };
	uint8_t ec1[1 + (QSC_MCELIECE_SYS_N / 8) + (QSC_MCELIECE_SYND_BYTES + 32)] = { 1 };

	qsc_mceliece_encrypt(ciphertext, publickey, e2 + 1, rng_generate);

	qsc_shake256_compute(ciphertext + QSC_MCELIECE_SYND_BYTES, QSC_MCELIECE_MAC_SIZE, e2, sizeof(e2));
	memcpy(ec1 + 1, e2 + 1, QSC_MCELIECE_SYS_N / 8);
	memcpy(ec1 + 1 + (QSC_MCELIECE_SYS_N / 8), ciphertext, QSC_MCELIECE_SYND_BYTES + QSC_MCELIECE_MAC_SIZE);
	qsc_shake256_compute(secret, QSC_MCELIECE_MAC_SIZE, ec1, sizeof(ec1));
}

void qsc_mceliece_generate_kem_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t))
{
	uint32_t ctr;

	ctr = 0;

	for (;;)
	{
		qsc_mceliece_sk_part_gen(privatekey, rng_generate);
		++ctr;

		if (qsc_mceliece_pk_gen(publickey, privatekey + QSC_MCELIECE_SYS_N / 8) == 0 || ctr == QSC_MCELIECE_KEYGEN_RETRIES_MAX)
		{
			break;
		}
	}

	rng_generate(privatekey, QSC_MCELIECE_SYS_N / 8);

	assert(ctr < QSC_MCELIECE_KEYGEN_RETRIES_MAX);
}
