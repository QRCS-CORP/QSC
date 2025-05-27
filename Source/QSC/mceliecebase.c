#include "mceliecebase.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

#if defined(QSC_SYSTEM_COMPILER_MSC)
#	pragma comment(linker, "/STACK:20480000,4096")
#endif

/* params.h */

#define MCELIECE_SHAREDSECRET_SIZE 32ULL

#if defined(QSC_MCELIECE_S1N3488T64)
#	define MCELIECE_GFBITS 12U
#	define MCELIECE_SYS_N 3488U
#	define MCELIECE_SYS_T 64U
#	define MCELIECE_COND_BYTES ((1 << (MCELIECE_GFBITS - 4)) * (2 * MCELIECE_GFBITS - 1))
#	define MCELIECE_IRR_BYTES (MCELIECE_SYS_T * 2)
#	define MCELIECE_PK_NROWS (MCELIECE_SYS_T * MCELIECE_GFBITS) 
#	define MCELIECE_PK_NCOLS (MCELIECE_SYS_N - MCELIECE_PK_NROWS)
#	define MCELIECE_PK_ROW_BYTES ((MCELIECE_PK_NCOLS + 7) / 8)
#	define MCELIECE_SYND_BYTES ((MCELIECE_PK_NROWS + 7) / 8)
#	define MCELIECE_GFMASK ((1 << MCELIECE_GFBITS) - 1)
#elif defined(QSC_MCELIECE_S3N4608T96)
#   define MCELIECE_GFBITS 13U
#   define MCELIECE_SYS_N 4608U
#   define MCELIECE_SYS_T 96U
#   define MCELIECE_COND_BYTES ((1 << (MCELIECE_GFBITS - 4)) * (2 * MCELIECE_GFBITS - 1))
#   define MCELIECE_IRR_BYTES (MCELIECE_SYS_T * 2)
#   define MCELIECE_PK_NROWS (MCELIECE_SYS_T * MCELIECE_GFBITS) 
#   define MCELIECE_PK_NCOLS (MCELIECE_SYS_N - MCELIECE_PK_NROWS)
#   define MCELIECE_PK_ROW_BYTES ((MCELIECE_PK_NCOLS + 7) / 8)
#   define MCELIECE_SYND_BYTES ((MCELIECE_PK_NROWS + 7) / 8)
#   define MCELIECE_GFMASK ((1 << MCELIECE_GFBITS) - 1)
#elif defined(QSC_MCELIECE_S5N6688T128)
#   define MCELIECE_GFBITS 13U
#   define MCELIECE_SYS_N 6688U
#   define MCELIECE_SYS_T 128U
#   define MCELIECE_COND_BYTES ((1 << (MCELIECE_GFBITS - 4)) * (2 * MCELIECE_GFBITS - 1))
#   define MCELIECE_IRR_BYTES (MCELIECE_SYS_T * 2)
#   define MCELIECE_PK_NROWS (MCELIECE_SYS_T * MCELIECE_GFBITS) 
#   define MCELIECE_PK_NCOLS (MCELIECE_SYS_N - MCELIECE_PK_NROWS)
#   define MCELIECE_PK_ROW_BYTES ((MCELIECE_PK_NCOLS + 7) / 8)
#   define MCELIECE_SYND_BYTES ((MCELIECE_PK_NROWS + 7) / 8)
#   define MCELIECE_GFMASK ((1 << MCELIECE_GFBITS) - 1)
#elif defined(QSC_MCELIECE_S6N6960T119)
#   define MCELIECE_GFBITS 13U
#   define MCELIECE_SYS_N 6960U
#   define MCELIECE_SYS_T 119U
#   define MCELIECE_COND_BYTES ((1 << (MCELIECE_GFBITS - 4)) * (2 * MCELIECE_GFBITS - 1))
#   define MCELIECE_IRR_BYTES (MCELIECE_SYS_T * 2)
#   define MCELIECE_PK_NROWS (MCELIECE_SYS_T * MCELIECE_GFBITS) 
#   define MCELIECE_PK_NCOLS (MCELIECE_SYS_N - MCELIECE_PK_NROWS)
#   define MCELIECE_PK_ROW_BYTES ((MCELIECE_PK_NCOLS + 7) / 8)
#   define MCELIECE_SYND_BYTES ((MCELIECE_PK_NROWS + 7) / 8)
#   define MCELIECE_GFMASK ((1 << MCELIECE_GFBITS) - 1)
#elif defined(QSC_MCELIECE_S7N8192T128)
#   define MCELIECE_GFBITS 13U
#   define MCELIECE_SYS_N 8192U
#   define MCELIECE_SYS_T 128U
#   define MCELIECE_COND_BYTES ((1 << (MCELIECE_GFBITS - 4)) * (2 * MCELIECE_GFBITS - 1))
#   define MCELIECE_IRR_BYTES (MCELIECE_SYS_T * 2)
#   define MCELIECE_PK_NROWS (MCELIECE_SYS_T * MCELIECE_GFBITS) 
#   define MCELIECE_PK_NCOLS (MCELIECE_SYS_N - MCELIECE_PK_NROWS)
#   define MCELIECE_PK_ROW_BYTES ((MCELIECE_PK_NCOLS + 7) / 8)
#   define MCELIECE_SYND_BYTES ((MCELIECE_PK_NROWS + 7) / 8)
#   define MCELIECE_GFMASK ((1 << MCELIECE_GFBITS) - 1)
#else
#	error "The McEliece parameter set is invalid!"
#endif

/* gf.c */

typedef uint16_t gf;

static gf gf_is_zero(gf a)
{
	uint32_t t;

	t = a;
	t -= 1U;
	t >>= 19U;

	return (gf)t;
}

static gf gf_add(gf in0, gf in1)
{
	return in0 ^ in1;
}

static gf gf_sq2(gf in)
{

	/* input: field element in
	   return: (in^2)^2 */

	const uint64_t Bf[4U] = { 0x1111111111111111ULL, 0x0303030303030303ULL, 0x000F000F000F000FULL, 0x000000FF000000FFULL };
	const uint64_t M[4U] = { 0x0001FF0000000000ULL, 0x000000FF80000000ULL, 0x000000007FC00000ULL, 0x00000000003FE000ULL };
	uint64_t t;
	uint64_t x;

	x = in;
	x = (x | (x << 24)) & Bf[3U];
	x = (x | (x << 12)) & Bf[2U];
	x = (x | (x << 6)) & Bf[1U];
	x = (x | (x << 3)) & Bf[0U];

	for (size_t i = 0U; i < 4U; ++i)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return x & MCELIECE_GFMASK;
}

static gf gf_sq2mul(gf in, gf m)
{
	/* input: field element in, m
	   return: ((in^2)^2)*m */
	const uint64_t M[6U] = { 0x1FF0000000000000ULL, 0x000FF80000000000ULL, 0x000007FC00000000ULL,
		0x00000003FE000000ULL, 0x0000000001FE0000ULL, 0x000000000001E000ULL };
	uint64_t x;
	uint64_t t0;
	uint64_t t1;
	uint64_t t;

	t0 = in;
	t1 = m;
	x = (t1 << 18) * (t0 & (1 << 6));
	t0 ^= (t0 << 21);

	x ^= (t1 * (t0 & 0x0000000010000001ULL));
	x ^= (t1 * (t0 & 0x0000000020000002ULL)) << 3;
	x ^= (t1 * (t0 & 0x0000000040000004ULL)) << 6;
	x ^= (t1 * (t0 & 0x0000000080000008ULL)) << 9;
	x ^= (t1 * (t0 & 0x0000000100000010ULL)) << 12;
	x ^= (t1 * (t0 & 0x0000000200000020ULL)) << 15;

	for (size_t i = 0U; i < 6U; ++i)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return x & MCELIECE_GFMASK;
}

#if defined(QSC_MCELIECE_S1N3488T64)

gf gf_mul(gf in0, gf in1)
{
	size_t i;
	uint32_t tmp;
	uint32_t t0;
	uint32_t t1;
	uint32_t t;

	t0 = in0;
	t1 = in1;
	tmp = t0 * (t1 & 1);

	for (i = 1U; i < MCELIECE_GFBITS; ++i)
	{
		tmp ^= (t0 * (t1 & (1 << i)));
	}

	t = tmp & 0x007FC000;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	t = tmp & 0x00003000;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	return tmp & ((1U << MCELIECE_GFBITS) - 1U);
}

static gf gf_sq(gf in)
{
	const uint32_t B[4U] = { 0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF };

	uint32_t x = in;
	uint32_t t;

	x = (x | (x << 8)) & B[3U];
	x = (x | (x << 4)) & B[2U];
	x = (x | (x << 2)) & B[1U];
	x = (x | (x << 1)) & B[0U];

	t = x & 0x7FC000;
	x ^= t >> 9;
	x ^= t >> 12;

	t = x & 0x3000;
	x ^= t >> 9;
	x ^= t >> 12;

	return x & ((1U << MCELIECE_GFBITS) - 1U);
}

static inline gf gf_sqmul(gf in, gf m)
{
	uint64_t x;
	uint64_t t0;
	uint64_t t1;
	uint64_t t;
	size_t i;
	const uint64_t M[3U] = { 0x0000001FF0000000, 0x000000000FF80000, 0x000000000007E000 };

	t0 = in;
	t1 = m;

	x = (t1 << 6) * (t0 & (1 << 6));

	t0 ^= (t0 << 7);

	x ^= (t1 * (t0 & (0x04001)));
	x ^= (t1 * (t0 & (0x08002))) << 1;
	x ^= (t1 * (t0 & (0x10004))) << 2;
	x ^= (t1 * (t0 & (0x20008))) << 3;
	x ^= (t1 * (t0 & (0x40010))) << 4;
	x ^= (t1 * (t0 & (0x80020))) << 5;

	for (i = 0U; i < 3U; i++)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return x & MCELIECE_GFMASK;
}

static gf gf_inv(gf in)
{
	gf tmp_11;
	gf tmp_1111;

	gf out = in;

	out = gf_sq(out);
	tmp_11 = gf_mul(out, in); // 11

	out = gf_sq(tmp_11);
	out = gf_sq(out);
	tmp_1111 = gf_mul(out, tmp_11); // 1111

	out = gf_sq(tmp_1111);
	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_mul(out, tmp_1111); // 11111111

	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_mul(out, tmp_11); // 1111111111

	out = gf_sq(out);
	out = gf_mul(out, in); // 11111111111

	return gf_sq(out); // 111111111110
}

static gf gf_frac(gf den, gf num)
{
	return gf_mul(gf_inv(den), num);
}

#else

static gf gf_mul(gf in0, gf in1)
{
	uint64_t t;
	uint64_t t0;
	uint64_t t1;
	uint64_t tmp;

	t0 = in0;
	t1 = in1;
	tmp = t0 * (t1 & 1);

	for (size_t i = 1U; i < MCELIECE_GFBITS; ++i)
	{
		tmp ^= (t0 * (t1 & (1ULL << i)));
	}

	t = tmp & 0x0000000001FF0000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	t = tmp & 0x000000000000E000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

	return tmp & MCELIECE_GFMASK;
}

static gf gf_sqmul(gf in, gf m)
{
	/* input: field element in, m
	   return: (in^2)*m */

	const uint64_t M[3U] = { 0x0000001FF0000000ULL, 0x000000000FF80000ULL, 0x000000000007E000ULL };
	uint64_t t;
	uint64_t t0;
	uint64_t t1;
	uint64_t x;

	t0 = in;
	t1 = m;
	x = (t1 << 6) * (t0 & (1 << 6));
	t0 ^= (t0 << 7);

	x ^= (t1 * (t0 & 0x0000000000004001ULL));
	x ^= (t1 * (t0 & 0x0000000000008002ULL)) << 1;
	x ^= (t1 * (t0 & 0x0000000000010004ULL)) << 2;
	x ^= (t1 * (t0 & 0x0000000000020008ULL)) << 3;
	x ^= (t1 * (t0 & 0x0000000000040010ULL)) << 4;
	x ^= (t1 * (t0 & 0x0000000000080020ULL)) << 5;

	for (size_t i = 0U; i < 3U; ++i)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return x & MCELIECE_GFMASK;
}

static gf gf_frac(gf den, gf num)
{
	/* input: field element den, num */
	/* return: (num/den) */

	gf tmp_11;
	gf tmp_1111;
	gf out;

	tmp_11 = gf_sqmul(den, den);			/* ^ 11 */
	tmp_1111 = gf_sq2mul(tmp_11, tmp_11);	/* ^ 1111 */
	out = gf_sq2(tmp_1111);
	out = gf_sq2mul(out, tmp_1111);			/* ^ 11111111 */
	out = gf_sq2(out);
	out = gf_sq2mul(out, tmp_1111);			/* ^ 111111111111 */

	return gf_sqmul(out, num);				/* ^ 1111111111110 = ^ -1 */
}

static gf gf_inv(gf den)
{
	return gf_frac(den, ((gf)1));
}

#endif

static void GF_mul(gf* out, const gf* in0, const gf* in1)
{
	QSC_SIMD_ALIGN gf prod[(MCELIECE_SYS_T * 2U) - 1U] = { 0U };
	size_t i;

	for (i = 0U; i < MCELIECE_SYS_T; ++i)
	{
		for (size_t j = 0U; j < MCELIECE_SYS_T; ++j)
		{
			prod[i + j] ^= gf_mul(in0[i], in1[j]);
		}
	}

	for (i = (MCELIECE_SYS_T - 1U) * 2U; i >= MCELIECE_SYS_T; --i)
	{
#if defined(QSC_MCELIECE_S1N3488T64)
		prod[i - MCELIECE_SYS_T + 3U] ^= prod[i];
		prod[i - MCELIECE_SYS_T + 1U] ^= prod[i];
		prod[i - MCELIECE_SYS_T] ^= gf_mul(prod[i], (gf)2U);
#elif defined(QSC_MCELIECE_S3N4608T96)
		prod[i - MCELIECE_SYS_T + 10U] ^= prod[i];
		prod[i - MCELIECE_SYS_T + 9U] ^= prod[i];
		prod[i - MCELIECE_SYS_T + 6U] ^= prod[i];
		prod[i - MCELIECE_SYS_T] ^= prod[i];
#elif defined(QSC_MCELIECE_S5N6688T128) || defined(QSC_MCELIECE_S7N8192T128)
		prod[i - MCELIECE_SYS_T + 7U] ^= prod[i];
		prod[i - MCELIECE_SYS_T + 2U] ^= prod[i];
		prod[i - MCELIECE_SYS_T + 1U] ^= prod[i];
		prod[i - MCELIECE_SYS_T] ^= prod[i];
#elif defined(QSC_MCELIECE_S6N6960T119)
		prod[i - MCELIECE_SYS_T + 8U] ^= prod[i];
		prod[i - MCELIECE_SYS_T] ^= prod[i];
#endif
	}

	qsc_memutils_copy(out, prod, MCELIECE_SYS_T * sizeof(gf));
}

/* util.c */

static void store_gf(uint8_t* dest, gf a)
{
	dest[0U] = a & 0x00FF;
	dest[1U] = a >> 8;
}

static uint16_t load_gf(const uint8_t* src)
{
	uint16_t a;

	a = src[1U];
	a <<= 8;
	a |= src[0U];

	return a & MCELIECE_GFMASK;
}

static uint32_t load4(const uint8_t* in)
{
	uint32_t ret;

	ret = in[3U];

	for (int32_t i = 2; i >= 0; --i)
	{
		ret <<= 8;
		ret |= in[i];
	}

	return ret;
}

static void store8(uint8_t* out, uint64_t in)
{
	out[0U] = in & 0xFF;
	out[1U] = (in >> 0x08) & 0xFFU;
	out[2U] = (in >> 0x10) & 0xFFU;
	out[3U] = (in >> 0x18) & 0xFFU;
	out[4U] = (in >> 0x20) & 0xFFU;
	out[5U] = (in >> 0x28) & 0xFFU;
	out[6U] = (in >> 0x30) & 0xFFU;
	out[7U] = (in >> 0x38) & 0xFFU;
}

static uint64_t load8(const uint8_t* in)
{
	uint64_t ret;

	ret = in[7U];

	for (int32_t i = 6; i >= 0; --i)
	{
		ret <<= 8;
		ret |= in[i];
	}

	return ret;
}

static gf bitrev(gf a)
{
	a = (gf)((a & 0x00FFU) << 8) | ((a & 0xFF00U) >> 8);
	a = (gf)((a & 0x0F0FU) << 4) | ((a & 0xF0F0U) >> 4);
	a = (gf)((a & 0x3333U) << 2) | ((a & 0xCCCCU) >> 2);
	a = (gf)((a & 0x5555U) << 1) | ((a & 0xAAAAU) >> 1);

#if defined(QSC_MCELIECE_S1N3488T64)
	return (a >> 4);
#else
	return (a >> 3);
#endif
}

/* sort */

static void int32_minmax(int32_t* a, int32_t* b)
{
	int32_t ab;
	int32_t c;

	ab = *b ^ *a;
	c = *b - *a;
	c ^= ab & (c ^ *b);
	c >>= 31;
	c &= ab;
	*a ^= c;
	*b ^= c;
}

static void int32_sort(int32_t* x, int64_t n)
{
	int64_t top;
	int64_t r;
	int64_t i;

	if (n >= 2)
	{
		top = 1;

		while (top < n - top)
		{
			top += top;
		}

		for (int64_t p = top; p > 0; p >>= 1)
		{
			for (i = 0; i < n - p; ++i)
			{
				if ((i & p) == 0)
				{
					int32_minmax(&x[i], &x[i + p]);
				}
			}

			i = 0;

			for (int64_t q = top; q > p; q >>= 1)
			{
				for (; i < n - q; ++i)
				{
					if ((i & p) == 0)
					{
						int32_t a = x[i + p];

						for (r = q; r > p; r >>= 1)
						{
							int32_minmax(&a, &x[i + r]);
						}

						x[i + p] = a;
					}
				}
			}
		}
	}
}

static void int64_minmax(uint64_t* a, uint64_t* b)
{
	uint64_t c = *b - *a;

	c >>= 63;
	c = ~c + 1U;
	c &= *a ^ *b;
	*a ^= c;
	*b ^= c;
}

static void uint64_sort(uint64_t *x, int64_t n)
{
	int64_t top;
	int64_t r;
	int64_t i;

	if (n >= 2)
	{
		top = 1;

		while (top < n - top)
		{
			top += top;
		}

		for (int64_t p = top; p > 0; p >>= 1)
		{
			for (i = 0; i < n - p; ++i)
			{
				if ((i & p) == 0)
				{
					int64_minmax(&x[i], &x[i + p]);
				}
			}

			i = 0;

			for (int64_t q = top; q > p; q >>= 1)
			{
				for (; i < n - q; ++i)
				{
					if ((i & p) == 0)
					{
						uint64_t a = x[i + p];

						for (r = q; r > p; r >>= 1)
						{
							int64_minmax(&a, &x[i + r]);
						}

						x[i + p] = a;
					}
				}
			}
		}
	}
}

/* root.c */

static gf eval(const gf* f, gf a)
{
	/* input: polynomial f and field element a
	   return f(a) */

	size_t i;
	gf r;

	r = f[MCELIECE_SYS_T];
	i = MCELIECE_SYS_T;

	do
	{
		--i;
		r = gf_mul(r, a);
		r = gf_add(r, f[i]);
	} 
	while (i > 0U);

	return r;
}

static void root(gf* out, const gf* f, const gf* L)
{
	/* input: polynomial f and list of field elements L
	   output: out = [ f(a) for a in L ] */

	for (size_t i = 0U; i < MCELIECE_SYS_N; ++i)
	{
		out[i] = eval(f, L[i]);
	}
}

/* synd.c */

static void synd(gf* out, const gf* f, const gf* L, const uint8_t* r)
{
	/* input: Goppa polynomial f, support L, received word r
	   output: out, the syndrome of length 2t */

	gf c;
	gf e;
	gf e_inv;

	qsc_memutils_clear(out, 2U * MCELIECE_SYS_T * sizeof(gf));

	for (size_t i = 0U; i < MCELIECE_SYS_N; ++i)
	{
		c = (r[i / 8U] >> (i % 8U)) & 1U;
		e = eval(f, L[i]);
		e_inv = gf_inv(gf_mul(e, e));

		for (size_t j = 0U; j < 2U * MCELIECE_SYS_T; ++j)
		{
			out[j] = gf_add(out[j], gf_mul(e_inv, c));
			e_inv = gf_mul(e_inv, L[i]);
		}
	}
}

/* transpose.c */

static void transpose_64x64(uint64_t* out, const uint64_t* in)
{
	/* input: in, a 64x64 matrix over GF(2) */
	/* output: out, transpose of in */

	QSC_SIMD_ALIGN uint64_t masks[6U][2U] =
	{
		{0x5555555555555555ULL, 0xAAAAAAAAAAAAAAAAULL},
		{0x3333333333333333ULL, 0xCCCCCCCCCCCCCCCCULL},
		{0x0F0F0F0F0F0F0F0FULL, 0xF0F0F0F0F0F0F0F0ULL},
		{0x00FF00FF00FF00FFULL, 0xFF00FF00FF00FF00ULL},
		{0x0000FFFF0000FFFFULL, 0xFFFF0000FFFF0000ULL},
		{0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL}
	};

	uint64_t x;
	uint64_t y;
	int32_t s;

	qsc_memutils_copy(out, in, 64U * sizeof(uint64_t));

	for (int32_t d = 5; d >= 0; d--)
	{
		s = 1 << d;

		for (size_t i = 0U; i < 64U; i += (size_t)s * 2U)
		{
			for (size_t j = i; j < i + s; ++j)
			{
				x = (out[j] & masks[d][0U]) | ((out[j + s] & masks[d][0U]) << s);
				y = ((out[j] & masks[d][1U]) >> s) | (out[j + s] & masks[d][1U]);
				out[j] = x;
				out[j + s] = y;
			}
		}
	}
}

/* benes.c */

#if defined(QSC_MCELIECE_S1N3488T64)

static void layer(uint64_t* data, uint64_t* bits, int32_t lgs)
{
	size_t i;
	size_t j;
	size_t s;
	uint64_t d;

	s = 1ULL << lgs;

	for (i = 0U; i < 64U; i += s * 2U)
	{
		for (j = i; j < i + s; j++)
		{
			d = (data[j + 0U] ^ data[j + s]);
			d &= (*bits);
			++bits;
			data[j] ^= d;
			data[j + s] ^= d;
		}
	}
}

void apply_benes(uint8_t* r, const uint8_t* bits, int32_t rev)
{
	QSC_SIMD_ALIGN uint64_t bs[64U];
	QSC_SIMD_ALIGN uint64_t cond[64U];
	const uint8_t* cond_ptr;
	size_t i;
	int32_t inc;
	int32_t low;

	for (i = 0U; i < 64U; i++)
	{
		bs[i] = load8(r + i * 8U);
	}

	if (rev == 0)
	{
		inc = 256;
		cond_ptr = bits;
	}
	else
	{
		inc = -256;
		cond_ptr = bits + (2U * MCELIECE_GFBITS - 2U) * 256U;
	}

	transpose_64x64(bs, bs);

	for (low = 0; low <= 5; low++)
	{
		for (i = 0; i < 64; i++)
		{
			cond[i] = load4(cond_ptr + i * 4);
		}

		transpose_64x64(cond, cond);
		layer(bs, cond, low);
		cond_ptr += inc;
	}

	transpose_64x64(bs, bs);

	for (low = 0; low <= 5; low++)
	{
		for (i = 0U; i < 32U; i++)
		{
			cond[i] = load8(cond_ptr + i * 8U);
		}

		layer(bs, cond, low);
		cond_ptr += inc;
	}

	for (low = 4; low >= 0; low--)
	{
		for (i = 0U; i < 32U; i++)
		{
			cond[i] = load8(cond_ptr + i * 8U);
		}

		layer(bs, cond, low);
		cond_ptr += inc;
	}

	transpose_64x64(bs, bs);

	for (low = 5; low >= 0; low--)
	{
		for (i = 0U; i < 64U; i++)
		{
			cond[i] = load4(cond_ptr + i * 4U);
		}

		transpose_64x64(cond, cond);
		layer(bs, cond, low);
		cond_ptr += inc;
	}

	transpose_64x64(bs, bs);

	for (i = 0U; i < 64U; i++)
	{
		store8(r + i * 8U, bs[i]);
	}
}

#else

static void layer_in(uint64_t data[2U][64U], const uint64_t* bits, int32_t lgs)
{
	/* middle layers of the benes network */

	uint64_t d;
	int32_t s;

	s = 1 << lgs;

	for (size_t i = 0U; i < 64U; i += (size_t)s * 2U)
	{
		for (size_t j = i; j < i + (size_t)s; ++j)
		{
			d = (data[0U][j] ^ data[0U][j + s]);
			d &= (*bits);
			++bits;
			data[0U][j] ^= d;
			data[0U][j + s] ^= d;

			d = (data[1U][j] ^ data[1U][j + s]);
			d &= (*bits);
			++bits;
			data[1U][j] ^= d;
			data[1U][j + s] ^= d;
		}
	}
}

static void layer_ex(uint64_t* data, const uint64_t* bits, int32_t lgs)
{
	/* first and last layers of the benes network */
	uint64_t d;
	int32_t s;

	s = 1 << lgs;

	for (size_t i = 0U; i < 128U; i += (size_t)s * 2U)
	{
		for (size_t j = i; j < i + (size_t)s; j++)
		{
			d = (data[j] ^ data[j + s]);
			d &= (*bits);
			++bits;
			data[j] ^= d;
			data[j + s] ^= d;
		}
	}
}

static void apply_benes(uint8_t* r, const uint8_t* bits, int32_t rev)
{
	/* input: r, sequence of bits to be permuted bits, condition bits of the Benes network rev,
	0 for normal application, !0 for inverse output: r, permuted bits */

	QSC_SIMD_ALIGN uint64_t r_int_v[2U][64U] = { 0U };
	QSC_SIMD_ALIGN uint64_t r_int_h[2U][64U] = { 0U };
	QSC_SIMD_ALIGN uint64_t b_int_v[64U] = { 0U };
	QSC_SIMD_ALIGN uint64_t b_int_h[64U];
	size_t i;
	int32_t inc;
	int32_t iter;
	uint8_t* r_ptr = r;
	const uint8_t* bits_ptr;

	if (rev != 0) 
	{
		bits_ptr = bits + 12288U; 
		inc = -1024; 
	}
	else 
	{
		bits_ptr = bits;         
		inc = 0;
	}

	for (i = 0; i < 64; ++i)
	{
		r_int_v[0U][i] = load8(r_ptr + i * 16U);
		r_int_v[1U][i] = load8(r_ptr + i * 16U + 8U);
	}

	transpose_64x64(r_int_h[0U], r_int_v[0U]);
	transpose_64x64(r_int_h[1U], r_int_v[1U]);

	for (iter = 0; iter <= 6; ++iter)
	{
		for (i = 0U; i < 64U; ++i)
		{
			b_int_v[i] = load8(bits_ptr); 
			bits_ptr += 8U;
		}

		bits_ptr += inc;
		transpose_64x64(b_int_h, b_int_v);
		layer_ex(r_int_h[0U], b_int_h, iter);
	}

	transpose_64x64(r_int_v[0U], r_int_h[0U]);
	transpose_64x64(r_int_v[1U], r_int_h[1U]);

	for (iter = 0; iter <= 5; ++iter)
	{
		for (i = 0U; i < 64U; ++i) 
		{ 
			b_int_v[i] = load8(bits_ptr); 
			bits_ptr += 8U;
		}

		bits_ptr += inc;
		layer_in(r_int_v, b_int_v, iter);
	}

	for (iter = 4; iter >= 0; --iter)
	{
		for (i = 0U; i < 64U; ++i) 
		{ 
			b_int_v[i] = load8(bits_ptr); 
			bits_ptr += 8U; 
		}

		bits_ptr += inc;
		layer_in(r_int_v, b_int_v, iter);
	}

	transpose_64x64(r_int_h[0U], r_int_v[0U]);
	transpose_64x64(r_int_h[1U], r_int_v[1U]);

	for (iter = 6; iter >= 0; --iter)
	{
		for (i = 0U; i < 64U; ++i)
		{
			b_int_v[i] = load8(bits_ptr);
			bits_ptr += 8U;
		}

		bits_ptr += inc;
		transpose_64x64(b_int_h, b_int_v);
		layer_ex(r_int_h[0U], b_int_h, iter);
	}

	transpose_64x64(r_int_v[0U], r_int_h[0U]);
	transpose_64x64(r_int_v[1U], r_int_h[1U]);

	for (i = 0; i < 64; ++i)
	{
		store8(r_ptr + i * 16U, r_int_v[0U][i]);
		store8(r_ptr + i * 16U + 8U, r_int_v[1U][i]);
	}
}
#endif

static void support_gen(gf* s, const uint8_t* c)
{
	/* input: condition bits c output: support s */

	QSC_SIMD_ALIGN uint8_t L[MCELIECE_GFBITS][(1U << MCELIECE_GFBITS) / 8U] = { 0U };
	size_t i;
	size_t j;
	gf a;

	for (i = 0U; i < (1U << MCELIECE_GFBITS); ++i)
	{
		a = bitrev((gf)i);

		for (j = 0U; j < MCELIECE_GFBITS; ++j)
		{
			L[j][i / 8U] |= ((a >> j) & 1) << (i % 8U);
		}
	}

	for (j = 0U; j < MCELIECE_GFBITS; ++j)
	{
		apply_benes(L[j], c, 0);
	}

	for (i = 0U; i < MCELIECE_SYS_N; ++i)
	{
		s[i] = 0U;
		j = MCELIECE_GFBITS;

		do
		{
			--j;
			s[i] <<= 1;
			s[i] |= (L[j][i / 8U] >> (i % 8U)) & 1;
		} 
		while (j != 0U);
	}
}

/* bm.c */

static void bm(gf* out, const gf* s)
{
	/* the Berlekamp-Massey algorithm. 
	input: s, sequence of field elements
	output: out, minimal polynomial of s */

	QSC_SIMD_ALIGN gf T[MCELIECE_SYS_T + 1U] = { 0U };
	QSC_SIMD_ALIGN gf C[MCELIECE_SYS_T + 1U] = { 0U };
	QSC_SIMD_ALIGN gf B[MCELIECE_SYS_T + 1U] = { 0U };
	size_t i;
	gf b;
	gf d;
	gf f;
	uint16_t N;
	uint16_t L;
	uint16_t mle;
	uint16_t mne;

	b = 1U;
	L = 0U;
	B[1U] = 1U;
	C[0U] = 1U;

	for (N = 0U; N < 2U * MCELIECE_SYS_T; ++N)
	{
		d = 0U;
		
		for (i = 0U; i <= qsc_intutils_min((size_t)N, (size_t)MCELIECE_SYS_T); ++i)
		{
			d ^= gf_mul(C[i], s[N - i]);
		}

		mne = d; 
		mne -= 1U;   
		mne >>= 15; 
		mne -= 1U;
		mle = N;
		mle -= 2U * L; 
		mle >>= 15U; 
		mle -= 1U;
		mle &= mne;

		qsc_memutils_copy(T, C, MCELIECE_SYS_T * sizeof(gf));

		f = gf_frac(b, d);

		for (i = 0U; i <= MCELIECE_SYS_T; ++i)
		{
			C[i] ^= gf_mul(f, B[i]) & mne;
		}

		L = (L & ~mle) | ((N + 1U - L) & mle);

		for (i = 0U; i <= MCELIECE_SYS_T; ++i)
		{
			B[i] = (B[i] & ~mle) | (T[i] & mle);
		}

		b = (b & ~mle) | (d & mle);

		for (i = MCELIECE_SYS_T; i >= 1U; --i)
		{
			B[i] = B[i - 1U];
		}

		B[0U] = 0U;
	}

	for (i = 0U; i <= MCELIECE_SYS_T; ++i)
	{
		out[i] = C[MCELIECE_SYS_T - i];
	}
}

/* controlbits.c */

static void cbrecursion(uint8_t* out, int64_t pos, int64_t step, const int16_t* pi, int64_t w, int64_t n, int32_t* temp)
{
	/* parameters: 1 <= w <= 14; n = 2^w.
	input: permutation pi of {0,1,...,n-1}
	output: (2m-1)n/2 control bits at positions pos,pos+step,...
	output position pos is by definition 1&(out[pos/8]>>(pos&7))
	caller must 0-initialize positions first, temp must have space for int32_t[2*n] */

	int32_t* A = temp;
	int32_t* B = (temp + n);
	/* q can start anywhere between temp+n and temp+n/2 */
	int16_t* q = ((int16_t*)(temp + n + n / 4U));
	int64_t i;
	int64_t j;
	int64_t x;

	if (w == 1) 
	{
		out[pos >> 3U] ^= pi[0U] << (pos & 7);
		return;
	}

	for (x = 0; x < n; ++x)
	{
		A[x] = ((pi[x] ^ 1) << 16) | pi[x ^ 1U];
	}

	int32_sort(A, n); /* A = (id<<16)+pibar */

	for (x = 0; x < n; ++x) 
	{
		int32_t Ax = A[x];
		int32_t px = Ax & 0x0000FFFFL;
		int32_t cx = px;

		if ((int32_t)x < cx)
		{
			cx = (int32_t)x;
		}

		B[x] = (px << 16) | cx;
	}

	/* B = (p<<16)+c */

	for (x = 0; x < n; ++x)
	{
		A[x] = (A[x] << 16) | (int32_t)x; /* A = (pibar<<16)+id */
	}

	int32_sort(A, n); /* A = (id<<16)+pibar^-1 */

	for (x = 0; x < n; ++x)
	{
		A[x] = (A[x] << 16) + (B[x] >> 16); /* A = (pibar^(-1)<<16)+pibar */
	}

	int32_sort(A, n); /* A = (id<<16)+pibar^2 */

	if (w <= 10)
	{
		for (x = 0; x < n; ++x)
		{
			B[x] = ((A[x] & 0x0000FFFFL) << 10) | (B[x] & 0x000003FFL);
		}

		for (i = 1; i < w - 1; ++i) 
		{
			/* B = (p<<10)+c */

			for (x = 0; x < n; ++x)
			{
				A[x] = ((B[x] & ~0x000003FFL) << 6) | (int32_t)x; /* A = (p<<16)+id */
			}

			int32_sort(A, n); /* A = (id<<16)+p^{-1} */

			for (x = 0; x < n; ++x)
			{
				A[x] = (A[x] << 20) | B[x]; /* A = (p^{-1}<<20)+(p<<10)+c */
			}

			int32_sort(A, n); /* A = (id<<20)+(pp<<10)+cp */

			for (x = 0; x < n; ++x)
			{
				int32_t ppcpx = A[x] & 0x000FFFFFL;
				int32_t ppcx = (A[x] & 0x000FFC00L) | (B[x] & 0x000003FFL);

				if (ppcpx < ppcx)
				{
					ppcx = ppcpx;
				}

				B[x] = ppcx;
			}
		}

		for (x = 0; x < n; ++x)
		{
			B[x] &= 0x000003FFL;
		}
	}
	else
	{
		for (x = 0; x < n; ++x)
		{
			B[x] = (A[x] << 16) | (B[x] & 0x0000FFFFL);
		}

		for (i = 1; i < w - 1; ++i)
		{
			/* B = (p<<16)+c */

			for (x = 0; x < n; ++x)
			{
				A[x] = (B[x] & ~0x0000FFFFL) | (int32_t)x;
			}

			int32_sort(A, n); /* A = (id<<16)+p^(-1) */

			for (x = 0; x < n; ++x)
			{
				A[x] = (A[x] << 16) | (B[x] & 0x0000FFFFL);
			}

			/* A = p^(-1)<<16+c */

			if (i < w - 2) 
			{
				for (x = 0; x < n; ++x)
				{
					B[x] = (A[x] & ~0x0000FFFFL) | (B[x] >> 16);
				}

				/* B = (p^(-1)<<16)+p */

				int32_sort(B, n); /* B = (id<<16)+p^(-2) */

				for (x = 0; x < n; ++x)
				{
					B[x] = (B[x] << 16) | (A[x] & 0x0000FFFFL);
				}
				/* B = (p^(-2)<<16)+c */
			}

			int32_sort(A, n);

			/* A = id<<16+cp */
			for (x = 0; x < n; ++x)
			{
				int32_t cpx = (B[x] & ~0x0000FFFF) | (A[x] & 0x0000FFFF);

				if (cpx < B[x])
				{
					B[x] = cpx;
				}
			}
		}

		for (x = 0; x < n; ++x)
		{
			B[x] &= 0x0000FFFF;
		}
	}

	for (x = 0; x < n; ++x)
	{
		A[x] = (((int32_t)pi[x]) << 16) + (int32_t)x;
	}

	int32_sort(A, n); /* A = (id<<16)+pi^(-1) */

	for (j = 0; j < n / 2; ++j)
	{
		x = 2 * j;
		int32_t fj = B[x] & 1;			/* f[j] */
		int32_t Fx = (int32_t)x + fj;	/* F[x] */
		int32_t Fx1 = Fx ^ 1;			/* F[x+1] */

		out[pos >> 3] ^= fj << (pos & 7);
		pos += step;

		B[x] = (A[x] << 16) | Fx;
		B[x + 1U] = (A[x + 1U] << 16) | Fx1;
	}

	/* B = (pi^(-1)<<16)+F */
	int32_sort(B, n);
	/* B = (id<<16)+F(pi) */
	pos += (2 * w - 3) * step * (n / 2);

	for (int64_t k = 0; k < n / 2; ++k)
	{
		int64_t y = 2 * k;
		int32_t lk = B[y] & 1;			/* l[k] */
		int32_t Ly = (int32_t)y + lk;	/* L[y] */
		int32_t Ly1 = Ly ^ 1;			/* L[y+1] */

		out[pos >> 3] ^= lk << (pos & 7);
		pos += step;
		A[y] = (Ly << 16) | (B[y] & 0x0000FFFFL);
		A[y + 1U] = (Ly1 << 16) | (B[y + 1U] & 0x0000FFFFL);
	}

	/* A = (L<<16)+F(pi) */
	int32_sort(A, n); /* A = (id<<16)+F(pi(L)) = (id<<16)+M */
	pos -= (2 * w - 2) * step * (n / 2);

	for (j = 0; j < n / 2; ++j)
	{
		q[j] = (A[2U * j] & 0x0000FFFFL) >> 1;
		q[j + n / 2U] = (A[2U * j + 1U] & 0x0000FFFFL) >> 1;
	}

	cbrecursion(out, pos, step * 2, q, w - 1, n / 2, temp);
	cbrecursion(out, pos + step, step * 2, q + n / 2, w - 1, n / 2, temp);
}

static void cblayer(int16_t* p, const uint8_t* cb, int32_t s, int32_t n)
{
	/* input: p, an array of int16_t
	   input: n, length of p
	   input: s, meaning that stride-2^s cswaps are performed
	   input: cb, the control bits
	   output: the result of apply the control bits to p */

	const int32_t stride = 1 << s;
	int32_t index;
	int16_t d;
	int16_t m;

	index = 0;

	for (size_t i = 0U; i < (size_t)n; i += stride * 2U)
	{
		for (size_t j = 0U; j < (size_t)stride; ++j)
		{
			d = p[i + j] ^ p[i + j + stride];
			m = (cb[index >> 3] >> (index & 7)) & 1;
			m = -m;
			d &= m;
			p[i + j] ^= d;
			p[i + j + stride] ^= d;
			++index;
		}
	}
}

static void controlbits_from_permutation(uint8_t* out, const int16_t* pi, int64_t w, int64_t n)
{
	/* parameters: 1 <= w <= 14; n = 2^w
	   input: permutation pi of {0,1,...,n-1}
	   output: (2m-1)n/2 control bits at positions 0,1,...
	   output position pos is by definition 1&(out[pos/8]>>(pos&7)) */

	QSC_SIMD_ALIGN int32_t temp[(1 << MCELIECE_GFBITS) * 2U * sizeof(int32_t)] = { 0 };
	QSC_SIMD_ALIGN int16_t pi_test[(1 << MCELIECE_GFBITS) * sizeof(int16_t)] = { 0 };
	int32_t i;
	int16_t diff;
	const uint8_t* ptr;

	while (true)
	{
		qsc_memutils_clear(out, (size_t)(((2 * w - 1) * n / 2) + 7) / 8U);
		cbrecursion(out, 0, 1, pi, w, n, temp);

		for (i = 0; i < n; ++i)
		{
			pi_test[i] = (int16_t)i;
		}

		ptr = out;

		for (i = 0; i < w; ++i)
		{
			cblayer(pi_test, ptr, i, (int32_t)n);
			ptr += n >> 4;
		}

		for (i = (int32_t)w - 2; i >= 0; --i)
		{
			cblayer(pi_test, ptr, i, (int32_t)n);
			ptr += n >> 4;
		}

		diff = 0;

		for (i = 0; i < n; ++i)
		{
			diff |= pi[i] ^ pi_test[i];
		}

		if (diff == 0)
		{
			break;
		}
	}
}

/* decrypt.c */

static int32_t decrypt(uint8_t* e, const uint8_t* sk, const uint8_t* c)
{
	/* Niederreiter decryption with the Berlekamp decoder.
	   input: sk, secret key c, ciphertext
	   output: e, error vector
	   return: 0 for success; 1 for failure */

	QSC_SIMD_ALIGN gf g[MCELIECE_SYS_T + 1U] = { 0U };
	QSC_SIMD_ALIGN gf L[MCELIECE_SYS_N];
	QSC_SIMD_ALIGN gf s[MCELIECE_SYS_T * 2U];
	QSC_SIMD_ALIGN gf s_cmp[MCELIECE_SYS_T * 2U];
	QSC_SIMD_ALIGN gf locator[MCELIECE_SYS_T + 1U];
	QSC_SIMD_ALIGN gf images[MCELIECE_SYS_N];
	QSC_SIMD_ALIGN uint8_t r[MCELIECE_SYS_N / 8U];
	int32_t i;
	int32_t w;
	uint16_t check;
	gf t;

	w = 0;
	qsc_memutils_copy(r, c, MCELIECE_SYND_BYTES);
	qsc_memutils_clear(r + MCELIECE_SYND_BYTES, (MCELIECE_SYS_N / 8U) - MCELIECE_SYND_BYTES);

	for (i = 0; i < MCELIECE_SYS_T; ++i)
	{
		g[i] = load_gf(sk);
		sk += 2U;
	} 
	
	g[MCELIECE_SYS_T] = 1U;
	support_gen(L, sk);
	synd(s, g, L, r);
	bm(locator, s);
	root(images, locator, L);

	qsc_memutils_clear(e, MCELIECE_SYS_N / 8U);

	for (i = 0U; i < MCELIECE_SYS_N; ++i)
	{
		t = gf_is_zero(images[i]) & 1;
		e[i / 8U] |= t << (i % 8U);
		w += t;
	}

	synd(s_cmp, g, L, e);
	check = (uint16_t)w;
	check ^= MCELIECE_SYS_T;

	for (i = 0; i < MCELIECE_SYS_T * 2; ++i)
	{
		check |= s[i] ^ s_cmp[i];
	}

	check -= 1U;
	check >>= 15;

	return (check ^ 1U);
}

/* encrypt.c */

static uint8_t same_mask(uint16_t x, uint16_t y)
{
	uint32_t mask;

	mask = (uint32_t)(x ^ y);
	mask -= 1U;
	mask >>= 31U;
	mask = ~mask + 1U;

	return mask & 0x000000FFUL;
}

static bool gen_e(uint8_t* e, bool (*rng_generate)(uint8_t*, size_t))
{
	/* output: e, an error vector of weight t */
	QSC_SIMD_ALIGN uint16_t ind[MCELIECE_SYS_T] = { 0U };
	QSC_SIMD_ALIGN uint8_t val[MCELIECE_SYS_T] = { 0U };
	size_t eq;
	size_t i;
	size_t j;
	uint8_t mask;
	bool res;
#if defined(QSC_MCELIECE_S7N8192T128)
	QSC_SIMD_ALIGN uint8_t brnd[MCELIECE_SYS_T * sizeof(uint16_t)];
#else
	QSC_SIMD_ALIGN uint16_t nrnd[MCELIECE_SYS_T * 2U] = { 0U };
	QSC_SIMD_ALIGN uint8_t brnd[MCELIECE_SYS_T * 2U * sizeof(uint16_t)];
	size_t count;
#endif

	res = true;

	while (res)
	{
		if (!rng_generate(brnd, sizeof(brnd)))
		{
			res = false;
			break;
		}

#if defined(QSC_MCELIECE_S7N8192T128)
		for (i = 0U; i < MCELIECE_SYS_T; ++i)
		{
			ind[i] = load_gf(brnd + i * 2U);
		}
#else
		for (i = 0U; i < MCELIECE_SYS_T * 2U; ++i)
		{
			nrnd[i] = load_gf(brnd + i * 2U);
		}

		/* moving and counting indices in the correct range */

		count = 0U;

		for (i = 0U; i < MCELIECE_SYS_T * 2U; ++i)
		{
			if (nrnd[i] < MCELIECE_SYS_N)
			{
				ind[count] = nrnd[i];
				++count;

				if (count >= MCELIECE_SYS_T)
				{
					break;
				}
			}
		}

		if (count < MCELIECE_SYS_T)
		{
			continue;
		}
#endif

		/* check for repetition */

		eq = 0U;

		for (i = 1U; i < MCELIECE_SYS_T; ++i)
		{
			for (j = 0U; j < i; ++j)
			{
				if (ind[i] == ind[j])
				{
					eq = 1U;
					break;
				}
			}
		}

		if (eq == 0U)
		{
			break;
		}
	}

	for (j = 0U; j < MCELIECE_SYS_T; ++j)
	{
		val[j] = (uint8_t)(1U << (ind[j] & 7));
	}

	for (i = 0U; i < MCELIECE_SYS_N / 8U; ++i)
	{
		e[i] = 0U;

		for (j = 0U; j < MCELIECE_SYS_T; ++j)
		{
			mask = same_mask((uint16_t)i, (ind[j] >> 3));
			e[i] |= val[j] & mask;
		}
	}

	return res;
}

static void syndrome(uint8_t* s, const uint8_t* pk, const uint8_t* e)
{
	/* input: public key pk, error vector e
	   output: syndrome s */

	QSC_SIMD_ALIGN uint8_t row[MCELIECE_SYS_N / 8U];
	const uint8_t *pk_ptr = pk;
	size_t j;
	uint8_t b;
#if defined(QSC_MCELIECE_S6N6960T119)
	int32_t tail;
	tail = MCELIECE_PK_NROWS % 8;
#endif

	qsc_memutils_clear(s, MCELIECE_SYND_BYTES);

	for (size_t i = 0U; i < MCELIECE_PK_NROWS; ++i)
	{
		qsc_memutils_clear(row, MCELIECE_SYS_N / 8U);

		for (j = 0U; j < MCELIECE_PK_ROW_BYTES; ++j)
		{
			row[MCELIECE_SYS_N / 8U - MCELIECE_PK_ROW_BYTES + j] = pk_ptr[j];
		}

#if defined(QSC_MCELIECE_S6N6960T119)
		for (j = MCELIECE_SYS_N / 8U - 1U; j >= MCELIECE_SYS_N / 8U - MCELIECE_PK_ROW_BYTES; --j)
		{
			row[j] = (uint8_t)((row[j] << tail) | (row[j - 1U] >> (8U - tail)));
		}

		row[i / 8U] |= 1U << (i % 8U);
#else
		row[i / 8U] |= 1U << (i % 8U);
#endif

		b = 0U;

		for (j = 0U; j < MCELIECE_SYS_N / 8U; ++j)
		{
			b ^= row[j] & e[j];
		}

		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		b &= 1;
		s[i / 8U] |= (b << (i % 8U));

		pk_ptr += MCELIECE_PK_ROW_BYTES;
	}
}

static bool encrypt(uint8_t *s, const uint8_t *pk, uint8_t *e, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = gen_e(e, rng_generate);
	syndrome(s, pk, e);

	return res;
}

/* operations.c */

#if defined(QSC_MCELIECE_S6N6960T119)
static int32_t check_c_padding(const uint8_t* c)
{
	/* check if the padding bits of c are all zero */
	uint8_t b;
	int32_t ret;

	b = c[MCELIECE_SYND_BYTES - 1U] >> (MCELIECE_PK_NROWS % 8U);
	b -= 1U;
	b >>= 7U;
	ret = b;

	return ret - 1;
}

static int32_t check_pk_padding(const uint8_t* pk)
{
	/* Note artifact, no longer used */
	uint8_t b;
	int32_t ret;

	b = 0U;

	for (size_t i = 0U; i < MCELIECE_PK_NROWS; i++)
	{
		b |= pk[i * MCELIECE_PK_ROW_BYTES + MCELIECE_PK_ROW_BYTES - 1U];
	}

	b >>= (MCELIECE_PK_NCOLS % 8);
	b -= 1;
	b >>= 7;
	ret = b;

	return (ret - 1);
}
#endif

/* pk_gen.c */

static bool pk_gen(uint8_t* pk, const uint8_t* sk, const uint32_t* perm, int16_t* pi)
{
	/* input: secret key sk output: public key pk */
	QSC_SIMD_ALIGN uint64_t buf[1U << MCELIECE_GFBITS] = { 0U };
	QSC_SIMD_ALIGN gf g[MCELIECE_SYS_T + 1U] = { 0U };	/* Goppa polynomial */
	QSC_SIMD_ALIGN gf L[MCELIECE_SYS_N] = { 0U };		/* support */
	QSC_SIMD_ALIGN gf inv[MCELIECE_SYS_N] = { 0U };
	size_t i;
	size_t j;
	size_t k;
	size_t col;
	size_t row;
	uint8_t b;
	uint8_t mask;
	bool res;

#if defined(QSC_MISRA_FULL_COMPLIANCE)
	/* Note: if it fails here with stackoverflow, increase the maximum stack size
	* to +/- 20 MB to account for the large matrix array */
	QSC_SIMD_ALIGN uint8_t mat[MCELIECE_PK_NROWS * sizeof(uint8_t*)][MCELIECE_SYS_N / 8U] = { 0 };
	res = true;
#else
	uint8_t** mat;

	res = false;
	mat = (uint8_t**)qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, MCELIECE_PK_NROWS * sizeof(uint8_t*));

	if (mat != NULL)
	{
		for (i = 0; i < MCELIECE_PK_NROWS; ++i)
		{
			mat[i] = (uint8_t*)qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, MCELIECE_SYS_N / 8);

			if (mat[i] == NULL)
			{
				for (size_t j = 0; j < i; ++j)
				{
					qsc_memutils_aligned_free(mat[j]);
					mat[j] = NULL;
				}

				qsc_memutils_aligned_free(mat);
				mat = NULL;
				break;
			}
		}

		res = true;
	}
#endif

	if (res)
	{
#if defined(QSC_MCELIECE_S6N6960T119)
		uint8_t *pk_ptr = pk;
		int32_t tail;
#endif
		g[MCELIECE_SYS_T] = 1U;

		for (i = 0U; i < MCELIECE_SYS_T; ++i)
		{
			g[i] = load_gf(sk);
			sk += 2U;
		}

		for (i = 0U; i < (1U << MCELIECE_GFBITS); i++)
		{
			buf[i] = perm[i];
			buf[i] <<= 31;
			buf[i] |= i;
		}

		uint64_sort(buf, 1 << MCELIECE_GFBITS);

		for (i = 1U; i < (1U << MCELIECE_GFBITS); ++i)
		{
			if ((buf[i - 1U] >> 31) == (buf[i] >> 31))
			{
				return false;
			}
		}

		for (i = 0U; i < (1U << MCELIECE_GFBITS); ++i)
		{
			pi[i] = buf[i] & MCELIECE_GFMASK;
		}

		for (i = 0U; i < MCELIECE_SYS_N; ++i)
		{
			L[i] = bitrev(pi[i]);
		}

		/* filling the matrix */

		root(inv, g, L);

		for (i = 0U; i < MCELIECE_SYS_N; ++i)
		{
			inv[i] = gf_inv(inv[i]);
		}

		for (i = 0U; i < MCELIECE_PK_NROWS; ++i)
		{
			for (j = 0U; j < MCELIECE_SYS_N / 8U; ++j)
			{
				mat[i][j] = 0U;
			}
		}

		for (i = 0U; i < MCELIECE_SYS_T; ++i)
		{
			for (j = 0U; j < MCELIECE_SYS_N; j += 8U)
			{
				for (k = 0U; k < MCELIECE_GFBITS; ++k)
				{
					b = (inv[j + 7U] >> k) & 1;
					b <<= 1;
					b |= (inv[j + 6U] >> k) & 1;
					b <<= 1;
					b |= (inv[j + 5U] >> k) & 1;
					b <<= 1;
					b |= (inv[j + 4U] >> k) & 1;
					b <<= 1;
					b |= (inv[j + 3U] >> k) & 1;
					b <<= 1;
					b |= (inv[j + 2U] >> k) & 1;
					b <<= 1;
					b |= (inv[j + 1U] >> k) & 1;
					b <<= 1;
					b |= (inv[j] >> k) & 1;

					mat[i * MCELIECE_GFBITS + k][j / 8U] = b;
				}
			}

			for (j = 0U; j < MCELIECE_SYS_N; ++j)
			{
				inv[j] = gf_mul(inv[j], L[j]);
			}
		}

		/* gaussian elimination */

		for (i = 0U; i < (MCELIECE_PK_NROWS + 7U) / 8U; ++i)
		{
			for (j = 0U; j < 8U; ++j)
			{
				row = i * 8U + j;

				if (row >= MCELIECE_PK_NROWS)
				{
					break;
				}

				for (k = row + 1U; k < MCELIECE_PK_NROWS; ++k)
				{
					mask = mat[row][i] ^ mat[k][i];
					mask >>= j;
					mask &= 1U;
					mask = -mask;

					for (col = 0U; col < MCELIECE_SYS_N / 8U; ++col)
					{
						mat[row][col] ^= mat[k][col] & mask;
					}
				}

				/* return if not systematic */
				if (((mat[row][i] >> j) & 1) == 0U)
				{
					return false;
				}

				for (k = 0U; k < MCELIECE_PK_NROWS; ++k)
				{
					if (k != row)
					{
						mask = mat[k][i] >> j;
						mask &= 1;
						mask = -mask;

						for (col = 0U; col < MCELIECE_SYS_N / 8U; ++col)
						{
							mat[k][col] ^= mat[row][col] & mask;
						}
					}
				}
			}
		}


#if defined(QSC_MCELIECE_S6N6960T119)
		tail = MCELIECE_PK_NROWS % 8;

		for (i = 0U; i < MCELIECE_PK_NROWS; ++i)
		{
			for (j = (MCELIECE_PK_NROWS - 1U) / 8U; j < MCELIECE_SYS_N / 8U - 1U; ++j)
			{
				*pk_ptr = (uint8_t)((mat[i][j] >> tail) | (mat[i][j + 1U] << (8U - tail)));
				++pk_ptr;
			}

			*pk_ptr = (mat[i][j] >> tail);
			++pk_ptr;
		}
#else
		for (i = 0U; i < MCELIECE_PK_NROWS; ++i)
		{
			qsc_memutils_copy(pk + i * MCELIECE_PK_ROW_BYTES, mat[i] + MCELIECE_PK_NROWS / 8U, MCELIECE_PK_ROW_BYTES);
		}
#endif

#if !defined(QSC_MISRA_FULL_COMPLIANCE)
		for (size_t i = 0; i < MCELIECE_PK_NROWS; ++i)
		{
			qsc_memutils_aligned_free(mat[i]);
			mat[i] = NULL;
		}

		qsc_memutils_aligned_free(mat);
		mat = NULL;
#endif
	}

	return res;
}

/* sk_gen.c */

static int32_t genpoly_gen(gf* out, const gf* f)
{
	/* input: f, element in GF((2^m)^t)
	   output: out, minimal polynomial of f
	   return: 0 for success and -1 for failure */

	QSC_SIMD_ALIGN gf mat[MCELIECE_SYS_T + 1U][MCELIECE_SYS_T] = { 0U };
	size_t c;
	size_t i;
	size_t j;
	size_t k;
	int32_t res;
	gf inv;
	gf mask;
	gf t;

	/* fill matrix */

	res = 0;
	mat[0U][0U] = 1U;

	for (i = 0U; i < MCELIECE_SYS_T; ++i)
	{
		mat[1U][i] = f[i];
	}

	for (j = 2U; j <= MCELIECE_SYS_T; ++j)
	{
		GF_mul(mat[j], mat[j - 1U], f);
	}

	/* gaussian */

	for (j = 0U; j < MCELIECE_SYS_T; ++j)
	{
		for (k = j + 1U; k < MCELIECE_SYS_T; ++k)
		{
			mask = gf_is_zero(mat[j][j]);

			for (c = j; c < MCELIECE_SYS_T + 1U; ++c)
			{
				mat[c][j] ^= mat[c][k] & mask;
			}
		}

		if (mat[j][j] != 0U)
		{
			inv = gf_inv(mat[j][j]);

			for (c = j; c < MCELIECE_SYS_T + 1U; ++c)
			{
				mat[c][j] = gf_mul(mat[c][j], inv);
			}

			for (k = 0U; k < MCELIECE_SYS_T; ++k)
			{
				if (k != j)
				{
					t = mat[j][k];

					for (c = j; c < MCELIECE_SYS_T + 1U; ++c)
					{
						mat[c][k] ^= gf_mul(mat[c][j], t);
					}
				}
			}
		}
		else
		{
			/* return if not systematic */
			res = -1;
			break;
		}

		for (i = 0U; i < MCELIECE_SYS_T; ++i)
		{
			out[i] = mat[MCELIECE_SYS_T][i];
		}
	}

	return res;
}

bool qsc_mceliece_ref_encapsulate(uint8_t* c, uint8_t* key, const uint8_t* pk, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_SIMD_ALIGN uint8_t one_ec[1U + MCELIECE_SYS_N / 8U + (MCELIECE_SYND_BYTES + 32U)] = { 0U };
	QSC_SIMD_ALIGN uint8_t two_e[1U + MCELIECE_SYS_N / 8U] = { 0U };
	uint8_t *e = two_e + 1U;
	bool res;

#if defined(QSC_MCELIECE_S6N6960T119)
	uint8_t mask;
	int32_t i;
	int32_t padding_ok;

	padding_ok = check_pk_padding(pk);
#endif

	one_ec[0U] = 1U;
	two_e[0U] = 2U;

	res = encrypt(c, pk, e, rng_generate);

	if (res)
	{
		qsc_shake256_compute(c + MCELIECE_SYND_BYTES, MCELIECE_SHAREDSECRET_SIZE, two_e, sizeof(two_e));
		qsc_memutils_copy(one_ec + 1U, e, MCELIECE_SYS_N / 8U);
		qsc_memutils_copy(one_ec + 1U + MCELIECE_SYS_N / 8U, c, MCELIECE_SYND_BYTES + 32U);
		qsc_shake256_compute(key, MCELIECE_SHAREDSECRET_SIZE, one_ec, sizeof(one_ec));

#if defined(QSC_MCELIECE_S6N6960T119)
		/* clear outputs(set to all 0's) if padding bits are not all zero */
		mask = padding_ok;
		mask ^= 0xFF;

		for (i = 0U; i < MCELIECE_SYND_BYTES + 32U; ++i)
		{
			c[i] &= mask;
		}

		for (i = 0U; i < 32U; ++i)
		{
			key[i] &= mask;
		}

		res = res && (padding_ok == 0);
#endif
	}
	else
	{
		qsc_memutils_clear(c, MCELIECE_SYND_BYTES);
	}

	return res;
}

bool qsc_mceliece_ref_decapsulate(uint8_t* key, const uint8_t* c, const uint8_t* sk)
{
	QSC_SIMD_ALIGN uint8_t conf[32U];
	QSC_SIMD_ALIGN uint8_t preimage[1U + MCELIECE_SYS_N / 8U + (MCELIECE_SYND_BYTES + 32U)] = { 0U };
	QSC_SIMD_ALIGN uint8_t two_e[1U + MCELIECE_SYS_N / 8U] = { 0U };
	const uint8_t *s = sk + 40U + MCELIECE_IRR_BYTES + MCELIECE_COND_BYTES;
	size_t i;
	uint16_t m;
	uint8_t ret_confirm;
	uint8_t ret_decrypt;
	uint8_t *e = two_e + 1U;
	uint8_t *x = preimage;
#if defined(QSC_MCELIECE_S6N6960T119)
	int32_t padding_ok;
	uint8_t mask;

	padding_ok = check_c_padding(c);
#endif

	two_e[0U] = 2U;
	ret_confirm = 0U;
	ret_decrypt = (uint8_t)decrypt(e, (sk + 40U), c);
	qsc_shake256_compute(conf, MCELIECE_SHAREDSECRET_SIZE, two_e, sizeof(two_e));

	for (i = 0U; i < 32U; ++i)
	{
		ret_confirm |= conf[i] ^ c[MCELIECE_SYND_BYTES + i];
	}

	m = ret_decrypt | ret_confirm;
	m -= 1U;
	m >>= 8U;

	*x = m & 1U;
	++x;

	for (i = 0U; i < MCELIECE_SYS_N / 8U; ++i)
	{
		*x = (~m & s[i]) | (m & e[i]);
		++x;
	}

	for (i = 0U; i < MCELIECE_SYND_BYTES + 32U; ++i)
	{
		*x = c[i];
		++x;
	}

	qsc_shake256_compute(key, MCELIECE_SHAREDSECRET_SIZE, preimage, sizeof(preimage));

#if defined(QSC_MCELIECE_S6N6960T119)
	// clear outputs (set to all 1's) if padding bits are not all zero

	mask = (uint8_t)padding_ok;

	for (i = 0U; i < 32U; ++i)
	{
		key[i] |= mask;
	}

	return (ret_decrypt == 0U) && (ret_confirm == 0U) && (padding_ok == 0);
#else
	return (ret_decrypt == 0U) && (ret_confirm == 0U);
#endif
}

bool qsc_mceliece_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_SIMD_ALIGN uint32_t perm[1U << MCELIECE_GFBITS] = { 0U };	/* random permutation as 32-bit integers */
	QSC_SIMD_ALIGN int16_t pi[1U << MCELIECE_GFBITS];	/* random permutation */
	QSC_SIMD_ALIGN gf f[MCELIECE_SYS_T] = { 0U };		/* element in GF(2 ^ mt) */
	QSC_SIMD_ALIGN gf irr[MCELIECE_SYS_T];				/* Goppa polynomial */
	QSC_SIMD_ALIGN uint8_t r[(MCELIECE_SYS_N / 8U) + ((1U << MCELIECE_GFBITS) * sizeof(uint32_t)) + (MCELIECE_SYS_T * 2U) + 32U] = { 0U };
	QSC_SIMD_ALIGN uint8_t seed[33U] = { 0U };
	const uint8_t* rp;
	uint8_t *skp;
	int32_t i;
	bool res;

	seed[0U] = 64;

	if (rng_generate((seed + 1U), 32U))
	{
		while (true)
		{
			rp = &r[sizeof(r) - 32U];
			skp = sk;

			/* expanding and updating the seed */
			qsc_shake256_compute(r, sizeof(r), seed, 33U);
			qsc_memutils_copy(skp, seed + 1U, 32U);
			skp += 32U + 8U;
			qsc_memutils_copy(seed + 1U, &r[sizeof(r) - 32U], 32U);

			/* generating irreducible polynomial */

			rp -= sizeof(f);

			for (i = 0; i < MCELIECE_SYS_T; ++i)
			{
				f[i] = load_gf(rp + i * 2U);
			}

			if (genpoly_gen(irr, f) != 0)
			{
				continue;
			}

			for (i = 0; i < MCELIECE_SYS_T; ++i)
			{
				store_gf(skp + i * 2U, irr[i]);
			}

			skp += MCELIECE_IRR_BYTES;

			/* generating permutation */

			rp -= sizeof(perm);

			for (i = 0; i < (1 << MCELIECE_GFBITS); ++i)
			{
				perm[i] = load4(rp + i * 4U);
			}

			if (!pk_gen(pk, skp - MCELIECE_IRR_BYTES, perm, pi))
			{
				continue;
			}

			controlbits_from_permutation(skp, pi, MCELIECE_GFBITS, 1 << MCELIECE_GFBITS);
			skp += MCELIECE_COND_BYTES;

			/* storing the random string s */
			rp -= MCELIECE_SYS_N / 8U;
			qsc_memutils_copy(skp, rp, MCELIECE_SYS_N / 8U);

			/* storing positions of the 32 pivots */
			store8(sk + 32U, 0x00000000FFFFFFFFULL);

			break;
		}
		res = true;
	}
	else
	{
		res = false;
	}

	return res;
}

