#include "mceliecebase.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

/* params.h */

#define MCELIECE_SHAREDSECRET_SIZE 32

#if defined(QSC_MCELIECE_S3N4608T96)
#   define MCELIECE_GFBITS 13
#   define MCELIECE_SYS_N 4608
#   define MCELIECE_SYS_T 96
#   define MCELIECE_COND_BYTES ((1 << (MCELIECE_GFBITS - 4)) * (2 * MCELIECE_GFBITS - 1))
#   define MCELIECE_IRR_BYTES (MCELIECE_SYS_T * 2)
#   define MCELIECE_PK_NROWS (MCELIECE_SYS_T * MCELIECE_GFBITS) 
#   define MCELIECE_PK_NCOLS (MCELIECE_SYS_N - MCELIECE_PK_NROWS)
#   define MCELIECE_PK_ROW_BYTES ((MCELIECE_PK_NCOLS + 7) / 8)
#   define MCELIECE_SYND_BYTES ((MCELIECE_PK_NROWS + 7) / 8)
#   define MCELIECE_GFMASK ((1 << MCELIECE_GFBITS) - 1)
#elif defined(QSC_MCELIECE_S5N6688T128)
#   define MCELIECE_GFBITS 13
#   define MCELIECE_SYS_N 6688
#   define MCELIECE_SYS_T 128
#   define MCELIECE_COND_BYTES ((1 << (MCELIECE_GFBITS - 4)) * (2 * MCELIECE_GFBITS - 1))
#   define MCELIECE_IRR_BYTES (MCELIECE_SYS_T * 2)
#   define MCELIECE_PK_NROWS (MCELIECE_SYS_T * MCELIECE_GFBITS) 
#   define MCELIECE_PK_NCOLS (MCELIECE_SYS_N - MCELIECE_PK_NROWS)
#   define MCELIECE_PK_ROW_BYTES ((MCELIECE_PK_NCOLS + 7) / 8)
#   define MCELIECE_SYND_BYTES ((MCELIECE_PK_NROWS + 7) / 8)
#   define MCELIECE_GFMASK ((1 << MCELIECE_GFBITS) - 1)
#elif defined(QSC_MCELIECE_S5N6960T119)
#   define MCELIECE_GFBITS 13
#   define MCELIECE_SYS_N 6960
#   define MCELIECE_SYS_T 119
#   define MCELIECE_COND_BYTES ((1 << (MCELIECE_GFBITS - 4)) * (2 * MCELIECE_GFBITS - 1))
#   define MCELIECE_IRR_BYTES (MCELIECE_SYS_T * 2)
#   define MCELIECE_PK_NROWS (MCELIECE_SYS_T * MCELIECE_GFBITS) 
#   define MCELIECE_PK_NCOLS (MCELIECE_SYS_N - MCELIECE_PK_NROWS)
#   define MCELIECE_PK_ROW_BYTES ((MCELIECE_PK_NCOLS + 7) / 8)
#   define MCELIECE_SYND_BYTES ((MCELIECE_PK_NROWS + 7) / 8)
#   define MCELIECE_GFMASK ((1 << MCELIECE_GFBITS) - 1)
#elif defined(QSC_MCELIECE_S5N8192T128)
#   define MCELIECE_GFBITS 13
#   define MCELIECE_SYS_N 8192
#   define MCELIECE_SYS_T 128
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
	t -= 1;
	t >>= 19;

	return (gf)t;
}

static gf gf_add(gf in0, gf in1)
{
	return in0 ^ in1;
}

static gf gf_mul(gf in0, gf in1)
{
	uint64_t t;
	uint64_t t0;
	uint64_t t1;
	uint64_t tmp;

	t0 = in0;
	t1 = in1;
	tmp = t0 * (t1 & 1);

	for (size_t i = 1; i < MCELIECE_GFBITS; ++i)
	{
		tmp ^= (t0 * (t1 & (1ULL << i)));
	}

	t = tmp & 0x0000000001FF0000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	t = tmp & 0x000000000000E000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

	return tmp & MCELIECE_GFMASK;
}

static gf gf_sq2(gf in)
{

	/* input: field element in
	   return: (in^2)^2 */

	const uint64_t Bf[] = { 0x1111111111111111ULL, 0x0303030303030303ULL, 0x000F000F000F000FULL, 0x000000FF000000FFULL };
	const uint64_t M[] = { 0x0001FF0000000000ULL, 0x000000FF80000000ULL, 0x000000007FC00000ULL, 0x00000000003FE000ULL };
	uint64_t t;
	uint64_t x;

	x = in;
	x = (x | (x << 24)) & Bf[3];
	x = (x | (x << 12)) & Bf[2];
	x = (x | (x << 6)) & Bf[1];
	x = (x | (x << 3)) & Bf[0];

	for (size_t i = 0; i < 4; ++i)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return x & MCELIECE_GFMASK;
}

static gf gf_sqmul(gf in, gf m)
{
	/* input: field element in, m
	   return: (in^2)*m */

	const uint64_t M[] = { 0x0000001FF0000000ULL, 0x000000000FF80000ULL, 0x000000000007E000ULL };
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

	for (size_t i = 0; i < 3; ++i)
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
	const uint64_t M[] = { 0x1FF0000000000000ULL, 0x000FF80000000000ULL, 0x000007FC00000000ULL,
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

	for (size_t i = 0; i < 6; ++i)
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

static void GF_mul(gf* out, const gf* in0, const gf* in1)
{
	/* input: in0, in1 in GF((2^m)^t)
	   output: out = in0*in1 */

	gf prod[MCELIECE_SYS_T * 2 - 1] = { 0 };
	size_t i;

	for (i = 0; i < MCELIECE_SYS_T; ++i)
	{
		for (size_t j = 0; j < MCELIECE_SYS_T; ++j)
		{
			prod[i + j] ^= gf_mul(in0[i], in1[j]);
		}
	}

	for (i = (MCELIECE_SYS_T - 1) * 2; i >= MCELIECE_SYS_T; --i)
	{
#if defined(QSC_MCELIECE_S3N4608T96)
		prod[i - MCELIECE_SYS_T + 10] ^= prod[i];
		prod[i - MCELIECE_SYS_T + 9] ^= prod[i];
		prod[i - MCELIECE_SYS_T + 6] ^= prod[i];
		prod[i - MCELIECE_SYS_T] ^= prod[i];
#elif defined(QSC_MCELIECE_S5N6688T128) || defined(QSC_MCELIECE_S5N8192T128)
		prod[i - MCELIECE_SYS_T + 7] ^= prod[i];
		prod[i - MCELIECE_SYS_T + 2] ^= prod[i];
		prod[i - MCELIECE_SYS_T + 1] ^= prod[i];
		prod[i - MCELIECE_SYS_T] ^= prod[i];
#elif defined(QSC_MCELIECE_S5N6960T119)
		prod[i - MCELIECE_SYS_T + 8] ^= prod[i];
		prod[i - MCELIECE_SYS_T] ^= prod[i];
#endif
	}

	qsc_memutils_copy(out, prod, MCELIECE_SYS_T * sizeof(gf));
}

/* util.c */

static void store_gf(uint8_t* dest, gf a)
{
	dest[0] = a & 0x00FF;
	dest[1] = a >> 8;
}

static uint16_t load_gf(const uint8_t* src)
{
	uint16_t a;

	a = src[1];
	a <<= 8;
	a |= src[0];

	return a & MCELIECE_GFMASK;
}

static uint32_t load4(const uint8_t* in)
{
	uint32_t ret;

	ret = in[3];

	for (int32_t i = 2; i >= 0; --i)
	{
		ret <<= 8;
		ret |= in[i];
	}

	return ret;
}

static void store8(uint8_t* out, uint64_t in)
{
	out[0] = in & 0xFF;
	out[1] = (in >> 0x08) & 0xFF;
	out[2] = (in >> 0x10) & 0xFF;
	out[3] = (in >> 0x18) & 0xFF;
	out[4] = (in >> 0x20) & 0xFF;
	out[5] = (in >> 0x28) & 0xFF;
	out[6] = (in >> 0x30) & 0xFF;
	out[7] = (in >> 0x38) & 0xFF;
}

static uint64_t load8(const uint8_t* in)
{
	uint64_t ret;

	ret = in[7];

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

	return (a >> 3);
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
	c = ~c + 1;
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
	while (i > 0);

	return r;
}

static void root(gf* out, const gf* f, const gf* L)
{
	/* input: polynomial f and list of field elements L
	   output: out = [ f(a) for a in L ] */

	for (size_t i = 0; i < MCELIECE_SYS_N; ++i)
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

	qsc_memutils_clear(out, 2 * MCELIECE_SYS_T * sizeof(gf));

	for (size_t i = 0; i < MCELIECE_SYS_N; ++i)
	{
		c = (r[i / 8] >> (i % 8)) & 1;
		e = eval(f, L[i]);
		e_inv = gf_inv(gf_mul(e, e));

		for (size_t j = 0; j < 2 * MCELIECE_SYS_T; ++j)
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

	uint64_t masks[6][2] =
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

	qsc_memutils_copy(out, in, 64 * sizeof(uint64_t));

	for (int32_t d = 5; d >= 0; d--)
	{
		s = 1 << d;

		for (size_t i = 0; i < 64; i += (size_t)s * 2)
		{
			for (size_t j = i; j < i + s; ++j)
			{
				x = (out[j] & masks[d][0]) | ((out[j + s] & masks[d][0]) << s);
				y = ((out[j] & masks[d][1]) >> s) | (out[j + s] & masks[d][1]);
				out[j] = x;
				out[j + s] = y;
			}
		}
	}
}

/* benes.c */

static void layer_in(uint64_t data[2][64], const uint64_t* bits, int32_t lgs)
{
	/* middle layers of the benes network */

	uint64_t d;
	int32_t s;

	s = 1 << lgs;

	for (size_t i = 0; i < 64; i += (size_t)s * 2)
	{
		for (size_t j = i; j < i + (size_t)s; ++j)
		{
			d = (data[0][j] ^ data[0][j + s]);
			d &= (*bits);
			++bits;
			data[0][j] ^= d;
			data[0][j + s] ^= d;

			d = (data[1][j] ^ data[1][j + s]);
			d &= (*bits);
			++bits;
			data[1][j] ^= d;
			data[1][j + s] ^= d;
		}
	}
}

static void layer_ex(uint64_t* data, const uint64_t* bits, int32_t lgs)
{
	/* first and last layers of the benes network */
	uint64_t d;
	int32_t s;

	s = 1 << lgs;

	for (size_t i = 0; i < 128; i += (size_t)s * 2)
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

	uint64_t r_int_v[2][64] = { 0 };
	uint64_t r_int_h[2][64] = { 0 };
	uint64_t b_int_v[64] = { 0 };
	uint64_t b_int_h[64];
	size_t i;
	int32_t inc;
	int32_t iter;
	uint8_t* r_ptr = r;
	const uint8_t* bits_ptr;

	if (rev != 0) 
	{
		bits_ptr = bits + 12288; 
		inc = -1024; 
	}
	else 
	{
		bits_ptr = bits;         
		inc = 0;
	}

	for (i = 0; i < 64; ++i)
	{
		r_int_v[0][i] = load8(r_ptr + i * 16);
		r_int_v[1][i] = load8(r_ptr + i * 16 + 8);
	}

	transpose_64x64(r_int_h[0], r_int_v[0]);
	transpose_64x64(r_int_h[1], r_int_v[1]);

	for (iter = 0; iter <= 6; ++iter)
	{
		for (i = 0; i < 64; ++i)
		{
			b_int_v[i] = load8(bits_ptr); 
			bits_ptr += 8;
		}

		bits_ptr += inc;
		transpose_64x64(b_int_h, b_int_v);
		layer_ex(r_int_h[0], b_int_h, iter);
	}

	transpose_64x64(r_int_v[0], r_int_h[0]);
	transpose_64x64(r_int_v[1], r_int_h[1]);

	for (iter = 0; iter <= 5; ++iter)
	{
		for (i = 0; i < 64; ++i) 
		{ 
			b_int_v[i] = load8(bits_ptr); 
			bits_ptr += 8;
		}

		bits_ptr += inc;
		layer_in(r_int_v, b_int_v, iter);
	}

	for (iter = 4; iter >= 0; --iter)
	{
		for (i = 0; i < 64; ++i) 
		{ 
			b_int_v[i] = load8(bits_ptr); 
			bits_ptr += 8; 
		}

		bits_ptr += inc;
		layer_in(r_int_v, b_int_v, iter);
	}

	transpose_64x64(r_int_h[0], r_int_v[0]);
	transpose_64x64(r_int_h[1], r_int_v[1]);

	for (iter = 6; iter >= 0; --iter)
	{
		for (i = 0; i < 64; ++i)
		{
			b_int_v[i] = load8(bits_ptr);
			bits_ptr += 8;
		}

		bits_ptr += inc;
		transpose_64x64(b_int_h, b_int_v);
		layer_ex(r_int_h[0], b_int_h, iter);
	}

	transpose_64x64(r_int_v[0], r_int_h[0]);
	transpose_64x64(r_int_v[1], r_int_h[1]);

	for (i = 0; i < 64; ++i)
	{
		store8(r_ptr + i * 16 + 0, r_int_v[0][i]);
		store8(r_ptr + i * 16 + 8, r_int_v[1][i]);
	}
}

static void support_gen(gf* s, const uint8_t* c)
{
	/* input: condition bits c output: support s */

	uint8_t L[MCELIECE_GFBITS][(1 << MCELIECE_GFBITS) / 8] = { 0 };
	size_t i;
	size_t j;
	gf a;

	for (i = 0; i < (1 << MCELIECE_GFBITS); ++i)
	{
		a = bitrev((gf)i);

		for (j = 0; j < MCELIECE_GFBITS; ++j)
		{
			L[j][i / 8] |= ((a >> j) & 1) << (i % 8);
		}
	}

	for (j = 0; j < MCELIECE_GFBITS; ++j)
	{
		apply_benes(L[j], c, 0);
	}

	for (i = 0; i < MCELIECE_SYS_N; ++i)
	{
		s[i] = 0;
		j = MCELIECE_GFBITS;

		do
		{
			--j;
			s[i] <<= 1;
			s[i] |= (L[j][i / 8] >> (i % 8)) & 1;
		} 
		while (j != 0);
	}
}

/* bm.c */

static void bm(gf* out, const gf* s)
{
	/* the Berlekamp-Massey algorithm. 
	input: s, sequence of field elements
	output: out, minimal polynomial of s */

	gf T[MCELIECE_SYS_T + 1] = { 0 };
	gf C[MCELIECE_SYS_T + 1] = { 0 };
	gf B[MCELIECE_SYS_T + 1] = { 0 };
	size_t i;
	gf b;
	gf d;
	gf f;
	uint16_t N;
	uint16_t L;
	uint16_t mle;
	uint16_t mne;

	b = 1;
	L = 0;
	B[1] = 1;
	C[0] = 1;

	for (N = 0; N < 2 * MCELIECE_SYS_T; ++N)
	{
		d = 0;
		
		for (i = 0; i <= qsc_intutils_min((size_t)N, (size_t)MCELIECE_SYS_T); ++i)
		{
			d ^= gf_mul(C[i], s[N - i]);
		}

		mne = d; 
		mne -= 1;   
		mne >>= 15; 
		mne -= 1;
		mle = N;
		mle -= 2 * L; 
		mle >>= 15; 
		mle -= 1;
		mle &= mne;

		qsc_memutils_copy(T, C, MCELIECE_SYS_T * sizeof(gf));

		f = gf_frac(b, d);

		for (i = 0; i <= MCELIECE_SYS_T; ++i)
		{
			C[i] ^= gf_mul(f, B[i]) & mne;
		}

		L = (L & ~mle) | ((N + 1 - L) & mle);

		for (i = 0; i <= MCELIECE_SYS_T; ++i)
		{
			B[i] = (B[i] & ~mle) | (T[i] & mle);
		}

		b = (b & ~mle) | (d & mle);

		for (i = MCELIECE_SYS_T; i >= 1; --i)
		{
			B[i] = B[i - 1];
		}

		B[0] = 0;
	}

	for (i = 0; i <= MCELIECE_SYS_T; ++i)
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
	int16_t* q = ((int16_t*)(temp + n + n / 4));
	int64_t i;
	int64_t j;
	int64_t x;

	if (w == 1) 
	{
		out[pos >> 3] ^= pi[0] << (pos & 7);
		return;
	}

	for (x = 0; x < n; ++x)
	{
		A[x] = ((pi[x] ^ 1) << 16) | pi[x ^ 1];
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
		B[x + 1] = (A[x + 1] << 16) | Fx1;
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
		A[y + 1] = (Ly1 << 16) | (B[y + 1] & 0x0000FFFFL);
	}

	/* A = (L<<16)+F(pi) */
	int32_sort(A, n); /* A = (id<<16)+F(pi(L)) = (id<<16)+M */
	pos -= (2 * w - 2) * step * (n / 2);

	for (j = 0; j < n / 2; ++j)
	{
		q[j] = (A[2 * j] & 0x0000FFFFL) >> 1;
		q[j + n / 2] = (A[2 * j + 1] & 0x0000FFFFL) >> 1;
	}

	cbrecursion(out, pos, step * 2, q, w - 1, n / 2, temp);
	cbrecursion(out, pos + step, step * 2, q + n / 2, w - 1, n / 2, temp);
}


static void layer(int16_t* p, const uint8_t* cb, int32_t s, int32_t n)
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

	for (size_t i = 0; i < n; i += stride * 2)
	{
		for (size_t j = 0; j < stride; ++j)
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

	int32_t* temp;
	int16_t* pi_test;
	int32_t i;
	int16_t diff;
	const uint8_t* ptr;

	temp = qsc_memutils_malloc((size_t)n * 2 * sizeof(int32_t));
	pi_test = qsc_memutils_malloc((size_t)n * sizeof(int16_t));

	assert(temp != NULL);
	assert(pi_test != NULL);

	if (temp != NULL && pi_test != NULL)
	{
		while (true)
		{
			qsc_memutils_clear(out, (size_t)(((2 * w - 1) * n / 2) + 7) / 8);
			cbrecursion(out, 0, 1, pi, w, n, temp);

			// check for correctness

			for (i = 0; i < n; ++i)
			{
				pi_test[i] = (int16_t)i;
			}

			ptr = out;

			for (i = 0; i < w; ++i)
			{
				layer(pi_test, ptr, i, (int32_t)n);
				ptr += n >> 4;
			}

			for (i = (int32_t)w - 2; i >= 0; --i)
			{
				layer(pi_test, ptr, i, (int32_t)n);
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

		qsc_memutils_alloc_free(pi_test);
		qsc_memutils_alloc_free(temp);
	}
}

/* decrypt.c */

static int32_t decrypt(uint8_t* e, const uint8_t* sk, const uint8_t* c)
{
	/* Niederreiter decryption with the Berlekamp decoder.
	   input: sk, secret key c, ciphertext
	   output: e, error vector
	   return: 0 for success; 1 for failure */

	gf g[MCELIECE_SYS_T + 1] = { 0 };
	gf L[MCELIECE_SYS_N];
	gf s[MCELIECE_SYS_T * 2];
	gf s_cmp[MCELIECE_SYS_T * 2];
	gf locator[MCELIECE_SYS_T + 1];
	gf images[MCELIECE_SYS_N];
	uint8_t r[MCELIECE_SYS_N / 8];
	int32_t i;
	int32_t w;
	uint16_t check;
	gf t;

	w = 0;
	qsc_memutils_copy(r, c, MCELIECE_SYND_BYTES);
	qsc_memutils_clear(r + MCELIECE_SYND_BYTES, (MCELIECE_SYS_N / 8) - MCELIECE_SYND_BYTES);

	for (i = 0; i < MCELIECE_SYS_T; ++i)
	{
		g[i] = load_gf(sk);
		sk += 2;
	} 
	
	g[MCELIECE_SYS_T] = 1;
	support_gen(L, sk);
	synd(s, g, L, r);
	bm(locator, s);
	root(images, locator, L);

	qsc_memutils_clear(e, MCELIECE_SYS_N / 8);

	for (i = 0; i < MCELIECE_SYS_N; ++i)
	{
		t = gf_is_zero(images[i]) & 1;
		e[i / 8] |= t << (i % 8);
		w += t;
	}

	synd(s_cmp, g, L, e);
	check = (uint16_t)w;
	check ^= MCELIECE_SYS_T;

	for (i = 0; i < MCELIECE_SYS_T * 2; ++i)
	{
		check |= s[i] ^ s_cmp[i];
	}

	check -= 1;
	check >>= 15;

	return (check ^ 1);
}

/* encrypt.c */

static uint8_t same_mask(uint16_t x, uint16_t y)
{
	uint32_t mask;

	mask = (uint32_t)(x ^ y);
	mask -= 1;
	mask >>= 31;
	mask = ~mask + 1;

	return mask & 0x000000FFUL;
}

static void gen_e(uint8_t* e, bool (*rng_generate)(uint8_t*, size_t))
{
	/* output: e, an error vector of weight t */
	uint16_t ind[MCELIECE_SYS_T] = { 0 };
	uint8_t val[MCELIECE_SYS_T] = { 0 };
	size_t eq;
	size_t i;
	size_t j;
	uint8_t mask;
#if defined(QSC_MCELIECE_S5N8192T128)
	uint8_t brnd[MCELIECE_SYS_T * sizeof(uint16_t)];
#else
	size_t count;
	uint16_t nrnd[MCELIECE_SYS_T * 2] = { 0 };
	uint8_t brnd[MCELIECE_SYS_T * 2 * sizeof(uint16_t)];
#endif

	while (true)
	{
		rng_generate(brnd, sizeof(brnd));

#if defined(QSC_MCELIECE_S5N8192T128)
		for (i = 0; i < MCELIECE_SYS_T; ++i)
		{
			ind[i] = load_gf(brnd + i * 2);
		}
#else
		for (i = 0; i < MCELIECE_SYS_T * 2; ++i)
		{
			nrnd[i] = load_gf(brnd + i * 2);
		}

		/* moving and counting indices in the correct range */

		count = 0;

		for (i = 0; i < MCELIECE_SYS_T * 2; ++i)
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

		eq = 0;

		for (i = 1; i < MCELIECE_SYS_T; ++i)
		{
			for (j = 0; j < i; ++j)
			{
				if (ind[i] == ind[j])
				{
					eq = 1;
					break;
				}
			}
		}

		if (eq == 0)
		{
			break;
		}
	}

	for (j = 0; j < MCELIECE_SYS_T; ++j)
	{
		val[j] = (uint8_t)(1 << (ind[j] & 7));
	}

	for (i = 0; i < MCELIECE_SYS_N / 8; ++i)
	{
		e[i] = 0;

		for (j = 0; j < MCELIECE_SYS_T; ++j)
		{
			mask = same_mask((uint16_t)i, (ind[j] >> 3));
			e[i] |= val[j] & mask;
		}
	}
}

static void syndrome(uint8_t* s, const uint8_t* pk, const uint8_t* e)
{
	/* input: public key pk, error vector e
	   output: syndrome s */

	uint8_t row[MCELIECE_SYS_N / 8];
	const uint8_t *pk_ptr = pk;
	size_t j;
	uint8_t b;
#if defined(QSC_MCELIECE_S5N6960T119)
	int32_t tail;
	tail = MCELIECE_PK_NROWS % 8;
#endif

	qsc_memutils_clear(s, MCELIECE_SYND_BYTES);

	for (size_t i = 0; i < MCELIECE_PK_NROWS; ++i)
	{
		qsc_memutils_clear(row, MCELIECE_SYS_N / 8);

		for (j = 0; j < MCELIECE_PK_ROW_BYTES; ++j)
		{
			row[MCELIECE_SYS_N / 8 - MCELIECE_PK_ROW_BYTES + j] = pk_ptr[j];
		}

#if defined(QSC_MCELIECE_S5N6960T119)
		for (j = MCELIECE_SYS_N / 8 - 1; j >= MCELIECE_SYS_N / 8 - MCELIECE_PK_ROW_BYTES; --j)
		{
			row[j] = (uint8_t)((row[j] << tail) | (row[j - 1] >> (8 - tail)));
		}

		row[i / 8] |= 1 << (i % 8);
#else
		row[i / 8] |= 1 << (i % 8);
#endif

		b = 0;

		for (j = 0; j < MCELIECE_SYS_N / 8; ++j)
		{
			b ^= row[j] & e[j];
		}

		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		b &= 1;
		s[i / 8] |= (b << (i % 8));

		pk_ptr += MCELIECE_PK_ROW_BYTES;
	}
}

static void encrypt(uint8_t *s, const uint8_t *pk, uint8_t *e, bool (*rng_generate)(uint8_t*, size_t))
{
	gen_e(e, rng_generate);
	syndrome(s, pk, e);
}

/* operations.c */

#if defined(QSC_MCELIECE_S5N6960T119)
static int32_t check_c_padding(const uint8_t* c)
{
	/* Note artifact, no longer used */
	/* check if the padding bits of c are all zero */
	uint8_t b;
	int ret;

	b = c[MCELIECE_SYND_BYTES - 1] >> (MCELIECE_PK_NROWS % 8);
	b -= 1;
	b >>= 7;
	ret = b;

	return ret - 1;
}

static int32_t check_pk_padding(const uint8_t* pk)
{
	/* Note artifact, no longer used */
	uint8_t b;
	int32_t ret;

	b = 0;

	for (size_t i = 0; i < MCELIECE_PK_NROWS; i++)
	{
		b |= pk[i * MCELIECE_PK_ROW_BYTES + MCELIECE_PK_ROW_BYTES - 1];
	}

	b >>= (MCELIECE_PK_NCOLS % 8);
	b -= 1;
	b >>= 7;
	ret = b;

	return (ret - 1);
}
#endif

/* pk_gen.c */

static int32_t pk_gen(uint8_t* pk, const uint8_t* sk, const uint32_t* perm, int16_t* pi)
{
	/* input: secret key sk output: public key pk */

	uint64_t buf[1 << MCELIECE_GFBITS] = { 0 };
	gf g[MCELIECE_SYS_T + 1] = { 0 };	/* Goppa polynomial */
	gf L[MCELIECE_SYS_N] = { 0 };		/* support */
	gf inv[MCELIECE_SYS_N];
	uint8_t** mat;
	size_t i;
	size_t j;
	size_t k;
	size_t col;
	size_t row;
	int32_t res;
	uint8_t b;
	uint8_t mask;
	bool balc;

#if defined(QSC_MCELIECE_S5N6960T119)
	uint8_t *pk_ptr = pk;
	int32_t tail;
#endif

	res = -1;

	mat = (uint8_t**)qsc_memutils_malloc(MCELIECE_PK_NROWS * sizeof(uint8_t*));
	assert(mat != NULL);

	if (mat != NULL)
	{
		balc = true;

		for (i = 0; i < MCELIECE_PK_NROWS; ++i)
		{
			mat[i] = (uint8_t*)qsc_memutils_malloc(MCELIECE_SYS_N / 8);

			if (mat[i] == NULL)
			{
				balc = false;
				break;
			}
		}

		if (balc == true)
		{
			g[MCELIECE_SYS_T] = 1;

			for (i = 0; i < MCELIECE_SYS_T; ++i)
			{
				g[i] = load_gf(sk); sk += 2;
			}

			for (i = 0; i < (1 << MCELIECE_GFBITS); i++)
			{
				buf[i] = perm[i];
				buf[i] <<= 31;
				buf[i] |= i;
			}

			uint64_sort(buf, 1 << MCELIECE_GFBITS);

			for (i = 1; i < (1 << MCELIECE_GFBITS); ++i)
			{
				if ((buf[i - 1] >> 31) == (buf[i] >> 31))
				{
					res = -2;
					break;
				}
			}
			
			if (res != -2)
			{
				for (i = 0; i < (1 << MCELIECE_GFBITS); ++i)
				{
					pi[i] = buf[i] & MCELIECE_GFMASK;
				}

				for (i = 0; i < MCELIECE_SYS_N; ++i)
				{
					L[i] = bitrev(pi[i]);
				}

				/* filling the matrix */

				root(inv, g, L);

				for (i = 0; i < MCELIECE_SYS_N; ++i)
				{
					inv[i] = gf_inv(inv[i]);
				}

				for (i = 0; i < MCELIECE_PK_NROWS; ++i)
				{
					for (j = 0; j < MCELIECE_SYS_N / 8; ++j)
					{
						mat[i][j] = 0;
					}
				}

				for (i = 0; i < MCELIECE_SYS_T; ++i)
				{
					for (j = 0; j < MCELIECE_SYS_N; j += 8)
					{
						for (k = 0; k < MCELIECE_GFBITS; ++k)
						{
							b = (inv[j + 7] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 6] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 5] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 4] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 3] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 2] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 1] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 0] >> k) & 1;

							mat[i * MCELIECE_GFBITS + k][j / 8] = b;
						}
					}

					for (j = 0; j < MCELIECE_SYS_N; ++j)
					{
						inv[j] = gf_mul(inv[j], L[j]);
					}
				}

				/* gaussian elimination */

				for (i = 0; i < (MCELIECE_PK_NROWS + 7) / 8; ++i)
				{
					for (j = 0; j < 8; ++j)
					{
						row = i * 8 + j;

						if (row >= MCELIECE_PK_NROWS)
						{
							break;
						}

						for (k = row + 1; k < MCELIECE_PK_NROWS; ++k)
						{
							mask = mat[row][i] ^ mat[k][i];
							mask >>= j;
							mask &= 1;
							mask = -mask;

							for (col = 0; col < MCELIECE_SYS_N / 8; ++col)
							{
								mat[row][col] ^= mat[k][col] & mask;
							}
						}

						if (((mat[row][i] >> j) & 1) == 0) /* return if not systematic */
						{
							for (i = 0; i < MCELIECE_PK_NROWS; ++i)
							{
								qsc_memutils_alloc_free(mat[i]);
							}

							qsc_memutils_alloc_free(mat);

							return -1;
						}

						for (k = 0; k < MCELIECE_PK_NROWS; ++k)
						{
							if (k != row)
							{
								mask = mat[k][i] >> j;
								mask &= 1;
								mask = -mask;

								for (col = 0; col < MCELIECE_SYS_N / 8; ++col)
								{
									mat[k][col] ^= mat[row][col] & mask;
								}
							}
						}
					}
				}

#if defined(QSC_MCELIECE_S5N6960T119)
				tail = MCELIECE_PK_NROWS % 8;

				for (i = 0; i < MCELIECE_PK_NROWS; ++i)
				{
					for (j = (MCELIECE_PK_NROWS - 1) / 8; j < MCELIECE_SYS_N / 8 - 1; ++j)
					{
						*pk_ptr = (uint8_t)((mat[i][j] >> tail) | (mat[i][j + 1] << (8 - tail)));
						++pk_ptr;
					}

					*pk_ptr = (mat[i][j] >> tail);
					++pk_ptr;
				}
#else
				for (i = 0; i < MCELIECE_PK_NROWS; ++i)
				{
					qsc_memutils_copy(pk + i * MCELIECE_PK_ROW_BYTES, mat[i] + MCELIECE_PK_NROWS / 8, MCELIECE_PK_ROW_BYTES);
				}
#endif
			}

			res = 0;
		}

		for (i = 0; i < MCELIECE_PK_NROWS; ++i)
		{
			qsc_memutils_alloc_free(mat[i]);
		}

		qsc_memutils_alloc_free(mat);
	}

	return res;
}

/* sk_gen.c */

static int32_t genpoly_gen(gf* out, const gf* f)
{
	/* input: f, element in GF((2^m)^t)
	   output: out, minimal polynomial of f
	   return: 0 for success and -1 for failure */

	gf mat[MCELIECE_SYS_T + 1][MCELIECE_SYS_T] = { 0 };
	gf inv;
	gf mask;
	gf t;
	int32_t res;
	size_t c;
	size_t i;
	size_t j;
	size_t k;

	/* fill matrix */

	res = 0;
	mat[0][0] = 1;

	for (i = 0; i < MCELIECE_SYS_T; ++i)
	{
		mat[1][i] = f[i];
	}

	for (j = 2; j <= MCELIECE_SYS_T; ++j)
	{
		GF_mul(mat[j], mat[j - 1], f);
	}

	/* gaussian */

	for (j = 0; j < MCELIECE_SYS_T; ++j)
	{
		for (k = j + 1; k < MCELIECE_SYS_T; ++k)
		{
			mask = gf_is_zero(mat[j][j]);

			for (c = j; c < MCELIECE_SYS_T + 1; ++c)
			{
				mat[c][j] ^= mat[c][k] & mask;
			}
		}

		if (mat[j][j] != 0)
		{
			inv = gf_inv(mat[j][j]);

			for (c = j; c < MCELIECE_SYS_T + 1; ++c)
			{
				mat[c][j] = gf_mul(mat[c][j], inv);
			}

			for (k = 0; k < MCELIECE_SYS_T; ++k)
			{
				if (k != j)
				{
					t = mat[j][k];

					for (c = j; c < MCELIECE_SYS_T + 1; ++c)
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

		for (i = 0; i < MCELIECE_SYS_T; ++i)
		{
			out[i] = mat[MCELIECE_SYS_T][i];
		}
	}

	return res;
}

int32_t qsc_mceliece_ref_encapsulate(uint8_t* c, uint8_t* key, const uint8_t* pk, bool (*rng_generate)(uint8_t*, size_t))
{
	uint8_t one_ec[1 + MCELIECE_SYS_N / 8 + (MCELIECE_SYND_BYTES + 32)] = { 0 };
	uint8_t two_e[1 + MCELIECE_SYS_N / 8] = { 0 };
	uint8_t *e = two_e + 1;
#if defined(QSC_MCELIECE_S5N6960T119)
	uint8_t mask;
	int32_t i;
	int32_t padding_ok;

	padding_ok = check_pk_padding(pk);
#endif

	one_ec[0] = 1;
	two_e[0] = 2;
	encrypt(c, pk, e, rng_generate);

	qsc_shake256_compute(c + MCELIECE_SYND_BYTES, MCELIECE_SHAREDSECRET_SIZE, two_e, sizeof(two_e));
	qsc_memutils_copy(one_ec + 1, e, MCELIECE_SYS_N / 8);
	qsc_memutils_copy(one_ec + 1 + MCELIECE_SYS_N / 8, c, MCELIECE_SYND_BYTES + 32);
	qsc_shake256_compute(key, MCELIECE_SHAREDSECRET_SIZE, one_ec, sizeof(one_ec));

#if defined(QSC_MCELIECE_S5N6960T119)
	/* clear outputs(set to all 0's) if padding bits are not all zero */

	mask = padding_ok;
	mask ^= 0xFF;

	for (i = 0; i < MCELIECE_SYND_BYTES + 32; ++i)
	{
		c[i] &= mask;
	}

	for (i = 0; i < 32; ++i)
	{
		key[i] &= mask;
	}

	return padding_ok;
#else
	return 0;
#endif
}

int32_t qsc_mceliece_ref_decapsulate(uint8_t* key, const uint8_t* c, const uint8_t* sk)
{
	uint8_t conf[32];
	uint8_t preimage[1 + MCELIECE_SYS_N / 8 + (MCELIECE_SYND_BYTES + 32)] = { 0 };
	uint8_t two_e[1 + MCELIECE_SYS_N / 8] = { 0 };
	const uint8_t *s = sk + 40 + MCELIECE_IRR_BYTES + MCELIECE_COND_BYTES;
	size_t i;
	uint16_t m;
	uint8_t ret_confirm;
	uint8_t ret_decrypt;
	uint8_t *e = two_e + 1;
	uint8_t *x = preimage;
#if defined(QSC_MCELIECE_S5N6960T119)
	int padding_ok;
	uint8_t mask;

	padding_ok = check_c_padding(c);
#endif

	two_e[0] = 2;
	ret_confirm = 0;
	ret_decrypt = (uint8_t)decrypt(e, (sk + 40), c);
	qsc_shake256_compute(conf, MCELIECE_SHAREDSECRET_SIZE, two_e, sizeof(two_e));

	for (i = 0; i < 32; ++i)
	{
		ret_confirm |= conf[i] ^ c[MCELIECE_SYND_BYTES + i];
	}

	m = ret_decrypt | ret_confirm;
	m -= 1;
	m >>= 8;

	*x = m & 1;
	++x;

	for (i = 0; i < MCELIECE_SYS_N / 8; ++i)
	{
		*x = (~m & s[i]) | (m & e[i]);
		++x;
	}

	for (i = 0; i < MCELIECE_SYND_BYTES + 32; ++i)
	{
		*x = c[i];
		++x;
	}

	qsc_shake256_compute(key, MCELIECE_SHAREDSECRET_SIZE, preimage, sizeof(preimage));

#if defined(QSC_MCELIECE_S5N6960T119)
	// clear outputs (set to all 1's) if padding bits are not all zero

	mask = (uint8_t)padding_ok;

	for (i = 0; i < 32; ++i)
	{
		key[i] |= mask;
	}

	return (ret_decrypt + ret_confirm + padding_ok);
#else
	return (ret_decrypt + ret_confirm);
#endif
}

int32_t qsc_mceliece_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
	uint32_t perm[1 << MCELIECE_GFBITS] = { 0 };	/* random permutation as 32-bit integers */
	int16_t pi[1 << MCELIECE_GFBITS];	/* random permutation */
	gf f[MCELIECE_SYS_T] = { 0 };		/* element in GF(2 ^ mt) */
	gf irr[MCELIECE_SYS_T];				/* Goppa polynomial */
	uint8_t r[(MCELIECE_SYS_N / 8) + ((1 << MCELIECE_GFBITS) * sizeof(uint32_t)) + (MCELIECE_SYS_T * 2) + 32] = { 0 };
	uint8_t seed[33] = { 0 };
	const uint8_t* rp;
	uint8_t *skp;
	int32_t i;

	seed[0] = 64;
	rng_generate((seed + 1), 32);

	while (true)
	{
		rp = &r[sizeof(r) - 32];
		skp = sk;

		/* expanding and updating the seed */
		qsc_shake256_compute(r, sizeof(r), seed, 33);
		qsc_memutils_copy(skp, seed + 1, 32);
		skp += 32 + 8;
		qsc_memutils_copy(seed + 1, &r[sizeof(r) - 32], 32);

		/* generating irreducible polynomial */

		rp -= sizeof(f);

		for (i = 0; i < MCELIECE_SYS_T; ++i)
		{
			f[i] = load_gf(rp + i * 2);
		}

		if (genpoly_gen(irr, f) != 0)
		{
			continue;
		}

		for (i = 0; i < MCELIECE_SYS_T; ++i)
		{
			store_gf(skp + i * 2, irr[i]);
		}

		skp += MCELIECE_IRR_BYTES;

		/* generating permutation */

		rp -= sizeof(perm);

		for (i = 0; i < (1 << MCELIECE_GFBITS); ++i)
		{
			perm[i] = load4(rp + i * 4);
		}

		if (pk_gen(pk, skp - MCELIECE_IRR_BYTES, perm, pi) != 0)
		{
			continue;
		}

		controlbits_from_permutation(skp, pi, MCELIECE_GFBITS, 1 << MCELIECE_GFBITS);
		skp += MCELIECE_COND_BYTES;

		/* storing the random string s */
		rp -= MCELIECE_SYS_N / 8;
		qsc_memutils_copy(skp, rp, MCELIECE_SYS_N / 8);

		/* storing positions of the 32 pivots */
		store8(sk + 32, 0x00000000FFFFFFFFULL);

		break;
	}

	return 0;
}

