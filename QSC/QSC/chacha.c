#include "chacha.h"
#include "intutils.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_HAS_AVX)
#	include "intrinsics.h"
#endif

#define CHACHA_STATE_SIZE 16

#if defined(QSC_SYSTEM_HAS_AVX)
#	define CHACHA_AVXBLOCK_SIZE (4 * QSC_CHACHA_BLOCK_SIZE)
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
#	define CHACHA_AVX2BLOCK_SIZE (8 * QSC_CHACHA_BLOCK_SIZE)
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
#	define CHACHA_AVX512BLOCK_SIZE (16 * QSC_CHACHA_BLOCK_SIZE)
#endif

static void chacha_increment(qsc_chacha_state* ctx)
{
	++ctx->state[12];

	if (ctx->state[12] == 0)
	{
		++ctx->state[13];
	}
}

static void chacha_permute_p512c(qsc_chacha_state* ctx, uint8_t* output)
{
	uint32_t x0;
	uint32_t x1;
	uint32_t x2;
	uint32_t x3;
	uint32_t x4;
	uint32_t x5;
	uint32_t x6;
	uint32_t x7;
	uint32_t x8;
	uint32_t x9;
	uint32_t x10;
	uint32_t x11;
	uint32_t x12;
	uint32_t x13;
	uint32_t x14;
	uint32_t x15;
	size_t ctr;

	x0 = ctx->state[0];
	x1 = ctx->state[1];
	x2 = ctx->state[2];
	x3 = ctx->state[3];
	x4 = ctx->state[4];
	x5 = ctx->state[5];
	x6 = ctx->state[6];
	x7 = ctx->state[7];
	x8 = ctx->state[8];
	x9 = ctx->state[9];
	x10 = ctx->state[10];
	x11 = ctx->state[11];
	x12 = ctx->state[12];
	x13 = ctx->state[13];
	x14 = ctx->state[14];
	x15 = ctx->state[15];
	ctr = QSC_CHACHA_ROUND_COUNT;

	while (ctr != 0)
	{
		x0 += x4;
		x12 = qsc_intutils_rotl32(x12 ^ x0, 16);
		x8 += x12;
		x4 = qsc_intutils_rotl32(x4 ^ x8, 12);
		x0 += x4;
		x12 = qsc_intutils_rotl32(x12 ^ x0, 8);
		x8 += x12;
		x4 = qsc_intutils_rotl32(x4 ^ x8, 7);
		x1 += x5;
		x13 = qsc_intutils_rotl32(x13 ^ x1, 16);
		x9 += x13;
		x5 = qsc_intutils_rotl32(x5 ^ x9, 12);
		x1 += x5;
		x13 = qsc_intutils_rotl32(x13 ^ x1, 8);
		x9 += x13;
		x5 = qsc_intutils_rotl32(x5 ^ x9, 7);
		x2 += x6;
		x14 = qsc_intutils_rotl32(x14 ^ x2, 16);
		x10 += x14;
		x6 = qsc_intutils_rotl32(x6 ^ x10, 12);
		x2 += x6;
		x14 = qsc_intutils_rotl32(x14 ^ x2, 8);
		x10 += x14;
		x6 = qsc_intutils_rotl32(x6 ^ x10, 7);
		x3 += x7;
		x15 = qsc_intutils_rotl32(x15 ^ x3, 16);
		x11 += x15;
		x7 = qsc_intutils_rotl32(x7 ^ x11, 12);
		x3 += x7;
		x15 = qsc_intutils_rotl32(x15 ^ x3, 8);
		x11 += x15;
		x7 = qsc_intutils_rotl32(x7 ^ x11, 7);
		x0 += x5;
		x15 = qsc_intutils_rotl32(x15 ^ x0, 16);
		x10 += x15;
		x5 = qsc_intutils_rotl32(x5 ^ x10, 12);
		x0 += x5;
		x15 = qsc_intutils_rotl32(x15 ^ x0, 8);
		x10 += x15;
		x5 = qsc_intutils_rotl32(x5 ^ x10, 7);
		x1 += x6;
		x12 = qsc_intutils_rotl32(x12 ^ x1, 16);
		x11 += x12;
		x6 = qsc_intutils_rotl32(x6 ^ x11, 12);
		x1 += x6;
		x12 = qsc_intutils_rotl32(x12 ^ x1, 8);
		x11 += x12;
		x6 = qsc_intutils_rotl32(x6 ^ x11, 7);
		x2 += x7;
		x13 = qsc_intutils_rotl32(x13 ^ x2, 16);
		x8 += x13;
		x7 = qsc_intutils_rotl32(x7 ^ x8, 12);
		x2 += x7;
		x13 = qsc_intutils_rotl32(x13 ^ x2, 8);
		x8 += x13;
		x7 = qsc_intutils_rotl32(x7 ^ x8, 7);
		x3 += x4;
		x14 = qsc_intutils_rotl32(x14 ^ x3, 16);
		x9 += x14;
		x4 = qsc_intutils_rotl32(x4 ^ x9, 12);
		x3 += x4;
		x14 = qsc_intutils_rotl32(x14 ^ x3, 8);
		x9 += x14;
		x4 = qsc_intutils_rotl32(x4 ^ x9, 7);
		ctr -= 2;
	}

	qsc_intutils_le32to8(output, x0 + ctx->state[0]);
	qsc_intutils_le32to8(output + 4, x1 + ctx->state[1]);
	qsc_intutils_le32to8(output + 8, x2 + ctx->state[2]);
	qsc_intutils_le32to8(output + 12, x3 + ctx->state[3]);
	qsc_intutils_le32to8(output + 16, x4 + ctx->state[4]);
	qsc_intutils_le32to8(output + 20, x5 + ctx->state[5]);
	qsc_intutils_le32to8(output + 24, x6 + ctx->state[6]);
	qsc_intutils_le32to8(output + 28, x7 + ctx->state[7]);
	qsc_intutils_le32to8(output + 32, x8 + ctx->state[8]);
	qsc_intutils_le32to8(output + 36, x9 + ctx->state[9]);
	qsc_intutils_le32to8(output + 40, x10 + ctx->state[10]);
	qsc_intutils_le32to8(output + 44, x11 + ctx->state[11]);
	qsc_intutils_le32to8(output + 48, x12 + ctx->state[12]);
	qsc_intutils_le32to8(output + 52, x13 + ctx->state[13]);
	qsc_intutils_le32to8(output + 56, x14 + ctx->state[14]);
	qsc_intutils_le32to8(output + 60, x15 + ctx->state[15]);
}

#if defined(QSC_SYSTEM_HAS_AVX512)

typedef struct
{
	__m512i state[16];
	__m512i outw[16];
} chacha_avx512_state;

static void pack_columns_x512(__m512i* v1, __m512i* v2)
{
	const __m512i M1 = _mm512_set_epi32(30, 28, 26, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 0);
	const __m512i M2 = _mm512_set_epi32(31, 29, 27, 25, 23, 21, 19, 17, 15, 13, 11, 9, 7, 5, 3, 1);
	__m512i t1;
	__m512i t2;

	t1 = _mm512_mask_permutex2var_epi32(*v1, 0xFFFFU, M1, *v2);
	t2 = _mm512_mask_permutex2var_epi32(*v1, 0xFFFFU, M2, *v2);
	*v1 = t1;
	*v2 = t2;
}

static void unpack_columns_x512(__m512i* v1, __m512i* v2)
{
	const __m512i M1 = _mm512_set_epi32(23, 7, 22, 6, 21, 5, 20, 4, 19, 3, 18, 2, 17, 1, 16, 0);
	const __m512i M2 = _mm512_set_epi32(31, 15, 30, 14, 29, 13, 28, 12, 27, 11, 26, 10, 25, 9, 24, 8);
	__m512i t1;
	__m512i t2;

	t1 = _mm512_mask_permutex2var_epi32(*v1, 0xFFFFU, M1, *v2);
	t2 = _mm512_mask_permutex2var_epi32(*v1, 0xFFFFU, M2, *v2);
	*v1 = t1;
	*v2 = t2;
}

static void leincrement_x512(__m512i* v1, __m512i* v2)
{
	const __m512i NAD = _mm512_set_epi64(16, 16, 16, 16, 16, 16, 16, 16);

	unpack_columns_x512(v1, v2);
	*v1 = _mm512_add_epi64(*v1, NAD);
	*v2 = _mm512_add_epi64(*v2, NAD);
	pack_columns_x512(v1, v2);
}

inline static __m512i chacha_rotl512(const __m512i x, uint32_t shift)
{
	return _mm512_or_si512(_mm512_slli_epi32(x, shift), _mm512_srli_epi32(x, 32 - shift));
}

static __m512i chacha_load512(const uint8_t* v)
{
	const uint32_t* v32 = (uint32_t*)v;

	return _mm512_set_epi32(v32[0], v32[16], v32[32], v32[48], v32[64], v32[80], v32[96], v32[112], 
		v32[128], v32[144], v32[160], v32[176], v32[192], v32[208], v32[224], v32[240]);
}

static void chacha_store512(uint8_t* output, const __m512i x)
{
	uint32_t tmp[16];

	_mm512_storeu_si512((__m512i*)tmp, x);

	qsc_intutils_le32to8(output, tmp[15]);
	qsc_intutils_le32to8(((uint8_t*)output + 64), tmp[14]);
	qsc_intutils_le32to8(((uint8_t*)output + 128), tmp[13]);
	qsc_intutils_le32to8(((uint8_t*)output + 192), tmp[12]);
	qsc_intutils_le32to8(((uint8_t*)output + 256), tmp[11]);
	qsc_intutils_le32to8(((uint8_t*)output + 320), tmp[10]);
	qsc_intutils_le32to8(((uint8_t*)output + 384), tmp[9]);
	qsc_intutils_le32to8(((uint8_t*)output + 448), tmp[8]);
	qsc_intutils_le32to8(((uint8_t*)output + 512), tmp[7]);
	qsc_intutils_le32to8(((uint8_t*)output + 576), tmp[6]);
	qsc_intutils_le32to8(((uint8_t*)output + 640), tmp[5]);
	qsc_intutils_le32to8(((uint8_t*)output + 704), tmp[4]);
	qsc_intutils_le32to8(((uint8_t*)output + 768), tmp[3]);
	qsc_intutils_le32to8(((uint8_t*)output + 832), tmp[2]);
	qsc_intutils_le32to8(((uint8_t*)output + 896), tmp[1]);
	qsc_intutils_le32to8(((uint8_t*)output + 960), tmp[0]);
}

static void chacha_permute_p16x512h(chacha_avx512_state* ctxw)
{
	__m512i x0;
	__m512i x1;
	__m512i x2;
	__m512i x3;
	__m512i x4;
	__m512i x5;
	__m512i x6;
	__m512i x7;
	__m512i x8;
	__m512i x9;
	__m512i x10;
	__m512i x11;
	__m512i x12;
	__m512i x13;
	__m512i x14;
	__m512i x15;
	size_t ctr;

	x0 = ctxw->state[0];
	x1 = ctxw->state[1];
	x2 = ctxw->state[2];
	x3 = ctxw->state[3];
	x4 = ctxw->state[4];
	x5 = ctxw->state[5];
	x6 = ctxw->state[6];
	x7 = ctxw->state[7];
	x8 = ctxw->state[8];
	x9 = ctxw->state[9];
	x10 = ctxw->state[10];
	x11 = ctxw->state[11];
	x12 = ctxw->state[12];
	x13 = ctxw->state[13];
	x14 = ctxw->state[14];
	x15 = ctxw->state[15];
	ctr = QSC_CHACHA_ROUND_COUNT;

	while (ctr != 0)
	{
		x0 = _mm512_add_epi32(x0, x4);
		x12 = chacha_rotl512(_mm512_xor_si512(x12, x0), 16);
		x8 = _mm512_add_epi32(x8, x12);
		x4 = chacha_rotl512(_mm512_xor_si512(x4, x8), 12);
		x0 = _mm512_add_epi32(x0, x4);
		x12 = chacha_rotl512(_mm512_xor_si512(x12, x0), 8);
		x8 = _mm512_add_epi32(x8, x12);
		x4 = chacha_rotl512(_mm512_xor_si512(x4, x8), 7);
		x1 = _mm512_add_epi32(x1, x5);
		x13 = chacha_rotl512(_mm512_xor_si512(x13, x1), 16);
		x9 = _mm512_add_epi32(x9, x13);
		x5 = chacha_rotl512(_mm512_xor_si512(x5, x9), 12);
		x1 = _mm512_add_epi32(x1, x5);
		x13 = chacha_rotl512(_mm512_xor_si512(x13, x1), 8);
		x9 = _mm512_add_epi32(x9, x13);
		x5 = chacha_rotl512(_mm512_xor_si512(x5, x9), 7);
		x2 = _mm512_add_epi32(x2, x6);
		x14 = chacha_rotl512(_mm512_xor_si512(x14, x2), 16);
		x10 = _mm512_add_epi32(x10, x14);
		x6 = chacha_rotl512(_mm512_xor_si512(x6, x10), 12);
		x2 = _mm512_add_epi32(x2, x6);
		x14 = chacha_rotl512(_mm512_xor_si512(x14, x2), 8);
		x10 = _mm512_add_epi32(x10, x14);
		x6 = chacha_rotl512(_mm512_xor_si512(x6, x10), 7);
		x3 = _mm512_add_epi32(x3, x7);
		x15 = chacha_rotl512(_mm512_xor_si512(x15, x3), 16);
		x11 = _mm512_add_epi32(x11, x15);
		x7 = chacha_rotl512(_mm512_xor_si512(x7, x11), 12);
		x3 = _mm512_add_epi32(x3, x7);
		x15 = chacha_rotl512(_mm512_xor_si512(x15, x3), 8);
		x11 = _mm512_add_epi32(x11, x15);
		x7 = chacha_rotl512(_mm512_xor_si512(x7, x11), 7);
		x0 = _mm512_add_epi32(x0, x5);
		x15 = chacha_rotl512(_mm512_xor_si512(x15, x0), 16);
		x10 = _mm512_add_epi32(x10, x15);
		x5 = chacha_rotl512(_mm512_xor_si512(x5, x10), 12);
		x0 = _mm512_add_epi32(x0, x5);
		x15 = chacha_rotl512(_mm512_xor_si512(x15, x0), 8);
		x10 = _mm512_add_epi32(x10, x15);
		x5 = chacha_rotl512(_mm512_xor_si512(x5, x10), 7);
		x1 = _mm512_add_epi32(x1, x6);
		x12 = chacha_rotl512(_mm512_xor_si512(x12, x1), 16);
		x11 = _mm512_add_epi32(x11, x12);
		x6 = chacha_rotl512(_mm512_xor_si512(x6, x11), 12);
		x1 = _mm512_add_epi32(x1, x6);
		x12 = chacha_rotl512(_mm512_xor_si512(x12, x1), 8);
		x11 = _mm512_add_epi32(x11, x12);
		x6 = chacha_rotl512(_mm512_xor_si512(x6, x11), 7);
		x2 = _mm512_add_epi32(x2, x7);
		x13 = chacha_rotl512(_mm512_xor_si512(x13, x2), 16);
		x8 = _mm512_add_epi32(x8, x13);
		x7 = chacha_rotl512(_mm512_xor_si512(x7, x8), 12);
		x2 = _mm512_add_epi32(x2, x7);
		x13 = chacha_rotl512(_mm512_xor_si512(x13, x2), 8);
		x8 = _mm512_add_epi32(x8, x13);
		x7 = chacha_rotl512(_mm512_xor_si512(x7, x8), 7);
		x3 = _mm512_add_epi32(x3, x4);
		x14 = chacha_rotl512(_mm512_xor_si512(x14, x3), 16);
		x9 = _mm512_add_epi32(x9, x14);
		x4 = chacha_rotl512(_mm512_xor_si512(x4, x9), 12);
		x3 = _mm512_add_epi32(x3, x4);
		x14 = chacha_rotl512(_mm512_xor_si512(x14, x3), 8);
		x9 = _mm512_add_epi32(x9, x14);
		x4 = chacha_rotl512(_mm512_xor_si512(x4, x9), 7);
		ctr -= 2;
	}

	ctxw->outw[0] = _mm512_add_epi32(x0, ctxw->state[0]);
	ctxw->outw[1] = _mm512_add_epi32(x1, ctxw->state[1]);
	ctxw->outw[2] = _mm512_add_epi32(x2, ctxw->state[2]);
	ctxw->outw[3] = _mm512_add_epi32(x3, ctxw->state[3]);
	ctxw->outw[4] = _mm512_add_epi32(x4, ctxw->state[4]);
	ctxw->outw[5] = _mm512_add_epi32(x5, ctxw->state[5]);
	ctxw->outw[6] = _mm512_add_epi32(x6, ctxw->state[6]);
	ctxw->outw[7] = _mm512_add_epi32(x7, ctxw->state[7]);
	ctxw->outw[8] = _mm512_add_epi32(x8, ctxw->state[8]);
	ctxw->outw[9] = _mm512_add_epi32(x9, ctxw->state[9]);
	ctxw->outw[10] = _mm512_add_epi32(x10, ctxw->state[10]);
	ctxw->outw[11] = _mm512_add_epi32(x11, ctxw->state[11]);
	ctxw->outw[12] = _mm512_add_epi32(x12, ctxw->state[12]);
	ctxw->outw[13] = _mm512_add_epi32(x13, ctxw->state[13]);
	ctxw->outw[14] = _mm512_add_epi32(x14, ctxw->state[14]);
	ctxw->outw[15] = _mm512_add_epi32(x15, ctxw->state[15]);
}

#elif defined(QSC_SYSTEM_HAS_AVX2)

typedef struct
{
	__m256i state[16];
	__m256i outw[16];
} chacha_avx2_state;

inline static __m256i chacha_rotl256(const __m256i x, uint32_t shift)
{
	return _mm256_or_si256(_mm256_slli_epi32(x, shift), _mm256_srli_epi32(x, 32 - shift));
}

static __m256i chacha_load256(const uint8_t* v)
{
	const uint32_t* v32 = (uint32_t*)v;

	return _mm256_set_epi32(v32[0], v32[16], v32[32], v32[48], v32[64], v32[80], v32[96], v32[112]);
}

static void chacha_store256(uint8_t* output, const __m256i x)
{
	uint32_t tmp[8];

	_mm256_storeu_si256((__m256i*)tmp, x);

	qsc_intutils_le32to8(output, tmp[7]);
	qsc_intutils_le32to8(((uint8_t*)output + 64), tmp[6]);
	qsc_intutils_le32to8(((uint8_t*)output + 128), tmp[5]);
	qsc_intutils_le32to8(((uint8_t*)output + 192), tmp[4]);
	qsc_intutils_le32to8(((uint8_t*)output + 256), tmp[3]);
	qsc_intutils_le32to8(((uint8_t*)output + 320), tmp[2]);
	qsc_intutils_le32to8(((uint8_t*)output + 384), tmp[1]);
	qsc_intutils_le32to8(((uint8_t*)output + 448), tmp[0]);
}

static void chacha_permute_p8x512h(chacha_avx2_state* ctxw)
{
	__m256i x0;
	__m256i x1;
	__m256i x2;
	__m256i x3;
	__m256i x4;
	__m256i x5;
	__m256i x6;
	__m256i x7;
	__m256i x8;
	__m256i x9;
	__m256i x10;
	__m256i x11;
	__m256i x12;
	__m256i x13;
	__m256i x14;
	__m256i x15;
	size_t ctr;

	x0 = ctxw->state[0];
	x1 = ctxw->state[1];
	x2 = ctxw->state[2];
	x3 = ctxw->state[3];
	x4 = ctxw->state[4];
	x5 = ctxw->state[5];
	x6 = ctxw->state[6];
	x7 = ctxw->state[7];
	x8 = ctxw->state[8];
	x9 = ctxw->state[9];
	x10 = ctxw->state[10];
	x11 = ctxw->state[11];
	x12 = ctxw->state[12];
	x13 = ctxw->state[13];
	x14 = ctxw->state[14];
	x15 = ctxw->state[15];
	ctr = QSC_CHACHA_ROUND_COUNT;

	while (ctr != 0)
	{
		x0 = _mm256_add_epi32(x0, x4);
		x12 = chacha_rotl256(_mm256_xor_si256(x12, x0), 16);
		x8 = _mm256_add_epi32(x8, x12);
		x4 = chacha_rotl256(_mm256_xor_si256(x4, x8), 12);
		x0 = _mm256_add_epi32(x0, x4);
		x12 = chacha_rotl256(_mm256_xor_si256(x12, x0), 8);
		x8 = _mm256_add_epi32(x8, x12);
		x4 = chacha_rotl256(_mm256_xor_si256(x4, x8), 7);
		x1 = _mm256_add_epi32(x1, x5);
		x13 = chacha_rotl256(_mm256_xor_si256(x13, x1), 16);
		x9 = _mm256_add_epi32(x9, x13);
		x5 = chacha_rotl256(_mm256_xor_si256(x5, x9), 12);
		x1 = _mm256_add_epi32(x1, x5);
		x13 = chacha_rotl256(_mm256_xor_si256(x13, x1), 8);
		x9 = _mm256_add_epi32(x9, x13);
		x5 = chacha_rotl256(_mm256_xor_si256(x5, x9), 7);
		x2 = _mm256_add_epi32(x2, x6);
		x14 = chacha_rotl256(_mm256_xor_si256(x14, x2), 16);
		x10 = _mm256_add_epi32(x10, x14);
		x6 = chacha_rotl256(_mm256_xor_si256(x6, x10), 12);
		x2 = _mm256_add_epi32(x2, x6);
		x14 = chacha_rotl256(_mm256_xor_si256(x14, x2), 8);
		x10 = _mm256_add_epi32(x10, x14);
		x6 = chacha_rotl256(_mm256_xor_si256(x6, x10), 7);
		x3 = _mm256_add_epi32(x3, x7);
		x15 = chacha_rotl256(_mm256_xor_si256(x15, x3), 16);
		x11 = _mm256_add_epi32(x11, x15);
		x7 = chacha_rotl256(_mm256_xor_si256(x7, x11), 12);
		x3 = _mm256_add_epi32(x3, x7);
		x15 = chacha_rotl256(_mm256_xor_si256(x15, x3), 8);
		x11 = _mm256_add_epi32(x11, x15);
		x7 = chacha_rotl256(_mm256_xor_si256(x7, x11), 7);
		x0 = _mm256_add_epi32(x0, x5);
		x15 = chacha_rotl256(_mm256_xor_si256(x15, x0), 16);
		x10 = _mm256_add_epi32(x10, x15);
		x5 = chacha_rotl256(_mm256_xor_si256(x5, x10), 12);
		x0 = _mm256_add_epi32(x0, x5);
		x15 = chacha_rotl256(_mm256_xor_si256(x15, x0), 8);
		x10 = _mm256_add_epi32(x10, x15);
		x5 = chacha_rotl256(_mm256_xor_si256(x5, x10), 7);
		x1 = _mm256_add_epi32(x1, x6);
		x12 = chacha_rotl256(_mm256_xor_si256(x12, x1), 16);
		x11 = _mm256_add_epi32(x11, x12);
		x6 = chacha_rotl256(_mm256_xor_si256(x6, x11), 12);
		x1 = _mm256_add_epi32(x1, x6);
		x12 = chacha_rotl256(_mm256_xor_si256(x12, x1), 8);
		x11 = _mm256_add_epi32(x11, x12);
		x6 = chacha_rotl256(_mm256_xor_si256(x6, x11), 7);
		x2 = _mm256_add_epi32(x2, x7);
		x13 = chacha_rotl256(_mm256_xor_si256(x13, x2), 16);
		x8 = _mm256_add_epi32(x8, x13);
		x7 = chacha_rotl256(_mm256_xor_si256(x7, x8), 12);
		x2 = _mm256_add_epi32(x2, x7);
		x13 = chacha_rotl256(_mm256_xor_si256(x13, x2), 8);
		x8 = _mm256_add_epi32(x8, x13);
		x7 = chacha_rotl256(_mm256_xor_si256(x7, x8), 7);
		x3 = _mm256_add_epi32(x3, x4);
		x14 = chacha_rotl256(_mm256_xor_si256(x14, x3), 16);
		x9 = _mm256_add_epi32(x9, x14);
		x4 = chacha_rotl256(_mm256_xor_si256(x4, x9), 12);
		x3 = _mm256_add_epi32(x3, x4);
		x14 = chacha_rotl256(_mm256_xor_si256(x14, x3), 8);
		x9 = _mm256_add_epi32(x9, x14);
		x4 = chacha_rotl256(_mm256_xor_si256(x4, x9), 7);
		ctr -= 2;
	}

	ctxw->outw[0] = _mm256_add_epi32(x0, ctxw->state[0]);
	ctxw->outw[1] = _mm256_add_epi32(x1, ctxw->state[1]);
	ctxw->outw[2] = _mm256_add_epi32(x2, ctxw->state[2]);
	ctxw->outw[3] = _mm256_add_epi32(x3, ctxw->state[3]);
	ctxw->outw[4] = _mm256_add_epi32(x4, ctxw->state[4]);
	ctxw->outw[5] = _mm256_add_epi32(x5, ctxw->state[5]);
	ctxw->outw[6] = _mm256_add_epi32(x6, ctxw->state[6]);
	ctxw->outw[7] = _mm256_add_epi32(x7, ctxw->state[7]);
	ctxw->outw[8] = _mm256_add_epi32(x8, ctxw->state[8]);
	ctxw->outw[9] = _mm256_add_epi32(x9, ctxw->state[9]);
	ctxw->outw[10] = _mm256_add_epi32(x10, ctxw->state[10]);
	ctxw->outw[11] = _mm256_add_epi32(x11, ctxw->state[11]);
	ctxw->outw[12] = _mm256_add_epi32(x12, ctxw->state[12]);
	ctxw->outw[13] = _mm256_add_epi32(x13, ctxw->state[13]);
	ctxw->outw[14] = _mm256_add_epi32(x14, ctxw->state[14]);
	ctxw->outw[15] = _mm256_add_epi32(x15, ctxw->state[15]);
}

#elif defined(QSC_SYSTEM_HAS_AVX)

typedef struct
{
	__m128i state[16];
	__m128i outw[16];
} chacha_avx_state;

inline static __m128i chacha_rotl128(const __m128i x, uint32_t shift)
{
	return _mm_or_si128(_mm_slli_epi32(x, shift), _mm_srli_epi32(x, 32 - shift));
}

static __m128i chacha_load128(const uint8_t* v)
{
	const uint32_t* v32 = (uint32_t*)v;

	return _mm_set_epi32(v32[0], v32[16], v32[32], v32[48]);
}

static void chacha_store128(uint8_t* output, const __m128i x)
{
	uint32_t tmp[4];

	_mm_storeu_si128((__m128i*)tmp, x);

	qsc_intutils_le32to8(output, tmp[3]);
	qsc_intutils_le32to8(((uint8_t*)output + 64), tmp[2]);
	qsc_intutils_le32to8(((uint8_t*)output + 128), tmp[1]);
	qsc_intutils_le32to8(((uint8_t*)output + 192), tmp[0]);
}

static void chacha_permute_p4x512h(chacha_avx_state* ctxw)
{
	__m128i x0;
	__m128i x1;
	__m128i x2;
	__m128i x3;
	__m128i x4;
	__m128i x5;
	__m128i x6;
	__m128i x7;
	__m128i x8;
	__m128i x9;
	__m128i x10;
	__m128i x11;
	__m128i x12;
	__m128i x13;
	__m128i x14;
	__m128i x15;
	size_t ctr;

	x0 = ctxw->state[0];
	x1 = ctxw->state[1];
	x2 = ctxw->state[2];
	x3 = ctxw->state[3];
	x4 = ctxw->state[4];
	x5 = ctxw->state[5];
	x6 = ctxw->state[6];
	x7 = ctxw->state[7];
	x8 = ctxw->state[8];
	x9 = ctxw->state[9];
	x10 = ctxw->state[10];
	x11 = ctxw->state[11];
	x12 = ctxw->state[12];
	x13 = ctxw->state[13];
	x14 = ctxw->state[14];
	x15 = ctxw->state[15];
	ctr = QSC_CHACHA_ROUND_COUNT;

	while (ctr != 0)
	{
		x0 = _mm_add_epi32(x0, x4);
		x12 = chacha_rotl128(_mm_xor_si128(x12, x0), 16);
		x8 = _mm_add_epi32(x8, x12);
		x4 = chacha_rotl128(_mm_xor_si128(x4, x8), 12);
		x0 = _mm_add_epi32(x0, x4);
		x12 = chacha_rotl128(_mm_xor_si128(x12, x0), 8);
		x8 = _mm_add_epi32(x8, x12);
		x4 = chacha_rotl128(_mm_xor_si128(x4, x8), 7);
		x1 = _mm_add_epi32(x1, x5);
		x13 = chacha_rotl128(_mm_xor_si128(x13, x1), 16);
		x9 = _mm_add_epi32(x9, x13);
		x5 = chacha_rotl128(_mm_xor_si128(x5, x9), 12);
		x1 = _mm_add_epi32(x1, x5);
		x13 = chacha_rotl128(_mm_xor_si128(x13, x1), 8);
		x9 = _mm_add_epi32(x9, x13);
		x5 = chacha_rotl128(_mm_xor_si128(x5, x9), 7);
		x2 = _mm_add_epi32(x2, x6);
		x14 = chacha_rotl128(_mm_xor_si128(x14, x2), 16);
		x10 = _mm_add_epi32(x10, x14);
		x6 = chacha_rotl128(_mm_xor_si128(x6, x10), 12);
		x2 = _mm_add_epi32(x2, x6);
		x14 = chacha_rotl128(_mm_xor_si128(x14, x2), 8);
		x10 = _mm_add_epi32(x10, x14);
		x6 = chacha_rotl128(_mm_xor_si128(x6, x10), 7);
		x3 = _mm_add_epi32(x3, x7);
		x15 = chacha_rotl128(_mm_xor_si128(x15, x3), 16);
		x11 = _mm_add_epi32(x11, x15);
		x7 = chacha_rotl128(_mm_xor_si128(x7, x11), 12);
		x3 = _mm_add_epi32(x3, x7);
		x15 = chacha_rotl128(_mm_xor_si128(x15, x3), 8);
		x11 = _mm_add_epi32(x11, x15);
		x7 = chacha_rotl128(_mm_xor_si128(x7, x11), 7);
		x0 = _mm_add_epi32(x0, x5);
		x15 = chacha_rotl128(_mm_xor_si128(x15, x0), 16);
		x10 = _mm_add_epi32(x10, x15);
		x5 = chacha_rotl128(_mm_xor_si128(x5, x10), 12);
		x0 = _mm_add_epi32(x0, x5);
		x15 = chacha_rotl128(_mm_xor_si128(x15, x0), 8);
		x10 = _mm_add_epi32(x10, x15);
		x5 = chacha_rotl128(_mm_xor_si128(x5, x10), 7);
		x1 = _mm_add_epi32(x1, x6);
		x12 = chacha_rotl128(_mm_xor_si128(x12, x1), 16);
		x11 = _mm_add_epi32(x11, x12);
		x6 = chacha_rotl128(_mm_xor_si128(x6, x11), 12);
		x1 = _mm_add_epi32(x1, x6);
		x12 = chacha_rotl128(_mm_xor_si128(x12, x1), 8);
		x11 = _mm_add_epi32(x11, x12);
		x6 = chacha_rotl128(_mm_xor_si128(x6, x11), 7);
		x2 = _mm_add_epi32(x2, x7);
		x13 = chacha_rotl128(_mm_xor_si128(x13, x2), 16);
		x8 = _mm_add_epi32(x8, x13);
		x7 = chacha_rotl128(_mm_xor_si128(x7, x8), 12);
		x2 = _mm_add_epi32(x2, x7);
		x13 = chacha_rotl128(_mm_xor_si128(x13, x2), 8);
		x8 = _mm_add_epi32(x8, x13);
		x7 = chacha_rotl128(_mm_xor_si128(x7, x8), 7);
		x3 = _mm_add_epi32(x3, x4);
		x14 = chacha_rotl128(_mm_xor_si128(x14, x3), 16);
		x9 = _mm_add_epi32(x9, x14);
		x4 = chacha_rotl128(_mm_xor_si128(x4, x9), 12);
		x3 = _mm_add_epi32(x3, x4);
		x14 = chacha_rotl128(_mm_xor_si128(x14, x3), 8);
		x9 = _mm_add_epi32(x9, x14);
		x4 = chacha_rotl128(_mm_xor_si128(x4, x9), 7);
		ctr -= 2;
	}

	ctxw->outw[0] = _mm_add_epi32(x0, ctxw->state[0]);
	ctxw->outw[1] = _mm_add_epi32(x1, ctxw->state[1]);
	ctxw->outw[2] = _mm_add_epi32(x2, ctxw->state[2]);
	ctxw->outw[3] = _mm_add_epi32(x3, ctxw->state[3]);
	ctxw->outw[4] = _mm_add_epi32(x4, ctxw->state[4]);
	ctxw->outw[5] = _mm_add_epi32(x5, ctxw->state[5]);
	ctxw->outw[6] = _mm_add_epi32(x6, ctxw->state[6]);
	ctxw->outw[7] = _mm_add_epi32(x7, ctxw->state[7]);
	ctxw->outw[8] = _mm_add_epi32(x8, ctxw->state[8]);
	ctxw->outw[9] = _mm_add_epi32(x9, ctxw->state[9]);
	ctxw->outw[10] = _mm_add_epi32(x10, ctxw->state[10]);
	ctxw->outw[11] = _mm_add_epi32(x11, ctxw->state[11]);
	ctxw->outw[12] = _mm_add_epi32(x12, ctxw->state[12]);
	ctxw->outw[13] = _mm_add_epi32(x13, ctxw->state[13]);
	ctxw->outw[14] = _mm_add_epi32(x14, ctxw->state[14]);
	ctxw->outw[15] = _mm_add_epi32(x15, ctxw->state[15]);
}

#endif

void qsc_chacha_dispose(qsc_chacha_state* ctx)
{
	qsc_memutils_clear((uint8_t*)ctx->state, sizeof(ctx->state));
}

void qsc_chacha_initialize(qsc_chacha_state* ctx, const qsc_chacha_keyparams* keyparams)
{
	assert(ctx != NULL);
	assert(keyparams->nonce != NULL);
	assert(keyparams->key != NULL);
	assert(keyparams->keylen == 16 || keyparams->keylen == 32);

	if (keyparams->keylen == 32)
	{
		ctx->state[0] = 0x61707865ULL;
		ctx->state[1] = 0x3320646EULL;
		ctx->state[2] = 0x79622D32ULL;
		ctx->state[3] = 0x6B206574ULL;
		ctx->state[4] = qsc_intutils_le8to32(keyparams->key);
		ctx->state[5] = qsc_intutils_le8to32(keyparams->key + 4);
		ctx->state[6] = qsc_intutils_le8to32(keyparams->key + 8);
		ctx->state[7] = qsc_intutils_le8to32(keyparams->key + 12);
		ctx->state[8] = qsc_intutils_le8to32(keyparams->key + 16);
		ctx->state[9] = qsc_intutils_le8to32(keyparams->key + 20);
		ctx->state[10] = qsc_intutils_le8to32(keyparams->key + 24);
		ctx->state[11] = qsc_intutils_le8to32(keyparams->key + 28);
		ctx->state[12] = 0;
		ctx->state[13] = 0;
		ctx->state[14] = qsc_intutils_le8to32(keyparams->nonce);
		ctx->state[15] = qsc_intutils_le8to32(keyparams->nonce + 4);
	}
	else
	{
		ctx->state[0] = 0x61707865ULL;
		ctx->state[1] = 0x3120646EULL;
		ctx->state[2] = 0x79622D36ULL;
		ctx->state[3] = 0x6B206574ULL;
		ctx->state[4] = qsc_intutils_le8to32(keyparams->key + 0);
		ctx->state[5] = qsc_intutils_le8to32(keyparams->key + 4);
		ctx->state[6] = qsc_intutils_le8to32(keyparams->key + 8);
		ctx->state[7] = qsc_intutils_le8to32(keyparams->key + 12);
		ctx->state[8] = qsc_intutils_le8to32(keyparams->key + 0);
		ctx->state[9] = qsc_intutils_le8to32(keyparams->key + 4);
		ctx->state[10] = qsc_intutils_le8to32(keyparams->key + 8);
		ctx->state[11] = qsc_intutils_le8to32(keyparams->key + 12);
		ctx->state[12] = 0;
		ctx->state[13] = 0;
		ctx->state[14] = qsc_intutils_le8to32(keyparams->nonce);
		ctx->state[15] = qsc_intutils_le8to32(keyparams->nonce + 4);
	}
}

void qsc_chacha_transform(qsc_chacha_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(output != NULL);
	assert(input != NULL);

	size_t i;
	size_t oft;

	oft = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (length >= CHACHA_AVX512BLOCK_SIZE)
	{
		chacha_avx512_state ctxw;
		uint8_t ctrblk[64];
		__m512i tmpin;

		for (i = 0; i < 16; ++i)
		{
			ctxw.state[i] = _mm512_set1_epi32(ctx->state[i]);
		}

		/* initialize the nonce */
		unpack_columns_x512(&ctxw.state[12], &ctxw.state[13]);
		ctxw.state[12] = _mm512_add_epi64(ctxw.state[12], _mm512_set_epi64(8, 9, 10, 11, 12, 13, 14, 15));
		ctxw.state[13] = _mm512_add_epi64(ctxw.state[13], _mm512_set_epi64(0, 1, 2, 3, 4, 5, 6, 7));
		pack_columns_x512(&ctxw.state[12], &ctxw.state[13]);

		while (length >= CHACHA_AVX512BLOCK_SIZE)
		{
			chacha_permute_p16x512h(&ctxw);

			for (i = 0; i < 16; ++i)
			{
				tmpin = chacha_load512(((uint8_t*)input + oft + (i * 4)));
				ctxw.outw[i] = _mm512_xor_si512(ctxw.outw[i], tmpin);
				chacha_store512(((uint8_t*)output + oft + (i * 4)), ctxw.outw[i]);
			}

			leincrement_x512(&ctxw.state[12], &ctxw.state[13]);
			oft += CHACHA_AVX512BLOCK_SIZE;
			length -= CHACHA_AVX512BLOCK_SIZE;
		}

		/* store the nonce */
		_mm512_storeu_si512((__m512i*)ctrblk, ctxw.state[12]);
		ctx->state[12] = qsc_intutils_le8to32(((uint8_t*)ctrblk + 60));
		_mm512_storeu_si512((__m512i*)ctrblk, ctxw.state[13]);
		ctx->state[13] = qsc_intutils_le8to32(((uint8_t*)ctrblk + 60));
	}

#elif defined(QSC_SYSTEM_HAS_AVX2)

	if (length >= CHACHA_AVX2BLOCK_SIZE)
	{
		chacha_avx2_state ctxw;
		uint32_t ctrblk[16];
		__m256i tmpin;

		for (i = 0; i < 16; ++i)
		{
			ctxw.state[i] = _mm256_set1_epi32(ctx->state[i]);
		}

		while (length >= CHACHA_AVX2BLOCK_SIZE)
		{
			ctrblk[0] = ctx->state[12];
			ctrblk[8] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[1] = ctx->state[12];
			ctrblk[9] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[2] = ctx->state[12];
			ctrblk[10] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[3] = ctx->state[12];
			ctrblk[11] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[4] = ctx->state[12];
			ctrblk[12] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[5] = ctx->state[12];
			ctrblk[13] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[6] = ctx->state[12];
			ctrblk[14] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[7] = ctx->state[12];
			ctrblk[15] = ctx->state[13];
			chacha_increment(ctx);

			ctxw.state[12] = _mm256_set_epi32(ctrblk[0], ctrblk[1], ctrblk[2], ctrblk[3], ctrblk[4], ctrblk[5], ctrblk[6], ctrblk[7]);
			ctxw.state[13] = _mm256_set_epi32(ctrblk[8], ctrblk[9], ctrblk[10], ctrblk[11], ctrblk[12], ctrblk[13], ctrblk[14], ctrblk[15]);

			chacha_permute_p8x512h(&ctxw);

			for (i = 0; i < 16; ++i)
			{
				tmpin = chacha_load256(((uint8_t*)input + oft + (i * 4)));
				ctxw.outw[i] = _mm256_xor_si256(ctxw.outw[i], tmpin);
				chacha_store256(((uint8_t*)output + oft + (i * 4)), ctxw.outw[i]);
			}

			oft += CHACHA_AVX2BLOCK_SIZE;
			length -= CHACHA_AVX2BLOCK_SIZE;
		}
	}

#elif defined(QSC_SYSTEM_HAS_AVX)

	if (length >= CHACHA_AVXBLOCK_SIZE)
	{
		chacha_avx_state ctxw;
		uint32_t ctrblk[8];
		__m128i tmpin;

		for (i = 0; i < 16; ++i)
		{
			ctxw.state[i] = _mm_set1_epi32(ctx->state[i]);
		}

		while (length >= CHACHA_AVXBLOCK_SIZE)
		{
			ctrblk[0] = ctx->state[12];
			ctrblk[4] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[1] = ctx->state[12];
			ctrblk[5] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[2] = ctx->state[12];
			ctrblk[6] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[3] = ctx->state[12];
			ctrblk[7] = ctx->state[13];
			chacha_increment(ctx);
			ctxw.state[12] = _mm_set_epi32(ctrblk[0], ctrblk[1], ctrblk[2], ctrblk[3]);
			ctxw.state[13] = _mm_set_epi32(ctrblk[4], ctrblk[5], ctrblk[6], ctrblk[7]);

			chacha_permute_p4x512h(&ctxw);

			for (i = 0; i < 16; ++i)
			{
				tmpin = chacha_load128(((uint8_t*)input + oft + (i * 4)));
				ctxw.outw[i] = _mm_xor_si128(ctxw.outw[i], tmpin);
				chacha_store128(((uint8_t*)output + oft + (i * 4)), ctxw.outw[i]);
			}

			oft += CHACHA_AVXBLOCK_SIZE;
			length -= CHACHA_AVXBLOCK_SIZE;
		}
	}

#endif

	if (length != 0)
	{
		while (length >= QSC_CHACHA_BLOCK_SIZE)
		{
			chacha_permute_p512c(ctx, ((uint8_t*)output + oft));
			chacha_increment(ctx);
			qsc_memutils_xor(((uint8_t*)output + oft), ((uint8_t*)input + oft), QSC_CHACHA_BLOCK_SIZE);
			oft += QSC_CHACHA_BLOCK_SIZE;
			length -= QSC_CHACHA_BLOCK_SIZE;
		}

		if (length != 0)
		{
			uint8_t tmp[QSC_CHACHA_BLOCK_SIZE] = { 0 };
			chacha_permute_p512c(ctx, tmp);
			chacha_increment(ctx);
			memcpy(((uint8_t*)output + oft), tmp, length);

			for (i = oft; i < oft + length; ++i)
			{
				output[i] ^= input[i];
			}
		}
	}
}