#include "chacha.h"
#include "intutils.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_HAS_AVX)
#	include "intrinsics.h"
#endif

#define CHACHA_STATE_SIZE 16ULL

#if defined(QSC_SYSTEM_HAS_AVX)
#	define CHACHA_AVXBLOCK_SIZE (4U * QSC_CHACHA_BLOCK_SIZE)
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
#	define CHACHA_AVX2BLOCK_SIZE (8U * QSC_CHACHA_BLOCK_SIZE)
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
#	define CHACHA_AVX512BLOCK_SIZE (16U * QSC_CHACHA_BLOCK_SIZE)
#endif

static void chacha_increment(qsc_chacha_state* ctx)
{
	++ctx->state[12U];

	if (ctx->state[12U] == 0U) 
	{ 
		++ctx->state[13U]; 
	}
}

static void chacha_permute_p512c(const qsc_chacha_state* ctx, uint8_t* output)
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

	x0 = ctx->state[0U];
	x1 = ctx->state[1U];
	x2 = ctx->state[2U];
	x3 = ctx->state[3U];
	x4 = ctx->state[4U];
	x5 = ctx->state[5U];
	x6 = ctx->state[6U];
	x7 = ctx->state[7U];
	x8 = ctx->state[8U];
	x9 = ctx->state[9U];
	x10 = ctx->state[10U];
	x11 = ctx->state[11U];
	x12 = ctx->state[12U];
	x13 = ctx->state[13U];
	x14 = ctx->state[14U];
	x15 = ctx->state[15U];
	ctr = QSC_CHACHA_ROUND_COUNT;

	while (ctr != 0U)
	{
		x0 += x4;
		x12 = qsc_intutils_rotl32(x12 ^ x0, 16U);
		x8 += x12;
		x4 = qsc_intutils_rotl32(x4 ^ x8, 12U);
		x0 += x4;
		x12 = qsc_intutils_rotl32(x12 ^ x0, 8U);
		x8 += x12;
		x4 = qsc_intutils_rotl32(x4 ^ x8, 7U);
		x1 += x5;
		x13 = qsc_intutils_rotl32(x13 ^ x1, 16U);
		x9 += x13;
		x5 = qsc_intutils_rotl32(x5 ^ x9, 12U);
		x1 += x5;
		x13 = qsc_intutils_rotl32(x13 ^ x1, 8U);
		x9 += x13;
		x5 = qsc_intutils_rotl32(x5 ^ x9, 7U);
		x2 += x6;
		x14 = qsc_intutils_rotl32(x14 ^ x2, 16U);
		x10 += x14;
		x6 = qsc_intutils_rotl32(x6 ^ x10, 12U);
		x2 += x6;
		x14 = qsc_intutils_rotl32(x14 ^ x2, 8U);
		x10 += x14;
		x6 = qsc_intutils_rotl32(x6 ^ x10, 7U);
		x3 += x7;
		x15 = qsc_intutils_rotl32(x15 ^ x3, 16U);
		x11 += x15;
		x7 = qsc_intutils_rotl32(x7 ^ x11, 12U);
		x3 += x7;
		x15 = qsc_intutils_rotl32(x15 ^ x3, 8U);
		x11 += x15;
		x7 = qsc_intutils_rotl32(x7 ^ x11, 7U);
		x0 += x5;
		x15 = qsc_intutils_rotl32(x15 ^ x0, 16U);
		x10 += x15;
		x5 = qsc_intutils_rotl32(x5 ^ x10, 12U);
		x0 += x5;
		x15 = qsc_intutils_rotl32(x15 ^ x0, 8U);
		x10 += x15;
		x5 = qsc_intutils_rotl32(x5 ^ x10, 7U);
		x1 += x6;
		x12 = qsc_intutils_rotl32(x12 ^ x1, 16U);
		x11 += x12;
		x6 = qsc_intutils_rotl32(x6 ^ x11, 12U);
		x1 += x6;
		x12 = qsc_intutils_rotl32(x12 ^ x1, 8U);
		x11 += x12;
		x6 = qsc_intutils_rotl32(x6 ^ x11, 7U);
		x2 += x7;
		x13 = qsc_intutils_rotl32(x13 ^ x2, 16U);
		x8 += x13;
		x7 = qsc_intutils_rotl32(x7 ^ x8, 12U);
		x2 += x7;
		x13 = qsc_intutils_rotl32(x13 ^ x2, 8U);
		x8 += x13;
		x7 = qsc_intutils_rotl32(x7 ^ x8, 7U);
		x3 += x4;
		x14 = qsc_intutils_rotl32(x14 ^ x3, 16U);
		x9 += x14;
		x4 = qsc_intutils_rotl32(x4 ^ x9, 12U);
		x3 += x4;
		x14 = qsc_intutils_rotl32(x14 ^ x3, 8U);
		x9 += x14;
		x4 = qsc_intutils_rotl32(x4 ^ x9, 7U);
		ctr -= 2U;
	}

	qsc_intutils_le32to8(output, x0 + ctx->state[0U]);
	qsc_intutils_le32to8(output + 4U, x1 + ctx->state[1U]);
	qsc_intutils_le32to8(output + 8U, x2 + ctx->state[2U]);
	qsc_intutils_le32to8(output + 12U, x3 + ctx->state[3U]);
	qsc_intutils_le32to8(output + 16U, x4 + ctx->state[4U]);
	qsc_intutils_le32to8(output + 20U, x5 + ctx->state[5U]);
	qsc_intutils_le32to8(output + 24U, x6 + ctx->state[6U]);
	qsc_intutils_le32to8(output + 28U, x7 + ctx->state[7U]);
	qsc_intutils_le32to8(output + 32U, x8 + ctx->state[8U]);
	qsc_intutils_le32to8(output + 36U, x9 + ctx->state[9U]);
	qsc_intutils_le32to8(output + 40U, x10 + ctx->state[10U]);
	qsc_intutils_le32to8(output + 44U, x11 + ctx->state[11U]);
	qsc_intutils_le32to8(output + 48U, x12 + ctx->state[12U]);
	qsc_intutils_le32to8(output + 52U, x13 + ctx->state[13U]);
	qsc_intutils_le32to8(output + 56U, x14 + ctx->state[14U]);
	qsc_intutils_le32to8(output + 60U, x15 + ctx->state[15U]);
}

#if defined(QSC_SYSTEM_HAS_AVX512)

typedef struct
{
	__m512i state[16U];
	__m512i outw[16U];
} chacha_avx512_state;

inline static __m512i chacha_rotl512(const __m512i x, uint32_t shift)
{
	return _mm512_or_si512(_mm512_slli_epi32(x, shift), _mm512_srli_epi32(x, 32U - shift));
}

static __m512i chacha_load512(const uint8_t* v)
{
	const uint32_t* v32 = (const uint32_t*)v;

	return _mm512_set_epi32(v32[0U], v32[16U], v32[32U], v32[48U], v32[64U], v32[80U], v32[96U], v32[112U], 
		v32[128U], v32[144U], v32[160U], v32[176U], v32[192U], v32[208U], v32[224U], v32[240U]);
}

static void chacha_store512(uint8_t* output, const __m512i x)
{
	uint32_t tmp[16U];

	_mm512_storeu_si512((__m512i*)tmp, x);

	qsc_intutils_le32to8(output, tmp[15U]);
	qsc_intutils_le32to8((output + 64U), tmp[14U]);
	qsc_intutils_le32to8((output + 128U), tmp[13U]);
	qsc_intutils_le32to8((output + 192U), tmp[12U]);
	qsc_intutils_le32to8((output + 256U), tmp[11U]);
	qsc_intutils_le32to8((output + 320U), tmp[10U]);
	qsc_intutils_le32to8((output + 384U), tmp[9U]);
	qsc_intutils_le32to8((output + 448U), tmp[8U]);
	qsc_intutils_le32to8((output + 512U), tmp[7U]);
	qsc_intutils_le32to8((output + 576U), tmp[6U]);
	qsc_intutils_le32to8((output + 640U), tmp[5U]);
	qsc_intutils_le32to8((output + 704U), tmp[4U]);
	qsc_intutils_le32to8((output + 768U), tmp[3U]);
	qsc_intutils_le32to8((output + 832U), tmp[2U]);
	qsc_intutils_le32to8((output + 896U), tmp[1U]);
	qsc_intutils_le32to8((output + 960U), tmp[0U]);
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

	x0 = ctxw->state[0U];
	x1 = ctxw->state[1U];
	x2 = ctxw->state[2U];
	x3 = ctxw->state[3U];
	x4 = ctxw->state[4U];
	x5 = ctxw->state[5U];
	x6 = ctxw->state[6U];
	x7 = ctxw->state[7U];
	x8 = ctxw->state[8U];
	x9 = ctxw->state[9U];
	x10 = ctxw->state[10U];
	x11 = ctxw->state[11U];
	x12 = ctxw->state[12U];
	x13 = ctxw->state[13U];
	x14 = ctxw->state[14U];
	x15 = ctxw->state[15U];
	ctr = QSC_CHACHA_ROUND_COUNT;

	while (ctr != 0U)
	{
		x0 = _mm512_add_epi32(x0, x4);
		x12 = chacha_rotl512(_mm512_xor_si512(x12, x0), 16U);
		x8 = _mm512_add_epi32(x8, x12);
		x4 = chacha_rotl512(_mm512_xor_si512(x4, x8), 12U);
		x0 = _mm512_add_epi32(x0, x4);
		x12 = chacha_rotl512(_mm512_xor_si512(x12, x0), 8U);
		x8 = _mm512_add_epi32(x8, x12);
		x4 = chacha_rotl512(_mm512_xor_si512(x4, x8), 7U);
		x1 = _mm512_add_epi32(x1, x5);
		x13 = chacha_rotl512(_mm512_xor_si512(x13, x1), 16U);
		x9 = _mm512_add_epi32(x9, x13);
		x5 = chacha_rotl512(_mm512_xor_si512(x5, x9), 12U);
		x1 = _mm512_add_epi32(x1, x5);
		x13 = chacha_rotl512(_mm512_xor_si512(x13, x1), 8U);
		x9 = _mm512_add_epi32(x9, x13);
		x5 = chacha_rotl512(_mm512_xor_si512(x5, x9), 7U);
		x2 = _mm512_add_epi32(x2, x6);
		x14 = chacha_rotl512(_mm512_xor_si512(x14, x2), 16U);
		x10 = _mm512_add_epi32(x10, x14);
		x6 = chacha_rotl512(_mm512_xor_si512(x6, x10), 12U);
		x2 = _mm512_add_epi32(x2, x6);
		x14 = chacha_rotl512(_mm512_xor_si512(x14, x2), 8U);
		x10 = _mm512_add_epi32(x10, x14);
		x6 = chacha_rotl512(_mm512_xor_si512(x6, x10), 7U);
		x3 = _mm512_add_epi32(x3, x7);
		x15 = chacha_rotl512(_mm512_xor_si512(x15, x3), 16U);
		x11 = _mm512_add_epi32(x11, x15);
		x7 = chacha_rotl512(_mm512_xor_si512(x7, x11), 12U);
		x3 = _mm512_add_epi32(x3, x7);
		x15 = chacha_rotl512(_mm512_xor_si512(x15, x3), 8U);
		x11 = _mm512_add_epi32(x11, x15);
		x7 = chacha_rotl512(_mm512_xor_si512(x7, x11), 7U);
		x0 = _mm512_add_epi32(x0, x5);
		x15 = chacha_rotl512(_mm512_xor_si512(x15, x0), 16U);
		x10 = _mm512_add_epi32(x10, x15);
		x5 = chacha_rotl512(_mm512_xor_si512(x5, x10), 12U);
		x0 = _mm512_add_epi32(x0, x5);
		x15 = chacha_rotl512(_mm512_xor_si512(x15, x0), 8U);
		x10 = _mm512_add_epi32(x10, x15);
		x5 = chacha_rotl512(_mm512_xor_si512(x5, x10), 7U);
		x1 = _mm512_add_epi32(x1, x6);
		x12 = chacha_rotl512(_mm512_xor_si512(x12, x1), 16U);
		x11 = _mm512_add_epi32(x11, x12);
		x6 = chacha_rotl512(_mm512_xor_si512(x6, x11), 12U);
		x1 = _mm512_add_epi32(x1, x6);
		x12 = chacha_rotl512(_mm512_xor_si512(x12, x1), 8U);
		x11 = _mm512_add_epi32(x11, x12);
		x6 = chacha_rotl512(_mm512_xor_si512(x6, x11), 7U);
		x2 = _mm512_add_epi32(x2, x7);
		x13 = chacha_rotl512(_mm512_xor_si512(x13, x2), 16U);
		x8 = _mm512_add_epi32(x8, x13);
		x7 = chacha_rotl512(_mm512_xor_si512(x7, x8), 12U);
		x2 = _mm512_add_epi32(x2, x7);
		x13 = chacha_rotl512(_mm512_xor_si512(x13, x2), 8U);
		x8 = _mm512_add_epi32(x8, x13);
		x7 = chacha_rotl512(_mm512_xor_si512(x7, x8), 7U);
		x3 = _mm512_add_epi32(x3, x4);
		x14 = chacha_rotl512(_mm512_xor_si512(x14, x3), 16U);
		x9 = _mm512_add_epi32(x9, x14);
		x4 = chacha_rotl512(_mm512_xor_si512(x4, x9), 12U);
		x3 = _mm512_add_epi32(x3, x4);
		x14 = chacha_rotl512(_mm512_xor_si512(x14, x3), 8U);
		x9 = _mm512_add_epi32(x9, x14);
		x4 = chacha_rotl512(_mm512_xor_si512(x4, x9), 7U);
		ctr -= 2U;
	}

	ctxw->outw[0U] = _mm512_add_epi32(x0, ctxw->state[0U]);
	ctxw->outw[1U] = _mm512_add_epi32(x1, ctxw->state[1U]);
	ctxw->outw[2U] = _mm512_add_epi32(x2, ctxw->state[2U]);
	ctxw->outw[3U] = _mm512_add_epi32(x3, ctxw->state[3U]);
	ctxw->outw[4U] = _mm512_add_epi32(x4, ctxw->state[4U]);
	ctxw->outw[5U] = _mm512_add_epi32(x5, ctxw->state[5U]);
	ctxw->outw[6U] = _mm512_add_epi32(x6, ctxw->state[6U]);
	ctxw->outw[7U] = _mm512_add_epi32(x7, ctxw->state[7U]);
	ctxw->outw[8U] = _mm512_add_epi32(x8, ctxw->state[8U]);
	ctxw->outw[9U] = _mm512_add_epi32(x9, ctxw->state[9U]);
	ctxw->outw[10U] = _mm512_add_epi32(x10, ctxw->state[10U]);
	ctxw->outw[11U] = _mm512_add_epi32(x11, ctxw->state[11U]);
	ctxw->outw[12U] = _mm512_add_epi32(x12, ctxw->state[12U]);
	ctxw->outw[13U] = _mm512_add_epi32(x13, ctxw->state[13U]);
	ctxw->outw[14U] = _mm512_add_epi32(x14, ctxw->state[14U]);
	ctxw->outw[15U] = _mm512_add_epi32(x15, ctxw->state[15U]);
}

#elif defined(QSC_SYSTEM_HAS_AVX2)

typedef struct
{
	 __m256i state[16U];
	__m256i outw[16U];
} chacha_avx2_state;

inline static __m256i chacha_rotl256(const __m256i x, uint32_t shift)
{
	return _mm256_or_si256(_mm256_slli_epi32(x, shift), _mm256_srli_epi32(x, 32 - shift));
}

static __m256i chacha_load256(const uint8_t* v)
{
	const uint32_t* v32 = (const uint32_t*)v;

	return _mm256_set_epi32(v32[0U], v32[16U], v32[32U], v32[48U], v32[64U], v32[80U], v32[96U], v32[112U]);
}

static void chacha_store256(uint8_t* output, const __m256i x)
{
	uint32_t tmp[8U];

	_mm256_storeu_si256((__m256i*)tmp, x);

	qsc_intutils_le32to8(output, tmp[7U]);
	qsc_intutils_le32to8((output + 64U), tmp[6U]);
	qsc_intutils_le32to8((output + 128U), tmp[5U]);
	qsc_intutils_le32to8((output + 192U), tmp[4U]);
	qsc_intutils_le32to8((output + 256U), tmp[3U]);
	qsc_intutils_le32to8((output + 320U), tmp[2U]);
	qsc_intutils_le32to8((output + 384U), tmp[1U]);
	qsc_intutils_le32to8((output + 448U), tmp[0U]);
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

	x0 = ctxw->state[0U];
	x1 = ctxw->state[1U];
	x2 = ctxw->state[2U];
	x3 = ctxw->state[3U];
	x4 = ctxw->state[4U];
	x5 = ctxw->state[5U];
	x6 = ctxw->state[6U];
	x7 = ctxw->state[7U];
	x8 = ctxw->state[8U];
	x9 = ctxw->state[9U];
	x10 = ctxw->state[10U];
	x11 = ctxw->state[11U];
	x12 = ctxw->state[12U];
	x13 = ctxw->state[13U];
	x14 = ctxw->state[14U];
	x15 = ctxw->state[15U];
	ctr = QSC_CHACHA_ROUND_COUNT;

	while (ctr != 0U)
	{
		x0 = _mm256_add_epi32(x0, x4);
		x12 = chacha_rotl256(_mm256_xor_si256(x12, x0), 16U);
		x8 = _mm256_add_epi32(x8, x12);
		x4 = chacha_rotl256(_mm256_xor_si256(x4, x8), 12U);
		x0 = _mm256_add_epi32(x0, x4);
		x12 = chacha_rotl256(_mm256_xor_si256(x12, x0), 8U);
		x8 = _mm256_add_epi32(x8, x12);
		x4 = chacha_rotl256(_mm256_xor_si256(x4, x8), 7U);
		x1 = _mm256_add_epi32(x1, x5);
		x13 = chacha_rotl256(_mm256_xor_si256(x13, x1), 16U);
		x9 = _mm256_add_epi32(x9, x13);
		x5 = chacha_rotl256(_mm256_xor_si256(x5, x9), 12U);
		x1 = _mm256_add_epi32(x1, x5);
		x13 = chacha_rotl256(_mm256_xor_si256(x13, x1), 8U);
		x9 = _mm256_add_epi32(x9, x13);
		x5 = chacha_rotl256(_mm256_xor_si256(x5, x9), 7U);
		x2 = _mm256_add_epi32(x2, x6);
		x14 = chacha_rotl256(_mm256_xor_si256(x14, x2), 16U);
		x10 = _mm256_add_epi32(x10, x14);
		x6 = chacha_rotl256(_mm256_xor_si256(x6, x10), 12U);
		x2 = _mm256_add_epi32(x2, x6);
		x14 = chacha_rotl256(_mm256_xor_si256(x14, x2), 8U);
		x10 = _mm256_add_epi32(x10, x14);
		x6 = chacha_rotl256(_mm256_xor_si256(x6, x10), 7U);
		x3 = _mm256_add_epi32(x3, x7);
		x15 = chacha_rotl256(_mm256_xor_si256(x15, x3), 16U);
		x11 = _mm256_add_epi32(x11, x15);
		x7 = chacha_rotl256(_mm256_xor_si256(x7, x11), 12U);
		x3 = _mm256_add_epi32(x3, x7);
		x15 = chacha_rotl256(_mm256_xor_si256(x15, x3), 8U);
		x11 = _mm256_add_epi32(x11, x15);
		x7 = chacha_rotl256(_mm256_xor_si256(x7, x11), 7U);
		x0 = _mm256_add_epi32(x0, x5);
		x15 = chacha_rotl256(_mm256_xor_si256(x15, x0), 16U);
		x10 = _mm256_add_epi32(x10, x15);
		x5 = chacha_rotl256(_mm256_xor_si256(x5, x10), 12U);
		x0 = _mm256_add_epi32(x0, x5);
		x15 = chacha_rotl256(_mm256_xor_si256(x15, x0), 8U);
		x10 = _mm256_add_epi32(x10, x15);
		x5 = chacha_rotl256(_mm256_xor_si256(x5, x10), 7U);
		x1 = _mm256_add_epi32(x1, x6);
		x12 = chacha_rotl256(_mm256_xor_si256(x12, x1), 16U);
		x11 = _mm256_add_epi32(x11, x12);
		x6 = chacha_rotl256(_mm256_xor_si256(x6, x11), 12U);
		x1 = _mm256_add_epi32(x1, x6);
		x12 = chacha_rotl256(_mm256_xor_si256(x12, x1), 8U);
		x11 = _mm256_add_epi32(x11, x12);
		x6 = chacha_rotl256(_mm256_xor_si256(x6, x11), 7U);
		x2 = _mm256_add_epi32(x2, x7);
		x13 = chacha_rotl256(_mm256_xor_si256(x13, x2), 16U);
		x8 = _mm256_add_epi32(x8, x13);
		x7 = chacha_rotl256(_mm256_xor_si256(x7, x8), 12U);
		x2 = _mm256_add_epi32(x2, x7);
		x13 = chacha_rotl256(_mm256_xor_si256(x13, x2), 8U);
		x8 = _mm256_add_epi32(x8, x13);
		x7 = chacha_rotl256(_mm256_xor_si256(x7, x8), 7U);
		x3 = _mm256_add_epi32(x3, x4);
		x14 = chacha_rotl256(_mm256_xor_si256(x14, x3), 16U);
		x9 = _mm256_add_epi32(x9, x14);
		x4 = chacha_rotl256(_mm256_xor_si256(x4, x9), 12U);
		x3 = _mm256_add_epi32(x3, x4);
		x14 = chacha_rotl256(_mm256_xor_si256(x14, x3), 8U);
		x9 = _mm256_add_epi32(x9, x14);
		x4 = chacha_rotl256(_mm256_xor_si256(x4, x9), 7U);
		ctr -= 2;
	}

	ctxw->outw[0U] = _mm256_add_epi32(x0, ctxw->state[0U]);
	ctxw->outw[1U] = _mm256_add_epi32(x1, ctxw->state[1U]);
	ctxw->outw[2U] = _mm256_add_epi32(x2, ctxw->state[2U]);
	ctxw->outw[3U] = _mm256_add_epi32(x3, ctxw->state[3U]);
	ctxw->outw[4U] = _mm256_add_epi32(x4, ctxw->state[4U]);
	ctxw->outw[5U] = _mm256_add_epi32(x5, ctxw->state[5U]);
	ctxw->outw[6U] = _mm256_add_epi32(x6, ctxw->state[6U]);
	ctxw->outw[7U] = _mm256_add_epi32(x7, ctxw->state[7U]);
	ctxw->outw[8U] = _mm256_add_epi32(x8, ctxw->state[8U]);
	ctxw->outw[9U] = _mm256_add_epi32(x9, ctxw->state[9U]);
	ctxw->outw[10U] = _mm256_add_epi32(x10, ctxw->state[10U]);
	ctxw->outw[11U] = _mm256_add_epi32(x11, ctxw->state[11U]);
	ctxw->outw[12U] = _mm256_add_epi32(x12, ctxw->state[12U]);
	ctxw->outw[13U] = _mm256_add_epi32(x13, ctxw->state[13U]);
	ctxw->outw[14U] = _mm256_add_epi32(x14, ctxw->state[14U]);
	ctxw->outw[15U] = _mm256_add_epi32(x15, ctxw->state[15U]);
}

#elif defined(QSC_SYSTEM_HAS_AVX)

typedef struct
{
	__m128i state[16U];
	__m128i outw[16U];
} chacha_avx_state;

inline static __m128i chacha_rotl128(const __m128i x, uint32_t shift)
{
	return _mm_or_si128(_mm_slli_epi32(x, shift), _mm_srli_epi32(x, 32 - shift));
}

static __m128i chacha_load128(const uint8_t* v)
{
	const uint32_t* v32 = (const uint32_t*)v;

	return _mm_set_epi32(v32[0U], v32[16U], v32[32U], v32[48U]);
}

static void chacha_store128(uint8_t* output, const __m128i x)
{
	uint32_t tmp[4U];

	_mm_storeu_si128((__m128i*)tmp, x);

	qsc_intutils_le32to8(output, tmp[3U]);
	qsc_intutils_le32to8((output + 64U), tmp[2U]);
	qsc_intutils_le32to8((output + 128U), tmp[1U]);
	qsc_intutils_le32to8((output + 192U), tmp[0U]);
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

	x0 = ctxw->state[0U];
	x1 = ctxw->state[1U];
	x2 = ctxw->state[2U];
	x3 = ctxw->state[3U];
	x4 = ctxw->state[4U];
	x5 = ctxw->state[5U];
	x6 = ctxw->state[6U];
	x7 = ctxw->state[7U];
	x8 = ctxw->state[8U];
	x9 = ctxw->state[9U];
	x10 = ctxw->state[10U];
	x11 = ctxw->state[11U];
	x12 = ctxw->state[12U];
	x13 = ctxw->state[13U];
	x14 = ctxw->state[14U];
	x15 = ctxw->state[15U];
	ctr = QSC_CHACHA_ROUND_COUNT;

	while (ctr != 0U)
	{
		x0 = _mm_add_epi32(x0, x4);
		x12 = chacha_rotl128(_mm_xor_si128(x12, x0), 16U);
		x8 = _mm_add_epi32(x8, x12);
		x4 = chacha_rotl128(_mm_xor_si128(x4, x8), 12U);
		x0 = _mm_add_epi32(x0, x4);
		x12 = chacha_rotl128(_mm_xor_si128(x12, x0), 8U);
		x8 = _mm_add_epi32(x8, x12);
		x4 = chacha_rotl128(_mm_xor_si128(x4, x8), 7U);
		x1 = _mm_add_epi32(x1, x5);
		x13 = chacha_rotl128(_mm_xor_si128(x13, x1), 16U);
		x9 = _mm_add_epi32(x9, x13);
		x5 = chacha_rotl128(_mm_xor_si128(x5, x9), 12U);
		x1 = _mm_add_epi32(x1, x5);
		x13 = chacha_rotl128(_mm_xor_si128(x13, x1), 8U);
		x9 = _mm_add_epi32(x9, x13);
		x5 = chacha_rotl128(_mm_xor_si128(x5, x9), 7U);
		x2 = _mm_add_epi32(x2, x6);
		x14 = chacha_rotl128(_mm_xor_si128(x14, x2), 16U);
		x10 = _mm_add_epi32(x10, x14);
		x6 = chacha_rotl128(_mm_xor_si128(x6, x10), 12U);
		x2 = _mm_add_epi32(x2, x6);
		x14 = chacha_rotl128(_mm_xor_si128(x14, x2), 8U);
		x10 = _mm_add_epi32(x10, x14);
		x6 = chacha_rotl128(_mm_xor_si128(x6, x10), 7U);
		x3 = _mm_add_epi32(x3, x7);
		x15 = chacha_rotl128(_mm_xor_si128(x15, x3), 16U);
		x11 = _mm_add_epi32(x11, x15);
		x7 = chacha_rotl128(_mm_xor_si128(x7, x11), 12U);
		x3 = _mm_add_epi32(x3, x7);
		x15 = chacha_rotl128(_mm_xor_si128(x15, x3), 8U);
		x11 = _mm_add_epi32(x11, x15);
		x7 = chacha_rotl128(_mm_xor_si128(x7, x11), 7U);
		x0 = _mm_add_epi32(x0, x5);
		x15 = chacha_rotl128(_mm_xor_si128(x15, x0), 16U);
		x10 = _mm_add_epi32(x10, x15);
		x5 = chacha_rotl128(_mm_xor_si128(x5, x10), 12U);
		x0 = _mm_add_epi32(x0, x5);
		x15 = chacha_rotl128(_mm_xor_si128(x15, x0), 8U);
		x10 = _mm_add_epi32(x10, x15);
		x5 = chacha_rotl128(_mm_xor_si128(x5, x10), 7U);
		x1 = _mm_add_epi32(x1, x6);
		x12 = chacha_rotl128(_mm_xor_si128(x12, x1), 16U);
		x11 = _mm_add_epi32(x11, x12);
		x6 = chacha_rotl128(_mm_xor_si128(x6, x11), 12U);
		x1 = _mm_add_epi32(x1, x6);
		x12 = chacha_rotl128(_mm_xor_si128(x12, x1), 8U);
		x11 = _mm_add_epi32(x11, x12);
		x6 = chacha_rotl128(_mm_xor_si128(x6, x11), 7U);
		x2 = _mm_add_epi32(x2, x7);
		x13 = chacha_rotl128(_mm_xor_si128(x13, x2), 16U);
		x8 = _mm_add_epi32(x8, x13);
		x7 = chacha_rotl128(_mm_xor_si128(x7, x8), 12U);
		x2 = _mm_add_epi32(x2, x7);
		x13 = chacha_rotl128(_mm_xor_si128(x13, x2), 8U);
		x8 = _mm_add_epi32(x8, x13);
		x7 = chacha_rotl128(_mm_xor_si128(x7, x8), 7U);
		x3 = _mm_add_epi32(x3, x4);
		x14 = chacha_rotl128(_mm_xor_si128(x14, x3), 16U);
		x9 = _mm_add_epi32(x9, x14);
		x4 = chacha_rotl128(_mm_xor_si128(x4, x9), 12U);
		x3 = _mm_add_epi32(x3, x4);
		x14 = chacha_rotl128(_mm_xor_si128(x14, x3), 8U);
		x9 = _mm_add_epi32(x9, x14);
		x4 = chacha_rotl128(_mm_xor_si128(x4, x9), 7U);
		ctr -= 2U;
	}

	ctxw->outw[0U] = _mm_add_epi32(x0, ctxw->state[0U]);
	ctxw->outw[1U] = _mm_add_epi32(x1, ctxw->state[1U]);
	ctxw->outw[2U] = _mm_add_epi32(x2, ctxw->state[2U]);
	ctxw->outw[3U] = _mm_add_epi32(x3, ctxw->state[3U]);
	ctxw->outw[4U] = _mm_add_epi32(x4, ctxw->state[4U]);
	ctxw->outw[5U] = _mm_add_epi32(x5, ctxw->state[5U]);
	ctxw->outw[6U] = _mm_add_epi32(x6, ctxw->state[6U]);
	ctxw->outw[7U] = _mm_add_epi32(x7, ctxw->state[7U]);
	ctxw->outw[8U] = _mm_add_epi32(x8, ctxw->state[8U]);
	ctxw->outw[9U] = _mm_add_epi32(x9, ctxw->state[9U]);
	ctxw->outw[10U] = _mm_add_epi32(x10, ctxw->state[10U]);
	ctxw->outw[11U] = _mm_add_epi32(x11, ctxw->state[11U]);
	ctxw->outw[12U] = _mm_add_epi32(x12, ctxw->state[12U]);
	ctxw->outw[13U] = _mm_add_epi32(x13, ctxw->state[13U]);
	ctxw->outw[14U] = _mm_add_epi32(x14, ctxw->state[14U]);
	ctxw->outw[15U] = _mm_add_epi32(x15, ctxw->state[15U]);
}

#endif

void qsc_chacha_dispose(qsc_chacha_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx->state, sizeof(ctx->state));
	}
}

void qsc_chacha_initialize(qsc_chacha_state* ctx, const qsc_chacha_keyparams* keyparams)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);
	QSC_ASSERT(keyparams->nonce != NULL);
	QSC_ASSERT(keyparams->key != NULL);
	QSC_ASSERT(keyparams->keylen == 16U || keyparams->keylen == 32U);

	if (ctx != NULL && keyparams != NULL)
	{
		if (keyparams->keylen == 32U)
		{
			ctx->state[0U] = 0x61707865ULL;
			ctx->state[1U] = 0x3320646EULL;
			ctx->state[2U] = 0x79622D32ULL;
			ctx->state[3U] = 0x6B206574ULL;
			ctx->state[4U] = qsc_intutils_le8to32(keyparams->key);
			ctx->state[5U] = qsc_intutils_le8to32(keyparams->key + 4U);
			ctx->state[6U] = qsc_intutils_le8to32(keyparams->key + 8U);
			ctx->state[7U] = qsc_intutils_le8to32(keyparams->key + 12U);
			ctx->state[8U] = qsc_intutils_le8to32(keyparams->key + 16U);
			ctx->state[9U] = qsc_intutils_le8to32(keyparams->key + 20U);
			ctx->state[10U] = qsc_intutils_le8to32(keyparams->key + 24U);
			ctx->state[11U] = qsc_intutils_le8to32(keyparams->key + 28U);
			ctx->state[12U] = 0U;
			ctx->state[13U] = qsc_intutils_le8to32(keyparams->nonce);
			ctx->state[14U] = qsc_intutils_le8to32(keyparams->nonce + 4U);
			ctx->state[15U] = qsc_intutils_le8to32(keyparams->nonce + 8U);
		}
		else
		{
			ctx->state[0U] = 0x61707865ULL;
			ctx->state[1U] = 0x3120646EULL;
			ctx->state[2U] = 0x79622D36ULL;
			ctx->state[3U] = 0x6B206574ULL;
			ctx->state[4U] = qsc_intutils_le8to32(keyparams->key);
			ctx->state[5U] = qsc_intutils_le8to32(keyparams->key + 4U);
			ctx->state[6U] = qsc_intutils_le8to32(keyparams->key + 8U);
			ctx->state[7U] = qsc_intutils_le8to32(keyparams->key + 12U);
			ctx->state[8U] = qsc_intutils_le8to32(keyparams->key);
			ctx->state[9U] = qsc_intutils_le8to32(keyparams->key + 4U);
			ctx->state[10U] = qsc_intutils_le8to32(keyparams->key + 8U);
			ctx->state[11U] = qsc_intutils_le8to32(keyparams->key + 12U);
			ctx->state[12U] = 0U;
			ctx->state[13U] = qsc_intutils_le8to32(keyparams->nonce);
			ctx->state[14U] = qsc_intutils_le8to32(keyparams->nonce + 4U);
			ctx->state[15U] = qsc_intutils_le8to32(keyparams->nonce + 8U);
		}
	}
}

void qsc_chacha_transform(qsc_chacha_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	size_t i;
	size_t oft;

	if (ctx != NULL && output != NULL && input != NULL && length != 0U)
	{
		oft = 0U;

#if defined(QSC_SYSTEM_HAS_AVX512)

		if (length >= CHACHA_AVX512BLOCK_SIZE)
		{
			chacha_avx512_state ctxw;
			uint32_t ctrblk[16U];
			__m512i tmpin;

			for (i = 0U; i < 16U; ++i)
			{
				ctxw.state[i] = _mm512_set1_epi32(ctx->state[i]);
			}

			while (length >= CHACHA_AVX512BLOCK_SIZE)
			{
				/* initialize the nonce */
				ctrblk[0U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[1U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[2U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[3U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[4U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[5U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[6U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[7U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[8U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[9U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[10U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[11U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[12U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[13U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[14U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[15U] = ctx->state[12U];
				chacha_increment(ctx);

				ctxw.state[12U] = _mm512_set_epi32(ctrblk[0U], ctrblk[1U], ctrblk[2U], ctrblk[3U], ctrblk[4U], ctrblk[5U], ctrblk[6U], ctrblk[7U],
					ctrblk[8U], ctrblk[9U], ctrblk[10U], ctrblk[11U], ctrblk[12U], ctrblk[13U], ctrblk[14U], ctrblk[15U]);

				chacha_permute_p16x512h(&ctxw);

				for (i = 0U; i < 16U; ++i)
				{
					tmpin = chacha_load512(input + oft + (i * sizeof(uint32_t)));
					ctxw.outw[i] = _mm512_xor_si512(ctxw.outw[i], tmpin);
					chacha_store512(output + oft + (i * sizeof(uint32_t)), ctxw.outw[i]);
				}

				oft += CHACHA_AVX512BLOCK_SIZE;
				length -= CHACHA_AVX512BLOCK_SIZE;
			}
		}

#elif defined(QSC_SYSTEM_HAS_AVX2)

		if (length >= CHACHA_AVX2BLOCK_SIZE)
		{
			chacha_avx2_state ctxw;
			uint32_t ctrblk[8U];
			__m256i tmpin;

			for (i = 0U; i < 16U; ++i)
			{
				ctxw.state[i] = _mm256_set1_epi32(ctx->state[i]);
			}

			while (length >= CHACHA_AVX2BLOCK_SIZE)
			{
				ctrblk[0U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[1U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[2U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[3U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[4U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[5U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[6U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[7U] = ctx->state[12U];
				chacha_increment(ctx);

				ctxw.state[12U] = _mm256_set_epi32(ctrblk[0U], ctrblk[1U], ctrblk[2U], ctrblk[3U], ctrblk[4U], ctrblk[5U], ctrblk[6U], ctrblk[7U]);

				chacha_permute_p8x512h(&ctxw);

				for (i = 0U; i < 16U; ++i)
				{
					tmpin = chacha_load256(input + oft + (i * sizeof(uint32_t)));
					ctxw.outw[i] = _mm256_xor_si256(ctxw.outw[i], tmpin);
					chacha_store256(output + oft + (i * sizeof(uint32_t)), ctxw.outw[i]);
				}

				oft += CHACHA_AVX2BLOCK_SIZE;
				length -= CHACHA_AVX2BLOCK_SIZE;
			}
		}

#elif defined(QSC_SYSTEM_HAS_AVX)

		if (length >= CHACHA_AVXBLOCK_SIZE)
		{
			chacha_avx_state ctxw;
			uint32_t ctrblk[4U];
			__m128i tmpin;

			for (i = 0U; i < 16U; ++i)
			{
				ctxw.state[i] = _mm_set1_epi32(ctx->state[i]);
			}

			while (length >= CHACHA_AVXBLOCK_SIZE)
			{
				ctrblk[0U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[1U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[2U] = ctx->state[12U];
				chacha_increment(ctx);
				ctrblk[3U] = ctx->state[12U];
				chacha_increment(ctx);
				ctxw.state[12U] = _mm_set_epi32(ctrblk[0U], ctrblk[1U], ctrblk[2U], ctrblk[3U]);

				chacha_permute_p4x512h(&ctxw);

				for (i = 0U; i < 16U; ++i)
				{
					tmpin = chacha_load128(input + oft + (i * sizeof(uint32_t)));
					ctxw.outw[i] = _mm_xor_si128(ctxw.outw[i], tmpin);
					chacha_store128(output + oft + (i * sizeof(uint32_t)), ctxw.outw[i]);
				}

				oft += CHACHA_AVXBLOCK_SIZE;
				length -= CHACHA_AVXBLOCK_SIZE;
			}
		}

#endif

		if (length != 0U)
		{
			while (length >= QSC_CHACHA_BLOCK_SIZE)
			{
				chacha_permute_p512c(ctx, output + oft);
				chacha_increment(ctx);
				qsc_memutils_xor(output + oft, input + oft, QSC_CHACHA_BLOCK_SIZE);
				oft += QSC_CHACHA_BLOCK_SIZE;
				length -= QSC_CHACHA_BLOCK_SIZE;
			}

			if (length != 0U)
			{
				uint8_t tmp[QSC_CHACHA_BLOCK_SIZE] = { 0U };

				chacha_permute_p512c(ctx, tmp);
				chacha_increment(ctx);
				qsc_memutils_copy(output + oft, tmp, length);

				for (i = oft; i < oft + length; ++i)
				{
					output[i] ^= input[i];
				}
			}
		}
	}
}

/* chacha-poly1305*/

static void chacha_poly1305_finalize(qsc_chacha_poly1305_state* ctx, uint8_t* tag)
{
	uint8_t fblk[QSC_POLY1305_BLOCK_SIZE] = { 0U };

	qsc_intutils_le64to8(fblk, ctx->aadlen);
	qsc_intutils_le64to8(fblk + sizeof(uint64_t), ctx->msglen);
	qsc_poly1305_blockupdate(&ctx->pstate, fblk);
	qsc_poly1305_finalize(&ctx->pstate, tag);
}

void qsc_chacha_poly1305_set_associated(qsc_chacha_poly1305_state* ctx, const uint8_t* data, size_t datalen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(data != NULL);

	if (ctx != NULL && data != NULL)
	{
		qsc_poly1305_update(&ctx->pstate, data, datalen);
		ctx->aadlen = datalen;

		/* RFC 8439 §2.8: zero-pad AAD to 16-byte boundary */
		const size_t rem = datalen & 15U;

		if (rem != 0U)
		{
			uint8_t pad[QSC_POLY1305_BLOCK_SIZE] = { 0U };
			qsc_poly1305_update(&ctx->pstate, pad, QSC_POLY1305_BLOCK_SIZE - rem);
		}
	}
}

bool qsc_chacha_poly1305_decrypt(qsc_chacha_poly1305_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	bool res;

	res = false;

	if (ctx != NULL && output != NULL && input != NULL && length != 0U)
	{
		uint8_t tag[QSC_POLY1305_MAC_SIZE] = { 0U };
		const size_t mlen = length - QSC_POLY1305_MAC_SIZE;

		qsc_poly1305_update(&ctx->pstate, input, mlen);
		ctx->msglen = mlen;

		/* RFC 8439 §2.8: zero-pad ciphertext to 16-byte boundary */
		const size_t rem = mlen & 15U;

		if (rem != 0U)
		{
			uint8_t pad[QSC_POLY1305_BLOCK_SIZE] = { 0U };
			qsc_poly1305_update(&ctx->pstate, pad, QSC_POLY1305_BLOCK_SIZE - rem);
		}

		chacha_poly1305_finalize(ctx, tag);

		if (qsc_intutils_verify(input + mlen, tag, QSC_POLY1305_MAC_SIZE) == 0U)
		{
			qsc_chacha_transform(&ctx->cstate, output, input, mlen);
			res = true;
		}
	}

	return res;
}

void qsc_chacha_poly1305_dispose(qsc_chacha_poly1305_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_chacha_dispose(&ctx->cstate);
		qsc_poly1305_dispose(&ctx->pstate);
		ctx->aadlen = 0U;
		ctx->msglen = 0U;
	}
}

void qsc_chacha_poly1305_encrypt(qsc_chacha_poly1305_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	if (ctx != NULL && output != NULL && input != NULL && length != 0U)
	{
		qsc_chacha_transform(&ctx->cstate, output, input, length);
		qsc_poly1305_update(&ctx->pstate, output, length);
		ctx->msglen = length;

		/* RFC 8439 §2.8: zero-pad ciphertext to 16-byte boundary */
		const size_t rem = length & 15U;

		if (rem != 0U)
		{
			uint8_t pad[QSC_POLY1305_BLOCK_SIZE] = { 0U };
			qsc_poly1305_update(&ctx->pstate, pad, QSC_POLY1305_BLOCK_SIZE - rem);
		}

		chacha_poly1305_finalize(ctx, output + length);
	}
}

void qsc_chacha_poly1305_initialize(qsc_chacha_poly1305_state* ctx, const qsc_chacha_keyparams* keyparams)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);

	if (ctx != NULL && keyparams != NULL)
	{
		uint8_t pkey[64U] = { 0U };
		uint8_t ptxt[64U] = { 0U };

		qsc_chacha_poly1305_dispose(ctx);
		qsc_chacha_initialize(&ctx->cstate, keyparams);
		qsc_chacha_transform(&ctx->cstate, pkey, ptxt, sizeof(pkey));
		qsc_poly1305_initialize(&ctx->pstate, pkey);
		qsc_memutils_secure_erase(pkey, sizeof(pkey));
	}
}


