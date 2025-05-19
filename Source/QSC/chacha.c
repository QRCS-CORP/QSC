#include "chacha.h"
#include "intutils.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_HAS_AVX)
#	include "intrinsics.h"
#endif

#define CHACHA_STATE_SIZE 16ULL

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

	while (ctr != 0U)
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

	qsc_intutils_le32to8(output, x0 + ctx->state[0U]);
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

inline static __m512i chacha_rotl512(const __m512i x, uint32_t shift)
{
	return _mm512_or_si512(_mm512_slli_epi32(x, shift), _mm512_srli_epi32(x, 32 - shift));
}

static __m512i chacha_load512(const uint8_t* v)
{
	const uint32_t* v32 = (const uint32_t*)v;

	return _mm512_set_epi32(v32[0U], v32[16], v32[32], v32[48], v32[64], v32[80], v32[96], v32[112], 
		v32[128], v32[144], v32[160], v32[176], v32[192], v32[208], v32[224], v32[240]);
}

static void chacha_store512(uint8_t* output, const __m512i x)
{
	QSC_ALIGN(64) uint32_t tmp[16];

	_mm512_storeu_si512((__m512i*)tmp, x);

	qsc_intutils_le32to8(output, tmp[15]);
	qsc_intutils_le32to8((output + 64), tmp[14]);
	qsc_intutils_le32to8((output + 128), tmp[13]);
	qsc_intutils_le32to8((output + 192), tmp[12]);
	qsc_intutils_le32to8((output + 256), tmp[11]);
	qsc_intutils_le32to8((output + 320), tmp[10]);
	qsc_intutils_le32to8((output + 384), tmp[9]);
	qsc_intutils_le32to8((output + 448), tmp[8]);
	qsc_intutils_le32to8((output + 512), tmp[7]);
	qsc_intutils_le32to8((output + 576), tmp[6]);
	qsc_intutils_le32to8((output + 640), tmp[5]);
	qsc_intutils_le32to8((output + 704), tmp[4]);
	qsc_intutils_le32to8((output + 768), tmp[3]);
	qsc_intutils_le32to8((output + 832), tmp[2]);
	qsc_intutils_le32to8((output + 896), tmp[1]);
	qsc_intutils_le32to8((output + 960), tmp[0U]);
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

	while (ctr != 0U)
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

	ctxw->outw[0U] = _mm512_add_epi32(x0, ctxw->state[0U]);
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
	const uint32_t* v32 = (const uint32_t*)v;

	return _mm256_set_epi32(v32[0U], v32[16], v32[32], v32[48], v32[64], v32[80], v32[96], v32[112]);
}

static void chacha_store256(uint8_t* output, const __m256i x)
{
	QSC_ALIGN(32) uint32_t tmp[8];

	_mm256_storeu_si256((__m256i*)tmp, x);

	qsc_intutils_le32to8(output, tmp[7]);
	qsc_intutils_le32to8((output + 64), tmp[6]);
	qsc_intutils_le32to8((output + 128), tmp[5]);
	qsc_intutils_le32to8((output + 192), tmp[4]);
	qsc_intutils_le32to8((output + 256), tmp[3]);
	qsc_intutils_le32to8((output + 320), tmp[2]);
	qsc_intutils_le32to8((output + 384), tmp[1]);
	qsc_intutils_le32to8((output + 448), tmp[0U]);
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

	while (ctr != 0U)
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

	ctxw->outw[0U] = _mm256_add_epi32(x0, ctxw->state[0U]);
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
	const uint32_t* v32 = (const uint32_t*)v;

	return _mm_set_epi32(v32[0U], v32[16], v32[32], v32[48]);
}

static void chacha_store128(uint8_t* output, const __m128i x)
{
	QSC_ALIGN(16) uint32_t tmp[4];

	_mm_storeu_si128((__m128i*)tmp, x);

	qsc_intutils_le32to8(output, tmp[3]);
	qsc_intutils_le32to8((output + 64), tmp[2]);
	qsc_intutils_le32to8((output + 128), tmp[1]);
	qsc_intutils_le32to8((output + 192), tmp[0U]);
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

	while (ctr != 0U)
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

	ctxw->outw[0U] = _mm_add_epi32(x0, ctxw->state[0U]);
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
	QSC_ASSERT(ctx != NULL);

	qsc_memutils_clear((uint8_t*)ctx->state, sizeof(ctx->state));
}

void qsc_chacha_initialize(qsc_chacha_state* ctx, const qsc_chacha_keyparams* keyparams)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams->nonce != NULL);
	QSC_ASSERT(keyparams->key != NULL);
	QSC_ASSERT(keyparams->keylen == 16 || keyparams->keylen == 32);

	if (keyparams->keylen == 32)
	{
		ctx->state[0U] = 0x61707865ULL;
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
		ctx->state[12] = 0U;
		ctx->state[13] = qsc_intutils_le8to32(keyparams->nonce);
		ctx->state[14] = qsc_intutils_le8to32(keyparams->nonce + 4);
		ctx->state[15] = qsc_intutils_le8to32(keyparams->nonce + 8);
	}
	else
	{
		ctx->state[0U] = 0x61707865ULL;
		ctx->state[1] = 0x3120646EULL;
		ctx->state[2] = 0x79622D36ULL;
		ctx->state[3] = 0x6B206574ULL;
		ctx->state[4] = qsc_intutils_le8to32(keyparams->key);
		ctx->state[5] = qsc_intutils_le8to32(keyparams->key + 4);
		ctx->state[6] = qsc_intutils_le8to32(keyparams->key + 8);
		ctx->state[7] = qsc_intutils_le8to32(keyparams->key + 12);
		ctx->state[8] = qsc_intutils_le8to32(keyparams->key);
		ctx->state[9] = qsc_intutils_le8to32(keyparams->key + 4);
		ctx->state[10] = qsc_intutils_le8to32(keyparams->key + 8);
		ctx->state[11] = qsc_intutils_le8to32(keyparams->key + 12);
		ctx->state[12] = 0U;
		ctx->state[13] = qsc_intutils_le8to32(keyparams->nonce);
		ctx->state[14] = qsc_intutils_le8to32(keyparams->nonce + 4);
		ctx->state[15] = qsc_intutils_le8to32(keyparams->nonce + 8);
	}
}

void qsc_chacha_transform(qsc_chacha_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	size_t i;
	size_t oft;

	oft = 0U;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (length >= CHACHA_AVX512BLOCK_SIZE)
	{
		chacha_avx512_state ctxw;
		QSC_ALIGN(64) uint8_t ctrblk[64];
		__m512i tmpin;

		for (i = 0U; i < 16; ++i)
		{
			ctxw.state[i] = _mm512_set1_epi32(ctx->state[i]);
		}

		while (length >= CHACHA_AVX512BLOCK_SIZE)
		{
			/* initialize the nonce */
			ctrblk[0U] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[1] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[2] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[3] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[4] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[5] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[6] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[7] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[8] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[9] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[10] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[11] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[12] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[13] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[14] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[15] = ctx->state[12];
			chacha_increment(ctx);

			ctxw.state[12] = _mm512_set_epi32(ctrblk[0U], ctrblk[1], ctrblk[2], ctrblk[3], ctrblk[4], ctrblk[5], ctrblk[6], ctrblk[7], 
				ctrblk[8], ctrblk[9], ctrblk[10], ctrblk[11], ctrblk[12], ctrblk[13], ctrblk[14], ctrblk[15]);

			chacha_permute_p16x512h(&ctxw);

			for (i = 0U; i < 16; ++i)
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
		QSC_ALIGN(32) uint32_t ctrblk[8];
		__m256i tmpin;

		for (i = 0U; i < 16; ++i)
		{
			ctxw.state[i] = _mm256_set1_epi32(ctx->state[i]);
		}

		while (length >= CHACHA_AVX2BLOCK_SIZE)
		{
			ctrblk[0U] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[1] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[2] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[3] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[4] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[5] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[6] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[7] = ctx->state[12];
			chacha_increment(ctx);

			ctxw.state[12] = _mm256_set_epi32(ctrblk[0U], ctrblk[1], ctrblk[2], ctrblk[3], ctrblk[4], ctrblk[5], ctrblk[6], ctrblk[7]);

			chacha_permute_p8x512h(&ctxw);

			for (i = 0U; i < 16; ++i)
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
		QSC_ALIGN(16) uint32_t ctrblk[4];
		__m128i tmpin;

		for (i = 0U; i < 16; ++i)
		{
			ctxw.state[i] = _mm_set1_epi32(ctx->state[i]);
		}

		while (length >= CHACHA_AVXBLOCK_SIZE)
		{
			ctrblk[0U] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[1] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[2] = ctx->state[12];
			chacha_increment(ctx);
			ctrblk[3] = ctx->state[12];
			chacha_increment(ctx);
			ctxw.state[12] = _mm_set_epi32(ctrblk[0U], ctrblk[1], ctrblk[2], ctrblk[3]);

			chacha_permute_p4x512h(&ctxw);

			for (i = 0U; i < 16; ++i)
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

/* chacha-poly1305*/

static void chacha_poly1305_aligned_update(qsc_poly1305_state* pstate, const uint8_t* message, size_t msglen)
{
	size_t len;
	size_t oft;

	len = msglen;
	oft = 0U;

	while (len >= QSC_POLY1305_BLOCK_SIZE)
	{
		qsc_poly1305_blockupdate(pstate, message + oft);

		len -= QSC_POLY1305_BLOCK_SIZE;
		oft += QSC_POLY1305_BLOCK_SIZE;
	}

	if (len != 0U)
	{
		uint8_t pad[QSC_POLY1305_BLOCK_SIZE] = { 0U };

		qsc_memutils_copy(pad, message + oft, len);
		qsc_poly1305_blockupdate(pstate, pad);
	}
}

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

	chacha_poly1305_aligned_update(&ctx->pstate, data, datalen);
	ctx->aadlen = datalen;
}

bool qsc_chacha_poly1305_decrypt(qsc_chacha_poly1305_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	uint8_t tag[QSC_POLY1305_MAC_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;
	mlen = length - QSC_POLY1305_MAC_SIZE;
	chacha_poly1305_aligned_update(&ctx->pstate, input, mlen);
	ctx->msglen = mlen;
	chacha_poly1305_finalize(ctx, tag);

	if (qsc_intutils_verify(input + mlen, tag, QSC_POLY1305_MAC_SIZE) == 0U)
	{
		qsc_chacha_transform(&ctx->cstate, output, input, mlen);
		res = true;
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

void qsc_chacha_poly1305_initialize(qsc_chacha_poly1305_state* ctx, const qsc_chacha_keyparams* keyparams)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);

	uint8_t pkey[64] = { 0U };
	uint8_t ptxt[64] = { 0U };

	qsc_chacha_poly1305_dispose(ctx);
	qsc_chacha_initialize(&ctx->cstate, keyparams);
	qsc_chacha_transform(&ctx->cstate, pkey, ptxt, sizeof(pkey));
	qsc_poly1305_initialize(&ctx->pstate, pkey);
}

void qsc_chacha_poly1305_encrypt(qsc_chacha_poly1305_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	qsc_chacha_transform(&ctx->cstate, output, input, length);
	chacha_poly1305_aligned_update(&ctx->pstate, output, length);
	ctx->msglen = length;
	chacha_poly1305_finalize(ctx, output + length);
}


