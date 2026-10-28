#include "chacha.h"
#include "intutils.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_ARM_INTRINSICS)
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
	if (ctx->state[12U] == UINT32_MAX)
	{
		ctx->state[12U] = 0U;
		ctx->exhausted = true;
	}
	else
	{
		++ctx->state[12U];
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

#if defined(QSC_SYSTEM_ARM_INTRINSICS)

static void chacha_permute_p4x512_arm(const uint32x4_t* state, uint32x4_t* output)
{
	/* generate four ChaCha keystream blocks in NEON lanes */

	uint32x4_t x0;
	uint32x4_t x1;
	uint32x4_t x2;
	uint32x4_t x3;
	uint32x4_t x4;
	uint32x4_t x5;
	uint32x4_t x6;
	uint32x4_t x7;
	uint32x4_t x8;
	uint32x4_t x9;
	uint32x4_t x10;
	uint32x4_t x11;
	uint32x4_t x12;
	uint32x4_t x13;
	uint32x4_t x14;
	uint32x4_t x15;
	size_t ctr;

	/* note: borrows caller storage. Reentrant for independent outputs */

	x0 = state[0U];
	x1 = state[1U];
	x2 = state[2U];
	x3 = state[3U];
	x4 = state[4U];
	x5 = state[5U];
	x6 = state[6U];
	x7 = state[7U];
	x8 = state[8U];
	x9 = state[9U];
	x10 = state[10U];
	x11 = state[11U];
	x12 = state[12U];
	x13 = state[13U];
	x14 = state[14U];
	x15 = state[15U];
	ctr = QSC_CHACHA_ROUND_COUNT;

	while (ctr != 0U)
	{
		x0 = vaddq_u32(x0, x4);
		x12 = veorq_u32(x12, x0);
		x12 = vorrq_u32(vshlq_n_u32(x12, 16), vshrq_n_u32(x12, 16));
		x8 = vaddq_u32(x8, x12);
		x4 = veorq_u32(x4, x8);
		x4 = vorrq_u32(vshlq_n_u32(x4, 12), vshrq_n_u32(x4, 20));
		x0 = vaddq_u32(x0, x4);
		x12 = veorq_u32(x12, x0);
		x12 = vorrq_u32(vshlq_n_u32(x12, 8), vshrq_n_u32(x12, 24));
		x8 = vaddq_u32(x8, x12);
		x4 = veorq_u32(x4, x8);
		x4 = vorrq_u32(vshlq_n_u32(x4, 7), vshrq_n_u32(x4, 25));
		x1 = vaddq_u32(x1, x5);
		x13 = veorq_u32(x13, x1);
		x13 = vorrq_u32(vshlq_n_u32(x13, 16), vshrq_n_u32(x13, 16));
		x9 = vaddq_u32(x9, x13);
		x5 = veorq_u32(x5, x9);
		x5 = vorrq_u32(vshlq_n_u32(x5, 12), vshrq_n_u32(x5, 20));
		x1 = vaddq_u32(x1, x5);
		x13 = veorq_u32(x13, x1);
		x13 = vorrq_u32(vshlq_n_u32(x13, 8), vshrq_n_u32(x13, 24));
		x9 = vaddq_u32(x9, x13);
		x5 = veorq_u32(x5, x9);
		x5 = vorrq_u32(vshlq_n_u32(x5, 7), vshrq_n_u32(x5, 25));
		x2 = vaddq_u32(x2, x6);
		x14 = veorq_u32(x14, x2);
		x14 = vorrq_u32(vshlq_n_u32(x14, 16), vshrq_n_u32(x14, 16));
		x10 = vaddq_u32(x10, x14);
		x6 = veorq_u32(x6, x10);
		x6 = vorrq_u32(vshlq_n_u32(x6, 12), vshrq_n_u32(x6, 20));
		x2 = vaddq_u32(x2, x6);
		x14 = veorq_u32(x14, x2);
		x14 = vorrq_u32(vshlq_n_u32(x14, 8), vshrq_n_u32(x14, 24));
		x10 = vaddq_u32(x10, x14);
		x6 = veorq_u32(x6, x10);
		x6 = vorrq_u32(vshlq_n_u32(x6, 7), vshrq_n_u32(x6, 25));
		x3 = vaddq_u32(x3, x7);
		x15 = veorq_u32(x15, x3);
		x15 = vorrq_u32(vshlq_n_u32(x15, 16), vshrq_n_u32(x15, 16));
		x11 = vaddq_u32(x11, x15);
		x7 = veorq_u32(x7, x11);
		x7 = vorrq_u32(vshlq_n_u32(x7, 12), vshrq_n_u32(x7, 20));
		x3 = vaddq_u32(x3, x7);
		x15 = veorq_u32(x15, x3);
		x15 = vorrq_u32(vshlq_n_u32(x15, 8), vshrq_n_u32(x15, 24));
		x11 = vaddq_u32(x11, x15);
		x7 = veorq_u32(x7, x11);
		x7 = vorrq_u32(vshlq_n_u32(x7, 7), vshrq_n_u32(x7, 25));
		x0 = vaddq_u32(x0, x5);
		x15 = veorq_u32(x15, x0);
		x15 = vorrq_u32(vshlq_n_u32(x15, 16), vshrq_n_u32(x15, 16));
		x10 = vaddq_u32(x10, x15);
		x5 = veorq_u32(x5, x10);
		x5 = vorrq_u32(vshlq_n_u32(x5, 12), vshrq_n_u32(x5, 20));
		x0 = vaddq_u32(x0, x5);
		x15 = veorq_u32(x15, x0);
		x15 = vorrq_u32(vshlq_n_u32(x15, 8), vshrq_n_u32(x15, 24));
		x10 = vaddq_u32(x10, x15);
		x5 = veorq_u32(x5, x10);
		x5 = vorrq_u32(vshlq_n_u32(x5, 7), vshrq_n_u32(x5, 25));
		x1 = vaddq_u32(x1, x6);
		x12 = veorq_u32(x12, x1);
		x12 = vorrq_u32(vshlq_n_u32(x12, 16), vshrq_n_u32(x12, 16));
		x11 = vaddq_u32(x11, x12);
		x6 = veorq_u32(x6, x11);
		x6 = vorrq_u32(vshlq_n_u32(x6, 12), vshrq_n_u32(x6, 20));
		x1 = vaddq_u32(x1, x6);
		x12 = veorq_u32(x12, x1);
		x12 = vorrq_u32(vshlq_n_u32(x12, 8), vshrq_n_u32(x12, 24));
		x11 = vaddq_u32(x11, x12);
		x6 = veorq_u32(x6, x11);
		x6 = vorrq_u32(vshlq_n_u32(x6, 7), vshrq_n_u32(x6, 25));
		x2 = vaddq_u32(x2, x7);
		x13 = veorq_u32(x13, x2);
		x13 = vorrq_u32(vshlq_n_u32(x13, 16), vshrq_n_u32(x13, 16));
		x8 = vaddq_u32(x8, x13);
		x7 = veorq_u32(x7, x8);
		x7 = vorrq_u32(vshlq_n_u32(x7, 12), vshrq_n_u32(x7, 20));
		x2 = vaddq_u32(x2, x7);
		x13 = veorq_u32(x13, x2);
		x13 = vorrq_u32(vshlq_n_u32(x13, 8), vshrq_n_u32(x13, 24));
		x8 = vaddq_u32(x8, x13);
		x7 = veorq_u32(x7, x8);
		x7 = vorrq_u32(vshlq_n_u32(x7, 7), vshrq_n_u32(x7, 25));
		x3 = vaddq_u32(x3, x4);
		x14 = veorq_u32(x14, x3);
		x14 = vorrq_u32(vshlq_n_u32(x14, 16), vshrq_n_u32(x14, 16));
		x9 = vaddq_u32(x9, x14);
		x4 = veorq_u32(x4, x9);
		x4 = vorrq_u32(vshlq_n_u32(x4, 12), vshrq_n_u32(x4, 20));
		x3 = vaddq_u32(x3, x4);
		x14 = veorq_u32(x14, x3);
		x14 = vorrq_u32(vshlq_n_u32(x14, 8), vshrq_n_u32(x14, 24));
		x9 = vaddq_u32(x9, x14);
		x4 = veorq_u32(x4, x9);
		x4 = vorrq_u32(vshlq_n_u32(x4, 7), vshrq_n_u32(x4, 25));
		ctr -= 2U;
	}

	output[0U] = vaddq_u32(x0, state[0U]);
	output[1U] = vaddq_u32(x1, state[1U]);
	output[2U] = vaddq_u32(x2, state[2U]);
	output[3U] = vaddq_u32(x3, state[3U]);
	output[4U] = vaddq_u32(x4, state[4U]);
	output[5U] = vaddq_u32(x5, state[5U]);
	output[6U] = vaddq_u32(x6, state[6U]);
	output[7U] = vaddq_u32(x7, state[7U]);
	output[8U] = vaddq_u32(x8, state[8U]);
	output[9U] = vaddq_u32(x9, state[9U]);
	output[10U] = vaddq_u32(x10, state[10U]);
	output[11U] = vaddq_u32(x11, state[11U]);
	output[12U] = vaddq_u32(x12, state[12U]);
	output[13U] = vaddq_u32(x13, state[13U]);
	output[14U] = vaddq_u32(x14, state[14U]);
	output[15U] = vaddq_u32(x15, state[15U]);
}

#endif

#if defined(QSC_SYSTEM_HAS_AVX2)

static void chacha_xor8_avx2(uint8_t* output, const uint8_t* input, const __m256i* words)
{
	/* transpose sixteen word vectors into eight contiguous 64-byte ChaCha20 blocks */

	__m256i t[8U];
	__m256i u[8U];
	__m256i v[8U];
	__m256i x;
	size_t group;
	size_t i;

	for (group = 0U; group < 2U; ++group)
	{
		const size_t base = group * 8U;
		t[0U] = _mm256_unpacklo_epi32(words[base], words[base + 1U]);
		t[1U] = _mm256_unpackhi_epi32(words[base], words[base + 1U]);
		t[2U] = _mm256_unpacklo_epi32(words[base + 2U], words[base + 3U]);
		t[3U] = _mm256_unpackhi_epi32(words[base + 2U], words[base + 3U]);
		t[4U] = _mm256_unpacklo_epi32(words[base + 4U], words[base + 5U]);
		t[5U] = _mm256_unpackhi_epi32(words[base + 4U], words[base + 5U]);
		t[6U] = _mm256_unpacklo_epi32(words[base + 6U], words[base + 7U]);
		t[7U] = _mm256_unpackhi_epi32(words[base + 6U], words[base + 7U]);
		u[0U] = _mm256_unpacklo_epi64(t[0U], t[2U]);
		u[1U] = _mm256_unpackhi_epi64(t[0U], t[2U]);
		u[2U] = _mm256_unpacklo_epi64(t[1U], t[3U]);
		u[3U] = _mm256_unpackhi_epi64(t[1U], t[3U]);
		u[4U] = _mm256_unpacklo_epi64(t[4U], t[6U]);
		u[5U] = _mm256_unpackhi_epi64(t[4U], t[6U]);
		u[6U] = _mm256_unpacklo_epi64(t[5U], t[7U]);
		u[7U] = _mm256_unpackhi_epi64(t[5U], t[7U]);

		for (i = 0U; i < 4U; ++i)
		{
			v[i] = _mm256_permute2x128_si256(u[i], u[i + 4U], 0x20);
			v[i + 4U] = _mm256_permute2x128_si256(u[i], u[i + 4U], 0x31);
		}

		for (i = 0U; i < 8U; ++i)
		{
			x = _mm256_loadu_si256((const __m256i*)(const void*)(input + i * QSC_CHACHA_BLOCK_SIZE + group * sizeof(__m256i)));
			x = _mm256_xor_si256(x, v[i]);
			_mm256_storeu_si256((__m256i*)(void*)(output + i * QSC_CHACHA_BLOCK_SIZE + group * sizeof(__m256i)), x);
		}
	}

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(u, sizeof(u));
	qsc_memutils_secure_erase(v, sizeof(v));
}
#endif

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

#endif

#if defined(QSC_SYSTEM_HAS_AVX)

typedef struct
{
	__m128i state[16U];
	__m128i outw[16U];
} chacha_avx_state;

inline static __m128i chacha_rotl128(const __m128i x, uint32_t shift)
{
	return _mm_or_si128(_mm_slli_epi32(x, shift), _mm_srli_epi32(x, 32 - shift));
}

static void chacha_xor4_avx(uint8_t* output, const uint8_t* input, const __m128i* words)
{
	/* transpose four ChaCha word lanes into four contiguous output blocks */

	__m128i t0;
	__m128i t1;
	__m128i t2;
	__m128i t3;
	__m128i x;
	__m128i y;
	size_t group;

	for (group = 0U; group < 4U; ++group)
	{
		const size_t k = group * 4U;

		t0 = _mm_unpacklo_epi32(words[k], words[k + 1U]);
		t1 = _mm_unpackhi_epi32(words[k], words[k + 1U]);
		t2 = _mm_unpacklo_epi32(words[k + 2U], words[k + 3U]);
		t3 = _mm_unpackhi_epi32(words[k + 2U], words[k + 3U]);

		x = _mm_unpacklo_epi64(t0, t2);
		y = _mm_loadu_si128((const __m128i*)(const void*)(input + group * 16U));
		_mm_storeu_si128((__m128i*)(void*)(output + group * 16U), _mm_xor_si128(x, y));
		x = _mm_unpackhi_epi64(t0, t2);
		y = _mm_loadu_si128((const __m128i*)(const void*)(input + 64U + group * 16U));
		_mm_storeu_si128((__m128i*)(void*)(output + 64U + group * 16U), _mm_xor_si128(x, y));
		x = _mm_unpacklo_epi64(t1, t3);
		y = _mm_loadu_si128((const __m128i*)(const void*)(input + 128U + group * 16U));
		_mm_storeu_si128((__m128i*)(void*)(output + 128U + group * 16U), _mm_xor_si128(x, y));
		x = _mm_unpackhi_epi64(t1, t3);
		y = _mm_loadu_si128((const __m128i*)(const void*)(input + 192U + group * 16U));
		_mm_storeu_si128((__m128i*)(void*)(output + 192U + group * 16U), _mm_xor_si128(x, y));
	}
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
		qsc_memutils_secure_erase(ctx, sizeof(qsc_chacha_state));
	}
}

void qsc_chacha_initialize(qsc_chacha_state* ctx, const qsc_chacha_keyparams* keyparams)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);
	QSC_ASSERT(keyparams == NULL || keyparams->nonce != NULL);
	QSC_ASSERT(keyparams == NULL || keyparams->key != NULL);
	QSC_ASSERT(keyparams == NULL || (keyparams->keylen == 16U || keyparams->keylen == 32U));

	if (ctx != NULL && keyparams != NULL && keyparams->key != NULL && keyparams->nonce != NULL &&
		(keyparams->keylen == 16U || keyparams->keylen == 32U))
	{
		qsc_memutils_clear(ctx->stream, sizeof(ctx->stream));
		ctx->available = 0U;
		ctx->exhausted = false;

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
	else if (ctx != NULL)
	{
		/* invalid parameters must not leave a previous key usable. */
		qsc_chacha_dispose(ctx);
	}
}

static void chacha_transform_blocks(qsc_chacha_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
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
			__m256i lane[16U];

			for (i = 0U; i < 16U; ++i)
			{
				ctxw.state[i] = _mm512_set1_epi32(ctx->state[i]);
			}

			while (length >= CHACHA_AVX512BLOCK_SIZE)
			{
				/* expand sixteen consecutive RFC 8439 counter values into SIMD lanes. */
				for (i = 0U; i < 16U; ++i)
				{
					ctrblk[i] = ctx->state[12U];
					chacha_increment(ctx);
				}

				ctxw.state[12U] = _mm512_setr_epi32(ctrblk[0U], ctrblk[1U], ctrblk[2U], ctrblk[3U],
					ctrblk[4U], ctrblk[5U], ctrblk[6U], ctrblk[7U], ctrblk[8U], ctrblk[9U],
					ctrblk[10U], ctrblk[11U], ctrblk[12U], ctrblk[13U], ctrblk[14U], ctrblk[15U]);

				chacha_permute_p16x512h(&ctxw);

				for (i = 0U; i < 16U; ++i)
				{
					lane[i] = _mm512_castsi512_si256(ctxw.outw[i]);
				}

				chacha_xor8_avx2(output + oft, input + oft, lane);

				for (i = 0U; i < 16U; ++i)
				{
					lane[i] = _mm512_extracti64x4_epi64(ctxw.outw[i], 1);
				}

				chacha_xor8_avx2(output + oft + 8U * QSC_CHACHA_BLOCK_SIZE, input + oft + 8U * QSC_CHACHA_BLOCK_SIZE, lane);

				oft += CHACHA_AVX512BLOCK_SIZE;
				length -= CHACHA_AVX512BLOCK_SIZE;
			}

			qsc_memutils_secure_erase(&ctxw, sizeof(ctxw));
			qsc_memutils_secure_erase(lane, sizeof(lane));
		}

#elif defined(QSC_SYSTEM_HAS_AVX2)

		if (length >= CHACHA_AVX2BLOCK_SIZE)
		{
			chacha_avx2_state ctxw;
			uint32_t ctrblk[8U];

			for (i = 0U; i < 16U; ++i)
			{
				ctxw.state[i] = _mm256_set1_epi32(ctx->state[i]);
			}

			while (length >= CHACHA_AVX2BLOCK_SIZE)
			{
				for (i = 0U; i < 8U; ++i)
				{
					ctrblk[i] = ctx->state[12U];
					chacha_increment(ctx);
				}

				ctxw.state[12U] = _mm256_setr_epi32(ctrblk[0U], ctrblk[1U], ctrblk[2U], ctrblk[3U], ctrblk[4U], ctrblk[5U], ctrblk[6U], ctrblk[7U]);

				chacha_permute_p8x512h(&ctxw);
				chacha_xor8_avx2(output + oft, input + oft, ctxw.outw);

				oft += CHACHA_AVX2BLOCK_SIZE;
				length -= CHACHA_AVX2BLOCK_SIZE;
			}

			qsc_memutils_secure_erase(&ctxw, sizeof(ctxw));
		}

#endif

#if defined(QSC_SYSTEM_HAS_AVX)

		if (length >= CHACHA_AVXBLOCK_SIZE)
		{
			chacha_avx_state ctxw;
			uint32_t ctrblk[4U];

			for (i = 0U; i < 16U; ++i)
			{
				ctxw.state[i] = _mm_set1_epi32(ctx->state[i]);
			}

			while (length >= CHACHA_AVXBLOCK_SIZE)
			{
				for (i = 0U; i < 4U; ++i)
				{
					ctrblk[i] = ctx->state[12U];
					chacha_increment(ctx);
				}

				ctxw.state[12U] = _mm_setr_epi32(ctrblk[0U], ctrblk[1U], ctrblk[2U], ctrblk[3U]);

				chacha_permute_p4x512h(&ctxw);
				chacha_xor4_avx(output + oft, input + oft, ctxw.outw);

				oft += CHACHA_AVXBLOCK_SIZE;
				length -= CHACHA_AVXBLOCK_SIZE;
			}

			qsc_memutils_secure_erase(&ctxw, sizeof(ctxw));
		}

#elif defined(QSC_SYSTEM_ARM_INTRINSICS)

		if (length >= 4U * QSC_CHACHA_BLOCK_SIZE)
		{
			uint32x4_t state[CHACHA_STATE_SIZE];
			uint32x4_t stream[CHACHA_STATE_SIZE];
			uint32_t low[4U];
			uint32_t high[4U];
			uint32_t words[4U];

			for (i = 0U; i < CHACHA_STATE_SIZE; ++i)
			{
				state[i] = vdupq_n_u32(ctx->state[i]);
			}

			while (length >= 4U * QSC_CHACHA_BLOCK_SIZE)
			{
				for (size_t j = 0U; j < 4U; ++j)
				{
					low[j] = ctx->state[12U];
					high[j] = ctx->state[13U];
					chacha_increment(ctx);
				}

				state[12U] = vld1q_u32(low);
				state[13U] = vld1q_u32(high);
				chacha_permute_p4x512_arm(state, stream);

				for (i = 0U; i < CHACHA_STATE_SIZE; ++i)
				{
					for (size_t j = 0U; j < 4U; ++j)
					{
						words[j] = qsc_intutils_le8to32(input + oft + (j * QSC_CHACHA_BLOCK_SIZE) + (i * 4U));
					}

					vst1q_u32(words, veorq_u32(vld1q_u32(words), stream[i]));

					for (size_t j = 0U; j < 4U; ++j)
					{
						qsc_intutils_le32to8(output + oft + (j * QSC_CHACHA_BLOCK_SIZE) + (i * 4U), words[j]);
					}
				}

				oft += 4U * QSC_CHACHA_BLOCK_SIZE;
				length -= 4U * QSC_CHACHA_BLOCK_SIZE;
			}

			qsc_memutils_secure_erase(state, sizeof(state));
			qsc_memutils_secure_erase(stream, sizeof(stream));
			qsc_memutils_secure_erase(words, sizeof(words));
		}

#endif

		if (length != 0U)
		{
			while (length >= QSC_CHACHA_BLOCK_SIZE)
			{
				uint8_t block[QSC_CHACHA_BLOCK_SIZE];

				chacha_permute_p512c(ctx, block);
				chacha_increment(ctx);

				for (i = 0U; i < QSC_CHACHA_BLOCK_SIZE; ++i)
				{
					output[oft + i] = input[oft + i] ^ block[i];
				}

				qsc_memutils_secure_erase(block, sizeof(block));
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

				qsc_memutils_secure_erase(tmp, sizeof(tmp));
			}
		}
	}
}

static bool chacha_has_capacity(const qsc_chacha_state* ctx, size_t length)
{
	/* validate a requested stream length without advancing cipher state */
	uint64_t blocks;
	uint64_t needed;
	bool res;

	res = false;

	if (ctx != NULL &&
		ctx->state[0U] == UINT32_C(0x61707865) &&
		((ctx->state[1U] == UINT32_C(0x3320646E) && ctx->state[2U] == UINT32_C(0x79622D32)) ||
		 (ctx->state[1U] == UINT32_C(0x3120646E) && ctx->state[2U] == UINT32_C(0x79622D36))) &&
		ctx->state[3U] == UINT32_C(0x6B206574) &&
		ctx->available <= QSC_CHACHA_BLOCK_SIZE)
	{
		needed = (length > ctx->available) ? (uint64_t)(length - ctx->available) : 0U;
		blocks = (needed / QSC_CHACHA_BLOCK_SIZE) + ((needed % QSC_CHACHA_BLOCK_SIZE) != 0U ? 1U : 0U);
		res = blocks == 0U || (!ctx->exhausted && blocks <= (uint64_t)UINT32_MAX - (uint64_t)ctx->state[12U] + 1U);
	}

	return res;
}

bool qsc_chacha_transform_checked(qsc_chacha_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	uint8_t tmp[QSC_CHACHA_BLOCK_SIZE] = { 0U };
	size_t count;
	size_t i;
	size_t offset;
	bool res;

	res = false;

	if (ctx != NULL && (length == 0U || (output != NULL && input != NULL)))
	{
		if (chacha_has_capacity(ctx, length))
		{
			res = true;
			offset = 0U;

			if (ctx->available != 0U && length != 0U)
			{
				count = (length < ctx->available) ? length : ctx->available;

				for (i = 0U; i < count; ++i)
				{
					output[i] = input[i] ^ ctx->stream[QSC_CHACHA_BLOCK_SIZE - ctx->available + i];
				}

				qsc_memutils_secure_erase(ctx->stream + QSC_CHACHA_BLOCK_SIZE - ctx->available, count);
				ctx->available -= count;
				offset += count;
			}

			if (length - offset >= QSC_CHACHA_BLOCK_SIZE)
			{
				count = (length - offset) & ~(size_t)(QSC_CHACHA_BLOCK_SIZE - 1U);
				chacha_transform_blocks(ctx, output + offset, input + offset, count);
				offset += count;
			}

			if (length != offset)
			{
				count = length - offset;
				chacha_permute_p512c(ctx, tmp);
				chacha_increment(ctx);

				for (i = 0U; i < count; ++i)
				{
					output[offset + i] = input[offset + i] ^ tmp[i];
				}

				qsc_memutils_copy(ctx->stream, tmp, sizeof(tmp));
				qsc_memutils_secure_erase(ctx->stream, count);
				ctx->available = QSC_CHACHA_BLOCK_SIZE - count;
			}
		}
	}

	qsc_memutils_secure_erase(tmp, sizeof(tmp));

	return res;
}

void qsc_chacha_transform(qsc_chacha_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	if (!qsc_chacha_transform_checked(ctx, output, input, length) && output != NULL && length != 0U)
	{
		qsc_memutils_clear(output, length);
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
	size_t rem;

	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(data != NULL || datalen == 0U);

	if (ctx != NULL && (data != NULL || datalen == 0U) && chacha_has_capacity(&ctx->cstate, 0U))
	{
		if (datalen != 0U)
		{
			qsc_poly1305_update(&ctx->pstate, data, datalen);
		}

		ctx->aadlen = datalen;
		rem = datalen & (QSC_POLY1305_BLOCK_SIZE - 1U);

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

	if (ctx != NULL && output != NULL && input != NULL && length >= QSC_POLY1305_MAC_SIZE &&
		chacha_has_capacity(&ctx->cstate, length - QSC_POLY1305_MAC_SIZE))
	{
		uint8_t tag[QSC_POLY1305_MAC_SIZE] = { 0U };
		const size_t mlen = length - QSC_POLY1305_MAC_SIZE;

		qsc_poly1305_update(&ctx->pstate, input, mlen);
		ctx->msglen = mlen;

		/* RFC 8439 2.8: zero-pad ciphertext to 16-byte boundary */
		const size_t rem = mlen & 15U;

		if (rem != 0U)
		{
			uint8_t pad[QSC_POLY1305_BLOCK_SIZE] = { 0U };
			qsc_poly1305_update(&ctx->pstate, pad, QSC_POLY1305_BLOCK_SIZE - rem);
		}

		chacha_poly1305_finalize(ctx, tag);

		if (qsc_intutils_verify(input + mlen, tag, QSC_POLY1305_MAC_SIZE) == 0U)
		{
			res = qsc_chacha_transform_checked(&ctx->cstate, output, input, mlen);
		}

		qsc_memutils_secure_erase(tag, sizeof(tag));
		qsc_chacha_poly1305_dispose(ctx);
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

bool qsc_chacha_poly1305_encrypt_checked(qsc_chacha_poly1305_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL || length == 0U);

	bool res;

	res = false;

	if (ctx != NULL && output != NULL && (input != NULL || length == 0U) &&
		length <= SIZE_MAX - QSC_POLY1305_MAC_SIZE &&
		chacha_has_capacity(&ctx->cstate, length))
	{
		res = true;
		if (length != 0U)
		{
			/* process one record in a contiguous cipher/MAC operation.
			 * This amortizes Poly1305 SIMD setup over the entire record and
			 * avoids reinitializing its private four-lane powers per 4 KiB. */
			qsc_chacha_transform(&ctx->cstate, output, input, length);
			qsc_poly1305_update(&ctx->pstate, output, length);
		}
		ctx->msglen = length;

		/* RFC 8439 2.8: zero-pad ciphertext to 16-byte boundary */
		const size_t rem = length & 15U;

		if (rem != 0U)
		{
			uint8_t pad[QSC_POLY1305_BLOCK_SIZE] = { 0U };

			qsc_poly1305_update(&ctx->pstate, pad, QSC_POLY1305_BLOCK_SIZE - rem);
		}

		chacha_poly1305_finalize(ctx, output + length);
		qsc_chacha_poly1305_dispose(ctx);
	}

	return res;
}

void qsc_chacha_poly1305_encrypt(qsc_chacha_poly1305_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	if (!qsc_chacha_poly1305_encrypt_checked(ctx, output, input, length) &&
		output != NULL && length <= SIZE_MAX - QSC_POLY1305_MAC_SIZE)
	{
		qsc_memutils_clear(output, length + QSC_POLY1305_MAC_SIZE);
	}
}

void qsc_chacha_poly1305_initialize(qsc_chacha_poly1305_state* ctx, const qsc_chacha_keyparams* keyparams)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);
	QSC_ASSERT(keyparams == NULL || keyparams->key != NULL);
	QSC_ASSERT(keyparams == NULL || keyparams->nonce != NULL);
	QSC_ASSERT(keyparams == NULL || (keyparams->keylen == QSC_CHACHA_KEY128_SIZE || keyparams->keylen == QSC_CHACHA_KEY256_SIZE));

	if (ctx != NULL)
	{
		qsc_chacha_poly1305_dispose(ctx);

		if (keyparams != NULL && keyparams->key != NULL && keyparams->nonce != NULL &&
			(keyparams->keylen == QSC_CHACHA_KEY128_SIZE || keyparams->keylen == QSC_CHACHA_KEY256_SIZE))
		{
			uint8_t pkey[QSC_CHACHA_BLOCK_SIZE] = { 0U };

			qsc_chacha_initialize(&ctx->cstate, keyparams);
			/* derive the one-time Poly1305 key from ChaCha20 counter zero. */
			chacha_permute_p512c(&ctx->cstate, pkey);
			chacha_increment(&ctx->cstate);
			qsc_poly1305_initialize(&ctx->pstate, pkey);
			qsc_memutils_secure_erase(pkey, sizeof(pkey));
		}
	}
}


