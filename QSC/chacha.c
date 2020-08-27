#include "chacha.h"
#include "intutils.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_HAS_AVX)
#	include "intrinsics.h"
#endif

/*!
* \def QSC_CHACHA_BLOCK_SIZE
* \brief The natural block size of the message input
*/
#define QSC_CHACHA_BLOCK_SIZE 64

/*!
* \def QSC_CHACHA_STATE_SIZE
* \brief The size of the states internal array in 32-bit integers
*/
#define QSC_CHACHA_STATE_SIZE 16

#if defined(QSC_SYSTEM_HAS_AVX)
/*!
* \def QSC_CHACHA_AVXBLOCK_SIZE
* The minimum block size used to trigger AVX processing
*/
#	define QSC_CHACHA_AVXBLOCK_SIZE (4 * QSC_CHACHA_BLOCK_SIZE)
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
/*!
* \def QSC_CHACHA_AVX2BLOCK_SIZE
* The minimum block size used to trigger AVX2 processing
*/
#	define QSC_CHACHA_AVX2BLOCK_SIZE (8 * QSC_CHACHA_BLOCK_SIZE)
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
/*!
* \def QSC_CHACHA_AVX512BLOCK_SIZE
* The minimum block size used to trigger AVX512 processing
*/
#	define QSC_CHACHA_AVX512BLOCK_SIZE (16 * QSC_CHACHA_BLOCK_SIZE)
#endif

/*!
* \def QSC_CHACHA_ROUND_COUNT
* \brief The number of mixing rounds used by ChaCha
*/
#define QSC_CHACHA_ROUND_COUNT 20

static void chacha_increment(qsc_chacha_state* ctx)
{
	if (++ctx->state[12] == 0)
	{
		++ctx->state[13];
	}
}

static void chacha_permute_p512c(qsc_chacha_state* ctx, uint8_t* output)
{
	uint32_t X0 = ctx->state[0];
	uint32_t X1 = ctx->state[1];
	uint32_t X2 = ctx->state[2];
	uint32_t X3 = ctx->state[3];
	uint32_t X4 = ctx->state[4];
	uint32_t X5 = ctx->state[5];
	uint32_t X6 = ctx->state[6];
	uint32_t X7 = ctx->state[7];
	uint32_t X8 = ctx->state[8];
	uint32_t X9 = ctx->state[9];
	uint32_t X10 = ctx->state[10];
	uint32_t X11 = ctx->state[11];
	uint32_t X12 = ctx->state[12];
	uint32_t X13 = ctx->state[13];
	uint32_t X14 = ctx->state[14];
	uint32_t X15 = ctx->state[15];
	size_t ctr = 20;

	while (ctr != 0)
	{
		X0 += X4;
		X12 = qsc_intutils_rotl32(X12 ^ X0, 16);
		X8 += X12;
		X4 = qsc_intutils_rotl32(X4 ^ X8, 12);
		X0 += X4;
		X12 = qsc_intutils_rotl32(X12 ^ X0, 8);
		X8 += X12;
		X4 = qsc_intutils_rotl32(X4 ^ X8, 7);
		X1 += X5;
		X13 = qsc_intutils_rotl32(X13 ^ X1, 16);
		X9 += X13;
		X5 = qsc_intutils_rotl32(X5 ^ X9, 12);
		X1 += X5;
		X13 = qsc_intutils_rotl32(X13 ^ X1, 8);
		X9 += X13;
		X5 = qsc_intutils_rotl32(X5 ^ X9, 7);
		X2 += X6;
		X14 = qsc_intutils_rotl32(X14 ^ X2, 16);
		X10 += X14;
		X6 = qsc_intutils_rotl32(X6 ^ X10, 12);
		X2 += X6;
		X14 = qsc_intutils_rotl32(X14 ^ X2, 8);
		X10 += X14;
		X6 = qsc_intutils_rotl32(X6 ^ X10, 7);
		X3 += X7;
		X15 = qsc_intutils_rotl32(X15 ^ X3, 16);
		X11 += X15;
		X7 = qsc_intutils_rotl32(X7 ^ X11, 12);
		X3 += X7;
		X15 = qsc_intutils_rotl32(X15 ^ X3, 8);
		X11 += X15;
		X7 = qsc_intutils_rotl32(X7 ^ X11, 7);
		X0 += X5;
		X15 = qsc_intutils_rotl32(X15 ^ X0, 16);
		X10 += X15;
		X5 = qsc_intutils_rotl32(X5 ^ X10, 12);
		X0 += X5;
		X15 = qsc_intutils_rotl32(X15 ^ X0, 8);
		X10 += X15;
		X5 = qsc_intutils_rotl32(X5 ^ X10, 7);
		X1 += X6;
		X12 = qsc_intutils_rotl32(X12 ^ X1, 16);
		X11 += X12;
		X6 = qsc_intutils_rotl32(X6 ^ X11, 12);
		X1 += X6;
		X12 = qsc_intutils_rotl32(X12 ^ X1, 8);
		X11 += X12;
		X6 = qsc_intutils_rotl32(X6 ^ X11, 7);
		X2 += X7;
		X13 = qsc_intutils_rotl32(X13 ^ X2, 16);
		X8 += X13;
		X7 = qsc_intutils_rotl32(X7 ^ X8, 12);
		X2 += X7;
		X13 = qsc_intutils_rotl32(X13 ^ X2, 8);
		X8 += X13;
		X7 = qsc_intutils_rotl32(X7 ^ X8, 7);
		X3 += X4;
		X14 = qsc_intutils_rotl32(X14 ^ X3, 16);
		X9 += X14;
		X4 = qsc_intutils_rotl32(X4 ^ X9, 12);
		X3 += X4;
		X14 = qsc_intutils_rotl32(X14 ^ X3, 8);
		X9 += X14;
		X4 = qsc_intutils_rotl32(X4 ^ X9, 7);
		ctr -= 2;
	}

	qsc_intutils_le32to8(output, X0 + ctx->state[0]);
	qsc_intutils_le32to8(output + 4, X1 + ctx->state[1]);
	qsc_intutils_le32to8(output + 8, X2 + ctx->state[2]);
	qsc_intutils_le32to8(output + 12, X3 + ctx->state[3]);
	qsc_intutils_le32to8(output + 16, X4 + ctx->state[4]);
	qsc_intutils_le32to8(output + 20, X5 + ctx->state[5]);
	qsc_intutils_le32to8(output + 24, X6 + ctx->state[6]);
	qsc_intutils_le32to8(output + 28, X7 + ctx->state[7]);
	qsc_intutils_le32to8(output + 32, X8 + ctx->state[8]);
	qsc_intutils_le32to8(output + 36, X9 + ctx->state[9]);
	qsc_intutils_le32to8(output + 40, X10 + ctx->state[10]);
	qsc_intutils_le32to8(output + 44, X11 + ctx->state[11]);
	qsc_intutils_le32to8(output + 48, X12 + ctx->state[12]);
	qsc_intutils_le32to8(output + 52, X13 + ctx->state[13]);
	qsc_intutils_le32to8(output + 56, X14 + ctx->state[14]);
	qsc_intutils_le32to8(output + 60, X15 + ctx->state[15]);
}

#if defined(QSC_SYSTEM_HAS_AVX512)

typedef struct
{
	__m512i state[16];
	__m512i outw[16];
} chacha_avx512_state;

static __m512i chacha_rotl512(const __m512i x, size_t shift)
{
	return _mm512_or_si512(_mm512_slli_epi32(x, shift), _mm512_srli_epi32(x, 32 - shift));
}

static __m512i chacha_load512(const void* a)
{
	const uint32_t* a32 = a;
	return _mm512_set_epi32(a32[0], a32[16], a32[32], a32[48], a32[64], a32[80], a32[96], a32[112], a32[128], a32[144], a32[160], a32[176], a32[192], a32[208], a32[224], a32[240]);
}

static void chacha_store512(uint8_t* output, const __m512i x)
{
	uint8_t tmp[64];

	_mm512_storeu_si512((__m512i*)tmp, x);

	memcpy(output, tmp + 60, 4);
	memcpy(output + 64, tmp + 56, 4);
	memcpy(output + 128, tmp + 52, 4);
	memcpy(output + 192, tmp + 48, 4);
	memcpy(output + 256, tmp + 44, 4);
	memcpy(output + 320, tmp + 40, 4);
	memcpy(output + 384, tmp + 36, 4);
	memcpy(output + 448, tmp + 32, 4);
	memcpy(output + 512, tmp + 28, 4);
	memcpy(output + 576, tmp + 24, 4);
	memcpy(output + 640, tmp + 20, 4);
	memcpy(output + 704, tmp + 16, 4);
	memcpy(output + 768, tmp + 12, 4);
	memcpy(output + 832, tmp + 8, 4);
	memcpy(output + 896, tmp + 4, 4);
	memcpy(output + 960, tmp, 4);
}

static void chacha_permute_p16x512h(chacha_avx512_state* ctxw)
{
	__m512i X0 = ctxw->state[0];
	__m512i X1 = ctxw->state[1];
	__m512i X2 = ctxw->state[2];
	__m512i X3 = ctxw->state[3];
	__m512i X4 = ctxw->state[4];
	__m512i X5 = ctxw->state[5];
	__m512i X6 = ctxw->state[6];
	__m512i X7 = ctxw->state[7];
	__m512i X8 = ctxw->state[8];
	__m512i X9 = ctxw->state[9];
	__m512i X10 = ctxw->state[10];
	__m512i X11 = ctxw->state[11];
	__m512i X12 = ctxw->state[12];
	__m512i X13 = ctxw->state[13];
	__m512i X14 = ctxw->state[14];
	__m512i X15 = ctxw->state[15];

	size_t ctr = QSC_CHACHA_ROUND_COUNT;

	while (ctr != 0)
	{
		X0 = _mm512_add_epi32(X0, X4);
		X12 = chacha_rotl512(_mm512_xor_si512(X12, X0), 16);
		X8 = _mm512_add_epi32(X8, X12);
		X4 = chacha_rotl512(_mm512_xor_si512(X4, X8), 12);
		X0 = _mm512_add_epi32(X0, X4);
		X12 = chacha_rotl512(_mm512_xor_si512(X12, X0), 8);
		X8 = _mm512_add_epi32(X8, X12);
		X4 = chacha_rotl512(_mm512_xor_si512(X4, X8), 7);
		X1 = _mm512_add_epi32(X1, X5);
		X13 = chacha_rotl512(_mm512_xor_si512(X13, X1), 16);
		X9 = _mm512_add_epi32(X9, X13);
		X5 = chacha_rotl512(_mm512_xor_si512(X5, X9), 12);
		X1 = _mm512_add_epi32(X1, X5);
		X13 = chacha_rotl512(_mm512_xor_si512(X13, X1), 8);
		X9 = _mm512_add_epi32(X9, X13);
		X5 = chacha_rotl512(_mm512_xor_si512(X5, X9), 7);
		X2 = _mm512_add_epi32(X2, X6);
		X14 = chacha_rotl512(_mm512_xor_si512(X14, X2), 16);
		X10 = _mm512_add_epi32(X10, X14);
		X6 = chacha_rotl512(_mm512_xor_si512(X6, X10), 12);
		X2 = _mm512_add_epi32(X2, X6);
		X14 = chacha_rotl512(_mm512_xor_si512(X14, X2), 8);
		X10 = _mm512_add_epi32(X10, X14);
		X6 = chacha_rotl512(_mm512_xor_si512(X6, X10), 7);
		X3 = _mm512_add_epi32(X3, X7);
		X15 = chacha_rotl512(_mm512_xor_si512(X15, X3), 16);
		X11 = _mm512_add_epi32(X11, X15);
		X7 = chacha_rotl512(_mm512_xor_si512(X7, X11), 12);
		X3 = _mm512_add_epi32(X3, X7);
		X15 = chacha_rotl512(_mm512_xor_si512(X15, X3), 8);
		X11 = _mm512_add_epi32(X11, X15);
		X7 = chacha_rotl512(_mm512_xor_si512(X7, X11), 7);
		X0 = _mm512_add_epi32(X0, X5);
		X15 = chacha_rotl512(_mm512_xor_si512(X15, X0), 16);
		X10 = _mm512_add_epi32(X10, X15);
		X5 = chacha_rotl512(_mm512_xor_si512(X5, X10), 12);
		X0 = _mm512_add_epi32(X0, X5);
		X15 = chacha_rotl512(_mm512_xor_si512(X15, X0), 8);
		X10 = _mm512_add_epi32(X10, X15);
		X5 = chacha_rotl512(_mm512_xor_si512(X5, X10), 7);
		X1 = _mm512_add_epi32(X1, X6);
		X12 = chacha_rotl512(_mm512_xor_si512(X12, X1), 16);
		X11 = _mm512_add_epi32(X11, X12);
		X6 = chacha_rotl512(_mm512_xor_si512(X6, X11), 12);
		X1 = _mm512_add_epi32(X1, X6);
		X12 = chacha_rotl512(_mm512_xor_si512(X12, X1), 8);
		X11 = _mm512_add_epi32(X11, X12);
		X6 = chacha_rotl512(_mm512_xor_si512(X6, X11), 7);
		X2 = _mm512_add_epi32(X2, X7);
		X13 = chacha_rotl512(_mm512_xor_si512(X13, X2), 16);
		X8 = _mm512_add_epi32(X8, X13);
		X7 = chacha_rotl512(_mm512_xor_si512(X7, X8), 12);
		X2 = _mm512_add_epi32(X2, X7);
		X13 = chacha_rotl512(_mm512_xor_si512(X13, X2), 8);
		X8 = _mm512_add_epi32(X8, X13);
		X7 = chacha_rotl512(_mm512_xor_si512(X7, X8), 7);
		X3 = _mm512_add_epi32(X3, X4);
		X14 = chacha_rotl512(_mm512_xor_si512(X14, X3), 16);
		X9 = _mm512_add_epi32(X9, X14);
		X4 = chacha_rotl512(_mm512_xor_si512(X4, X9), 12);
		X3 = _mm512_add_epi32(X3, X4);
		X14 = chacha_rotl512(_mm512_xor_si512(X14, X3), 8);
		X9 = _mm512_add_epi32(X9, X14);
		X4 = chacha_rotl512(_mm512_xor_si512(X4, X9), 7);
		ctr -= 2;
	}

	ctxw->outw[0] = _mm512_add_epi32(X0, ctxw->state[0]);
	ctxw->outw[1] = _mm512_add_epi32(X1, ctxw->state[1]);
	ctxw->outw[2] = _mm512_add_epi32(X2, ctxw->state[2]);
	ctxw->outw[3] = _mm512_add_epi32(X3, ctxw->state[3]);
	ctxw->outw[4] = _mm512_add_epi32(X4, ctxw->state[4]);
	ctxw->outw[5] = _mm512_add_epi32(X5, ctxw->state[5]);
	ctxw->outw[6] = _mm512_add_epi32(X6, ctxw->state[6]);
	ctxw->outw[7] = _mm512_add_epi32(X7, ctxw->state[7]);
	ctxw->outw[8] = _mm512_add_epi32(X8, ctxw->state[8]);
	ctxw->outw[9] = _mm512_add_epi32(X9, ctxw->state[9]);
	ctxw->outw[10] = _mm512_add_epi32(X10, ctxw->state[10]);
	ctxw->outw[11] = _mm512_add_epi32(X11, ctxw->state[11]);
	ctxw->outw[12] = _mm512_add_epi32(X12, ctxw->state[12]);
	ctxw->outw[13] = _mm512_add_epi32(X13, ctxw->state[13]);
	ctxw->outw[14] = _mm512_add_epi32(X14, ctxw->state[14]);
	ctxw->outw[15] = _mm512_add_epi32(X15, ctxw->state[15]);
}

#elif defined(QSC_SYSTEM_HAS_AVX2)

typedef struct
{
	__m256i state[16];
	__m256i outw[16];
} chacha_avx2_state;

static __m256i chacha_rotl256(const __m256i x, size_t shift)
{
	return _mm256_or_si256(_mm256_slli_epi32(x, (int)shift), _mm256_srli_epi32(x, 32 - (int)shift));
}

static __m256i chacha_load256(const void* a)
{
	const uint32_t* a32 = a;
	return _mm256_set_epi32(a32[0], a32[16], a32[32], a32[48], a32[64], a32[80], a32[96], a32[112]);
}

static void chacha_store256(uint8_t* output, const __m256i x)
{
	uint8_t tmp[32];

	_mm256_storeu_si256((__m256i*)tmp, x);

	memcpy(output, tmp + 28, 4);
	memcpy(output + 64, tmp + 24, 4);
	memcpy(output + 128, tmp + 20, 4);
	memcpy(output + 192, tmp + 16, 4);
	memcpy(output + 256, tmp + 12, 4);
	memcpy(output + 320, tmp + 8, 4);
	memcpy(output + 384, tmp + 4, 4);
	memcpy(output + 448, tmp, 4);
}

static void chacha_permute_p8x512h(chacha_avx2_state* ctxw)
{
	__m256i X0 = ctxw->state[0];
	__m256i X1 = ctxw->state[1];
	__m256i X2 = ctxw->state[2];
	__m256i X3 = ctxw->state[3];
	__m256i X4 = ctxw->state[4];
	__m256i X5 = ctxw->state[5];
	__m256i X6 = ctxw->state[6];
	__m256i X7 = ctxw->state[7];
	__m256i X8 = ctxw->state[8];
	__m256i X9 = ctxw->state[9];
	__m256i X10 = ctxw->state[10];
	__m256i X11 = ctxw->state[11];
	__m256i X12 = ctxw->state[12];
	__m256i X13 = ctxw->state[13];
	__m256i X14 = ctxw->state[14];
	__m256i X15 = ctxw->state[15];

	size_t ctr = 20;

	while (ctr != 0)
	{
		X0 = _mm256_add_epi32(X0, X4);
		X12 = chacha_rotl256(_mm256_xor_si256(X12, X0), 16);
		X8 = _mm256_add_epi32(X8, X12);
		X4 = chacha_rotl256(_mm256_xor_si256(X4, X8), 12);
		X0 = _mm256_add_epi32(X0, X4);
		X12 = chacha_rotl256(_mm256_xor_si256(X12, X0), 8);
		X8 = _mm256_add_epi32(X8, X12);
		X4 = chacha_rotl256(_mm256_xor_si256(X4, X8), 7);
		X1 = _mm256_add_epi32(X1, X5);
		X13 = chacha_rotl256(_mm256_xor_si256(X13, X1), 16);
		X9 = _mm256_add_epi32(X9, X13);
		X5 = chacha_rotl256(_mm256_xor_si256(X5, X9), 12);
		X1 = _mm256_add_epi32(X1, X5);
		X13 = chacha_rotl256(_mm256_xor_si256(X13, X1), 8);
		X9 = _mm256_add_epi32(X9, X13);
		X5 = chacha_rotl256(_mm256_xor_si256(X5, X9), 7);
		X2 = _mm256_add_epi32(X2, X6);
		X14 = chacha_rotl256(_mm256_xor_si256(X14, X2), 16);
		X10 = _mm256_add_epi32(X10, X14);
		X6 = chacha_rotl256(_mm256_xor_si256(X6, X10), 12);
		X2 = _mm256_add_epi32(X2, X6);
		X14 = chacha_rotl256(_mm256_xor_si256(X14, X2), 8);
		X10 = _mm256_add_epi32(X10, X14);
		X6 = chacha_rotl256(_mm256_xor_si256(X6, X10), 7);
		X3 = _mm256_add_epi32(X3, X7);
		X15 = chacha_rotl256(_mm256_xor_si256(X15, X3), 16);
		X11 = _mm256_add_epi32(X11, X15);
		X7 = chacha_rotl256(_mm256_xor_si256(X7, X11), 12);
		X3 = _mm256_add_epi32(X3, X7);
		X15 = chacha_rotl256(_mm256_xor_si256(X15, X3), 8);
		X11 = _mm256_add_epi32(X11, X15);
		X7 = chacha_rotl256(_mm256_xor_si256(X7, X11), 7);
		X0 = _mm256_add_epi32(X0, X5);
		X15 = chacha_rotl256(_mm256_xor_si256(X15, X0), 16);
		X10 = _mm256_add_epi32(X10, X15);
		X5 = chacha_rotl256(_mm256_xor_si256(X5, X10), 12);
		X0 = _mm256_add_epi32(X0, X5);
		X15 = chacha_rotl256(_mm256_xor_si256(X15, X0), 8);
		X10 = _mm256_add_epi32(X10, X15);
		X5 = chacha_rotl256(_mm256_xor_si256(X5, X10), 7);
		X1 = _mm256_add_epi32(X1, X6);
		X12 = chacha_rotl256(_mm256_xor_si256(X12, X1), 16);
		X11 = _mm256_add_epi32(X11, X12);
		X6 = chacha_rotl256(_mm256_xor_si256(X6, X11), 12);
		X1 = _mm256_add_epi32(X1, X6);
		X12 = chacha_rotl256(_mm256_xor_si256(X12, X1), 8);
		X11 = _mm256_add_epi32(X11, X12);
		X6 = chacha_rotl256(_mm256_xor_si256(X6, X11), 7);
		X2 = _mm256_add_epi32(X2, X7);
		X13 = chacha_rotl256(_mm256_xor_si256(X13, X2), 16);
		X8 = _mm256_add_epi32(X8, X13);
		X7 = chacha_rotl256(_mm256_xor_si256(X7, X8), 12);
		X2 = _mm256_add_epi32(X2, X7);
		X13 = chacha_rotl256(_mm256_xor_si256(X13, X2), 8);
		X8 = _mm256_add_epi32(X8, X13);
		X7 = chacha_rotl256(_mm256_xor_si256(X7, X8), 7);
		X3 = _mm256_add_epi32(X3, X4);
		X14 = chacha_rotl256(_mm256_xor_si256(X14, X3), 16);
		X9 = _mm256_add_epi32(X9, X14);
		X4 = chacha_rotl256(_mm256_xor_si256(X4, X9), 12);
		X3 = _mm256_add_epi32(X3, X4);
		X14 = chacha_rotl256(_mm256_xor_si256(X14, X3), 8);
		X9 = _mm256_add_epi32(X9, X14);
		X4 = chacha_rotl256(_mm256_xor_si256(X4, X9), 7);
		ctr -= 2;
	}

	ctxw->outw[0] = _mm256_add_epi32(X0, ctxw->state[0]);
	ctxw->outw[1] = _mm256_add_epi32(X1, ctxw->state[1]);
	ctxw->outw[2] = _mm256_add_epi32(X2, ctxw->state[2]);
	ctxw->outw[3] = _mm256_add_epi32(X3, ctxw->state[3]);
	ctxw->outw[4] = _mm256_add_epi32(X4, ctxw->state[4]);
	ctxw->outw[5] = _mm256_add_epi32(X5, ctxw->state[5]);
	ctxw->outw[6] = _mm256_add_epi32(X6, ctxw->state[6]);
	ctxw->outw[7] = _mm256_add_epi32(X7, ctxw->state[7]);
	ctxw->outw[8] = _mm256_add_epi32(X8, ctxw->state[8]);
	ctxw->outw[9] = _mm256_add_epi32(X9, ctxw->state[9]);
	ctxw->outw[10] = _mm256_add_epi32(X10, ctxw->state[10]);
	ctxw->outw[11] = _mm256_add_epi32(X11, ctxw->state[11]);
	ctxw->outw[12] = _mm256_add_epi32(X12, ctxw->state[12]);
	ctxw->outw[13] = _mm256_add_epi32(X13, ctxw->state[13]);
	ctxw->outw[14] = _mm256_add_epi32(X14, ctxw->state[14]);
	ctxw->outw[15] = _mm256_add_epi32(X15, ctxw->state[15]);
}

#elif defined(QSC_SYSTEM_HAS_AVX)

typedef struct
{
	__m128i state[16];
	__m128i outw[16];
} chacha_avx_state;

static __m128i chacha_rotl128(const __m128i x, size_t shift)
{
	return _mm_or_si128(_mm_slli_epi32(x, shift), _mm_srli_epi32(x, 32 - shift));
}

static __m128i chacha_load128(const void* a)
{
	const uint32_t* a32 = a;
	return _mm_set_epi32(a32[0], a32[16], a32[32], a32[48]);
}

static void chacha_store128(uint8_t* output, const __m128i x)
{
	uint8_t tmp[16];

	_mm_storeu_si128((__m128i*)tmp, x);

	memcpy(output, tmp + 12, 4);
	memcpy(output + 64, tmp + 8, 4);
	memcpy(output + 128, tmp + 4, 4);
	memcpy(output + 192, tmp, 4);
}

static void chacha_permute_p4x512h(chacha_avx_state* ctxw)
{
	__m128i X0 = ctxw->state[0];
	__m128i X1 = ctxw->state[1];
	__m128i X2 = ctxw->state[2];
	__m128i X3 = ctxw->state[3];
	__m128i X4 = ctxw->state[4];
	__m128i X5 = ctxw->state[5];
	__m128i X6 = ctxw->state[6];
	__m128i X7 = ctxw->state[7];
	__m128i X8 = ctxw->state[8];
	__m128i X9 = ctxw->state[9];
	__m128i X10 = ctxw->state[10];
	__m128i X11 = ctxw->state[11];
	__m128i X12 = ctxw->state[12];
	__m128i X13 = ctxw->state[13];
	__m128i X14 = ctxw->state[14];
	__m128i X15 = ctxw->state[15];

	size_t ctr = 20;

	while (ctr != 0)
	{
		X0 = _mm_add_epi32(X0, X4);
		X12 = chacha_rotl128(_mm_xor_si128(X12, X0), 16);
		X8 = _mm_add_epi32(X8, X12);
		X4 = chacha_rotl128(_mm_xor_si128(X4, X8), 12);
		X0 = _mm_add_epi32(X0, X4);
		X12 = chacha_rotl128(_mm_xor_si128(X12, X0), 8);
		X8 = _mm_add_epi32(X8, X12);
		X4 = chacha_rotl128(_mm_xor_si128(X4, X8), 7);
		X1 = _mm_add_epi32(X1, X5);
		X13 = chacha_rotl128(_mm_xor_si128(X13, X1), 16);
		X9 = _mm_add_epi32(X9, X13);
		X5 = chacha_rotl128(_mm_xor_si128(X5, X9), 12);
		X1 = _mm_add_epi32(X1, X5);
		X13 = chacha_rotl128(_mm_xor_si128(X13, X1), 8);
		X9 = _mm_add_epi32(X9, X13);
		X5 = chacha_rotl128(_mm_xor_si128(X5, X9), 7);
		X2 = _mm_add_epi32(X2, X6);
		X14 = chacha_rotl128(_mm_xor_si128(X14, X2), 16);
		X10 = _mm_add_epi32(X10, X14);
		X6 = chacha_rotl128(_mm_xor_si128(X6, X10), 12);
		X2 = _mm_add_epi32(X2, X6);
		X14 = chacha_rotl128(_mm_xor_si128(X14, X2), 8);
		X10 = _mm_add_epi32(X10, X14);
		X6 = chacha_rotl128(_mm_xor_si128(X6, X10), 7);
		X3 = _mm_add_epi32(X3, X7);
		X15 = chacha_rotl128(_mm_xor_si128(X15, X3), 16);
		X11 = _mm_add_epi32(X11, X15);
		X7 = chacha_rotl128(_mm_xor_si128(X7, X11), 12);
		X3 = _mm_add_epi32(X3, X7);
		X15 = chacha_rotl128(_mm_xor_si128(X15, X3), 8);
		X11 = _mm_add_epi32(X11, X15);
		X7 = chacha_rotl128(_mm_xor_si128(X7, X11), 7);
		X0 = _mm_add_epi32(X0, X5);
		X15 = chacha_rotl128(_mm_xor_si128(X15, X0), 16);
		X10 = _mm_add_epi32(X10, X15);
		X5 = chacha_rotl128(_mm_xor_si128(X5, X10), 12);
		X0 = _mm_add_epi32(X0, X5);
		X15 = chacha_rotl128(_mm_xor_si128(X15, X0), 8);
		X10 = _mm_add_epi32(X10, X15);
		X5 = chacha_rotl128(_mm_xor_si128(X5, X10), 7);
		X1 = _mm_add_epi32(X1, X6);
		X12 = chacha_rotl128(_mm_xor_si128(X12, X1), 16);
		X11 = _mm_add_epi32(X11, X12);
		X6 = chacha_rotl128(_mm_xor_si128(X6, X11), 12);
		X1 = _mm_add_epi32(X1, X6);
		X12 = chacha_rotl128(_mm_xor_si128(X12, X1), 8);
		X11 = _mm_add_epi32(X11, X12);
		X6 = chacha_rotl128(_mm_xor_si128(X6, X11), 7);
		X2 = _mm_add_epi32(X2, X7);
		X13 = chacha_rotl128(_mm_xor_si128(X13, X2), 16);
		X8 = _mm_add_epi32(X8, X13);
		X7 = chacha_rotl128(_mm_xor_si128(X7, X8), 12);
		X2 = _mm_add_epi32(X2, X7);
		X13 = chacha_rotl128(_mm_xor_si128(X13, X2), 8);
		X8 = _mm_add_epi32(X8, X13);
		X7 = chacha_rotl128(_mm_xor_si128(X7, X8), 7);
		X3 = _mm_add_epi32(X3, X4);
		X14 = chacha_rotl128(_mm_xor_si128(X14, X3), 16);
		X9 = _mm_add_epi32(X9, X14);
		X4 = chacha_rotl128(_mm_xor_si128(X4, X9), 12);
		X3 = _mm_add_epi32(X3, X4);
		X14 = chacha_rotl128(_mm_xor_si128(X14, X3), 8);
		X9 = _mm_add_epi32(X9, X14);
		X4 = chacha_rotl128(_mm_xor_si128(X4, X9), 7);
		ctr -= 2;
	}

	ctxw->outw[0] = _mm_add_epi32(X0, ctxw->state[0]);
	ctxw->outw[1] = _mm_add_epi32(X1, ctxw->state[1]);
	ctxw->outw[2] = _mm_add_epi32(X2, ctxw->state[2]);
	ctxw->outw[3] = _mm_add_epi32(X3, ctxw->state[3]);
	ctxw->outw[4] = _mm_add_epi32(X4, ctxw->state[4]);
	ctxw->outw[5] = _mm_add_epi32(X5, ctxw->state[5]);
	ctxw->outw[6] = _mm_add_epi32(X6, ctxw->state[6]);
	ctxw->outw[7] = _mm_add_epi32(X7, ctxw->state[7]);
	ctxw->outw[8] = _mm_add_epi32(X8, ctxw->state[8]);
	ctxw->outw[9] = _mm_add_epi32(X9, ctxw->state[9]);
	ctxw->outw[10] = _mm_add_epi32(X10, ctxw->state[10]);
	ctxw->outw[11] = _mm_add_epi32(X11, ctxw->state[11]);
	ctxw->outw[12] = _mm_add_epi32(X12, ctxw->state[12]);
	ctxw->outw[13] = _mm_add_epi32(X13, ctxw->state[13]);
	ctxw->outw[14] = _mm_add_epi32(X14, ctxw->state[14]);
	ctxw->outw[15] = _mm_add_epi32(X15, ctxw->state[15]);
}

#endif

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
	size_t pos;

	pos = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (length >= QSC_CHACHA_AVX512BLOCK_SIZE)
	{
		const size_t SEGALN = length - (length % QSC_CHACHA_AVX512BLOCK_SIZE);

		__m512i tmpin;
		chacha_avx512_state ctxw;

		for (i = 0; i < 16; ++i)
		{
			ctxw.state[i] = _mm512_set1_epi32(ctx->state[i]);
		}

		uint32_t ctrblk[32];

		while (pos != SEGALN)
		{
			/* stagger the counters */
			ctrblk[0] = ctx->state[12];
			ctrblk[16] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[1] = ctx->state[12];
			ctrblk[17] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[2] = ctx->state[12];
			ctrblk[18] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[3] = ctx->state[12];
			ctrblk[19] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[4] = ctx->state[12];
			ctrblk[20] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[5] = ctx->state[12];
			ctrblk[21] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[6] = ctx->state[12];
			ctrblk[22] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[7] = ctx->state[12];
			ctrblk[23] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[8] = ctx->state[12];
			ctrblk[24] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[9] = ctx->state[12];
			ctrblk[25] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[10] = ctx->state[12];
			ctrblk[26] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[11] = ctx->state[12];
			ctrblk[27] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[12] = ctx->state[12];
			ctrblk[28] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[13] = ctx->state[12];
			ctrblk[29] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[14] = ctx->state[12];
			ctrblk[30] = ctx->state[13];
			chacha_increment(ctx);
			ctrblk[15] = ctx->state[12];
			ctrblk[31] = ctx->state[13];
			chacha_increment(ctx);

			ctxw.state[12] = _mm512_set_epi32(ctrblk[0], ctrblk[1], ctrblk[2], ctrblk[3], ctrblk[4], ctrblk[5], ctrblk[6], ctrblk[7], ctrblk[8], ctrblk[9], ctrblk[10], ctrblk[11], ctrblk[12], ctrblk[13], ctrblk[14], ctrblk[15]);
			ctxw.state[13] = _mm512_set_epi32(ctrblk[16], ctrblk[17], ctrblk[18], ctrblk[19], ctrblk[20], ctrblk[21], ctrblk[22], ctrblk[23], ctrblk[24], ctrblk[25], ctrblk[26], ctrblk[27], ctrblk[28], ctrblk[29], ctrblk[30], ctrblk[31]);

			chacha_permute_p16x512h(&ctxw);

			for (i = 0; i < 16; ++i)
			{
				tmpin = chacha_load512(input + pos + (i * 4));
				ctxw.outw[i] = _mm512_xor_si512(ctxw.outw[i], tmpin);
				chacha_store512(output + pos + (i * 4), ctxw.outw[i]);
			}

			pos += QSC_CHACHA_AVX512BLOCK_SIZE;
		}
	}

#elif defined(QSC_SYSTEM_HAS_AVX2)

	if (length >= QSC_CHACHA_AVX2BLOCK_SIZE)
	{
		const size_t SEGALN = length - (length % QSC_CHACHA_AVX2BLOCK_SIZE);

		__m256i tmpin;
		chacha_avx2_state ctxw;

		for (i = 0; i < 16; ++i)
		{
			ctxw.state[i] = _mm256_set1_epi32(ctx->state[i]);
		}

		uint32_t ctrblk[16];

		while (pos != SEGALN)
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
				tmpin = chacha_load256(input + pos + (i * 4));
				ctxw.outw[i] = _mm256_xor_si256(ctxw.outw[i], tmpin);
				chacha_store256(output + pos + (i * 4), ctxw.outw[i]);
			}

			pos += QSC_CHACHA_AVX2BLOCK_SIZE;
		}
	}

#elif defined(QSC_SYSTEM_HAS_AVX)

	if (length >= QSC_CHACHA_AVXBLOCK_SIZE)
	{
		const size_t SEGALN = length - (length % QSC_CHACHA_AVXBLOCK_SIZE);

		__m128i tmpin;
		chacha_avx_state ctxw;

		for (i = 0; i < 16; ++i)
		{
			ctxw.state[i] = _mm_set1_epi32(ctx->state[i]);
		}

		uint32_t ctrblk[8];

		while (pos != SEGALN)
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
				tmpin = chacha_load128(input + pos + (i * 4));
				ctxw.outw[i] = _mm_xor_si128(ctxw.outw[i], tmpin);
				chacha_store128(output + pos + (i * 4), ctxw.outw[i]);
			}

			pos += QSC_CHACHA_AVXBLOCK_SIZE;
		}
	}

#endif

	if (length != 0)
	{
		const size_t ALNSZE = length - (length % QSC_CHACHA_BLOCK_SIZE);

		while (pos != ALNSZE)
		{
			chacha_permute_p512c(ctx, output + pos);
			chacha_increment(ctx);
			qsc_memutils_xor(output + pos, input + pos, QSC_CHACHA_BLOCK_SIZE);
			pos += QSC_CHACHA_BLOCK_SIZE;
		}

		if (pos != length)
		{
			uint8_t tmp[QSC_CHACHA_BLOCK_SIZE];
			chacha_permute_p512c(ctx, tmp);
			chacha_increment(ctx);
			const size_t FNLSZE = length % QSC_CHACHA_BLOCK_SIZE;
			memcpy(output + (length - FNLSZE), tmp, FNLSZE);

			for (i = pos; i < length; ++i)
			{
				output[i] ^= input[i];
			}
		}
	}
}