#include "csx.h"
#include "intutils.h"
#include "memutils.h"
#if defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_ARM_INTRINSICS)
#	include "intrinsics.h"
#endif

/** \brief Select the CSX mixing-round profile; Keccak always uses 24 rounds. */
/* CSX uses the established 20-round cipher by default. */
#if defined(QSC_CSX_EXTENDED_ROUND_COUNTS)
/* The optional extended cipher uses 40 rounds. */
#	define CSX_ROUND_COUNT 40UL
#else
#	define CSX_ROUND_COUNT 20UL
#endif

/*!
\def CSX_NAME_SIZE
* \brief The byte size of the name array
*/
#define CSX_NAME_SIZE 14UL

/** \brief Bytes processed by eight parallel CSX blocks. */
#define CSX_AVX512_BLOCK (8U * QSC_CSX_BLOCK_SIZE)
/** \brief Bytes processed by four parallel CSX blocks. */
#define CSX_AVX2_BLOCK (4U * QSC_CSX_BLOCK_SIZE)

static const uint8_t csx_info[QSC_CSX_INFO_SIZE] =
{
	0x43U, 0x53U, 0x58U, 0x35U, 0x31U, 0x32U, 0x20U, 0x4BU, 0x4DU, 0x41U, 0x43U, 0x20U, 0x61U, 0x75U, 0x74U, 0x68U,
	0x65U, 0x6EU, 0x74U, 0x69U, 0x63U, 0x61U, 0x74U, 0x69U, 0x6FU, 0x6EU, 0x20U, 0x76U, 0x65U, 0x72U, 0x2EU, 0x20U,
	0x31U, 0x63U, 0x20U, 0x43U, 0x45U, 0x58U, 0x2BU, 0x2BU, 0x20U, 0x6CU, 0x69U, 0x62U, 0x72U, 0x61U, 0x72U, 0x79U
};

#if	defined(QSC_CSX_AUTHENTICATED)
static const uint8_t csx_name[CSX_NAME_SIZE] =
{
	0x43U, 0x53U, 0x58U, 0x35U, 0x31U, 0x32U, 0x2DU, 0x4BU, 0x4DU, 0x41U, 0x43U, 0x35U, 0x31U, 0x32U
};


#endif

static void csx_increment(qsc_csx_state* ctx)
{
	++ctx->state[12U];

	if (ctx->state[12U] == 0U)
	{
		++ctx->state[13U];
	}
}

static void csx_permute_p1024c(const qsc_csx_state* ctx, uint8_t* output)
{
	uint64_t X0 = ctx->state[0U];
	uint64_t X1 = ctx->state[1U];
	uint64_t X2 = ctx->state[2U];
	uint64_t X3 = ctx->state[3U];
	uint64_t X4 = ctx->state[4U];
	uint64_t X5 = ctx->state[5U];
	uint64_t X6 = ctx->state[6U];
	uint64_t X7 = ctx->state[7U];
	uint64_t X8 = ctx->state[8U];
	uint64_t X9 = ctx->state[9U];
	uint64_t X10 = ctx->state[10U];
	uint64_t X11 = ctx->state[11U];
	uint64_t X12 = ctx->state[12U];
	uint64_t X13 = ctx->state[13U];
	uint64_t X14 = ctx->state[14U];
	uint64_t X15 = ctx->state[15U];
	size_t ctr = CSX_ROUND_COUNT;

	/* new rotational constants:
	38,19,10,55
	33,4,51,13
	16,34,56,51
	4,53,42,41
	34,41,59,17
	23,31,37,20
	31,44,47,46
	12,47,44,30 */

	while (ctr != 0U)
	{
		/* round n */
		X0 += X4;
		X12 = qsc_intutils_rotl64(X12 ^ X0, 38U);
		X8 += X12;
		X4 = qsc_intutils_rotl64(X4 ^ X8, 19U);
		X0 += X4;
		X12 = qsc_intutils_rotl64(X12 ^ X0, 10U);
		X8 += X12;
		X4 = qsc_intutils_rotl64(X4 ^ X8, 55U);
		X1 += X5;
		X13 = qsc_intutils_rotl64(X13 ^ X1, 33U);
		X9 += X13;
		X5 = qsc_intutils_rotl64(X5 ^ X9, 4U);
		X1 += X5;
		X13 = qsc_intutils_rotl64(X13 ^ X1, 51U);
		X9 += X13;
		X5 = qsc_intutils_rotl64(X5 ^ X9, 13U);
		X2 += X6;
		X14 = qsc_intutils_rotl64(X14 ^ X2, 16U);
		X10 += X14;
		X6 = qsc_intutils_rotl64(X6 ^ X10, 34U);
		X2 += X6;
		X14 = qsc_intutils_rotl64(X14 ^ X2, 56U);
		X10 += X14;
		X6 = qsc_intutils_rotl64(X6 ^ X10, 51U);
		X3 += X7;
		X15 = qsc_intutils_rotl64(X15 ^ X3, 4U);
		X11 += X15;
		X7 = qsc_intutils_rotl64(X7 ^ X11, 53U);
		X3 += X7;
		X15 = qsc_intutils_rotl64(X15 ^ X3, 42U);
		X11 += X15;
		X7 = qsc_intutils_rotl64(X7 ^ X11, 41U);
		/* round n+1 */
		X0 += X5;
		X15 = qsc_intutils_rotl64(X15 ^ X0, 34U);
		X10 += X15;
		X5 = qsc_intutils_rotl64(X5 ^ X10, 41U);
		X0 += X5;
		X15 = qsc_intutils_rotl64(X15 ^ X0, 59U);
		X10 += X15;
		X5 = qsc_intutils_rotl64(X5 ^ X10, 17U);
		X1 += X6;
		X12 = qsc_intutils_rotl64(X12 ^ X1, 23U);
		X11 += X12;
		X6 = qsc_intutils_rotl64(X6 ^ X11, 31U);
		X1 += X6;
		X12 = qsc_intutils_rotl64(X12 ^ X1, 37U);
		X11 += X12;
		X6 = qsc_intutils_rotl64(X6 ^ X11, 20U);
		X2 += X7;
		X13 = qsc_intutils_rotl64(X13 ^ X2, 31U);
		X8 += X13;
		X7 = qsc_intutils_rotl64(X7 ^ X8, 44U);
		X2 += X7;
		X13 = qsc_intutils_rotl64(X13 ^ X2, 47U);
		X8 += X13;
		X7 = qsc_intutils_rotl64(X7 ^ X8, 46U);
		X3 += X4;
		X14 = qsc_intutils_rotl64(X14 ^ X3, 12U);
		X9 += X14;
		X4 = qsc_intutils_rotl64(X4 ^ X9, 47U);
		X3 += X4;
		X14 = qsc_intutils_rotl64(X14 ^ X3, 44U);
		X9 += X14;
		X4 = qsc_intutils_rotl64(X4 ^ X9, 30U);
		ctr -= 2;
	}

	qsc_intutils_le64to8(output, X0 + ctx->state[0U]);
	qsc_intutils_le64to8(output + 8, X1 + ctx->state[1U]);
	qsc_intutils_le64to8(output + 16, X2 + ctx->state[2U]);
	qsc_intutils_le64to8(output + 24, X3 + ctx->state[3U]);
	qsc_intutils_le64to8(output + 32, X4 + ctx->state[4U]);
	qsc_intutils_le64to8(output + 40, X5 + ctx->state[5U]);
	qsc_intutils_le64to8(output + 48, X6 + ctx->state[6U]);
	qsc_intutils_le64to8(output + 56, X7 + ctx->state[7U]);
	qsc_intutils_le64to8(output + 64, X8 + ctx->state[8U]);
	qsc_intutils_le64to8(output + 72, X9 + ctx->state[9U]);
	qsc_intutils_le64to8(output + 80, X10 + ctx->state[10U]);
	qsc_intutils_le64to8(output + 88, X11 + ctx->state[11U]);
	qsc_intutils_le64to8(output + 96, X12 + ctx->state[12U]);
	qsc_intutils_le64to8(output + 104, X13 + ctx->state[13U]);
	qsc_intutils_le64to8(output + 112, X14 + ctx->state[14U]);
	qsc_intutils_le64to8(output + 120, X15 + ctx->state[15U]);
}

#if defined(QSC_SYSTEM_ARM_INTRINSICS)

static void csx_permute_p2x1024_arm(const uint64x2_t* state, uint64x2_t* output)
{
	/* generate two CSX keystream blocks in paired NEON lanes */
	uint64x2_t X0 = state[0U];
	uint64x2_t X1 = state[1U];
	uint64x2_t X2 = state[2U];
	uint64x2_t X3 = state[3U];
	uint64x2_t X4 = state[4U];
	uint64x2_t X5 = state[5U];
	uint64x2_t X6 = state[6U];
	uint64x2_t X7 = state[7U];
	uint64x2_t X8 = state[8U];
	uint64x2_t X9 = state[9U];
	uint64x2_t X10 = state[10U];
	uint64x2_t X11 = state[11U];
	uint64x2_t X12 = state[12U];
	uint64x2_t X13 = state[13U];
	uint64x2_t X14 = state[14U];
	uint64x2_t X15 = state[15U];
	size_t ctr = CSX_ROUND_COUNT;

	/* new rotational constants=
	38,19,10,55
	33,4,51,13
	16,34,56,51
	4,53,42,41
	34,41,59,17
	23,31,37,20
	31,44,47,46
	12,47,44,30 */

	while (ctr != 0U)
	{
		/* round n */
		X0 = vaddq_u64(X0, X4);
		X12 = veorq_u64(X12, X0);
		X12 = vorrq_u64(vshlq_n_u64(X12, 38), vshrq_n_u64(X12, 26));
		X8 = vaddq_u64(X8, X12);
		X4 = veorq_u64(X4, X8);
		X4 = vorrq_u64(vshlq_n_u64(X4, 19), vshrq_n_u64(X4, 45));
		X0 = vaddq_u64(X0, X4);
		X12 = veorq_u64(X12, X0);
		X12 = vorrq_u64(vshlq_n_u64(X12, 10), vshrq_n_u64(X12, 54));
		X8 = vaddq_u64(X8, X12);
		X4 = veorq_u64(X4, X8);
		X4 = vorrq_u64(vshlq_n_u64(X4, 55), vshrq_n_u64(X4, 9));
		X1 = vaddq_u64(X1, X5);
		X13 = veorq_u64(X13, X1);
		X13 = vorrq_u64(vshlq_n_u64(X13, 33), vshrq_n_u64(X13, 31));
		X9 = vaddq_u64(X9, X13);
		X5 = veorq_u64(X5, X9);
		X5 = vorrq_u64(vshlq_n_u64(X5, 4), vshrq_n_u64(X5, 60));
		X1 = vaddq_u64(X1, X5);
		X13 = veorq_u64(X13, X1);
		X13 = vorrq_u64(vshlq_n_u64(X13, 51), vshrq_n_u64(X13, 13));
		X9 = vaddq_u64(X9, X13);
		X5 = veorq_u64(X5, X9);
		X5 = vorrq_u64(vshlq_n_u64(X5, 13), vshrq_n_u64(X5, 51));
		X2 = vaddq_u64(X2, X6);
		X14 = veorq_u64(X14, X2);
		X14 = vorrq_u64(vshlq_n_u64(X14, 16), vshrq_n_u64(X14, 48));
		X10 = vaddq_u64(X10, X14);
		X6 = veorq_u64(X6, X10);
		X6 = vorrq_u64(vshlq_n_u64(X6, 34), vshrq_n_u64(X6, 30));
		X2 = vaddq_u64(X2, X6);
		X14 = veorq_u64(X14, X2);
		X14 = vorrq_u64(vshlq_n_u64(X14, 56), vshrq_n_u64(X14, 8));
		X10 = vaddq_u64(X10, X14);
		X6 = veorq_u64(X6, X10);
		X6 = vorrq_u64(vshlq_n_u64(X6, 51), vshrq_n_u64(X6, 13));
		X3 = vaddq_u64(X3, X7);
		X15 = veorq_u64(X15, X3);
		X15 = vorrq_u64(vshlq_n_u64(X15, 4), vshrq_n_u64(X15, 60));
		X11 = vaddq_u64(X11, X15);
		X7 = veorq_u64(X7, X11);
		X7 = vorrq_u64(vshlq_n_u64(X7, 53), vshrq_n_u64(X7, 11));
		X3 = vaddq_u64(X3, X7);
		X15 = veorq_u64(X15, X3);
		X15 = vorrq_u64(vshlq_n_u64(X15, 42), vshrq_n_u64(X15, 22));
		X11 = vaddq_u64(X11, X15);
		X7 = veorq_u64(X7, X11);
		X7 = vorrq_u64(vshlq_n_u64(X7, 41), vshrq_n_u64(X7, 23));
		/* round n+1 */
		X0 = vaddq_u64(X0, X5);
		X15 = veorq_u64(X15, X0);
		X15 = vorrq_u64(vshlq_n_u64(X15, 34), vshrq_n_u64(X15, 30));
		X10 = vaddq_u64(X10, X15);
		X5 = veorq_u64(X5, X10);
		X5 = vorrq_u64(vshlq_n_u64(X5, 41), vshrq_n_u64(X5, 23));
		X0 = vaddq_u64(X0, X5);
		X15 = veorq_u64(X15, X0);
		X15 = vorrq_u64(vshlq_n_u64(X15, 59), vshrq_n_u64(X15, 5));
		X10 = vaddq_u64(X10, X15);
		X5 = veorq_u64(X5, X10);
		X5 = vorrq_u64(vshlq_n_u64(X5, 17), vshrq_n_u64(X5, 47));
		X1 = vaddq_u64(X1, X6);
		X12 = veorq_u64(X12, X1);
		X12 = vorrq_u64(vshlq_n_u64(X12, 23), vshrq_n_u64(X12, 41));
		X11 = vaddq_u64(X11, X12);
		X6 = veorq_u64(X6, X11);
		X6 = vorrq_u64(vshlq_n_u64(X6, 31), vshrq_n_u64(X6, 33));
		X1 = vaddq_u64(X1, X6);
		X12 = veorq_u64(X12, X1);
		X12 = vorrq_u64(vshlq_n_u64(X12, 37), vshrq_n_u64(X12, 27));
		X11 = vaddq_u64(X11, X12);
		X6 = veorq_u64(X6, X11);
		X6 = vorrq_u64(vshlq_n_u64(X6, 20), vshrq_n_u64(X6, 44));
		X2 = vaddq_u64(X2, X7);
		X13 = veorq_u64(X13, X2);
		X13 = vorrq_u64(vshlq_n_u64(X13, 31), vshrq_n_u64(X13, 33));
		X8 = vaddq_u64(X8, X13);
		X7 = veorq_u64(X7, X8);
		X7 = vorrq_u64(vshlq_n_u64(X7, 44), vshrq_n_u64(X7, 20));
		X2 = vaddq_u64(X2, X7);
		X13 = veorq_u64(X13, X2);
		X13 = vorrq_u64(vshlq_n_u64(X13, 47), vshrq_n_u64(X13, 17));
		X8 = vaddq_u64(X8, X13);
		X7 = veorq_u64(X7, X8);
		X7 = vorrq_u64(vshlq_n_u64(X7, 46), vshrq_n_u64(X7, 18));
		X3 = vaddq_u64(X3, X4);
		X14 = veorq_u64(X14, X3);
		X14 = vorrq_u64(vshlq_n_u64(X14, 12), vshrq_n_u64(X14, 52));
		X9 = vaddq_u64(X9, X14);
		X4 = veorq_u64(X4, X9);
		X4 = vorrq_u64(vshlq_n_u64(X4, 47), vshrq_n_u64(X4, 17));
		X3 = vaddq_u64(X3, X4);
		X14 = veorq_u64(X14, X3);
		X14 = vorrq_u64(vshlq_n_u64(X14, 44), vshrq_n_u64(X14, 20));
		X9 = vaddq_u64(X9, X14);
		X4 = veorq_u64(X4, X9);
		X4 = vorrq_u64(vshlq_n_u64(X4, 30), vshrq_n_u64(X4, 34));
		ctr -= 2U;
	}

	output[0U] = vaddq_u64(X0, state[0U]);
	output[1U] = vaddq_u64(X1, state[1U]);
	output[2U] = vaddq_u64(X2, state[2U]);
	output[3U] = vaddq_u64(X3, state[3U]);
	output[4U] = vaddq_u64(X4, state[4U]);
	output[5U] = vaddq_u64(X5, state[5U]);
	output[6U] = vaddq_u64(X6, state[6U]);
	output[7U] = vaddq_u64(X7, state[7U]);
	output[8U] = vaddq_u64(X8, state[8U]);
	output[9U] = vaddq_u64(X9, state[9U]);
	output[10U] = vaddq_u64(X10, state[10U]);
	output[11U] = vaddq_u64(X11, state[11U]);
	output[12U] = vaddq_u64(X12, state[12U]);
	output[13U] = vaddq_u64(X13, state[13U]);
	output[14U] = vaddq_u64(X14, state[14U]);
	output[15U] = vaddq_u64(X15, state[15U]);
}

#endif


#if defined(QSC_SYSTEM_HAS_AVX512)

typedef struct
{
	QSC_ALIGN(64) __m512i state[16U];
	QSC_ALIGN(64) __m512i outw[16U];
} csx_avx512_state;

inline static __m512i csx_rotl512(const __m512i x, uint32_t shift)
{
	return _mm512_or_si512(_mm512_slli_epi64(x, shift), _mm512_srli_epi64(x, 64U - shift));
}

/**
 * \brief Load eight unaligned little-endian message words.
 * \param v: The first word, with a 128-byte stride between words.
 * \return The words in CSX lane order.
 */
static __m512i csx_load512(const uint8_t* v)
{
	return _mm512_set_epi64((int64_t)qsc_intutils_le8to64(v), (int64_t)qsc_intutils_le8to64(v + 128U),
		(int64_t)qsc_intutils_le8to64(v + 256U), (int64_t)qsc_intutils_le8to64(v + 384U),
		(int64_t)qsc_intutils_le8to64(v + 512U), (int64_t)qsc_intutils_le8to64(v + 640U),
		(int64_t)qsc_intutils_le8to64(v + 768U), (int64_t)qsc_intutils_le8to64(v + 896U));
}

/**
 * \brief Store eight lanes as little-endian words and erase the staging buffer.
 * \param output: The first output word, with a 128-byte stride.
 * \param x: The output lanes.
 */
static void csx_store512(uint8_t* output, const __m512i x)
{
	QSC_ALIGN(64) uint64_t tmp[8U];

	_mm512_storeu_si512((__m512i*)tmp, x);

	qsc_intutils_le64to8(output, tmp[7U]);
	qsc_intutils_le64to8((output + 128), tmp[6U]);
	qsc_intutils_le64to8((output + 256), tmp[5U]);
	qsc_intutils_le64to8((output + 384), tmp[4U]);
	qsc_intutils_le64to8((output + 512), tmp[3U]);
	qsc_intutils_le64to8((output + 640), tmp[2U]);
	qsc_intutils_le64to8((output + 768), tmp[1U]);
	qsc_intutils_le64to8((output + 896), tmp[0U]);
	qsc_memutils_secure_erase(tmp, sizeof(tmp));
}

static void csx_increment512(__m512i* low, __m512i* high, const __m512i increment)
{
	/* add lane offsets to eight 128-bit counters, including low-word carry */
	__m512i previous;
	__mmask8 carry;

	previous = *low;
	*low = _mm512_add_epi64(*low, increment);
	carry = _mm512_cmplt_epu64_mask(*low, previous);
	*high = _mm512_mask_add_epi64(*high, carry, *high, _mm512_set1_epi64(1));
}

static void csx_permute_p8x1024h(csx_avx512_state* ctx)
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
	ctr = CSX_ROUND_COUNT;

	/* new rotational constants=
	38,19,10,55
	33,4,51,13
	16,34,56,51
	4,53,42,41
	34,41,59,17
	23,31,37,20
	31,44,47,46
	12,47,44,30 */

	while (ctr != 0U)
	{
		/* round n */
		x0 = _mm512_add_epi64(x0, x4);
		x12 = csx_rotl512(_mm512_xor_si512(x12, x0), 38);
		x8 = _mm512_add_epi64(x8, x12);
		x4 = csx_rotl512(_mm512_xor_si512(x4, x8), 19);
		x0 = _mm512_add_epi64(x0, x4);
		x12 = csx_rotl512(_mm512_xor_si512(x12, x0), 10);
		x8 = _mm512_add_epi64(x8, x12);
		x4 = csx_rotl512(_mm512_xor_si512(x4, x8), 55);
		x1 = _mm512_add_epi64(x1, x5);
		x13 = csx_rotl512(_mm512_xor_si512(x13, x1), 33);
		x9 = _mm512_add_epi64(x9, x13);
		x5 = csx_rotl512(_mm512_xor_si512(x5, x9), 4);
		x1 = _mm512_add_epi64(x1, x5);
		x13 = csx_rotl512(_mm512_xor_si512(x13, x1), 51);
		x9 = _mm512_add_epi64(x9, x13);
		x5 = csx_rotl512(_mm512_xor_si512(x5, x9), 13);
		x2 = _mm512_add_epi64(x2, x6);
		x14 = csx_rotl512(_mm512_xor_si512(x14, x2), 16);
		x10 = _mm512_add_epi64(x10, x14);
		x6 = csx_rotl512(_mm512_xor_si512(x6, x10), 34);
		x2 = _mm512_add_epi64(x2, x6);
		x14 = csx_rotl512(_mm512_xor_si512(x14, x2), 56);
		x10 = _mm512_add_epi64(x10, x14);
		x6 = csx_rotl512(_mm512_xor_si512(x6, x10), 51);
		x3 = _mm512_add_epi64(x3, x7);
		x15 = csx_rotl512(_mm512_xor_si512(x15, x3), 4);
		x11 = _mm512_add_epi64(x11, x15);
		x7 = csx_rotl512(_mm512_xor_si512(x7, x11), 53);
		x3 = _mm512_add_epi64(x3, x7);
		x15 = csx_rotl512(_mm512_xor_si512(x15, x3), 42);
		x11 = _mm512_add_epi64(x11, x15);
		x7 = csx_rotl512(_mm512_xor_si512(x7, x11), 41);
		/* round n+1 */
		x0 = _mm512_add_epi64(x0, x5);
		x15 = csx_rotl512(_mm512_xor_si512(x15, x0), 34);
		x10 = _mm512_add_epi64(x10, x15);
		x5 = csx_rotl512(_mm512_xor_si512(x5, x10), 41);
		x0 = _mm512_add_epi64(x0, x5);
		x15 = csx_rotl512(_mm512_xor_si512(x15, x0), 59);
		x10 = _mm512_add_epi64(x10, x15);
		x5 = csx_rotl512(_mm512_xor_si512(x5, x10), 17);
		x1 = _mm512_add_epi64(x1, x6);
		x12 = csx_rotl512(_mm512_xor_si512(x12, x1), 23);
		x11 = _mm512_add_epi64(x11, x12);
		x6 = csx_rotl512(_mm512_xor_si512(x6, x11), 31);
		x1 = _mm512_add_epi64(x1, x6);
		x12 = csx_rotl512(_mm512_xor_si512(x12, x1), 37);
		x11 = _mm512_add_epi64(x11, x12);
		x6 = csx_rotl512(_mm512_xor_si512(x6, x11), 20);
		x2 = _mm512_add_epi64(x2, x7);
		x13 = csx_rotl512(_mm512_xor_si512(x13, x2), 31);
		x8 = _mm512_add_epi64(x8, x13);
		x7 = csx_rotl512(_mm512_xor_si512(x7, x8), 44);
		x2 = _mm512_add_epi64(x2, x7);
		x13 = csx_rotl512(_mm512_xor_si512(x13, x2), 47);
		x8 = _mm512_add_epi64(x8, x13);
		x7 = csx_rotl512(_mm512_xor_si512(x7, x8), 46);
		x3 = _mm512_add_epi64(x3, x4);
		x14 = csx_rotl512(_mm512_xor_si512(x14, x3), 12);
		x9 = _mm512_add_epi64(x9, x14);
		x4 = csx_rotl512(_mm512_xor_si512(x4, x9), 47);
		x3 = _mm512_add_epi64(x3, x4);
		x14 = csx_rotl512(_mm512_xor_si512(x14, x3), 44);
		x9 = _mm512_add_epi64(x9, x14);
		x4 = csx_rotl512(_mm512_xor_si512(x4, x9), 30);
		ctr -= 2;
	}

	ctx->outw[0U] = _mm512_add_epi64(x0, ctx->state[0U]);
	ctx->outw[1U] = _mm512_add_epi64(x1, ctx->state[1U]);
	ctx->outw[2U] = _mm512_add_epi64(x2, ctx->state[2U]);
	ctx->outw[3U] = _mm512_add_epi64(x3, ctx->state[3U]);
	ctx->outw[4U] = _mm512_add_epi64(x4, ctx->state[4U]);
	ctx->outw[5U] = _mm512_add_epi64(x5, ctx->state[5U]);
	ctx->outw[6U] = _mm512_add_epi64(x6, ctx->state[6U]);
	ctx->outw[7U] = _mm512_add_epi64(x7, ctx->state[7U]);
	ctx->outw[8U] = _mm512_add_epi64(x8, ctx->state[8U]);
	ctx->outw[9U] = _mm512_add_epi64(x9, ctx->state[9U]);
	ctx->outw[10U] = _mm512_add_epi64(x10, ctx->state[10U]);
	ctx->outw[11U] = _mm512_add_epi64(x11, ctx->state[11U]);
	ctx->outw[12U] = _mm512_add_epi64(x12, ctx->state[12U]);
	ctx->outw[13U] = _mm512_add_epi64(x13, ctx->state[13U]);
	ctx->outw[14U] = _mm512_add_epi64(x14, ctx->state[14U]);
	ctx->outw[15U] = _mm512_add_epi64(x15, ctx->state[15U]);
}


#elif defined(QSC_SYSTEM_HAS_AVX2)

typedef struct
{
	QSC_ALIGN(32) __m256i state[16U];
	QSC_ALIGN(32) __m256i outw[16U];
} csx_avx256_state;

static __m256i csx_rotl256(const __m256i x, size_t shift)
{
	return _mm256_or_si256(_mm256_slli_epi64(x, (int32_t)shift), _mm256_srli_epi64(x, 64 - (int32_t)shift));
}

static __m256i csx_load256(const uint8_t* v)
{
	/* load four unaligned little-endian message words */
	return _mm256_set_epi64x((int64_t)qsc_intutils_le8to64(v), (int64_t)qsc_intutils_le8to64(v + 128U),
		(int64_t)qsc_intutils_le8to64(v + 256U), (int64_t)qsc_intutils_le8to64(v + 384U));
}

static void csx_store256(uint8_t* output, const __m256i x)
{
	/* store four lanes as little-endian words and erase the staging buffer */
	QSC_ALIGN(32) uint64_t tmp[4U];

	_mm256_storeu_si256((__m256i*)tmp, x);

	qsc_intutils_le64to8(output, tmp[3U]);
	qsc_intutils_le64to8((output + 128U), tmp[2U]);
	qsc_intutils_le64to8((output + 256U), tmp[1U]);
	qsc_intutils_le64to8((output + 384U), tmp[0U]);
	qsc_memutils_secure_erase(tmp, sizeof(tmp));
}

static void csx_increment256(__m256i* low, __m256i* high, const __m256i increment)
{
	/* add lane offsets to four 128-bit counters, including low-word carry */
	__m256i previous;
	__m256i carry;
	__m256i sign;

	sign = _mm256_set1_epi64x(INT64_MIN);
	previous = *low;
	*low = _mm256_add_epi64(*low, increment);
	carry = _mm256_cmpgt_epi64(_mm256_xor_si256(previous, sign), _mm256_xor_si256(*low, sign));
	*high = _mm256_sub_epi64(*high, carry);
}

static void csx_permute_p4x1024h(csx_avx256_state* ctx)
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
	ctr = CSX_ROUND_COUNT;

	/* new rotational constants:
	38,19,10,55
	33,4,51,13
	16,34,56,51
	4,53,42,41
	34,41,59,17
	23,31,37,20
	31,44,47,46
	12,47,44,30 */

	while (ctr != 0U)
	{
		/* round n */
		x0 = _mm256_add_epi64(x0, x4);
		x12 = csx_rotl256(_mm256_xor_si256(x12, x0), 38);
		x8 = _mm256_add_epi64(x8, x12);
		x4 = csx_rotl256(_mm256_xor_si256(x4, x8), 19);
		x0 = _mm256_add_epi64(x0, x4);
		x12 = csx_rotl256(_mm256_xor_si256(x12, x0), 10);
		x8 = _mm256_add_epi64(x8, x12);
		x4 = csx_rotl256(_mm256_xor_si256(x4, x8), 55);
		x1 = _mm256_add_epi64(x1, x5);
		x13 = csx_rotl256(_mm256_xor_si256(x13, x1), 33);
		x9 = _mm256_add_epi64(x9, x13);
		x5 = csx_rotl256(_mm256_xor_si256(x5, x9), 4);
		x1 = _mm256_add_epi64(x1, x5);
		x13 = csx_rotl256(_mm256_xor_si256(x13, x1), 51);
		x9 = _mm256_add_epi64(x9, x13);
		x5 = csx_rotl256(_mm256_xor_si256(x5, x9), 13);
		x2 = _mm256_add_epi64(x2, x6);
		x14 = csx_rotl256(_mm256_xor_si256(x14, x2), 16);
		x10 = _mm256_add_epi64(x10, x14);
		x6 = csx_rotl256(_mm256_xor_si256(x6, x10), 34);
		x2 = _mm256_add_epi64(x2, x6);
		x14 = csx_rotl256(_mm256_xor_si256(x14, x2), 56);
		x10 = _mm256_add_epi64(x10, x14);
		x6 = csx_rotl256(_mm256_xor_si256(x6, x10), 51);
		x3 = _mm256_add_epi64(x3, x7);
		x15 = csx_rotl256(_mm256_xor_si256(x15, x3), 4);
		x11 = _mm256_add_epi64(x11, x15);
		x7 = csx_rotl256(_mm256_xor_si256(x7, x11), 53);
		x3 = _mm256_add_epi64(x3, x7);
		x15 = csx_rotl256(_mm256_xor_si256(x15, x3), 42);
		x11 = _mm256_add_epi64(x11, x15);
		x7 = csx_rotl256(_mm256_xor_si256(x7, x11), 41);
		/* round n+1 */
		x0 = _mm256_add_epi64(x0, x5);
		x15 = csx_rotl256(_mm256_xor_si256(x15, x0), 34);
		x10 = _mm256_add_epi64(x10, x15);
		x5 = csx_rotl256(_mm256_xor_si256(x5, x10), 41);
		x0 = _mm256_add_epi64(x0, x5);
		x15 = csx_rotl256(_mm256_xor_si256(x15, x0), 59);
		x10 = _mm256_add_epi64(x10, x15);
		x5 = csx_rotl256(_mm256_xor_si256(x5, x10), 17);
		x1 = _mm256_add_epi64(x1, x6);
		x12 = csx_rotl256(_mm256_xor_si256(x12, x1), 23);
		x11 = _mm256_add_epi64(x11, x12);
		x6 = csx_rotl256(_mm256_xor_si256(x6, x11), 31);
		x1 = _mm256_add_epi64(x1, x6);
		x12 = csx_rotl256(_mm256_xor_si256(x12, x1), 37);
		x11 = _mm256_add_epi64(x11, x12);
		x6 = csx_rotl256(_mm256_xor_si256(x6, x11), 20);
		x2 = _mm256_add_epi64(x2, x7);
		x13 = csx_rotl256(_mm256_xor_si256(x13, x2), 31);
		x8 = _mm256_add_epi64(x8, x13);
		x7 = csx_rotl256(_mm256_xor_si256(x7, x8), 44);
		x2 = _mm256_add_epi64(x2, x7);
		x13 = csx_rotl256(_mm256_xor_si256(x13, x2), 47);
		x8 = _mm256_add_epi64(x8, x13);
		x7 = csx_rotl256(_mm256_xor_si256(x7, x8), 46);
		x3 = _mm256_add_epi64(x3, x4);
		x14 = csx_rotl256(_mm256_xor_si256(x14, x3), 12);
		x9 = _mm256_add_epi64(x9, x14);
		x4 = csx_rotl256(_mm256_xor_si256(x4, x9), 47);
		x3 = _mm256_add_epi64(x3, x4);
		x14 = csx_rotl256(_mm256_xor_si256(x14, x3), 44);
		x9 = _mm256_add_epi64(x9, x14);
		x4 = csx_rotl256(_mm256_xor_si256(x4, x9), 30);
		ctr -= 2;
	}

	ctx->outw[0U] = _mm256_add_epi64(x0, ctx->state[0U]);
	ctx->outw[1U] = _mm256_add_epi64(x1, ctx->state[1U]);
	ctx->outw[2U] = _mm256_add_epi64(x2, ctx->state[2U]);
	ctx->outw[3U] = _mm256_add_epi64(x3, ctx->state[3U]);
	ctx->outw[4U] = _mm256_add_epi64(x4, ctx->state[4U]);
	ctx->outw[5U] = _mm256_add_epi64(x5, ctx->state[5U]);
	ctx->outw[6U] = _mm256_add_epi64(x6, ctx->state[6U]);
	ctx->outw[7U] = _mm256_add_epi64(x7, ctx->state[7U]);
	ctx->outw[8U] = _mm256_add_epi64(x8, ctx->state[8U]);
	ctx->outw[9U] = _mm256_add_epi64(x9, ctx->state[9U]);
	ctx->outw[10U] = _mm256_add_epi64(x10, ctx->state[10U]);
	ctx->outw[11U] = _mm256_add_epi64(x11, ctx->state[11U]);
	ctx->outw[12U] = _mm256_add_epi64(x12, ctx->state[12U]);
	ctx->outw[13U] = _mm256_add_epi64(x13, ctx->state[13U]);
	ctx->outw[14U] = _mm256_add_epi64(x14, ctx->state[14U]);
	ctx->outw[15U] = _mm256_add_epi64(x15, ctx->state[15U]);
}

#endif

static void csx_mac_update(qsc_csx_state* ctx, const uint8_t* input, size_t length)
{
	qsc_kmac_update(&ctx->kstate, qsc_keccak_rate_512, input, length);
}

static void csx_transform(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	/* transform bytes while advancing the 128-bit block counter */
	uint8_t tmp[QSC_CSX_BLOCK_SIZE];
	size_t oft;

	oft = 0U;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (length >= CSX_AVX512_BLOCK)
	{
		csx_avx512_state ctxw;
		uint8_t ctrblk[64U];
		__m512i tmpin;
		size_t i;

		for (i = 0U; i < 16U; ++i)
		{
			uint64_t x = ctx->state[i];
			ctxw.state[i] = _mm512_set1_epi64(x);
		}

		/* initialize the nonce */
		csx_increment512(&ctxw.state[12U], &ctxw.state[13U], _mm512_set_epi64(0, 1, 2, 3, 4, 5, 6, 7));

		/* process 8 blocks in parallel (uses avx512 if available) */
		while (length >= CSX_AVX512_BLOCK)
		{
			csx_permute_p8x1024h(&ctxw);

			for (i = 0U; i < 16U; ++i)
			{
				tmpin = csx_load512((input + oft + (i * 8U)));
				ctxw.outw[i] = _mm512_xor_si512(ctxw.outw[i], tmpin);
				csx_store512((output + oft + (i * 8U)), ctxw.outw[i]);
			}

			csx_increment512(&ctxw.state[12U], &ctxw.state[13U], _mm512_set1_epi64(8));
			oft += CSX_AVX512_BLOCK;
			length -= CSX_AVX512_BLOCK;
		}

		/* store the nonce */
		_mm512_storeu_si512((__m512i*)ctrblk, ctxw.state[12U]);
		ctx->state[12U] = qsc_intutils_le8to64((ctrblk + 56U));
		_mm512_storeu_si512((__m512i*)ctrblk, ctxw.state[13U]);
		ctx->state[13U] = qsc_intutils_le8to64((ctrblk + 56U));
		qsc_memutils_secure_erase(&ctxw, sizeof(ctxw));
		qsc_memutils_secure_erase(&tmpin, sizeof(tmpin));
		qsc_memutils_secure_erase(ctrblk, sizeof(ctrblk));
	}

#elif defined(QSC_SYSTEM_HAS_AVX2)

	if (length >= CSX_AVX2_BLOCK)
	{
		csx_avx256_state ctxw;
		uint8_t ctrblk[32U];
		__m256i tmpin;
		size_t i;

		for (i = 0U; i < 16U; ++i)
		{
			uint64_t x = ctx->state[i];
			ctxw.state[i] = _mm256_set1_epi64x(x);
		}

		/* initialize the nonce */
		csx_increment256(&ctxw.state[12U], &ctxw.state[13U], _mm256_set_epi64x(0, 1, 2, 3));

		/* process four blocks in parallel */
		while (length >= CSX_AVX2_BLOCK)
		{
			csx_permute_p4x1024h(&ctxw);

			for (i = 0U; i < 16U; ++i)
			{
				tmpin = csx_load256(input + oft + (i * 8U));
				ctxw.outw[i] = _mm256_xor_si256(ctxw.outw[i], tmpin);
				csx_store256((output + oft + (i * 8U)), ctxw.outw[i]);
			}

			csx_increment256(&ctxw.state[12U], &ctxw.state[13U], _mm256_set1_epi64x(4));
			oft += CSX_AVX2_BLOCK;
			length -= CSX_AVX2_BLOCK;
		}

		/* store the nonce */
		_mm256_storeu_si256((__m256i*)ctrblk, ctxw.state[12U]);
		ctx->state[12U] = qsc_intutils_le8to64((ctrblk + 24U));
		_mm256_storeu_si256((__m256i*)ctrblk, ctxw.state[13U]);
		ctx->state[13U] = qsc_intutils_le8to64((ctrblk + 24U));
		qsc_memutils_secure_erase(&ctxw, sizeof(ctxw));
		qsc_memutils_secure_erase(&tmpin, sizeof(tmpin));
		qsc_memutils_secure_erase(ctrblk, sizeof(ctrblk));
	}

#elif defined(QSC_SYSTEM_ARM_INTRINSICS)

	if (length >= 2U * QSC_CSX_BLOCK_SIZE)
	{
		uint64x2_t state[QSC_CSX_STATE_SIZE];
		uint64x2_t stream[QSC_CSX_STATE_SIZE];
		uint64x2_t data;
		uint64_t next;
		uint64_t high;

		for (size_t i = 0U; i < QSC_CSX_STATE_SIZE; ++i)
		{
			state[i] = vdupq_n_u64(ctx->state[i]);
		}

		while (length >= 2U * QSC_CSX_BLOCK_SIZE)
		{
			next = ctx->state[12U] + 1U;
			high = ctx->state[13U] + (uint64_t)(next == 0U);
			state[12U] = vcombine_u64(vcreate_u64(ctx->state[12U]), vcreate_u64(next));
			state[13U] = vcombine_u64(vcreate_u64(ctx->state[13U]), vcreate_u64(high));
			csx_permute_p2x1024_arm(state, stream);

			for (size_t i = 0U; i < QSC_CSX_STATE_SIZE; ++i)
			{
				data = vcombine_u64(vcreate_u64(qsc_intutils_le8to64(input + oft + (i * 8U))),
					vcreate_u64(qsc_intutils_le8to64(input + oft + QSC_CSX_BLOCK_SIZE + (i * 8U))));
				data = veorq_u64(data, stream[i]);
				qsc_intutils_le64to8(output + oft + (i * 8U), vgetq_lane_u64(data, 0));
				qsc_intutils_le64to8(output + oft + QSC_CSX_BLOCK_SIZE + (i * 8U), vgetq_lane_u64(data, 1));
			}

			csx_increment(ctx);
			csx_increment(ctx);
			oft += 2U * QSC_CSX_BLOCK_SIZE;
			length -= 2U * QSC_CSX_BLOCK_SIZE;
		}

		qsc_memutils_secure_erase(state, sizeof(state));
		qsc_memutils_secure_erase(stream, sizeof(stream));
		qsc_memutils_secure_erase(&data, sizeof(data));
	}

#endif

	/* generate remaining blocks */
	while (length >= QSC_CSX_BLOCK_SIZE)
	{
		csx_permute_p1024c(ctx, tmp);
		qsc_memutils_xor(tmp, input + oft, QSC_CSX_BLOCK_SIZE);
		qsc_memutils_copy(output + oft, tmp, QSC_CSX_BLOCK_SIZE);
		csx_increment(ctx);
		oft += QSC_CSX_BLOCK_SIZE;
		length -= QSC_CSX_BLOCK_SIZE;
	}

	/* generate unaligned key-stream */
	if (length != 0U)
	{
		csx_permute_p1024c(ctx, tmp);
		csx_increment(ctx);
		qsc_memutils_xor(tmp, input + oft, length);
		qsc_memutils_copy(output + oft, tmp, length);
	}

	qsc_memutils_secure_erase(tmp, sizeof(tmp));
}

static void csx_load_key(qsc_csx_state* ctx, const uint8_t* key, const uint8_t* nonce, const uint8_t* code)
{
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_copy((uint8_t*)ctx->state, key, 64U);
	qsc_memutils_copy(((uint8_t*)ctx->state + 64U), code, 32U);
	qsc_memutils_copy(((uint8_t*)ctx->state + 96U), nonce, 16U);
	qsc_memutils_copy(((uint8_t*)ctx->state + 112U), (code + 32U), 16U);
#else
	ctx->state[0U] = qsc_intutils_le8to64(key);
	ctx->state[1U] = qsc_intutils_le8to64((key + 8U));
	ctx->state[2U] = qsc_intutils_le8to64((key + 16U));
	ctx->state[3U] = qsc_intutils_le8to64((key + 24U));
	ctx->state[4U] = qsc_intutils_le8to64((key + 32U));
	ctx->state[5U] = qsc_intutils_le8to64((key + 40U));
	ctx->state[6U] = qsc_intutils_le8to64((key + 48U));
	ctx->state[7U] = qsc_intutils_le8to64((key + 56U));
	ctx->state[8U] = qsc_intutils_le8to64(code);
	ctx->state[9U] = qsc_intutils_le8to64((code + 8U));
	ctx->state[10U] = qsc_intutils_le8to64((code + 16U));
	ctx->state[11U] = qsc_intutils_le8to64((code + 24U));
	ctx->state[12U] = qsc_intutils_le8to64(nonce);
	ctx->state[13U] = qsc_intutils_le8to64((nonce + 8U));
	ctx->state[14U] = qsc_intutils_le8to64((code + 32U));
	ctx->state[15U] = qsc_intutils_le8to64((code + 40U));
#endif
}

#if	defined(QSC_CSX_AUTHENTICATED)
static void csx_finalize(qsc_csx_state* ctx, uint8_t* output)
{
	uint8_t ctr[sizeof(uint64_t)] = { 0U };

	qsc_intutils_le64to8(ctr, ctx->counter);
	csx_mac_update(ctx, ctr, sizeof(ctr));

	/* authenticate with the standard Keccak-f[1600] 24-round KMAC. */
	qsc_kmac_finalize(&ctx->kstate, qsc_keccak_rate_512, output, QSC_CSX_MAC_SIZE);
}
#endif

/* CSX common */

void qsc_csx_dispose(qsc_csx_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	/* clear state */
	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx, sizeof(qsc_csx_state));
		/* Reserve the terminal byte count to reject use after disposal. */
		ctx->counter = UINT64_MAX;
	}
}

void qsc_csx_initialize(qsc_csx_state* ctx, const qsc_csx_keyparams* keyparams, bool encryption)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);
	QSC_ASSERT(keyparams == NULL || keyparams->nonce != NULL);
	QSC_ASSERT(keyparams == NULL || keyparams->key != NULL);
	QSC_ASSERT(keyparams == NULL || keyparams->keylen == QSC_CSX_KEY_SIZE);
	QSC_ASSERT(keyparams == NULL || keyparams->info != NULL || keyparams->infolen == 0U);

	if (ctx != NULL && keyparams != NULL && keyparams->key != NULL &&
		keyparams->nonce != NULL && keyparams->keylen == QSC_CSX_KEY_SIZE &&
		(keyparams->info != NULL || keyparams->infolen == 0U))
	{
		ctx->counter = 0U;
		ctx->encrypt = encryption;

#if defined(QSC_CSX_AUTHENTICATED)

		qsc_keccak_state kstate;
		uint8_t buf[QSC_KECCAK_512_RATE] = { 0U };
		uint8_t cpk[QSC_CSX_KEY_SIZE] = { 0U };
		uint8_t mck[QSC_CSX_KEY_SIZE] = { 0U };
		uint8_t nme[CSX_NAME_SIZE] = { 0U };

		/* load the information string */
		if (keyparams->infolen == 0U)
		{
			qsc_memutils_copy(nme, csx_name, CSX_NAME_SIZE);
		}
		else
		{
			const size_t INFLEN = qsc_intutils_min(keyparams->infolen, CSX_NAME_SIZE);
			qsc_memutils_copy(nme, keyparams->info, INFLEN);
		}

		/* initialize the cSHAKE generator state */
		qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, keyparams->key, keyparams->keylen, nme, sizeof(nme), NULL, 0U);

		/* extract the cipher key */
		qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, buf, 1U);
		qsc_memutils_copy(cpk, buf, QSC_CSX_KEY_SIZE);
		csx_load_key(ctx, cpk, keyparams->nonce, csx_info);
		qsc_memutils_secure_erase(cpk, sizeof(cpk));

		/* extract the mac key */
		qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, buf, 1U);
		qsc_memutils_copy(mck, buf, sizeof(mck));
		qsc_memutils_secure_erase(buf, sizeof(buf));

		/* initialize the mac generator state */
		qsc_memutils_secure_erase((uint8_t*)&ctx->kstate, sizeof(ctx->kstate));

		qsc_kmac_initialize(&ctx->kstate, qsc_keccak_rate_512, mck, sizeof(mck), NULL, 0U);
		qsc_memutils_secure_erase(mck, sizeof(mck));
		qsc_memutils_secure_erase(nme, sizeof(nme));
		qsc_keccak_dispose(&kstate);

#else

		uint8_t inf[QSC_CSX_INFO_SIZE] = { 0U };

		/* load the information string */
		if (keyparams->infolen == 0U)
		{
			qsc_memutils_copy(inf, csx_info, QSC_CSX_INFO_SIZE);
		}
		else
		{
			const size_t INFLEN = qsc_intutils_min(keyparams->infolen, QSC_CSX_INFO_SIZE);
			qsc_memutils_copy(inf, keyparams->info, INFLEN);
		}

		qsc_memutils_secure_erase((uint8_t*)ctx->state, sizeof(ctx->state));
		csx_load_key(ctx, keyparams->key, keyparams->nonce, inf);
		qsc_memutils_secure_erase(inf, sizeof(inf));

#endif
	}
	else if (ctx != NULL)
	{
		qsc_csx_dispose(ctx);
	}
}

void qsc_csx_set_associated(qsc_csx_state* ctx, const uint8_t* data, size_t length)
{
#if defined(QSC_CSX_AUTHENTICATED)
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(data != NULL || length == 0U);
	QSC_ASSERT(length <= UINT32_MAX);

	if (ctx != NULL && ctx->counter != UINT64_MAX && data != NULL &&
		length != 0U && length <= UINT32_MAX)
	{
		uint8_t code[sizeof(uint32_t)] = { 0U };

		/* add the ad data to the hash */
		csx_mac_update(ctx, data, length);
		/* add the length of the ad */
		qsc_intutils_le32to8(code, (uint32_t)length);
		csx_mac_update(ctx, code, sizeof(code));
	}
	else if (ctx != NULL && (length > UINT32_MAX || (data == NULL && length != 0U)))
	{
		qsc_csx_dispose(ctx);
	}
#else
	(void)ctx;
	(void)data;
	(void)length;
#endif
}

void qsc_csx_store_nonce(const qsc_csx_state* ctx, uint8_t nonce[QSC_CSX_NONCE_SIZE])
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(nonce != NULL);

	if (ctx != NULL && nonce != NULL)
	{
		qsc_intutils_le64to8(nonce, ctx->state[12U]);
		qsc_intutils_le64to8(nonce + sizeof(uint64_t), ctx->state[13U]);
	}
}

/**
 * \brief Check byte-count, tag-space, and nonce limits before transforming data.
 * \param ctx: The initialized cipher state.
 * \param length: The nonzero payload length.
 * \param finalize: True when a tag is read or written.
 * \return True if all counters and lengths remain representable.
 */
static bool csx_transform_valid(const qsc_csx_state* ctx, size_t length, bool finalize)
{
	uint64_t blocks;
	bool res;

	res = length != 0U && length < UINT64_MAX - ctx->counter;
#if defined(QSC_CSX_AUTHENTICATED)
	res = res && ctx->kstate.position < QSC_KECCAK_512_RATE &&
		(finalize == false || length <= SIZE_MAX - QSC_CSX_MAC_SIZE);
#else
	(void)finalize;
#endif
	blocks = (uint64_t)(length / QSC_CSX_BLOCK_SIZE) + (uint64_t)(length % QSC_CSX_BLOCK_SIZE != 0U);
	res = res && (ctx->state[13U] != UINT64_MAX || blocks <= UINT64_MAX - ctx->state[12U]);

	return res;
}

bool qsc_csx_transform(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	bool res;

	res = false;

	if (ctx != NULL && output != NULL && input != NULL && csx_transform_valid(ctx, length, true))
	{
#if defined(QSC_CSX_AUTHENTICATED)

		uint8_t ncopy[QSC_CSX_NONCE_SIZE] = { 0U };

		/* store the nonce */
		qsc_intutils_le64to8(ncopy, ctx->state[12U]);
		qsc_intutils_le64to8(ncopy + sizeof(uint64_t), ctx->state[13U]);

		/* update the processed bytes counter */
		ctx->counter += length;

		/* update the mac with the nonce */
		csx_mac_update(ctx, ncopy, sizeof(ncopy));

		if (ctx->encrypt)
		{
			/* use the transform to generate the key-stream and encrypt the data  */
			csx_transform(ctx, output, input, length);

			/* update the mac with the cipher-text */
			csx_mac_update(ctx, output, length);

			/* mac the cipher-text appending the code to the end of the array */
			csx_finalize(ctx, output + length);
			res = true;
		}
		else
		{
			uint8_t code[QSC_CSX_MAC_SIZE] = { 0U };

			/* update the mac with the cipher-text */
			csx_mac_update(ctx, input, length);

			/* generate the internal mac code */
			csx_finalize(ctx, code);

			/* compare the mac code with the one embedded in the cipher-text, bypassing the transform if the mac check fails */
			if (qsc_intutils_verify(code, input + length, QSC_CSX_MAC_SIZE) == 0U)
			{
				/* generate the key-stream and decrypt the array */
				csx_transform(ctx, output, input, length);
				res = true;
			}
			else
			{
				qsc_csx_dispose(ctx);
			}

			qsc_memutils_secure_erase(code, sizeof(code));
		}

#else

		ctx->counter += length;
		csx_transform(ctx, output, input, length);
		res = true;

#endif
	}

	return res;
}

bool qsc_csx_extended_transform(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length, bool finalize)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	bool res;

	res = false;

	if (ctx != NULL && output != NULL && input != NULL && csx_transform_valid(ctx, length, finalize))
	{
#if defined(QSC_CSX_AUTHENTICATED)

		uint8_t ncopy[QSC_CSX_NONCE_SIZE] = { 0U };

		/* store the nonce */
		qsc_intutils_le64to8(ncopy, ctx->state[12U]);
		qsc_intutils_le64to8(ncopy + sizeof(uint64_t), ctx->state[13U]);

		/* update the processed bytes counter */
		ctx->counter += length;

		/* update the mac with the nonce */
		csx_mac_update(ctx, ncopy, sizeof(ncopy));

		if (ctx->encrypt)
		{
			/* use the transform to generate the key-stream and encrypt the data  */
			csx_transform(ctx, output, input, length);

			/* update the mac with the cipher-text */
			csx_mac_update(ctx, output, length);

			if (finalize == true)
			{
				/* mac the cipher-text appending the code to the end of the array */
				csx_finalize(ctx, output + length);
			}

			res = true;
		}
		else
		{
			uint8_t code[QSC_CSX_MAC_SIZE] = { 0U };

			/* update the mac with the cipher-text */
			csx_mac_update(ctx, input, length);

			if (finalize == true)
			{
				/* generate the internal mac code */
				csx_finalize(ctx, code);

				/* compare the mac code with the one embedded in the cipher-text, bypassing the transform if the mac check fails */
				if (qsc_intutils_verify(code, input + length, QSC_CSX_MAC_SIZE) == 0U)
				{
					/* generate the key-stream and decrypt the array */
					csx_transform(ctx, output, input, length);
					res = true;
				}
				else
				{
					qsc_csx_dispose(ctx);
				}
			}
			else
			{
				/* generate the key-stream and decrypt the array */
				csx_transform(ctx, output, input, length);
				res = true;
			}
			qsc_memutils_secure_erase(code, sizeof(code));
		}

#else

		ctx->counter += length;
		csx_transform(ctx, output, input, length);
		res = true;

#endif
	}

	return res;
}
