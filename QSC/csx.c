#include "csx.h"
#include "intutils.h"
#include "memutils.h"
#include <stdlib.h>

#if defined(QSC_SYSTEM_HAS_AVX)
#	include "intrinsics.h"
#endif

/*!
\def QSC_CSX_BLOCK_SIZE
* \brief The internal block size in bytes, required by the encryption and decryption functions.
*/
#define QSC_CSX_BLOCK_SIZE 128

/*!
\def CSX256_ROUND_COUNT
* \brief The number of mixing rounds used by CSX-512
*/
#define CSX_ROUND_COUNT 40

/*!
\def CSX_NAME_LENGTH
* \brief The byte size of the name array
*/
#define CSX_NAME_LENGTH 14

static const uint8_t csx_info[QSC_CSX_INFO_SIZE] =
{
	0x43, 0x53, 0x58, 0x35, 0x31, 0x32, 0x20, 0x4B, 0x4D, 0x41, 0x43, 0x20, 0x61, 0x75, 0x74, 0x68,
	0x65, 0x6E, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x76, 0x65, 0x72, 0x2E, 0x20,
	0x31, 0x63, 0x20, 0x43, 0x45, 0x58, 0x2B, 0x2B, 0x20, 0x6C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79
};

static const uint8_t csx_name[CSX_NAME_LENGTH] =
{
	0x43, 0x53, 0x58, 0x35, 0x31, 0x32, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x35, 0x31, 0x32
};

static void csx_increment(qsc_csx_state* ctx)
{
	++ctx->nonce[0];

	if (ctx->nonce[0] == 0)
	{
		++ctx->nonce[1];
	}
}

static void csx_permute_p1024c(qsc_csx_state* ctx, uint8_t* output)
{
	uint64_t X0 = ctx->state[0];
	uint64_t X1 = ctx->state[1];
	uint64_t X2 = ctx->state[2];
	uint64_t X3 = ctx->state[3];
	uint64_t X4 = ctx->state[4];
	uint64_t X5 = ctx->state[5];
	uint64_t X6 = ctx->state[6];
	uint64_t X7 = ctx->state[7];
	uint64_t X8 = ctx->state[8];
	uint64_t X9 = ctx->state[9];
	uint64_t X10 = ctx->state[10];
	uint64_t X11 = ctx->state[11];
	uint64_t X12 = ctx->nonce[0];
	uint64_t X13 = ctx->nonce[1];
	uint64_t X14 = ctx->state[12];
	uint64_t X15 = ctx->state[13];
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

	while (ctr != 0)
	{
		/* round n */
		X0 += X4;
		X12 = qsc_intutils_rotl64(X12 ^ X0, 38);
		X8 += X12;
		X4 = qsc_intutils_rotl64(X4 ^ X8, 19);
		X0 += X4;
		X12 = qsc_intutils_rotl64(X12 ^ X0, 10);
		X8 += X12;
		X4 = qsc_intutils_rotl64(X4 ^ X8, 55);
		X1 += X5;
		X13 = qsc_intutils_rotl64(X13 ^ X1, 33);
		X9 += X13;
		X5 = qsc_intutils_rotl64(X5 ^ X9, 4);
		X1 += X5;
		X13 = qsc_intutils_rotl64(X13 ^ X1, 51);
		X9 += X13;
		X5 = qsc_intutils_rotl64(X5 ^ X9, 13);
		X2 += X6;
		X14 = qsc_intutils_rotl64(X14 ^ X2, 16);
		X10 += X14;
		X6 = qsc_intutils_rotl64(X6 ^ X10, 34);
		X2 += X6;
		X14 = qsc_intutils_rotl64(X14 ^ X2, 56);
		X10 += X14;
		X6 = qsc_intutils_rotl64(X6 ^ X10, 51);
		X3 += X7;
		X15 = qsc_intutils_rotl64(X15 ^ X3, 4);
		X11 += X15;
		X7 = qsc_intutils_rotl64(X7 ^ X11, 53);
		X3 += X7;
		X15 = qsc_intutils_rotl64(X15 ^ X3, 42);
		X11 += X15;
		X7 = qsc_intutils_rotl64(X7 ^ X11, 41);
		/* round n+1 */
		X0 += X5;
		X15 = qsc_intutils_rotl64(X15 ^ X0, 34);
		X10 += X15;
		X5 = qsc_intutils_rotl64(X5 ^ X10, 41);
		X0 += X5;
		X15 = qsc_intutils_rotl64(X15 ^ X0, 59);
		X10 += X15;
		X5 = qsc_intutils_rotl64(X5 ^ X10, 17);
		X1 += X6;
		X12 = qsc_intutils_rotl64(X12 ^ X1, 23);
		X11 += X12;
		X6 = qsc_intutils_rotl64(X6 ^ X11, 31);
		X1 += X6;
		X12 = qsc_intutils_rotl64(X12 ^ X1, 37);
		X11 += X12;
		X6 = qsc_intutils_rotl64(X6 ^ X11, 20);
		X2 += X7;
		X13 = qsc_intutils_rotl64(X13 ^ X2, 31);
		X8 += X13;
		X7 = qsc_intutils_rotl64(X7 ^ X8, 44);
		X2 += X7;
		X13 = qsc_intutils_rotl64(X13 ^ X2, 47);
		X8 += X13;
		X7 = qsc_intutils_rotl64(X7 ^ X8, 46);
		X3 += X4;
		X14 = qsc_intutils_rotl64(X14 ^ X3, 12);
		X9 += X14;
		X4 = qsc_intutils_rotl64(X4 ^ X9, 47);
		X3 += X4;
		X14 = qsc_intutils_rotl64(X14 ^ X3, 44);
		X9 += X14;
		X4 = qsc_intutils_rotl64(X4 ^ X9, 30);
		ctr -= 2;
	}

	qsc_intutils_le64to8(output, X0 + ctx->state[0]);
	qsc_intutils_le64to8(output + 8, X1 + ctx->state[1]);
	qsc_intutils_le64to8(output + 16, X2 + ctx->state[2]);
	qsc_intutils_le64to8(output + 24, X3 + ctx->state[3]);
	qsc_intutils_le64to8(output + 32, X4 + ctx->state[4]);
	qsc_intutils_le64to8(output + 40, X5 + ctx->state[5]);
	qsc_intutils_le64to8(output + 48, X6 + ctx->state[6]);
	qsc_intutils_le64to8(output + 56, X7 + ctx->state[7]);
	qsc_intutils_le64to8(output + 64, X8 + ctx->state[8]);
	qsc_intutils_le64to8(output + 72, X9 + ctx->state[9]);
	qsc_intutils_le64to8(output + 80, X10 + ctx->state[10]);
	qsc_intutils_le64to8(output + 88, X11 + ctx->state[11]);
	qsc_intutils_le64to8(output + 96, X12 + ctx->nonce[0]);
	qsc_intutils_le64to8(output + 104, X13 + ctx->nonce[1]);
	qsc_intutils_le64to8(output + 112, X14 + ctx->state[12]);
	qsc_intutils_le64to8(output + 120, X15 + ctx->state[13]);
}

#if defined(QSC_SYSTEM_HAS_AVX512)

static __m512i csx_rotl512(const __m512i x, size_t shift)
{
	return _mm512_or_si512(_mm512_slli_epi64(x, shift), _mm512_srli_epi64(x, 64 - shift));
}

static void csx_store512(__m512i input, uint64_t* output)
{
	_mm512_storeu_si512((__m512i*)output, input);
}

static void csx_store_8xull1024(__m512i* state, uint8_t* output)
{
	uint64_t tmp[8] = { 0 };
	size_t i;

	for (i = 0; i < 16; ++i)
	{
		csx_store512(state[i], tmp);
		qsc_intutils_le64to8(output + (i * 8), tmp[0]);
		qsc_intutils_le64to8(output + (i * 8) + 128, tmp[1]);
		qsc_intutils_le64to8(output + (i * 8) + 256, tmp[2]);
		qsc_intutils_le64to8(output + (i * 8) + 384, tmp[3]);
		qsc_intutils_le64to8(output + (i * 8) + 512, tmp[5]);
		qsc_intutils_le64to8(output + (i * 8) + 640, tmp[5]);
		qsc_intutils_le64to8(output + (i * 8) + 768, tmp[6]);
		qsc_intutils_le64to8(output + (i * 8) + 896, tmp[7]);
	}
}

static void csx_permute_p8x1024h(qsc_csx_state* ctx, uint64_t counter[16], uint8_t* output)
{
	const uint64_t* pstate = ctx->state;

	__m512i x[16] = { _mm512_set1_epi64(pstate[0]), _mm512_set1_epi64(pstate[1]), _mm512_set1_epi64(pstate[2]), _mm512_set1_epi64(pstate[3]),
		_mm512_set1_epi64(pstate[4]), _mm512_set1_epi64(pstate[5]), _mm512_set1_epi64(pstate[6]), _mm512_set1_epi64(pstate[7]),
		_mm512_set1_epi64(pstate[8]), _mm512_set1_epi64(pstate[9]), _mm512_set1_epi64(pstate[10]), _mm512_set1_epi64(pstate[11]),
		_mm512_loadu_si512((const __m512i*)&counter[0]), _mm512_loadu_si512((const __m512i*)&counter[8]), _mm512_set1_epi64(pstate[12]), _mm512_set1_epi64(pstate[13]) };

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

	while (ctr != 0)
	{
		/* round n */
		x[0] = _mm512_add_epi64(x[0], x[4]);
		x[12] = csx_rotl512(_mm512_xor_si512(x[12], x[0]), 38);
		x[8] = _mm512_add_epi64(x[8], x[12]);
		x[4] = csx_rotl512(_mm512_xor_si512(x[4], x[8]), 19);
		x[0] = _mm512_add_epi64(x[0], x[4]);
		x[12] = csx_rotl512(_mm512_xor_si512(x[12], x[0]), 10);
		x[8] = _mm512_add_epi64(x[8], x[12]);
		x[4] = csx_rotl512(_mm512_xor_si512(x[4], x[8]), 55);
		x[1] = _mm512_add_epi64(x[1], x[5]);
		x[13] = csx_rotl512(_mm512_xor_si512(x[13], x[1]), 33);
		x[9] = _mm512_add_epi64(x[9], x[13]);
		x[5] = csx_rotl512(_mm512_xor_si512(x[5], x[9]), 4);
		x[1] = _mm512_add_epi64(x[1], x[5]);
		x[13] = csx_rotl512(_mm512_xor_si512(x[13], x[1]), 51);
		x[9] = _mm512_add_epi64(x[9], x[13]);
		x[5] = csx_rotl512(_mm512_xor_si512(x[5], x[9]), 13);
		x[2] = _mm512_add_epi64(x[2], x[6]);
		x[14] = csx_rotl512(_mm512_xor_si512(x[14], x[2]), 16);
		x[10] = _mm512_add_epi64(x[10], x[14]);
		x[6] = csx_rotl512(_mm512_xor_si512(x[6], x[10]), 34);
		x[2] = _mm512_add_epi64(x[2], x[6]);
		x[14] = csx_rotl512(_mm512_xor_si512(x[14], x[2]), 56);
		x[10] = _mm512_add_epi64(x[10], x[14]);
		x[6] = csx_rotl512(_mm512_xor_si512(x[6], x[10]), 51);
		x[3] = _mm512_add_epi64(x[3], x[7]);
		x[15] = csx_rotl512(_mm512_xor_si512(x[15], x[3]), 4);
		x[11] = _mm512_add_epi64(x[11], x[15]);
		x[7] = csx_rotl512(_mm512_xor_si512(x[7], x[11]), 53);
		x[3] = _mm512_add_epi64(x[3], x[7]);
		x[15] = csx_rotl512(_mm512_xor_si512(x[15], x[3]), 42);
		x[11] = _mm512_add_epi64(x[11], x[15]);
		x[7] = csx_rotl512(_mm512_xor_si512(x[7], x[11]), 41);
		/* round n+1 */
		x[0] = _mm512_add_epi64(x[0], x[5]);
		x[15] = csx_rotl512(_mm512_xor_si512(x[15], x[0]), 34);
		x[10] = _mm512_add_epi64(x[10], x[15]);
		x[5] = csx_rotl512(_mm512_xor_si512(x[5], x[10]), 41);
		x[0] = _mm512_add_epi64(x[0], x[5]);
		x[15] = csx_rotl512(_mm512_xor_si512(x[15], x[0]), 59);
		x[10] = _mm512_add_epi64(x[10], x[15]);
		x[5] = csx_rotl512(_mm512_xor_si512(x[5], x[10]), 17);
		x[1] = _mm512_add_epi64(x[1], x[6]);
		x[12] = csx_rotl512(_mm512_xor_si512(x[12], x[1]), 23);
		x[11] = _mm512_add_epi64(x[11], x[12]);
		x[6] = csx_rotl512(_mm512_xor_si512(x[6], x[11]), 31);
		x[1] = _mm512_add_epi64(x[1], x[6]);
		x[12] = csx_rotl512(_mm512_xor_si512(x[12], x[1]), 37);
		x[11] = _mm512_add_epi64(x[11], x[12]);
		x[6] = csx_rotl512(_mm512_xor_si512(x[6], x[11]), 20);
		x[2] = _mm512_add_epi64(x[2], x[7]);
		x[13] = csx_rotl512(_mm512_xor_si512(x[13], x[2]), 31);
		x[8] = _mm512_add_epi64(x[8], x[13]);
		x[7] = csx_rotl512(_mm512_xor_si512(x[7], x[8]), 44);
		x[2] = _mm512_add_epi64(x[2], x[7]);
		x[13] = csx_rotl512(_mm512_xor_si512(x[13], x[2]), 47);
		x[8] = _mm512_add_epi64(x[8], x[13]);
		x[7] = csx_rotl512(_mm512_xor_si512(x[7], x[8]), 46);
		x[3] = _mm512_add_epi64(x[3], x[4]);
		x[14] = csx_rotl512(_mm512_xor_si512(x[14], x[3]), 12);
		x[9] = _mm512_add_epi64(x[9], x[14]);
		x[4] = csx_rotl512(_mm512_xor_si512(x[4], x[9]), 47);
		x[3] = _mm512_add_epi64(x[3], x[4]);
		x[14] = csx_rotl512(_mm512_xor_si512(x[14], x[3]), 44);
		x[9] = _mm512_add_epi64(x[9], x[14]);
		x[4] = csx_rotl512(_mm512_xor_si512(x[4], x[9]), 30);
		ctr -= 2;
	}

	x[0] = _mm512_add_epi64(x[0], _mm512_set1_epi64(pstate[0]));
	x[1] = _mm512_add_epi64(x[1], _mm512_set1_epi64(pstate[1]));
	x[2] = _mm512_add_epi64(x[2], _mm512_set1_epi64(pstate[2]));
	x[3] = _mm512_add_epi64(x[3], _mm512_set1_epi64(pstate[3]));
	x[4] = _mm512_add_epi64(x[4], _mm512_set1_epi64(pstate[4]));
	x[5] = _mm512_add_epi64(x[5], _mm512_set1_epi64(pstate[5]));
	x[6] = _mm512_add_epi64(x[6], _mm512_set1_epi64(pstate[6]));
	x[7] = _mm512_add_epi64(x[7], _mm512_set1_epi64(pstate[7]));
	x[8] = _mm512_add_epi64(x[8], _mm512_set1_epi64(pstate[8]));
	x[9] = _mm512_add_epi64(x[9], _mm512_set1_epi64(pstate[9]));
	x[10] = _mm512_add_epi64(x[10], _mm512_set1_epi64(pstate[10]));
	x[11] = _mm512_add_epi64(x[11], _mm512_set1_epi64(pstate[11]));
	x[12] = _mm512_add_epi64(x[12], _mm512_loadu_si512((const __m512i*)&counter[0]));
	x[13] = _mm512_add_epi64(x[13], _mm512_loadu_si512((const __m512i*)&counter[8]));
	x[14] = _mm512_add_epi64(x[14], _mm512_set1_epi64(pstate[12]));
	x[15] = _mm512_add_epi64(x[15], _mm512_set1_epi64(pstate[13]));

	csx_store_8xull1024(x, output);
}

#elif defined(QSC_SYSTEM_HAS_AVX2)

static __m256i csx_rotl256(const __m256i x, size_t shift)
{
	return _mm256_or_si256(_mm256_slli_epi64(x, (int)shift), _mm256_srli_epi64(x, 64 - shift));
}

static void csx_store256(__m256i input, uint64_t* output)
{
	_mm256_storeu_si256((__m256i*)output, input);
}

static void csx_store_4xull1024(__m256i* state, uint8_t* output)
{
	uint64_t tmp[4] = { 0 };
	size_t i;

	for (i = 0; i < 16; ++i)
	{
		csx_store256(state[i], tmp);
		qsc_intutils_le64to8(output + (i * 8), tmp[0]);
		qsc_intutils_le64to8(output + (i * 8) + 128, tmp[1]);
		qsc_intutils_le64to8(output + (i * 8) + 256, tmp[2]);
		qsc_intutils_le64to8(output + (i * 8) + 384, tmp[3]);
	}
}

static void csx_permute_p4x1024h(qsc_csx_state* ctx, uint64_t* counter, uint8_t* output)
{
	const uint64_t* pstate = ctx->state;

	__m256i x[16] = { _mm256_set1_epi64x(pstate[0]), _mm256_set1_epi64x(pstate[1]), _mm256_set1_epi64x(pstate[2]), _mm256_set1_epi64x(pstate[3]),
		_mm256_set1_epi64x(pstate[4]), _mm256_set1_epi64x(pstate[5]), _mm256_set1_epi64x(pstate[6]), _mm256_set1_epi64x(pstate[7]),
		_mm256_set1_epi64x(pstate[8]), _mm256_set1_epi64x(pstate[9]), _mm256_set1_epi64x(pstate[10]), _mm256_set1_epi64x(pstate[11]),
		_mm256_loadu_si256((const __m256i*)&counter[0]), _mm256_loadu_si256((const __m256i*)&counter[4]), _mm256_set1_epi64x(pstate[12]), _mm256_set1_epi64x(pstate[13]) };

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

	while (ctr != 0)
	{
		/* round n */
		x[0] = _mm256_add_epi64(x[0], x[4]);
		x[12] = csx_rotl256(_mm256_xor_si256(x[12], x[0]), 38);
		x[8] = _mm256_add_epi64(x[8], x[12]);
		x[4] = csx_rotl256(_mm256_xor_si256(x[4], x[8]), 19);
		x[0] = _mm256_add_epi64(x[0], x[4]);
		x[12] = csx_rotl256(_mm256_xor_si256(x[12], x[0]), 10);
		x[8] = _mm256_add_epi64(x[8], x[12]);
		x[4] = csx_rotl256(_mm256_xor_si256(x[4], x[8]), 55);
		x[1] = _mm256_add_epi64(x[1], x[5]);
		x[13] = csx_rotl256(_mm256_xor_si256(x[13], x[1]), 33);
		x[9] = _mm256_add_epi64(x[9], x[13]);
		x[5] = csx_rotl256(_mm256_xor_si256(x[5], x[9]), 4);
		x[1] = _mm256_add_epi64(x[1], x[5]);
		x[13] = csx_rotl256(_mm256_xor_si256(x[13], x[1]), 51);
		x[9] = _mm256_add_epi64(x[9], x[13]);
		x[5] = csx_rotl256(_mm256_xor_si256(x[5], x[9]), 13);
		x[2] = _mm256_add_epi64(x[2], x[6]);
		x[14] = csx_rotl256(_mm256_xor_si256(x[14], x[2]), 16);
		x[10] = _mm256_add_epi64(x[10], x[14]);
		x[6] = csx_rotl256(_mm256_xor_si256(x[6], x[10]), 34);
		x[2] = _mm256_add_epi64(x[2], x[6]);
		x[14] = csx_rotl256(_mm256_xor_si256(x[14], x[2]), 56);
		x[10] = _mm256_add_epi64(x[10], x[14]);
		x[6] = csx_rotl256(_mm256_xor_si256(x[6], x[10]), 51);
		x[3] = _mm256_add_epi64(x[3], x[7]);
		x[15] = csx_rotl256(_mm256_xor_si256(x[15], x[3]), 4);
		x[11] = _mm256_add_epi64(x[11], x[15]);
		x[7] = csx_rotl256(_mm256_xor_si256(x[7], x[11]), 53);
		x[3] = _mm256_add_epi64(x[3], x[7]);
		x[15] = csx_rotl256(_mm256_xor_si256(x[15], x[3]), 42);
		x[11] = _mm256_add_epi64(x[11], x[15]);
		x[7] = csx_rotl256(_mm256_xor_si256(x[7], x[11]), 41);
		/* round n+1 */
		x[0] = _mm256_add_epi64(x[0], x[5]);
		x[15] = csx_rotl256(_mm256_xor_si256(x[15], x[0]), 34);
		x[10] = _mm256_add_epi64(x[10], x[15]);
		x[5] = csx_rotl256(_mm256_xor_si256(x[5], x[10]), 41);
		x[0] = _mm256_add_epi64(x[0], x[5]);
		x[15] = csx_rotl256(_mm256_xor_si256(x[15], x[0]), 59);
		x[10] = _mm256_add_epi64(x[10], x[15]);
		x[5] = csx_rotl256(_mm256_xor_si256(x[5], x[10]), 17);
		x[1] = _mm256_add_epi64(x[1], x[6]);
		x[12] = csx_rotl256(_mm256_xor_si256(x[12], x[1]), 23);
		x[11] = _mm256_add_epi64(x[11], x[12]);
		x[6] = csx_rotl256(_mm256_xor_si256(x[6], x[11]), 31);
		x[1] = _mm256_add_epi64(x[1], x[6]);
		x[12] = csx_rotl256(_mm256_xor_si256(x[12], x[1]), 37);
		x[11] = _mm256_add_epi64(x[11], x[12]);
		x[6] = csx_rotl256(_mm256_xor_si256(x[6], x[11]), 20);
		x[2] = _mm256_add_epi64(x[2], x[7]);
		x[13] = csx_rotl256(_mm256_xor_si256(x[13], x[2]), 31);
		x[8] = _mm256_add_epi64(x[8], x[13]);
		x[7] = csx_rotl256(_mm256_xor_si256(x[7], x[8]), 44);
		x[2] = _mm256_add_epi64(x[2], x[7]);
		x[13] = csx_rotl256(_mm256_xor_si256(x[13], x[2]), 47);
		x[8] = _mm256_add_epi64(x[8], x[13]);
		x[7] = csx_rotl256(_mm256_xor_si256(x[7], x[8]), 46);
		x[3] = _mm256_add_epi64(x[3], x[4]);
		x[14] = csx_rotl256(_mm256_xor_si256(x[14], x[3]), 12);
		x[9] = _mm256_add_epi64(x[9], x[14]);
		x[4] = csx_rotl256(_mm256_xor_si256(x[4], x[9]), 47);
		x[3] = _mm256_add_epi64(x[3], x[4]);
		x[14] = csx_rotl256(_mm256_xor_si256(x[14], x[3]), 44);
		x[9] = _mm256_add_epi64(x[9], x[14]);
		x[4] = csx_rotl256(_mm256_xor_si256(x[4], x[9]), 30);
		ctr -= 2;
	}

	x[0] = _mm256_add_epi64(x[0], _mm256_set1_epi64x(pstate[0]));
	x[1] = _mm256_add_epi64(x[1], _mm256_set1_epi64x(pstate[1]));
	x[2] = _mm256_add_epi64(x[2], _mm256_set1_epi64x(pstate[2]));
	x[3] = _mm256_add_epi64(x[3], _mm256_set1_epi64x(pstate[3]));
	x[4] = _mm256_add_epi64(x[4], _mm256_set1_epi64x(pstate[4]));
	x[5] = _mm256_add_epi64(x[5], _mm256_set1_epi64x(pstate[5]));
	x[6] = _mm256_add_epi64(x[6], _mm256_set1_epi64x(pstate[6]));
	x[7] = _mm256_add_epi64(x[7], _mm256_set1_epi64x(pstate[7]));
	x[8] = _mm256_add_epi64(x[8], _mm256_set1_epi64x(pstate[8]));
	x[9] = _mm256_add_epi64(x[9], _mm256_set1_epi64x(pstate[9]));
	x[10] = _mm256_add_epi64(x[10], _mm256_set1_epi64x(pstate[10]));
	x[11] = _mm256_add_epi64(x[11], _mm256_set1_epi64x(pstate[11]));
	x[12] = _mm256_add_epi64(x[12], _mm256_loadu_si256((const __m256i*) & counter[0]));
	x[13] = _mm256_add_epi64(x[13], _mm256_loadu_si256((const __m256i*) & counter[4]));
	x[14] = _mm256_add_epi64(x[14], _mm256_set1_epi64x(pstate[12]));
	x[15] = _mm256_add_epi64(x[15], _mm256_set1_epi64x(pstate[13]));

	csx_store_4xull1024(x, output);
}

#endif

static void csx_load(qsc_csx_state* ctx, const uint8_t* key, const uint8_t* nonce, const uint8_t* code)
{
	/* load the key, nonce, and code into state */
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_copy((uint8_t*)ctx->state, key, 64);
	qsc_memutils_copy((uint8_t*)ctx->state + 64, code, 48);
	qsc_memutils_copy((uint8_t*)ctx->nonce, nonce, 16);
#else
	ctx->state[0] = qsc_intutils_le8to64(key);
	ctx->state[1] = qsc_intutils_le8to64(key + 8);
	ctx->state[2] = qsc_intutils_le8to64(key + 16);
	ctx->state[3] = qsc_intutils_le8to64(key + 24);
	ctx->state[4] = qsc_intutils_le8to64(key + 32);
	ctx->state[5] = qsc_intutils_le8to64(key + 40);
	ctx->state[6] = qsc_intutils_le8to64(key + 48);
	ctx->state[7] = qsc_intutils_le8to64(key + 56);
	ctx->state[8] = qsc_intutils_le8to64(code);
	ctx->state[9] = qsc_intutils_le8to64(code + 8);
	ctx->state[10] = qsc_intutils_le8to64(code + 16);
	ctx->state[11] = qsc_intutils_le8to64(code + 24);
	ctx->state[12] = qsc_intutils_le8to64(code + 32);
	ctx->state[13] = qsc_intutils_le8to64(code + 40);
	ctx->nonce[0] = qsc_intutils_le8to64(nonce);
	ctx->nonce[1] = qsc_intutils_le8to64(nonce + 8);

#endif
}

void csx_generate(qsc_csx_state* ctx, uint8_t* output, size_t length)
{
	size_t ctr;

	ctr = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	const size_t AVX512BLK = 8 * QSC_CSX_BLOCK_SIZE;

	if (length >= AVX512BLK)
	{
		const size_t SEGALN = length - (length % AVX512BLK);
		uint64_t tmpc[16] = { 0 };

		/* process 8 blocks in parallel (uses avx512 if available) */
		while (ctr != SEGALN)
		{
			memcpy(&tmpc[0], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[8], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			memcpy(&tmpc[1], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[9], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			memcpy(&tmpc[2], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[10], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			memcpy(&tmpc[3], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[11], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			memcpy(&tmpc[4], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[12], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			memcpy(&tmpc[5], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[13], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			memcpy(&tmpc[6], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[14], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			memcpy(&tmpc[7], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[15], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			csx_permute_p8x1024h(ctx, tmpc, output + ctr);
			ctr += AVX512BLK;
		}
	}

#elif defined(QSC_SYSTEM_HAS_AVX2)

	const size_t AVX2BLK = 4 * QSC_CSX_BLOCK_SIZE;

	if (length >= AVX2BLK)
	{
		const size_t SEGALN = length - (length % AVX2BLK);
		uint64_t tmpc[8] = { 0 };

		/* process 4 blocks in parallel (uses avx2 if available) */
		while (ctr != SEGALN)
		{
			memcpy(&tmpc[0], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[4], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			memcpy(&tmpc[1], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[5], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			memcpy(&tmpc[2], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[6], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			memcpy(&tmpc[3], &ctx->nonce[0], sizeof(uint64_t));
			memcpy(&tmpc[7], &ctx->nonce[1], sizeof(uint64_t));
			csx_increment(ctx);
			csx_permute_p4x1024h(ctx, tmpc, output + ctr);
			ctr += AVX2BLK;
		}
	}

#endif

	const size_t ALNLEN = length - (length % QSC_CSX_BLOCK_SIZE);

	/* generate remaining blocks */
	while (ctr != ALNLEN)
	{
		csx_permute_p1024c(ctx, output + ctr);
		csx_increment(ctx);
		ctr += QSC_CSX_BLOCK_SIZE;
	}

	/* generate unaligned key-stream */
	if (ctr != length)
	{
		uint8_t otp[QSC_CSX_BLOCK_SIZE] = { 0 };
		csx_permute_p1024c(ctx, otp);
		csx_increment(ctx);
		const size_t FNLLEN = length % QSC_CSX_BLOCK_SIZE;
		memcpy(output, otp, FNLLEN);
	}
}

static void csx_process(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	/* generate key-stream */
	csx_generate(ctx, output, length);

	/* xor with input */
	qsc_memutils_xor(output, input, length);
}

static bool csx_finalize(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t inputlen, uint8_t* ncopy)
{
	uint8_t ctr[sizeof(uint64_t)] = { 0 };
	uint8_t* pmsg;
	uint64_t mctr;
	size_t CPTLEN = QSC_CSX_NONCE_SIZE + inputlen + ctx->aadlen + sizeof(uint64_t);
	size_t mlen;
	size_t poff;
	bool res;

	res = false;
	mctr = 0;
	poff = 0;

	/* allocate the input array */
	pmsg = (uint8_t*)malloc(CPTLEN);

	if (pmsg != (uint8_t*)0)
	{
		qsc_memutils_clear(pmsg, CPTLEN);

		/* copy aad */
		if (ctx->aadlen != 0)
		{
			qsc_memutils_copy(pmsg, ctx->aad, ctx->aadlen);
		}

		/* copy the nonce */
		qsc_memutils_copy(pmsg + ctx->aadlen, ncopy, QSC_CSX_NONCE_SIZE);

		/* copy the ciphertext, aad, and mac counter to the buffer array */
		if (inputlen != 0)
		{
			qsc_memutils_copy(pmsg + ctx->aadlen + QSC_CSX_NONCE_SIZE, input, inputlen);
		}

		/* append the counter to the end of the mac input array */
		qsc_intutils_le64to8(ctr, ctx->counter);
		memcpy(pmsg + ctx->aadlen + QSC_CSX_NONCE_SIZE + inputlen, ctr, sizeof(ctr));

		ctx->aadlen = 0;
		mlen = CPTLEN;

		/* update the message */
		qsc_kmac_update(&ctx->kstate, keccak_rate_512, pmsg, mlen);
		/* finalize the mac and append code to output */
		qsc_kmac_finalize(&ctx->kstate, keccak_rate_512, output, QSC_CSX_MAC_SIZE);

		qsc_intutils_clear8(pmsg, CPTLEN);
		free(pmsg);

		res = true;
	}

	return res;
}

/* csx common */

void qsc_csx_dispose(qsc_csx_state* ctx)
{
	assert(ctx != NULL);

	/* clear state */
	if (ctx != NULL)
	{
		qsc_keccak_dispose(&ctx->kstate);
		qsc_intutils_clear64(ctx->state, QSC_CSX_STATE_SIZE);
		qsc_intutils_clear64(ctx->nonce, QSC_CSX_NONCE_SIZE);
		ctx->aadlen = 0;
		ctx->counter = 0;
		ctx->encrypt = false;
	}
}

void qsc_csx_initialize(qsc_csx_state* ctx, const qsc_csx_keyparams* keyparams, bool encryption)
{
	assert(keyparams->nonce != NULL);
	assert(keyparams->key != NULL);
	assert(keyparams->keylen == QSC_CSX_KEY_SIZE);

	qsc_keccak_state kstate;
	uint8_t buf[QSC_KECCAK_512_RATE] = { 0 };
	uint8_t cpk[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t inf[CSX_NAME_LENGTH] = { 0 };
	uint8_t mck[QSC_CSX_KEY_SIZE] = { 0 };

	/* initialize the state */
	qsc_memutils_clear((uint8_t*)kstate.state, QSC_KECCAK_STATE_SIZE * sizeof(uint64_t));
	ctx->counter = 0;
	ctx->encrypt = encryption;
	ctx->aad = NULL;
	ctx->aadlen = 0;

	/* load the information string */
	if (keyparams->infolen == 0)
	{
		qsc_memutils_copy(inf, csx_name, CSX_NAME_LENGTH);
	}
	else
	{
		const size_t INFLEN = qsc_intutils_min(keyparams->infolen, CSX_NAME_LENGTH);
		qsc_memutils_copy(inf, keyparams->info, INFLEN);
	}

	/* initialize the cSHAKE generator */
	qsc_cshake_initialize(&kstate, keccak_rate_512, keyparams->key, keyparams->keylen, inf, sizeof(inf), NULL, 0);

	/* extract the cipher key */
	qsc_cshake_squeezeblocks(&kstate, keccak_rate_512, buf, 1);
	qsc_memutils_copy(cpk, buf, QSC_CSX_KEY_SIZE);
	csx_load(ctx, cpk, keyparams->nonce, csx_info);

	/* extract the mac key */
	qsc_cshake_squeezeblocks(&kstate, keccak_rate_512, buf, 1);
	qsc_memutils_copy(mck, buf, sizeof(mck));

	/* initialize the mac generator */
	qsc_memutils_clear((uint8_t*)ctx->kstate.state, QSC_KECCAK_STATE_SIZE * sizeof(uint64_t));
	qsc_kmac_initialize(&ctx->kstate, keccak_rate_512, mck, sizeof(mck), NULL, 0/*, NULL, 0*/);
}

void qsc_csx_set_associated(qsc_csx_state* ctx, const uint8_t* data, size_t datalen)
{
	assert(ctx != NULL);

	ctx->aad = data;
	ctx->aadlen = datalen;
}

bool qsc_csx_transform(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(output != NULL);
	assert(input != NULL);

	uint8_t ncopy[QSC_CSX_NONCE_SIZE] = { 0 };
	bool res;

	res = false;

	/* store the nonce */
	qsc_intutils_le64to8(ncopy, ctx->nonce[0]);
	qsc_intutils_le64to8(ncopy + sizeof(uint64_t), ctx->nonce[1]);

	/* update the processed bytes counter */
	ctx->counter += length;

	if (ctx->encrypt)
	{
		/* use the transform to generate the key-stream and encrypt the data  */
		csx_process(ctx, output, input, length);

		/* mac the cipher-text appending the code to the end of the array */
		res = csx_finalize(ctx, output + length, output, length, ncopy);
	}
	else
	{
		uint8_t code[QSC_CSX_MAC_SIZE] = { 0 };

		/* generate the internal mac code from the cipher-text */
		if (csx_finalize(ctx, code, input, length, ncopy))
		{
			/* compare the mac code with the one embedded in the cipher-text, bypassing the transform if the mac check fails */
			if (qsc_intutils_verify(code, input + length, QSC_CSX_MAC_SIZE) == 0)
			{
				/* generate the key-stream and decrypt the array */
				csx_process(ctx, output, input, length);
				res = true;
			}
		}
	}

	return res;
}