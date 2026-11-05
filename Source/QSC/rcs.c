#include "rcs.h"
#include "intutils.h"
#include "memutils.h"

/* Build profile: 14/21 Rijndael-256 rounds by default, or 22/30 when
 * QSC_RCS_EXTENDED_ROUND_COUNTS is selected in rcs.h. Both profiles use
 * the standard 24-round Keccak/KMAC implementation. */
#if defined(QSC_RCS_EXTENDED_ROUND_COUNTS)
#	define RCS256_ROUND_COUNT 22U
#	define RCS512_ROUND_COUNT 30U
#else
#	define RCS256_ROUND_COUNT 14U
#	define RCS512_ROUND_COUNT 21U
#endif

/*!
\def RCS_ROUNDKEY_ELEMENT_SIZE
* The round key element size in bytes.
*/
#if defined(QSC_SYSTEM_RCS_AESNI_ENABLED)
#	define RCS_ROUNDKEY_ELEMENT_SIZE 16U
#	define RCS_AVX512_BLOCK 64U
#else
#	define RCS_ROUNDKEY_ELEMENT_SIZE 4U
#	define RCS_PREFETCH_TABLES
#endif

/*!
\def RCS256_ROUNDKEY_SIZE
* The size of the RCS-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_rcs_state struct.
*/
#define RCS256_ROUNDKEY_SIZE ((RCS256_ROUND_COUNT + 1U) * (QSC_RCS_BLOCK_SIZE / RCS_ROUNDKEY_ELEMENT_SIZE))

/*!
\def RCS512_ROUNDKEY_SIZE
* The size of the RCS-512 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_rcs_state struct.
*/
#define RCS512_ROUNDKEY_SIZE ((RCS512_ROUND_COUNT + 1U) * (QSC_RCS_BLOCK_SIZE / RCS_ROUNDKEY_ELEMENT_SIZE))

/*!
\def RCS256_MKEY_LENGTH
* The size of the hba-rhx256 mac key array
*/
#define RCS256_MKEY_LENGTH 32U

/*!
\def RCS512_MKEY_LENGTH
* The size of the hba-rhx512 mac key array
*/
#define RCS512_MKEY_LENGTH 64U

/*!
\def RCS_NAME_LENGTH
* The HBA implementation specific name array length.
*/
#if defined(QSC_RCS_AUTHENTICATED)
#define RCS_NAME_LENGTH 17U
#else
#define RCS_NAME_LENGTH 13U
#endif

/*!
\def RCS_INFO_DEFLEN
* The size in bytes of the internal default information string.
*/
#define RCS_INFO_DEFLEN 9U

#if defined(QSC_RCS_AUTHENTICATED)

static const uint8_t rcs256_name[RCS_NAME_LENGTH] =
{
	0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x52U, 0x43U, 0x53U, 0x4BU, 0x32U, 0x35U, 0x36U
};

static const uint8_t rcs512_name[RCS_NAME_LENGTH] =
{
	0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U, 0x52U, 0x43U, 0x53U, 0x4BU, 0x35U, 0x31U, 0x32U
};


#else

static const uint8_t rcs256_name[RCS_NAME_LENGTH] =
{
	0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x52U, 0x43U, 0x53U
};

static const uint8_t rcs512_name[RCS_NAME_LENGTH] =
{
	0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U, 0x52U, 0x43U, 0x53U
};

#endif

/* aes-ni and table-based fallback functions */

#if defined(QSC_SYSTEM_RCS_AESNI_ENABLED)

static void rcs_transform_256(const qsc_rcs_state* ctx, __m128i output[2U], const __m128i input[2U])
{
	/* encrypt one 32-byte Rijndael block with the expanded schedule */
	const __m128i BLEND_MASK = _mm_set_epi32(INT32_MIN, -2139095040, -2139095040, -2139062272);
	const __m128i SHIFT_MASK = _mm_set_epi8(3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0);
	const size_t RNDCNT = ctx->roundkeylen - 3U;
	size_t kctr;

	__m128i blk1 = _mm_loadu_si128(&input[0U]);
	__m128i blk2 = _mm_loadu_si128(&input[1U]);
	__m128i tmp1;
	__m128i tmp2;

	kctr = 0U;
	blk1 = _mm_xor_si128(blk1, ctx->roundkeys[kctr]);
	++kctr;
	blk2 = _mm_xor_si128(blk2, ctx->roundkeys[kctr]);

	while (kctr != RNDCNT)
	{
		/* mix the blocks */
		tmp1 = _mm_blendv_epi8(blk1, blk2, BLEND_MASK);
		tmp2 = _mm_blendv_epi8(blk2, blk1, BLEND_MASK);
		/* shuffle */
		tmp1 = _mm_shuffle_epi8(tmp1, SHIFT_MASK);
		tmp2 = _mm_shuffle_epi8(tmp2, SHIFT_MASK);
		++kctr;
		/* encrypt the first half-block */
		blk1 = _mm_aesenc_si128(tmp1, ctx->roundkeys[kctr]);
		++kctr;
		/* encrypt the second half-block */
		blk2 = _mm_aesenc_si128(tmp2, ctx->roundkeys[kctr]);
	}

	/* final block */
	tmp1 = _mm_blendv_epi8(blk1, blk2, BLEND_MASK);
	tmp2 = _mm_blendv_epi8(blk2, blk1, BLEND_MASK);
	tmp1 = _mm_shuffle_epi8(tmp1, SHIFT_MASK);
	tmp2 = _mm_shuffle_epi8(tmp2, SHIFT_MASK);
	++kctr;
	blk1 = _mm_aesenclast_si128(tmp1, ctx->roundkeys[kctr]);
	++kctr;
	blk2 = _mm_aesenclast_si128(tmp2, ctx->roundkeys[kctr]);

	/* store in output */
	_mm_storeu_si128(&output[0U], blk1);
	_mm_storeu_si128(&output[1U], blk2);
}

#if !defined(QSC_SYSTEM_HAS_VAES512) && !(defined(QSC_RCS_ENABLE_VAES256) && defined(__AVX2__) && defined(__VAES__))

static void rcs_transform_256x2(const qsc_rcs_state* ctx, __m128i output[4U], const __m128i input[4U])
{
	/* encrypt two independent 256-bit RCS counter blocks through interleaved AES-NI rounds */
	const __m128i blend = _mm_set_epi32(INT32_MIN, -2139095040, -2139095040, -2139062272);
	const __m128i shift = _mm_set_epi8(3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0);
	const size_t last = ctx->roundkeylen - 3U;
	__m128i a0;
	__m128i a1;
	__m128i b0;
	__m128i b1;
	__m128i t0;
	__m128i t1;
	__m128i t2;
	__m128i t3;
	size_t k;

	a0 = _mm_xor_si128(input[0U], ctx->roundkeys[0U]);
	a1 = _mm_xor_si128(input[1U], ctx->roundkeys[1U]);
	b0 = _mm_xor_si128(input[2U], ctx->roundkeys[0U]);
	b1 = _mm_xor_si128(input[3U], ctx->roundkeys[1U]);
	k = 1U;

	while (k != last)
	{
		t0 = _mm_shuffle_epi8(_mm_blendv_epi8(a0, a1, blend), shift);
		t1 = _mm_shuffle_epi8(_mm_blendv_epi8(a1, a0, blend), shift);
		t2 = _mm_shuffle_epi8(_mm_blendv_epi8(b0, b1, blend), shift);
		t3 = _mm_shuffle_epi8(_mm_blendv_epi8(b1, b0, blend), shift);
		++k;
		a0 = _mm_aesenc_si128(t0, ctx->roundkeys[k]);
		b0 = _mm_aesenc_si128(t2, ctx->roundkeys[k]);
		++k;
		a1 = _mm_aesenc_si128(t1, ctx->roundkeys[k]);
		b1 = _mm_aesenc_si128(t3, ctx->roundkeys[k]);
	}

	t0 = _mm_shuffle_epi8(_mm_blendv_epi8(a0, a1, blend), shift);
	t1 = _mm_shuffle_epi8(_mm_blendv_epi8(a1, a0, blend), shift);
	t2 = _mm_shuffle_epi8(_mm_blendv_epi8(b0, b1, blend), shift);
	t3 = _mm_shuffle_epi8(_mm_blendv_epi8(b1, b0, blend), shift);
	++k;
	output[0U] = _mm_aesenclast_si128(t0, ctx->roundkeys[k]);
	output[2U] = _mm_aesenclast_si128(t2, ctx->roundkeys[k]);
	++k;
	output[1U] = _mm_aesenclast_si128(t1, ctx->roundkeys[k]);
	output[3U] = _mm_aesenclast_si128(t3, ctx->roundkeys[k]);
}

#endif

#if defined(QSC_RCS_ENABLE_VAES256) && defined(__AVX2__) && defined(__VAES__) && !defined(QSC_SYSTEM_HAS_VAES512)

static inline __m256i rcs_shuffle256_vaes(const __m256i x)
{
	/* implement Rijndael-256's 32-byte ShiftRows correspondence with VAES */
    const __m256i same = _mm256_setr_epi8(
		(char)0x00, (char)0x80, (char)0x80, (char)0x80, (char)0x04, (char)0x05, (char)0x80, (char)0x80, (char)0x08, (char)0x09, (char)0x0E, (char)0x80, (char)0x0C, (char)0x0D, (char)0x80, (char)0x80,
		(char)0x00, (char)0x80, (char)0x80, (char)0x80, (char)0x04, (char)0x05, (char)0x80, (char)0x80, (char)0x08, (char)0x09, (char)0x0E, (char)0x80, (char)0x0C, (char)0x0D, (char)0x80, (char)0x80);
    const __m256i cross = _mm256_setr_epi8(
		(char)0x80, (char)0x01, (char)0x06, (char)0x07, (char)0x80, (char)0x80, (char)0x0A, (char)0x0B, (char)0x80, (char)0x80, (char)0x80, (char)0x0F, (char)0x80, (char)0x80, (char)0x02, (char)0x03,
		(char)0x80, (char)0x01, (char)0x06, (char)0x07, (char)0x80, (char)0x80, (char)0x0A, (char)0x0B, (char)0x80, (char)0x80, (char)0x80, (char)0x0F, (char)0x80, (char)0x80, (char)0x02, (char)0x03);
    __m256i y;
    __m256i z;

    y = _mm256_shuffle_epi8(x, same);
    z = _mm256_permute2x128_si256(x, x, 0x01);
    z = _mm256_shuffle_epi8(z, cross);

    return _mm256_or_si256(y, z);
}

static void rcs_transform_vaes256x2(const qsc_rcs_state* ctx, __m256i* output0, __m256i* output1, const __m256i input0, const __m256i input1)
{
	/* encrypt two independent Rijndael-256 counter blocks concurrently */
    const size_t RNDCNT = (ctx->roundkeylen / 2U) - 2U;
    __m256i a;
    __m256i b;
    __m256i key;
    size_t kctr;

    kctr = 0U;
    key = _mm256_inserti128_si256(_mm256_castsi128_si256(ctx->roundkeys[0U]), ctx->roundkeys[1U], 1);
    a = _mm256_xor_si256(input0, key);
    b = _mm256_xor_si256(input1, key);

    while (kctr < RNDCNT)
    {
        ++kctr;
        key = _mm256_inserti128_si256(_mm256_castsi128_si256(ctx->roundkeys[2U * kctr]), ctx->roundkeys[(2U * kctr) + 1U], 1);
        a = rcs_shuffle256_vaes(a);
        b = rcs_shuffle256_vaes(b);
        a = _mm256_aesenc_epi128(a, key);
        b = _mm256_aesenc_epi128(b, key);
    }

    ++kctr;
    key = _mm256_inserti128_si256(_mm256_castsi128_si256(ctx->roundkeys[2U * kctr]), ctx->roundkeys[(2U * kctr) + 1U], 1);
    a = rcs_shuffle256_vaes(a);
    b = rcs_shuffle256_vaes(b);
    *output0 = _mm256_aesenclast_epi128(a, key);
    *output1 = _mm256_aesenclast_epi128(b, key);
}
#endif

#if defined(QSC_SYSTEM_RCS_AESNI_ENABLED) && defined(QSC_SYSTEM_HAS_VAES512)

static void rcs_load2x128to512(const __m128i* k1, const __m128i* k2, __m512i* output)
{
	*output = _mm512_setzero_si512();
	*output = _mm512_inserti32x4(*output, *k1, 0U);
	*output = _mm512_inserti32x4(*output, *k2, 1U);
	*output = _mm512_inserti32x4(*output, *k1, 2U);
	*output = _mm512_inserti32x4(*output, *k2, 3U);
}

__m512i rcs_shuffle512(const __m512i* value, const __m512i* k0, const __m512i* k1, const __m512i* mask)
{
#if defined(__AVX512VBMI__)
	/* RCS's fixed 32-byte ShiftRows permutation for two adjacent blocks.
	 * the indices are public, and the permutation remains constant-time. */
	const __m512i indices = _mm512_set_epi64(
		0x23223D3C2F3E3938ULL,
		0x2B2A353427262130ULL,
		0x33322D2C3F2E2928ULL,
		0x3B3A252437363120ULL,
		0x03021D1C0F1E1918ULL,
		0x0B0A151407060110ULL,
		0x13120D0C1F0E0908ULL,
		0x1B1A050417161100ULL);

	(void)k0;
	(void)k1;
	(void)mask;

	return _mm512_permutexvar_epi8(indices, *value);
#else
	return _mm512_or_si512(_mm512_shuffle_epi8(*value, _mm512_add_epi8(*mask, *k0)), _mm512_shuffle_epi8(_mm512_permutex_epi64(*value, 0x4E), _mm512_add_epi8(*mask, *k1)));
#endif
}

static void rcs_transform_512(qsc_rcs_state* ctx, __m512i* output, const __m512i* input)
{
	const __m512i NI512K0 = _mm512_set_epi64(-1085102592571150096LL, -1085102592571150096LL, 8102099357864587376ULL, 8102099357864587376ULL,
		-1085102592571150096LL, -1085102592571150096LL, 8102099357864587376ULL, 8102099357864587376ULL);
	const __m512i NI512K1 = _mm512_set_epi64(8102099357864587376ULL, 8102099357864587376ULL, -1085102592571150096LL, -1085102592571150096LL,
		8102099357864587376ULL, 8102099357864587376ULL, -1085102592571150096LL, -1085102592571150096LL);
	const __m512i SWMASKL = _mm512_set_epi8(3, 2, 29, 28, 15, 30, 25, 24, 11, 10, 21, 20, 7, 6, 1, 16,
		19, 18, 13, 12, 31, 14, 9, 8, 27, 26, 5, 4, 23, 22, 17, 0,
		3, 2, 29, 28, 15, 30, 25, 24, 11, 10, 21, 20, 7, 6, 1, 16,
		19, 18, 13, 12, 31, 14, 9, 8, 27, 26, 5, 4, 23, 22, 17, 0);

	const size_t RNDCNT = (ctx->roundkeylen / 2U) - 2U;
	size_t kctr;
	__m512i x;

	kctr = 0U;
	x = *input;
	x = _mm512_xor_si512(x, ctx->roundkeysw[kctr]);

	while (kctr < RNDCNT)
	{
		++kctr;
		x = rcs_shuffle512(&x, &NI512K0, &NI512K1, &SWMASKL);
		x = _mm512_aesenc_epi128(x, ctx->roundkeysw[kctr]);
	}

	++kctr;
	x = rcs_shuffle512(&x, &NI512K0, &NI512K1, &SWMASKL);
	*output = _mm512_aesenclast_epi128(x, ctx->roundkeysw[kctr]);
}

static void rcs_transform_512x2(const qsc_rcs_state* ctx, __m512i* output0, __m512i* output1, const __m512i* input0, const __m512i* input1)
{
	/* encrypt four independent RCS counter blocks as two VAES-512 chains */
	const __m512i NI512K0 = _mm512_set_epi64(-1085102592571150096LL, -1085102592571150096LL, 8102099357864587376ULL, 8102099357864587376ULL,
		-1085102592571150096LL, -1085102592571150096LL, 8102099357864587376ULL, 8102099357864587376ULL);
	const __m512i NI512K1 = _mm512_set_epi64(8102099357864587376ULL, 8102099357864587376ULL, -1085102592571150096LL, -1085102592571150096LL,
		8102099357864587376ULL, 8102099357864587376ULL, -1085102592571150096LL, -1085102592571150096LL);
	const __m512i SWMASKL = _mm512_set_epi8(3, 2, 29, 28, 15, 30, 25, 24, 11, 10, 21, 20, 7, 6, 1, 16,
		19, 18, 13, 12, 31, 14, 9, 8, 27, 26, 5, 4, 23, 22, 17, 0,
		3, 2, 29, 28, 15, 30, 25, 24, 11, 10, 21, 20, 7, 6, 1, 16,
		19, 18, 13, 12, 31, 14, 9, 8, 27, 26, 5, 4, 23, 22, 17, 0);

	const size_t RNDCNT = (ctx->roundkeylen / 2U) - 2U;
	size_t kctr;
	__m512i a;
	__m512i b;

	kctr = 0U;
	a = _mm512_xor_si512(*input0, ctx->roundkeysw[kctr]);
	b = _mm512_xor_si512(*input1, ctx->roundkeysw[kctr]);

	while (kctr < RNDCNT)
	{
		++kctr;
		a = rcs_shuffle512(&a, &NI512K0, &NI512K1, &SWMASKL);
		b = rcs_shuffle512(&b, &NI512K0, &NI512K1, &SWMASKL);
		a = _mm512_aesenc_epi128(a, ctx->roundkeysw[kctr]);
		b = _mm512_aesenc_epi128(b, ctx->roundkeysw[kctr]);
	}

	++kctr;
	a = rcs_shuffle512(&a, &NI512K0, &NI512K1, &SWMASKL);
	b = rcs_shuffle512(&b, &NI512K0, &NI512K1, &SWMASKL);
	*output0 = _mm512_aesenclast_epi128(a, ctx->roundkeysw[kctr]);
	*output1 = _mm512_aesenclast_epi128(b, ctx->roundkeysw[kctr]);
}

#endif

static void rcs_ctr_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	/* transform bytes with counter mode; exact input/output aliasing is supported */
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	const size_t HLFBLK = QSC_RCS_BLOCK_SIZE / 2U;
	__m128i tmpn[2U];
	__m128i tmpo[2U];
	__m128i tmpi[2U];
	uint8_t tmpb[QSC_RCS_BLOCK_SIZE];
	size_t oft;

	oft = 0U;

#if defined(QSC_SYSTEM_RCS_AESNI_ENABLED) && defined(QSC_SYSTEM_HAS_VAES512)

	/* four-block AES-derived pipeline: two independent VAES-512 chains.
	 * retain the accepted two-block path for smaller remainders. a batch
	 * is permitted only if the entire request avoids low-64-bit rollover. */
	if (length >= 4096U &&
		((uint64_t)(length / QSC_RCS_BLOCK_SIZE) +
		(uint64_t)((length % QSC_RCS_BLOCK_SIZE) != 0U)) <=
		(UINT64_MAX - qsc_intutils_le8to64(ctx->nonce)))
	{
		QSC_ALIGN(64) uint8_t ctrblk[64U];
		const __m512i fourstep = _mm512_set_epi64(0, 0, 0, 4, 0, 0, 0, 4);
		__m512i nce0;
		__m512i nce1;
		__m512i out0;
		__m512i out1;
		__m512i in0;
		__m512i in1;

		qsc_memutils_copy(ctrblk, ctx->nonce, QSC_RCS_BLOCK_SIZE);
		qsc_memutils_copy(ctrblk + QSC_RCS_BLOCK_SIZE, ctx->nonce, QSC_RCS_BLOCK_SIZE);
		nce0 = _mm512_load_si512((const void*)ctrblk);
		nce0 = _mm512_add_epi64(nce0, _mm512_set_epi64(0, 0, 0, 1, 0, 0, 0, 0));
		nce1 = _mm512_add_epi64(nce0, _mm512_set_epi64(0, 0, 0, 2, 0, 0, 0, 2));

		while (length >= 128U)
		{
			rcs_transform_512x2(ctx, &out0, &out1, &nce0, &nce1);
			in0 = _mm512_loadu_si512((const void*)(input + oft));
			in1 = _mm512_loadu_si512((const void*)(input + oft + 64U));
			out0 = _mm512_xor_si512(out0, in0);
			out1 = _mm512_xor_si512(out1, in1);
			_mm512_storeu_si512((void*)(output + oft), out0);
			_mm512_storeu_si512((void*)(output + oft + 64U), out1);
			nce0 = _mm512_add_epi64(nce0, fourstep);
			nce1 = _mm512_add_epi64(nce1, fourstep);
			oft += 128U;
			length -= 128U;
		}

		_mm512_store_si512((void*)ctrblk, nce0);
		qsc_memutils_copy(ctx->nonce, ctrblk, QSC_RCS_BLOCK_SIZE);
		qsc_memutils_secure_erase(ctrblk, sizeof(ctrblk));
		qsc_memutils_secure_erase(&out0, sizeof(out0));
		qsc_memutils_secure_erase(&out1, sizeof(out1));
		qsc_memutils_secure_erase(&in0, sizeof(in0));
		qsc_memutils_secure_erase(&in1, sizeof(in1));
	}

	/* AES-compatible rollover guard: the fast 64-bit lane increment is safe
	 * only when every processed block and the final nonce remain below wrap.
	 * the rare rollover case uses the existing full-width scalar increment. */
	if (length >= RCS_AVX512_BLOCK &&
		((uint64_t)(length / QSC_RCS_BLOCK_SIZE) +
		(uint64_t)((length % QSC_RCS_BLOCK_SIZE) != 0U)) <=
		(UINT64_MAX - qsc_intutils_le8to64(ctx->nonce)))
	{
		QSC_ALIGN(64) uint8_t ctrblk[64U];
		__m512i ctrw;
		__m512i inpw;
		__m512i otpw;

		/* initialize and pre-set the nonce */
		ctrw = _mm512_set1_epi64(0);
		qsc_memutils_copy(ctrblk, ctx->nonce, QSC_RCS_BLOCK_SIZE);
		qsc_memutils_copy((ctrblk + QSC_RCS_BLOCK_SIZE), ctx->nonce, QSC_RCS_BLOCK_SIZE);
		ctrw = _mm512_load_si512(ctrblk);
		ctrw = _mm512_add_epi64(ctrw, _mm512_set_epi64(0, 0, 0, 1, 0, 0, 0, 0));

		/* process 2 blocks in parallel */
		while (length >= RCS_AVX512_BLOCK)
		{
			/* encrypt the nonce */
			rcs_transform_512(ctx, &otpw, &ctrw);
			/* load the input */
			inpw = _mm512_loadu_si512((const __m512i*)((uint8_t*)input + oft));
			/* xor encrypted encrypted nonce with the input */
			otpw = _mm512_xor_si512(otpw, inpw);
			/* increments only the first 64 bits of the nonce; with ulong rollover that is 2^64 output blocks available */
			ctrw = _mm512_add_epi64(ctrw, _mm512_set_epi64(0, 0, 0, 2, 0, 0, 0, 2));
			/* store in output */
			_mm512_storeu_si512((__m512i*)((uint8_t*)output + oft), otpw);

			oft += RCS_AVX512_BLOCK;
			length -= RCS_AVX512_BLOCK;
		}

		/* store the last position of the nonce */
		_mm512_storeu_si512((__m512i*)ctrblk, ctrw);
		qsc_memutils_copy(ctx->nonce, ctrblk, QSC_RCS_BLOCK_SIZE);
		qsc_memutils_secure_erase(ctrblk, sizeof(ctrblk));
		qsc_memutils_secure_erase(&inpw, sizeof(inpw));
		qsc_memutils_secure_erase(&otpw, sizeof(otpw));
	}

#endif

#if defined(QSC_RCS_ENABLE_VAES256) && defined(__AVX2__) && defined(__VAES__) && !defined(QSC_SYSTEM_HAS_VAES512)
    /* two 256-bit Rijndael counter blocks in two independent YMM chains.
     * the existing AES-NI implementation handles rollover and short tails. */
    if (length >= 64U &&
        ((uint64_t)(length / QSC_RCS_BLOCK_SIZE) +
        (uint64_t)((length % QSC_RCS_BLOCK_SIZE) != 0U)) <=
        (UINT64_MAX - qsc_intutils_le8to64(ctx->nonce)))
    {
        const __m256i increment = _mm256_set_epi64x(0, 0, 0, 2);
        __m256i counter0;
        __m256i counter1;
        __m256i cipher0;
        __m256i cipher1;
        __m256i input0;
        __m256i input1;

        counter0 = _mm256_loadu_si256((const __m256i*)(const void*)ctx->nonce);
        counter1 = _mm256_add_epi64(counter0, _mm256_set_epi64x(0, 0, 0, 1));

        while (length >= 64U)
        {
            rcs_transform_vaes256x2(ctx, &cipher0, &cipher1, counter0, counter1);
            input0 = _mm256_loadu_si256((const __m256i*)(const void*)(input + oft));
            input1 = _mm256_loadu_si256((const __m256i*)(const void*)(input + oft + 32U));
            cipher0 = _mm256_xor_si256(cipher0, input0);
            cipher1 = _mm256_xor_si256(cipher1, input1);
            _mm256_storeu_si256((__m256i*)(void*)(output + oft), cipher0);
            _mm256_storeu_si256((__m256i*)(void*)(output + oft + 32U), cipher1);
            counter0 = _mm256_add_epi64(counter0, increment);
            counter1 = _mm256_add_epi64(counter1, increment);
            oft += 64U;
            length -= 64U;
        }

        _mm256_storeu_si256((__m256i*)(void*)ctx->nonce, counter0);
		qsc_memutils_secure_erase(&cipher0, sizeof(cipher0));
		qsc_memutils_secure_erase(&cipher1, sizeof(cipher1));
		qsc_memutils_secure_erase(&input0, sizeof(input0));
		qsc_memutils_secure_erase(&input1, sizeof(input1));
    }
#endif

#if !defined(QSC_SYSTEM_HAS_VAES512) && !(defined(QSC_RCS_ENABLE_VAES256) && defined(__AVX2__) && defined(__VAES__))
	/* interleave two independent AES-NI Rijndael-256 blocks to hide round latency */
	if (length >= (2U * QSC_RCS_BLOCK_SIZE))
	{
		__m128i counters[4U];
		__m128i streams[4U];
		__m128i data[4U];

		while (length >= (2U * QSC_RCS_BLOCK_SIZE))
		{
			counters[0U] = _mm_loadu_si128((const __m128i*)(const void*)ctx->nonce);
			counters[1U] = _mm_loadu_si128((const __m128i*)(const void*)(ctx->nonce + HLFBLK));
			qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);
			counters[2U] = _mm_loadu_si128((const __m128i*)(const void*)ctx->nonce);
			counters[3U] = _mm_loadu_si128((const __m128i*)(const void*)(ctx->nonce + HLFBLK));
			qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);
			rcs_transform_256x2(ctx, streams, counters);

			data[0U] = _mm_loadu_si128((const __m128i*)(const void*)(input + oft));
			data[1U] = _mm_loadu_si128((const __m128i*)(const void*)(input + oft + HLFBLK));
			data[2U] = _mm_loadu_si128((const __m128i*)(const void*)(input + oft + QSC_RCS_BLOCK_SIZE));
			data[3U] = _mm_loadu_si128((const __m128i*)(const void*)(input + oft + QSC_RCS_BLOCK_SIZE + HLFBLK));
			_mm_storeu_si128((__m128i*)(void*)(output + oft), _mm_xor_si128(streams[0U], data[0U]));
			_mm_storeu_si128((__m128i*)(void*)(output + oft + HLFBLK), _mm_xor_si128(streams[1U], data[1U]));
			_mm_storeu_si128((__m128i*)(void*)(output + oft + QSC_RCS_BLOCK_SIZE), _mm_xor_si128(streams[2U], data[2U]));
			_mm_storeu_si128((__m128i*)(void*)(output + oft + QSC_RCS_BLOCK_SIZE + HLFBLK), _mm_xor_si128(streams[3U], data[3U]));
			oft += (2U * QSC_RCS_BLOCK_SIZE);
			length -= (2U * QSC_RCS_BLOCK_SIZE);
		}

		qsc_memutils_secure_erase(counters, sizeof(counters));
		qsc_memutils_secure_erase(streams, sizeof(streams));
		qsc_memutils_secure_erase(data, sizeof(data));
	}

#endif

	while (length >= QSC_RCS_BLOCK_SIZE)
	{
		tmpn[0U] = _mm_loadu_si128((const __m128i*)ctx->nonce);
		tmpn[1U] = _mm_loadu_si128((const __m128i*)(ctx->nonce + HLFBLK));

		rcs_transform_256(ctx, tmpo, tmpn);

		tmpi[0U] = _mm_loadu_si128((const __m128i*)(input + oft));
		tmpi[1U] = _mm_loadu_si128((const __m128i*)(input + HLFBLK + oft));

		tmpo[0U] = _mm_xor_si128(tmpo[0U], tmpi[0U]);
		tmpo[1U] = _mm_xor_si128(tmpo[1U], tmpi[1U]);

		qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);

		/* store in output */
		_mm_storeu_si128((__m128i*)(output + oft), tmpo[0U]);
		_mm_storeu_si128((__m128i*)(output + HLFBLK + oft), tmpo[1U]);

		length -= QSC_RCS_BLOCK_SIZE;
		oft += QSC_RCS_BLOCK_SIZE;
	}

	if (length != 0U)
	{
		tmpn[0U] = _mm_loadu_si128((const __m128i*)ctx->nonce);
		tmpn[1U] = _mm_loadu_si128((const __m128i*)(ctx->nonce + HLFBLK));

		rcs_transform_256(ctx, tmpo, tmpn);

		/* store in tmp */
		_mm_storeu_si128((__m128i*)tmpb, tmpo[0U]);
		_mm_storeu_si128((__m128i*)((uint8_t*)tmpb + HLFBLK), tmpo[1U]);

		for (size_t i = 0U; i < length; ++i)
		{
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);
	}

	qsc_memutils_secure_erase(tmpn, sizeof(tmpn));
	qsc_memutils_secure_erase(tmpo, sizeof(tmpo));
	qsc_memutils_secure_erase(tmpi, sizeof(tmpi));
	qsc_memutils_secure_erase(tmpb, sizeof(tmpb));
}

#else

#if !defined(QSC_SYSTEM_ARM_AES_ENABLED)

static inline void rcs_swapn(uint32_t cl, uint32_t ch, uint32_t s, uint32_t* x, uint32_t* y)
{
	uint32_t a = *x;
	uint32_t b = *y;
	*x = (a & cl) | ((b & cl) << s);
	*y = ((a & ch) >> s) | (b & ch);
}

static inline void rcs_swap2(uint32_t* x, uint32_t* y)
{
	/* 0101... / 1010...  (1-bit lanes) */
	rcs_swapn(0x55555555U, 0xAAAAAAAAU, 1U, x, y);
}

static inline void rcs_swap4(uint32_t* x, uint32_t* y)
{
	/* 0011... / 1100...  (2-bit lanes) */
	rcs_swapn(0x33333333U, 0xCCCCCCCCU, 2U, x, y);
}

static inline void rcs_swap8(uint32_t* x, uint32_t* y)
{
	/* 0000 1111... / 1111 0000...  (4-bit lanes) */
	rcs_swapn(0x0F0F0F0FU, 0xF0F0F0F0U, 4U, x, y);
}

static inline void rcs_ct_ortho(uint32_t* q)
{
	rcs_swap2(&q[0U], &q[1U]);
	rcs_swap2(&q[2U], &q[3U]);
	rcs_swap2(&q[4U], &q[5U]);
	rcs_swap2(&q[6U], &q[7U]);

	rcs_swap4(&q[0U], &q[2U]);
	rcs_swap4(&q[1U], &q[3U]);
	rcs_swap4(&q[4U], &q[6U]);
	rcs_swap4(&q[5U], &q[7U]);

	rcs_swap8(&q[0U], &q[4U]);
	rcs_swap8(&q[1U], &q[5U]);
	rcs_swap8(&q[2U], &q[6U]);
	rcs_swap8(&q[3U], &q[7U]);
}

static inline void rcs_ct_sbox(uint32_t* q)
{
	/* adapted from bearssl, author Thomas Pornin.
	 * This S-box implementation is a straightforward translation of
	 * the circuit described by Boyar and Peralta in "A new
	 * combinational logic minimization technique with applications
	 * to cryptology" (https://eprint.iacr.org/2009/191.pdf).
	 *
	 * Note that variables x* (input) and s* (output) are numbered
	 * in "reverse" order (x0 is the high bit, x7 is the low bit). */

	uint32_t s0;
	uint32_t s1;
	uint32_t s2;
	uint32_t s3;
	uint32_t s4;
	uint32_t s5;
	uint32_t s6;
	uint32_t s7;
	uint32_t t0;
	uint32_t t1;
	uint32_t t2;
	uint32_t t3;
	uint32_t t4;
	uint32_t t5;
	uint32_t t6;
	uint32_t t7;
	uint32_t t8;
	uint32_t t9;
	uint32_t t10;
	uint32_t t11;
	uint32_t t12;
	uint32_t t13;
	uint32_t t14;
	uint32_t t15;
	uint32_t t16;
	uint32_t t17;
	uint32_t t18;
	uint32_t t19;
	uint32_t t20;
	uint32_t t21;
	uint32_t t22;
	uint32_t t23;
	uint32_t t24;
	uint32_t t25;
	uint32_t t26;
	uint32_t t27;
	uint32_t t28;
	uint32_t t29;
	uint32_t t30;
	uint32_t t31;
	uint32_t t32;
	uint32_t t33;
	uint32_t t34;
	uint32_t t35;
	uint32_t t36;
	uint32_t t37;
	uint32_t t38;
	uint32_t t39;
	uint32_t t40;
	uint32_t t41;
	uint32_t t42;
	uint32_t t43;
	uint32_t t44;
	uint32_t t45;
	uint32_t t46;
	uint32_t t47;
	uint32_t t48;
	uint32_t t49;
	uint32_t t50;
	uint32_t t51;
	uint32_t t52;
	uint32_t t53;
	uint32_t t54;
	uint32_t t55;
	uint32_t t56;
	uint32_t t57;
	uint32_t t58;
	uint32_t t59;
	uint32_t t60;
	uint32_t t61;
	uint32_t t62;
	uint32_t t63;
	uint32_t t64;
	uint32_t t65;
	uint32_t t66;
	uint32_t t67;
	uint32_t x0;
	uint32_t x1;
	uint32_t x2;
	uint32_t x3;
	uint32_t x4;
	uint32_t x5;
	uint32_t x6;
	uint32_t x7;
	uint32_t y1;
	uint32_t y2;
	uint32_t y3;
	uint32_t y4;
	uint32_t y5;
	uint32_t y6;
	uint32_t y7;
	uint32_t y8;
	uint32_t y9;
	uint32_t y10;
	uint32_t y11;
	uint32_t y12;
	uint32_t y13;
	uint32_t y14;
	uint32_t y15;
	uint32_t y16;
	uint32_t y17;
	uint32_t y18;
	uint32_t y19;
	uint32_t y20;
	uint32_t y21;
	uint32_t z0;
	uint32_t z1;
	uint32_t z2;
	uint32_t z3;
	uint32_t z4;
	uint32_t z5;
	uint32_t z6;
	uint32_t z7;
	uint32_t z8;
	uint32_t z9;
	uint32_t z10;
	uint32_t z11;
	uint32_t z12;
	uint32_t z13;
	uint32_t z14;
	uint32_t z15;
	uint32_t z16;
	uint32_t z17;

	x0 = q[7U];
	x1 = q[6U];
	x2 = q[5U];
	x3 = q[4U];
	x4 = q[3U];
	x5 = q[2U];
	x6 = q[1U];
	x7 = q[0U];

	/* top linear transformation */
	y14 = x3 ^ x5;
	y13 = x0 ^ x6;
	y9 = x0 ^ x3;
	y8 = x0 ^ x5;
	t0 = x1 ^ x2;
	y1 = t0 ^ x7;
	y4 = y1 ^ x3;
	y12 = y13 ^ y14;
	y2 = y1 ^ x0;
	y5 = y1 ^ x6;
	y3 = y5 ^ y8;
	t1 = x4 ^ y12;
	y15 = t1 ^ x5;
	y20 = t1 ^ x1;
	y6 = y15 ^ x7;
	y10 = y15 ^ t0;
	y11 = y20 ^ y9;
	y7 = x7 ^ y11;
	y17 = y10 ^ y11;
	y19 = y10 ^ y8;
	y16 = t0 ^ y11;
	y21 = y13 ^ y16;
	y18 = x0 ^ y16;

	/* non-linear section */
	t2 = y12 & y15;
	t3 = y3 & y6;
	t4 = t3 ^ t2;
	t5 = y4 & x7;
	t6 = t5 ^ t2;
	t7 = y13 & y16;
	t8 = y5 & y1;
	t9 = t8 ^ t7;
	t10 = y2 & y7;
	t11 = t10 ^ t7;
	t12 = y9 & y11;
	t13 = y14 & y17;
	t14 = t13 ^ t12;
	t15 = y8 & y10;
	t16 = t15 ^ t12;
	t17 = t4 ^ t14;
	t18 = t6 ^ t16;
	t19 = t9 ^ t14;
	t20 = t11 ^ t16;
	t21 = t17 ^ y20;
	t22 = t18 ^ y19;
	t23 = t19 ^ y21;
	t24 = t20 ^ y18;

	t25 = t21 ^ t22;
	t26 = t21 & t23;
	t27 = t24 ^ t26;
	t28 = t25 & t27;
	t29 = t28 ^ t22;
	t30 = t23 ^ t24;
	t31 = t22 ^ t26;
	t32 = t31 & t30;
	t33 = t32 ^ t24;
	t34 = t23 ^ t33;
	t35 = t27 ^ t33;
	t36 = t24 & t35;
	t37 = t36 ^ t34;
	t38 = t27 ^ t36;
	t39 = t29 & t38;
	t40 = t25 ^ t39;

	t41 = t40 ^ t37;
	t42 = t29 ^ t33;
	t43 = t29 ^ t40;
	t44 = t33 ^ t37;
	t45 = t42 ^ t41;
	z0 = t44 & y15;
	z1 = t37 & y6;
	z2 = t33 & x7;
	z3 = t43 & y16;
	z4 = t40 & y1;
	z5 = t29 & y7;
	z6 = t42 & y11;
	z7 = t45 & y17;
	z8 = t41 & y10;
	z9 = t44 & y12;
	z10 = t37 & y3;
	z11 = t33 & y4;
	z12 = t43 & y13;
	z13 = t40 & y5;
	z14 = t29 & y2;
	z15 = t42 & y9;
	z16 = t45 & y14;
	z17 = t41 & y8;

	/* bottom linear transformation */
	t46 = z15 ^ z16;
	t47 = z10 ^ z11;
	t48 = z5 ^ z13;
	t49 = z9 ^ z10;
	t50 = z2 ^ z12;
	t51 = z2 ^ z5;
	t52 = z7 ^ z8;
	t53 = z0 ^ z3;
	t54 = z6 ^ z7;
	t55 = z16 ^ z17;
	t56 = z12 ^ t48;
	t57 = t50 ^ t53;
	t58 = z4 ^ t46;
	t59 = z3 ^ t54;
	t60 = t46 ^ t57;
	t61 = z14 ^ t57;
	t62 = t52 ^ t58;
	t63 = t49 ^ t58;
	t64 = z4 ^ t59;
	t65 = t61 ^ t62;
	t66 = z1 ^ t63;
	s0 = t59 ^ t63;
	s6 = t56 ^ ~t62;
	s7 = t48 ^ ~t60;
	t67 = t64 ^ t65;
	s3 = t53 ^ t66;
	s4 = t51 ^ t66;
	s5 = t47 ^ t65;
	s1 = t64 ^ ~s3;
	s2 = t55 ^ ~t67;

	q[7U] = s0;
	q[6U] = s1;
	q[5U] = s2;
	q[4U] = s3;
	q[3U] = s4;
	q[2U] = s5;
	q[1U] = s6;
	q[0U] = s7;
}

/*! \brief Prepare a complete Rijndael-256 schedule in a persistent bitsliced representation.
 * \param ctx Borrowed initialized RCS cipher context containing expanded round keys.
 * \param keys Writable schedule of RCS512_ROUND_COUNT + 1 rounds, eight words per round.
 * \note Round-key bytes are unchanged; this is a fixed-work representation conversion.
 *       The caller owns and securely erases the output. Reentrant for independent contexts.
 */
static void rcs_bitslice_prepare_keys(const qsc_rcs_state* ctx, uint32_t keys[RCS512_ROUND_COUNT + 1U][8U])
{
	uint8_t block[QSC_RCS_BLOCK_SIZE];
	uint32_t* q;
	size_t i;
	size_t j;

	for (i = 0U; i <= ctx->rounds; ++i)
	{
		for (j = 0U; j < 8U; ++j)
		{
			qsc_intutils_be32to8(block + (j * sizeof(uint32_t)), ctx->roundkeys[(i * 8U) + j]);
		}

		q = keys[i];

		for (j = 0U; j < 8U; ++j)
		{
			q[j] = (uint32_t)block[j] | ((uint32_t)block[j + 8U] << 8U) |
				((uint32_t)block[j + 16U] << 16U) | ((uint32_t)block[j + 24U] << 24U);
		}

		rcs_ct_ortho(q);
	}

	qsc_memutils_secure_erase(block, sizeof(block));
}

/*! \brief Apply Rijndael-256 ShiftRows directly to eight 32-bit AES bitplanes.
 * \param q Eight writable bitplanes representing the complete 32-byte block.
 * \note Uses the standard 8-column Rijndael shifts of 0, 1, 3 and 4 columns.
 *       The shifts and masks are fixed, independent of key and data.
 */
static inline void rcs_bitslice_shift_rows(uint32_t q[8U])
{
	uint32_t x;
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		x = q[i];
		q[i] = (x & UINT32_C(0x11111111)) |
			((x & UINT32_C(0x22222222)) >> 4U) | ((x & UINT32_C(0x22222222)) << 28U) |
			((x & UINT32_C(0x44444444)) >> 12U) | ((x & UINT32_C(0x44444444)) << 20U) |
			((x & UINT32_C(0x88888888)) >> 16U) | ((x & UINT32_C(0x88888888)) << 16U);
	}
}

/*! \brief Rotate each four-bit column of a bitslice one row toward the first row.
 * \param x The input 32-bit bitplane.
 * \return The fixed-permutation bitplane, preserving all eight columns.
 */
static inline uint32_t rcs_bitslice_rotate_right(uint32_t x)
{
	return ((x & UINT32_C(0xEEEEEEEE)) >> 1U) | ((x & UINT32_C(0x11111111)) << 3U);
}

/*! \brief Rotate each four-bit column of a bitslice one row toward the last row.
 * \param x The input 32-bit bitplane.
 * \return The fixed-permutation bitplane, preserving all eight columns.
 */
static inline uint32_t rcs_bitslice_rotate_left(uint32_t x)
{
	return ((x & UINT32_C(0x77777777)) << 1U) | ((x & UINT32_C(0x88888888)) >> 3U);
}

/*! \brief Rotate each four-bit column of a bitslice by two rows.
 * \param x The input 32-bit bitplane.
 * \return The fixed-permutation bitplane, preserving all eight columns.
 */
static inline uint32_t rcs_bitslice_rotate_two(uint32_t x)
{
	return ((x & UINT32_C(0x33333333)) << 2U) | ((x & UINT32_C(0xCCCCCCCC)) >> 2U);
}

/*! \brief Multiply all 32 lane elements of a bitsliced state by x in GF(2^8).
 * \param q Eight writable bitplanes, updated in place.
 * \note Fixed-work AES/Rijndael reduction polynomial 0x11B, no lookup tables.
 */
static inline void rcs_bitslice_xtime(uint32_t q[8U])
{
	uint32_t high;

	high = q[7U];
	q[7U] = q[6U];
	q[6U] = q[5U];
	q[5U] = q[4U];
	q[4U] = q[3U] ^ high;
	q[3U] = q[2U] ^ high;
	q[2U] = q[1U];
	q[1U] = q[0U] ^ high;
	q[0U] = high;
}

/*! \brief Apply Rijndael-256 MixColumns across all eight bitsliced columns.
 * \param q Eight writable bitplanes containing the state.
 * \param scratch Eight borrowed scratch words; the caller securely erases them.
 * \note All operations are fixed-work and branchless with respect to secret data.
 */
static inline void rcs_bitslice_mix_columns(uint32_t q[8U], uint32_t scratch[8U])
{
	uint32_t col;
	uint32_t pair;
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		scratch[i] = q[i] ^ rcs_bitslice_rotate_right(q[i]);
	}

	rcs_bitslice_xtime(scratch);

	for (i = 0U; i < 8U; ++i)
	{
		col = q[i];
		pair = col ^ rcs_bitslice_rotate_two(col);
		q[i] = col ^ pair ^ rcs_bitslice_rotate_left(pair) ^ scratch[i];
	}
}

static void rcs_transform_256_bitsliced(const qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, const uint32_t keys[RCS512_ROUND_COUNT + 1U][8U])
{
	/* encrypt one 32-byte Rijndael-256 counter block with persistent bitplanes */
	uint32_t q[8U];
	uint32_t scratch[8U];
	size_t i;
	size_t round;

	for (i = 0U; i < 8U; ++i)
	{
		q[i] = (uint32_t)input[i] | ((uint32_t)input[i + 8U] << 8U) |
			((uint32_t)input[i + 16U] << 16U) | ((uint32_t)input[i + 24U] << 24U);
	}

	rcs_ct_ortho(q);

	for (i = 0U; i < 8U; ++i)
	{
		q[i] ^= keys[0U][i];
	}

	for (round = 1U; round < ctx->rounds; ++round)
	{
		rcs_ct_sbox(q);
		rcs_bitslice_shift_rows(q);
		rcs_bitslice_mix_columns(q, scratch);

		for (i = 0U; i < 8U; ++i)
		{
			q[i] ^= keys[round][i];
		}
	}

	rcs_ct_sbox(q);
	rcs_bitslice_shift_rows(q);

	for (i = 0U; i < 8U; ++i)
	{
		q[i] ^= keys[ctx->rounds][i];
	}

	rcs_ct_ortho(q);

	for (i = 0U; i < 8U; ++i)
	{
		output[i] = (uint8_t)q[i];
		output[i + 8U] = (uint8_t)(q[i] >> 8U);
		output[i + 16U] = (uint8_t)(q[i] >> 16U);
		output[i + 24U] = (uint8_t)(q[i] >> 24U);
	}

	qsc_memutils_secure_erase(scratch, sizeof(scratch));
	qsc_memutils_secure_erase(q, sizeof(q));
}


#if UINTPTR_MAX > UINT32_MAX

static inline void rcs_ct_ortho64(uint64_t q[8U])
{
	/* transpose two parallel eight-byte-lane Rijndael states into bitplanes */
	uint64_t a;
	uint64_t b;
	uint64_t t;
	size_t i;

	for (i = 0U; i < 8U; i += 2U)
	{
		a = q[i];
		b = q[i + 1U];
		t = ((a >> 1U) ^ b) & UINT64_C(0x5555555555555555);
		q[i] = a ^ (t << 1U);
		q[i + 1U] = b ^ t;
	}

	for (i = 0U; i < 8U; i += 4U)
	{
		a = q[i];
		b = q[i + 2U];
		t = ((a >> 2U) ^ b) & UINT64_C(0x3333333333333333);
		q[i] = a ^ (t << 2U);
		q[i + 2U] = b ^ t;
		a = q[i + 1U];
		b = q[i + 3U];
		t = ((a >> 2U) ^ b) & UINT64_C(0x3333333333333333);
		q[i + 1U] = a ^ (t << 2U);
		q[i + 3U] = b ^ t;
	}

	for (i = 0U; i < 4U; ++i)
	{
		a = q[i];
		b = q[i + 4U];
		t = ((a >> 4U) ^ b) & UINT64_C(0x0F0F0F0F0F0F0F0F);
		q[i] = a ^ (t << 4U);
		q[i + 4U] = b ^ t;
	}
}

/*! \brief Apply the original Boolean Rijndael S-box to two independent 256-bit blocks.
 * \param q Eight writable 64-bit bitplanes: lower and upper 32-bit lanes are separate blocks.
 * \note Fixed Boolean circuit with no indexed tables, allocations or shared mutable state.
 * Each 32-bit half follows the same Boolean operations as rcs_ct_sbox().
 */
static inline void rcs_ct_sbox64(uint64_t* q)
{
	/* adapted from bearssl, author Thomas Pornin.
	 * This S-box implementation is a straightforward translation of
	 * the circuit described by Boyar and Peralta in "A new
	 * combinational logic minimization technique with applications
	 * to cryptology" (https://eprint.iacr.org/2009/191.pdf).
	 *
	 * Note that variables x* (input) and s* (output) are numbered
	 * in "reverse" order (x0 is the high bit, x7 is the low bit). */

	uint64_t s0;
	uint64_t s1;
	uint64_t s2;
	uint64_t s3;
	uint64_t s4;
	uint64_t s5;
	uint64_t s6;
	uint64_t s7;
	uint64_t t0;
	uint64_t t1;
	uint64_t t2;
	uint64_t t3;
	uint64_t t4;
	uint64_t t5;
	uint64_t t6;
	uint64_t t7;
	uint64_t t8;
	uint64_t t9;
	uint64_t t10;
	uint64_t t11;
	uint64_t t12;
	uint64_t t13;
	uint64_t t14;
	uint64_t t15;
	uint64_t t16;
	uint64_t t17;
	uint64_t t18;
	uint64_t t19;
	uint64_t t20;
	uint64_t t21;
	uint64_t t22;
	uint64_t t23;
	uint64_t t24;
	uint64_t t25;
	uint64_t t26;
	uint64_t t27;
	uint64_t t28;
	uint64_t t29;
	uint64_t t30;
	uint64_t t31;
	uint64_t t32;
	uint64_t t33;
	uint64_t t34;
	uint64_t t35;
	uint64_t t36;
	uint64_t t37;
	uint64_t t38;
	uint64_t t39;
	uint64_t t40;
	uint64_t t41;
	uint64_t t42;
	uint64_t t43;
	uint64_t t44;
	uint64_t t45;
	uint64_t t46;
	uint64_t t47;
	uint64_t t48;
	uint64_t t49;
	uint64_t t50;
	uint64_t t51;
	uint64_t t52;
	uint64_t t53;
	uint64_t t54;
	uint64_t t55;
	uint64_t t56;
	uint64_t t57;
	uint64_t t58;
	uint64_t t59;
	uint64_t t60;
	uint64_t t61;
	uint64_t t62;
	uint64_t t63;
	uint64_t t64;
	uint64_t t65;
	uint64_t t66;
	uint64_t t67;
	uint64_t x0;
	uint64_t x1;
	uint64_t x2;
	uint64_t x3;
	uint64_t x4;
	uint64_t x5;
	uint64_t x6;
	uint64_t x7;
	uint64_t y1;
	uint64_t y2;
	uint64_t y3;
	uint64_t y4;
	uint64_t y5;
	uint64_t y6;
	uint64_t y7;
	uint64_t y8;
	uint64_t y9;
	uint64_t y10;
	uint64_t y11;
	uint64_t y12;
	uint64_t y13;
	uint64_t y14;
	uint64_t y15;
	uint64_t y16;
	uint64_t y17;
	uint64_t y18;
	uint64_t y19;
	uint64_t y20;
	uint64_t y21;
	uint64_t z0;
	uint64_t z1;
	uint64_t z2;
	uint64_t z3;
	uint64_t z4;
	uint64_t z5;
	uint64_t z6;
	uint64_t z7;
	uint64_t z8;
	uint64_t z9;
	uint64_t z10;
	uint64_t z11;
	uint64_t z12;
	uint64_t z13;
	uint64_t z14;
	uint64_t z15;
	uint64_t z16;
	uint64_t z17;

	x0 = q[7U];
	x1 = q[6U];
	x2 = q[5U];
	x3 = q[4U];
	x4 = q[3U];
	x5 = q[2U];
	x6 = q[1U];
	x7 = q[0U];

	/* top linear transformation */
	y14 = x3 ^ x5;
	y13 = x0 ^ x6;
	y9 = x0 ^ x3;
	y8 = x0 ^ x5;
	t0 = x1 ^ x2;
	y1 = t0 ^ x7;
	y4 = y1 ^ x3;
	y12 = y13 ^ y14;
	y2 = y1 ^ x0;
	y5 = y1 ^ x6;
	y3 = y5 ^ y8;
	t1 = x4 ^ y12;
	y15 = t1 ^ x5;
	y20 = t1 ^ x1;
	y6 = y15 ^ x7;
	y10 = y15 ^ t0;
	y11 = y20 ^ y9;
	y7 = x7 ^ y11;
	y17 = y10 ^ y11;
	y19 = y10 ^ y8;
	y16 = t0 ^ y11;
	y21 = y13 ^ y16;
	y18 = x0 ^ y16;

	/* non-linear section */
	t2 = y12 & y15;
	t3 = y3 & y6;
	t4 = t3 ^ t2;
	t5 = y4 & x7;
	t6 = t5 ^ t2;
	t7 = y13 & y16;
	t8 = y5 & y1;
	t9 = t8 ^ t7;
	t10 = y2 & y7;
	t11 = t10 ^ t7;
	t12 = y9 & y11;
	t13 = y14 & y17;
	t14 = t13 ^ t12;
	t15 = y8 & y10;
	t16 = t15 ^ t12;
	t17 = t4 ^ t14;
	t18 = t6 ^ t16;
	t19 = t9 ^ t14;
	t20 = t11 ^ t16;
	t21 = t17 ^ y20;
	t22 = t18 ^ y19;
	t23 = t19 ^ y21;
	t24 = t20 ^ y18;

	t25 = t21 ^ t22;
	t26 = t21 & t23;
	t27 = t24 ^ t26;
	t28 = t25 & t27;
	t29 = t28 ^ t22;
	t30 = t23 ^ t24;
	t31 = t22 ^ t26;
	t32 = t31 & t30;
	t33 = t32 ^ t24;
	t34 = t23 ^ t33;
	t35 = t27 ^ t33;
	t36 = t24 & t35;
	t37 = t36 ^ t34;
	t38 = t27 ^ t36;
	t39 = t29 & t38;
	t40 = t25 ^ t39;

	t41 = t40 ^ t37;
	t42 = t29 ^ t33;
	t43 = t29 ^ t40;
	t44 = t33 ^ t37;
	t45 = t42 ^ t41;
	z0 = t44 & y15;
	z1 = t37 & y6;
	z2 = t33 & x7;
	z3 = t43 & y16;
	z4 = t40 & y1;
	z5 = t29 & y7;
	z6 = t42 & y11;
	z7 = t45 & y17;
	z8 = t41 & y10;
	z9 = t44 & y12;
	z10 = t37 & y3;
	z11 = t33 & y4;
	z12 = t43 & y13;
	z13 = t40 & y5;
	z14 = t29 & y2;
	z15 = t42 & y9;
	z16 = t45 & y14;
	z17 = t41 & y8;

	/* bottom linear transformation */
	t46 = z15 ^ z16;
	t47 = z10 ^ z11;
	t48 = z5 ^ z13;
	t49 = z9 ^ z10;
	t50 = z2 ^ z12;
	t51 = z2 ^ z5;
	t52 = z7 ^ z8;
	t53 = z0 ^ z3;
	t54 = z6 ^ z7;
	t55 = z16 ^ z17;
	t56 = z12 ^ t48;
	t57 = t50 ^ t53;
	t58 = z4 ^ t46;
	t59 = z3 ^ t54;
	t60 = t46 ^ t57;
	t61 = z14 ^ t57;
	t62 = t52 ^ t58;
	t63 = t49 ^ t58;
	t64 = z4 ^ t59;
	t65 = t61 ^ t62;
	t66 = z1 ^ t63;
	s0 = t59 ^ t63;
	s6 = t56 ^ ~t62;
	s7 = t48 ^ ~t60;
	t67 = t64 ^ t65;
	s3 = t53 ^ t66;
	s4 = t51 ^ t66;
	s5 = t47 ^ t65;
	s1 = t64 ^ ~s3;
	s2 = t55 ^ ~t67;

	q[7U] = s0;
	q[6U] = s1;
	q[5U] = s2;
	q[4U] = s3;
	q[3U] = s4;
	q[2U] = s5;
	q[1U] = s6;
	q[0U] = s7;
}

static inline void rcs_bitslice_shift_rows64(uint64_t q[8U])
{
	/* apply Rijndael-256 ShiftRows independently to both 32-bit bitplane halves */
	uint64_t x;
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		x = q[i];
		q[i] = (x & UINT64_C(0x1111111111111111)) |
			((x & UINT64_C(0x2222222022222220)) >> 4U) | ((x & UINT64_C(0x0000000200000002)) << 28U) |
			((x & UINT64_C(0x4444400044444000)) >> 12U) | ((x & UINT64_C(0x0000044400000444)) << 20U) |
			((x & UINT64_C(0x8888000088880000)) >> 16U) | ((x & UINT64_C(0x0000888800008888)) << 16U);
	}
}

static inline uint64_t rcs_bitslice_rotate_right64(uint64_t x)
{
	/* rotate each Rijndael column one row toward the first row in both blocks */
	return ((x & UINT64_C(0xEEEEEEEEEEEEEEEE)) >> 1U) | ((x & UINT64_C(0x1111111111111111)) << 3U);
}

static inline uint64_t rcs_bitslice_rotate_left64(uint64_t x)
{
	/* rotate each Rijndael column one row toward the last row in both blocks */
	return ((x & UINT64_C(0x7777777777777777)) << 1U) | ((x & UINT64_C(0x8888888888888888)) >> 3U);
}

static inline uint64_t rcs_bitslice_rotate_two64(uint64_t x)
{
	/* rotate Rijndael columns by two rows in both blocks */
	return ((x & UINT64_C(0x3333333333333333)) << 2U) | ((x & UINT64_C(0xCCCCCCCCCCCCCCCC)) >> 2U);
}

static inline void rcs_bitslice_xtime64(uint64_t q[8U])
{
	/* multiply 64 byte lanes by x under the Rijndael field polynomial */
	uint64_t high;

	high = q[7U];
	q[7U] = q[6U];
	q[6U] = q[5U];
	q[5U] = q[4U];
	q[4U] = q[3U] ^ high;
	q[3U] = q[2U] ^ high;
	q[2U] = q[1U];
	q[1U] = q[0U] ^ high;
	q[0U] = high;
}

static inline void rcs_bitslice_mix_columns64(uint64_t q[8U], uint64_t scratch[8U])
{
	/* apply Rijndael MixColumns to two 256-bit blocks simultaneously */
	uint64_t col;
	uint64_t pair;
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		scratch[i] = q[i] ^ rcs_bitslice_rotate_right64(q[i]);
	}

	rcs_bitslice_xtime64(scratch);

	for (i = 0U; i < 8U; ++i)
	{
		col = q[i];
		pair = col ^ rcs_bitslice_rotate_two64(col);
		q[i] = col ^ pair ^ rcs_bitslice_rotate_left64(pair) ^ scratch[i];
	}
}

static void rcs_transform_512_bitsliced(const qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, const uint32_t keys[RCS512_ROUND_COUNT + 1U][8U])
{
	/* encrypt two independent Rijndael-256 counter blocks with one Boolean circuit */
	uint64_t q[8U];
	uint64_t scratch[8U];
	uint64_t key;
	size_t i;
	size_t round;

	for (i = 0U; i < 8U; ++i)
	{
		q[i] = (uint64_t)input[i] | ((uint64_t)input[i + 8U] << 8U) |
			((uint64_t)input[i + 16U] << 16U) | ((uint64_t)input[i + 24U] << 24U) |
			((uint64_t)input[i + 32U] << 32U) | ((uint64_t)input[i + 40U] << 40U) |
			((uint64_t)input[i + 48U] << 48U) | ((uint64_t)input[i + 56U] << 56U);
	}

	rcs_ct_ortho64(q);

	for (i = 0U; i < 8U; ++i)
	{
		key = (uint64_t)keys[0U][i];
		q[i] ^= key | (key << 32U);
	}

	for (round = 1U; round < ctx->rounds; ++round)
	{
		rcs_ct_sbox64(q);
		rcs_bitslice_shift_rows64(q);
		rcs_bitslice_mix_columns64(q, scratch);

		for (i = 0U; i < 8U; ++i)
		{
			key = (uint64_t)keys[round][i];
			q[i] ^= key | (key << 32U);
		}
	}

	rcs_ct_sbox64(q);
	rcs_bitslice_shift_rows64(q);

	for (i = 0U; i < 8U; ++i)
	{
		key = (uint64_t)keys[ctx->rounds][i];
		q[i] ^= key | (key << 32U);
	}

	rcs_ct_ortho64(q);

	for (i = 0U; i < 8U; ++i)
	{
		output[i] = (uint8_t)q[i];
		output[i + 8U] = (uint8_t)(q[i] >> 8U);
		output[i + 16U] = (uint8_t)(q[i] >> 16U);
		output[i + 24U] = (uint8_t)(q[i] >> 24U);
		output[i + 32U] = (uint8_t)(q[i] >> 32U);
		output[i + 40U] = (uint8_t)(q[i] >> 40U);
		output[i + 48U] = (uint8_t)(q[i] >> 48U);
		output[i + 56U] = (uint8_t)(q[i] >> 56U);
	}

	qsc_memutils_secure_erase(scratch, sizeof(scratch));
	qsc_memutils_secure_erase(q, sizeof(q));
	qsc_memutils_secure_erase(&key, sizeof(key));
}

#endif

#else

/*! \def QSC_RCS_ARM_PRECONVERT_KEYS
 * \brief Opt-in preconversion of ARM Rijndael-256 round keys once per CTR call.
 * \note Experimental: requires native ARM correctness and throughput qualification
 * before enabling in product builds. Default path is unchanged.
 */

static uint8x16_t rcs_load_roundkey_arm(const uint32_t* key)
{
	/* convert four big-endian RCS round-key words to a NEON byte vector */
	/* load a 16-byte RCS subkey from four big-endian schedule words */
	uint8x16_t tmp;

	tmp = vreinterpretq_u8_u32(vld1q_u32(key));
#if defined(__AARCH64EL__) || defined(_M_ARM64) || (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
	tmp = vrev32q_u8(tmp);
#endif

	return tmp;
}

#if defined(QSC_RCS_ARM_PRECONVERT_KEYS)
static void rcs_transform_256(const qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, const uint8x16x2_t keys[RCS512_ROUND_COUNT + 1U])
#else
static void rcs_transform_256(const qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input)
#endif
{
	/* encrypt a Rijndael-256 counter block using preconverted ARM AES round keys */
	/* encrypt one 32-byte Rijndael block with the expanded schedule */
	/* transform one Rijndael-256 block using ARM AES rounds */
	/* first half's public byte indices before AES ShiftRows */
	static const uint8_t indices0[16U] = { 0U, 17U, 22U, 23U, 4U, 5U, 26U, 27U, 8U, 9U, 14U, 31U, 12U, 13U, 18U, 19U };
	/* second half's public byte indices before AES ShiftRows */
	static const uint8_t indices1[16U] = { 16U, 1U, 6U, 7U, 20U, 21U, 10U, 11U, 24U, 25U, 30U, 15U, 28U, 29U, 2U, 3U };
	const uint8x16_t shuffle0 = vld1q_u8(indices0);
	const uint8x16_t shuffle1 = vld1q_u8(indices1);
	const uint8x16_t zero = vdupq_n_u8(0U);
	uint8x16x2_t block;
	uint8x16_t first;
	uint8x16_t second;

#if defined(QSC_RCS_ARM_PRECONVERT_KEYS)
	block.val[0U] = veorq_u8(vld1q_u8(input), keys[0U].val[0U]);
#else
	block.val[0U] = veorq_u8(vld1q_u8(input), rcs_load_roundkey_arm(ctx->roundkeys));
#endif
#if defined(QSC_RCS_ARM_PRECONVERT_KEYS)
	block.val[1U] = veorq_u8(vld1q_u8(input + 16U), keys[0U].val[1U]);
#else
	block.val[1U] = veorq_u8(vld1q_u8(input + 16U), rcs_load_roundkey_arm(ctx->roundkeys + 4U));
#endif

	for (size_t i = 1U; i < ctx->rounds; ++i)
	{
		first = vaeseq_u8(vqtbl2q_u8(block, shuffle0), zero);
		second = vaeseq_u8(vqtbl2q_u8(block, shuffle1), zero);
#if defined(QSC_RCS_ARM_PRECONVERT_KEYS)
		block.val[0U] = veorq_u8(vaesmcq_u8(first), keys[i].val[0U]);
#else
		block.val[0U] = veorq_u8(vaesmcq_u8(first), rcs_load_roundkey_arm(ctx->roundkeys + (i * 8U)));
#endif
#if defined(QSC_RCS_ARM_PRECONVERT_KEYS)
		block.val[1U] = veorq_u8(vaesmcq_u8(second), keys[i].val[1U]);
#else
		block.val[1U] = veorq_u8(vaesmcq_u8(second), rcs_load_roundkey_arm(ctx->roundkeys + (i * 8U) + 4U));
#endif
	}

	first = vaeseq_u8(vqtbl2q_u8(block, shuffle0), zero);
	second = vaeseq_u8(vqtbl2q_u8(block, shuffle1), zero);
#if defined(QSC_RCS_ARM_PRECONVERT_KEYS)
	first = veorq_u8(first, keys[ctx->rounds].val[0U]);
#else
	first = veorq_u8(first, rcs_load_roundkey_arm(ctx->roundkeys + (ctx->rounds * 8U)));
#endif
#if defined(QSC_RCS_ARM_PRECONVERT_KEYS)
	second = veorq_u8(second, keys[ctx->rounds].val[1U]);
#else
	second = veorq_u8(second, rcs_load_roundkey_arm(ctx->roundkeys + (ctx->rounds * 8U) + 4U));
#endif
	vst1q_u8(output, first);
	vst1q_u8(output + 16U, second);
	qsc_memutils_secure_erase(&block, sizeof(block));
	qsc_memutils_secure_erase(&first, sizeof(first));
	qsc_memutils_secure_erase(&second, sizeof(second));
}

#endif

static void rcs_ctr_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	/* transform bytes with counter mode; exact input/output aliasing is supported */
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	uint8_t stream[QSC_RCS_BLOCK_SIZE] = { 0U };
#if !defined(QSC_SYSTEM_ARM_AES_ENABLED)
	uint32_t keys[RCS512_ROUND_COUNT + 1U][8U];
#elif defined(QSC_RCS_ARM_PRECONVERT_KEYS)
	uint8x16x2_t armkeys[RCS512_ROUND_COUNT + 1U];
#endif
	size_t i;
	size_t oft;
#if !defined(QSC_SYSTEM_ARM_AES_ENABLED)
	bool keys_prepared;
#endif

	oft = 0U;
#if !defined(QSC_SYSTEM_ARM_AES_ENABLED)
	keys_prepared = (length != 0U);

	if (keys_prepared == true)
	{
		rcs_bitslice_prepare_keys(ctx, keys);
	}
#elif defined(QSC_RCS_ARM_PRECONVERT_KEYS)
	/* convert endian-adjusted Rijndael-256 round keys once per CTR call.
	 * each element contains the two independent 128-bit halves of a round.
	 * the upper bound comes from the published RCS extended-round profile. */
	if (length != 0U)
	{
		for (i = 0U; i <= ctx->rounds; ++i)
		{
			armkeys[i].val[0U] = rcs_load_roundkey_arm(ctx->roundkeys + (i * 8U));
			armkeys[i].val[1U] = rcs_load_roundkey_arm(ctx->roundkeys + (i * 8U) + 4U);
		}
	}
#endif

#if !defined(QSC_SYSTEM_ARM_AES_ENABLED) && UINTPTR_MAX > UINT32_MAX
	if (length >= (2U * QSC_RCS_BLOCK_SIZE))
	{
		uint8_t counterblocks[2U * QSC_RCS_BLOCK_SIZE];
		uint8_t streams[2U * QSC_RCS_BLOCK_SIZE];

		while (length >= (2U * QSC_RCS_BLOCK_SIZE))
		{
			qsc_memutils_copy(counterblocks, ctx->nonce, QSC_RCS_BLOCK_SIZE);
			qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);
			qsc_memutils_copy(counterblocks + QSC_RCS_BLOCK_SIZE, ctx->nonce, QSC_RCS_BLOCK_SIZE);
			qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);
			rcs_transform_512_bitsliced(ctx, streams, counterblocks, keys);

			for (i = 0U; i < sizeof(streams); ++i)
			{
				output[oft + i] = input[oft + i] ^ streams[i];
			}

			oft += sizeof(streams);
			length -= sizeof(streams);
		}

		qsc_memutils_secure_erase(counterblocks, sizeof(counterblocks));
		qsc_memutils_secure_erase(streams, sizeof(streams));
	}
#endif

	while (length >= QSC_RCS_BLOCK_SIZE)
	{
		/* Keep the input live until the keystream XOR has completed. */
#if !defined(QSC_SYSTEM_ARM_AES_ENABLED)
		rcs_transform_256_bitsliced(ctx, stream, ctx->nonce, keys);
#elif defined(QSC_RCS_ARM_PRECONVERT_KEYS)
		rcs_transform_256(ctx, stream, ctx->nonce, armkeys);
#else
		rcs_transform_256(ctx, stream, ctx->nonce);
#endif

		for (i = 0U; i < QSC_RCS_BLOCK_SIZE; ++i)
		{
			output[oft + i] = input[oft + i] ^ stream[i];
		}

		qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);
		oft += QSC_RCS_BLOCK_SIZE;
		length -= QSC_RCS_BLOCK_SIZE;
	}

	if (length != 0U)
	{
#if !defined(QSC_SYSTEM_ARM_AES_ENABLED)
		rcs_transform_256_bitsliced(ctx, stream, ctx->nonce, keys);
#elif defined(QSC_RCS_ARM_PRECONVERT_KEYS)
		rcs_transform_256(ctx, stream, ctx->nonce, armkeys);
#else
		rcs_transform_256(ctx, stream, ctx->nonce);
#endif

		for (i = 0U; i < length; ++i)
		{
			output[oft + i] = input[oft + i] ^ stream[i];
		}

		qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);
	}

#if !defined(QSC_SYSTEM_ARM_AES_ENABLED)
	if (keys_prepared == true)
	{
		qsc_memutils_secure_erase(keys, sizeof(keys));
	}
#elif defined(QSC_RCS_ARM_PRECONVERT_KEYS)
	qsc_memutils_secure_erase(armkeys, sizeof(armkeys));
#endif
	qsc_memutils_secure_erase(stream, sizeof(stream));
}

#endif

#if defined(QSC_RCS_AUTHENTICATED)
static void rcs_mac_finalize(qsc_rcs_state* ctx, uint8_t* output)
{
	uint8_t ctr[sizeof(uint64_t)] = { 0U };
	uint64_t mctr = QSC_RCS_BLOCK_SIZE + ctx->counter + sizeof(uint64_t);

	qsc_intutils_le64to8(ctr, mctr);

	if (ctx->ctype == RCS256)
	{
		/* update the counter */
		qsc_kmac_update(&ctx->kstate, qsc_keccak_rate_256, ctr, sizeof(ctr));
		/* finalize the mac and append code to output */
		qsc_kmac_finalize(&ctx->kstate, qsc_keccak_rate_256, output, QSC_RCS256_MAC_SIZE);
	}
	else
	{
		qsc_kmac_update(&ctx->kstate, qsc_keccak_rate_512, ctr, sizeof(ctr));
		qsc_kmac_finalize(&ctx->kstate, qsc_keccak_rate_512, output, QSC_RCS512_MAC_SIZE);
	}
}
#endif

static void rcs_mac_update(qsc_rcs_state* ctx, const uint8_t* input, size_t length)
{
	if (ctx->ctype == RCS256)
	{
		qsc_kmac_update(&ctx->kstate, qsc_keccak_rate_256, input, length);
	}
	else
	{
		qsc_kmac_update(&ctx->kstate, qsc_keccak_rate_512, input, length);
	}
}

static void rcs_secure_expand(qsc_rcs_state* ctx, const qsc_rcs_keyparams* keyparams)
{
	/* expand the validated key and customization into cipher and MAC state */
	uint8_t sbuf[QSC_KECCAK_STATE_SIZE * sizeof(uint64_t)] = { 0U };
	qsc_keccak_state kstate;
	size_t i;
	size_t oft;
	size_t rlen;

	if (ctx->ctype == RCS256)
	{
		QSC_ALIGN(64) uint8_t tmpr[RCS256_ROUNDKEY_SIZE * RCS_ROUNDKEY_ELEMENT_SIZE] = { 0U };

		/* initialize an instance of cSHAKE */
		qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, keyparams->key, keyparams->keylen, rcs256_name, RCS_NAME_LENGTH, keyparams->info, keyparams->infolen);

		oft = 0U;
		rlen = RCS256_ROUNDKEY_SIZE * RCS_ROUNDKEY_ELEMENT_SIZE;

		while (rlen != 0U)
		{
			const size_t BLKLEN = (rlen > QSC_KECCAK_256_RATE) ? QSC_KECCAK_256_RATE : rlen;
			qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, sbuf, 1U);
			qsc_memutils_copy(tmpr + oft, sbuf, BLKLEN);

			oft += BLKLEN;
			rlen -= BLKLEN;
		}

#if defined(QSC_SYSTEM_RCS_AESNI_ENABLED)
		const size_t RNKLEN = (QSC_RCS_BLOCK_SIZE / sizeof(__m128i)) * (ctx->rounds + 1U);

		/* copy p-rand bytes to round keys */
		for (i = 0U; i < RNKLEN; ++i)
		{
			ctx->roundkeys[i] = _mm_loadu_si128((const __m128i*)(tmpr + (i * sizeof(__m128i))));
		}

#else
		/* realign in big endian format for ACS test vectors; RCS is the fallback to the AES-NI implementation */
		for (i = 0U; i < RCS256_ROUNDKEY_SIZE; ++i)
		{
			ctx->roundkeys[i] = qsc_intutils_be8to32(tmpr + (i * sizeof(uint32_t)));
		}
#endif

#if defined(QSC_RCS_AUTHENTICATED)
		uint8_t mkey[RCS256_MKEY_LENGTH];

		/* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */
		qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, sbuf, 1U);
		qsc_memutils_copy(mkey, sbuf, RCS256_MKEY_LENGTH);

		qsc_kmac_initialize(&ctx->kstate, qsc_keccak_rate_256, mkey, sizeof(mkey), NULL, 0U);

		qsc_memutils_secure_erase(mkey, sizeof(mkey));
#endif

		qsc_memutils_secure_erase(tmpr, sizeof(tmpr));
		qsc_memutils_secure_erase(sbuf, sizeof(sbuf));
		/* clear the shake buffer */
		qsc_keccak_dispose(&kstate);
	}
	else
	{
		QSC_ALIGN(64) uint8_t tmpr[RCS512_ROUNDKEY_SIZE * RCS_ROUNDKEY_ELEMENT_SIZE] = { 0U };

		/* initialize an instance of cSHAKE */
		qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, keyparams->key, keyparams->keylen, rcs512_name, RCS_NAME_LENGTH, keyparams->info, keyparams->infolen);

		oft = 0U;
		rlen = RCS512_ROUNDKEY_SIZE * RCS_ROUNDKEY_ELEMENT_SIZE;

		while (rlen != 0U)
		{
			const size_t BLKLEN = (rlen > QSC_KECCAK_512_RATE) ? QSC_KECCAK_512_RATE : rlen;
			qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, sbuf, 1U);
			qsc_memutils_copy(tmpr + oft, sbuf, BLKLEN);
			oft += BLKLEN;
			rlen -= BLKLEN;
		}

#if defined(QSC_SYSTEM_RCS_AESNI_ENABLED)
		const size_t RNKLEN = (QSC_RCS_BLOCK_SIZE / sizeof(__m128i)) * (ctx->rounds + 1U);

		/* copy p-rand bytes to round keys */
		for (i = 0U; i < RNKLEN; ++i)
		{
			ctx->roundkeys[i] = _mm_loadu_si128((const __m128i*)(tmpr + (i * sizeof(__m128i))));
		}
#else
		/* realign in big endian format for ACS test vectors; RCS is the fallback to the AES-NI implementation */
		for (i = 0U; i < RCS512_ROUNDKEY_SIZE; ++i)
		{
			ctx->roundkeys[i] = qsc_intutils_be8to32(tmpr + (i * sizeof(uint32_t)));
		}
#endif

#if defined(QSC_RCS_AUTHENTICATED)
		uint8_t mkey[RCS512_MKEY_LENGTH];

		/* use two permutation calls (no buffering) to seperate the cipher/mac key outputs to match the CEX implementation */
		qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, sbuf, 1U);
		qsc_memutils_copy(mkey, sbuf, RCS512_MKEY_LENGTH);

		qsc_kmac_initialize(&ctx->kstate, qsc_keccak_rate_512, mkey, sizeof(mkey), NULL, 0U);

		qsc_memutils_secure_erase(mkey, sizeof(mkey));
#endif

		qsc_memutils_secure_erase(tmpr, sizeof(tmpr));
		qsc_memutils_secure_erase(sbuf, sizeof(sbuf));
		/* clear the shake buffer */
		qsc_keccak_dispose(&kstate);
	}

#if defined(QSC_SYSTEM_RCS_AESNI_ENABLED)
#	if defined(QSC_SYSTEM_RCS_AESNI_ENABLED) && defined(QSC_SYSTEM_HAS_VAES512)
	/* store the avx-512 round keys qsc_keccak_initialize_state*/
	qsc_memutils_secure_erase(ctx->roundkeysw, sizeof(ctx->roundkeysw));

	for (i = 0U; i < ctx->roundkeylen; i += 2U)
	{
		rcs_load2x128to512(&ctx->roundkeys[i], &ctx->roundkeys[i + 1U], &ctx->roundkeysw[i / 2U]);
	}
#	endif
#endif
}

/* rcs common */

void qsc_rcs_dispose(qsc_rcs_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
#if defined(QSC_RCS_AUTHENTICATED)
		qsc_keccak_dispose(&ctx->kstate);
#endif

#if defined(QSC_SYSTEM_RCS_AESNI_ENABLED)
#	if defined(QSC_SYSTEM_RCS_AESNI_ENABLED) && defined(QSC_SYSTEM_HAS_VAES512)
		qsc_memutils_secure_erase(ctx->roundkeysw, sizeof(ctx->roundkeysw));
#	endif
#endif

		qsc_memutils_secure_erase(ctx->roundkeys, sizeof(ctx->roundkeys));
		qsc_memutils_secure_erase(ctx->nonce, sizeof(ctx->nonce));
		ctx->counter = 0U;
		ctx->ctype = RCS256;
		ctx->roundkeylen = 0U;
		ctx->rounds = 0U;
		ctx->encrypt = false;
	}
}

static bool rcs_state_valid(const qsc_rcs_state* ctx)
{
	/* validate the initialized cipher profile without inspecting secret key bytes */
	bool res;

	res = (ctx->ctype == RCS256 && ctx->rounds == RCS256_ROUND_COUNT &&
		ctx->roundkeylen == RCS256_ROUNDKEY_SIZE) ||
		(ctx->ctype == RCS512 && ctx->rounds == RCS512_ROUND_COUNT &&
		ctx->roundkeylen == RCS512_ROUNDKEY_SIZE);

	return res;
}

static bool rcs_transform_valid(const qsc_rcs_state* ctx, size_t length, bool finalize)
{
	/* check state, encoded length, tag space and full-width nonce exhaustion */
	uint64_t blocks;
	uint64_t high;
	bool res;
#if defined(QSC_RCS_AUTHENTICATED)
	size_t taglen;
#endif

	res = rcs_state_valid(ctx);
#if defined(QSC_RCS_AUTHENTICATED)
	taglen = ctx->ctype == RCS256 ? QSC_RCS256_MAC_SIZE : QSC_RCS512_MAC_SIZE;
	res = res && ctx->counter <= UINT64_MAX - QSC_RCS_BLOCK_SIZE - sizeof(uint64_t) &&
		length <= UINT64_MAX - QSC_RCS_BLOCK_SIZE - sizeof(uint64_t) - ctx->counter &&
		(finalize == false || length <= SIZE_MAX - taglen) &&
		ctx->kstate.position < (ctx->ctype == RCS256 ? QSC_KECCAK_256_RATE : QSC_KECCAK_512_RATE);
#else
	(void)finalize;
#endif
	blocks = (uint64_t)(length / QSC_RCS_BLOCK_SIZE) + (uint64_t)(length % QSC_RCS_BLOCK_SIZE != 0U);
	high = qsc_intutils_le8to64(ctx->nonce + 8U) & qsc_intutils_le8to64(ctx->nonce + 16U) &
		qsc_intutils_le8to64(ctx->nonce + 24U);
	res = res && (high != UINT64_MAX || blocks <= UINT64_MAX - qsc_intutils_le8to64(ctx->nonce));

	return res;
}

void qsc_rcs_initialize(qsc_rcs_state* ctx, const qsc_rcs_keyparams* keyparams, bool encryption)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);
	QSC_ASSERT(keyparams == NULL || keyparams->nonce != NULL);
	QSC_ASSERT(keyparams == NULL || keyparams->key != NULL);
	QSC_ASSERT(keyparams == NULL || keyparams->keylen == QSC_RCS256_KEY_SIZE || keyparams->keylen == QSC_RCS512_KEY_SIZE);
	QSC_ASSERT(keyparams == NULL || keyparams->info != NULL || keyparams->infolen == 0U);
	QSC_ASSERT(keyparams == NULL || keyparams->infolen <= SIZE_MAX / 8U);

	if (ctx != NULL && keyparams != NULL && keyparams->key != NULL && keyparams->nonce != NULL &&
		(keyparams->keylen == QSC_RCS256_KEY_SIZE || keyparams->keylen == QSC_RCS512_KEY_SIZE) &&
		(keyparams->info != NULL || keyparams->infolen == 0U) && keyparams->infolen <= SIZE_MAX / 8U)
	{
		ctx->ctype = keyparams->keylen == QSC_RCS512_KEY_SIZE ? RCS512 : RCS256;
		qsc_memutils_secure_erase(ctx->roundkeys, sizeof(ctx->roundkeys));
		qsc_memutils_copy(ctx->nonce, keyparams->nonce, QSC_RCS_NONCE_SIZE);
		ctx->counter = 1U;
		ctx->encrypt = encryption;

		if (ctx->ctype == RCS256)
		{
			/* initialize rcs state */
			ctx->roundkeylen = RCS256_ROUNDKEY_SIZE;
			ctx->rounds = RCS256_ROUND_COUNT;
		}
		else
		{
			/* initialize rcs state */
			ctx->roundkeylen = RCS512_ROUNDKEY_SIZE;
			ctx->rounds = RCS512_ROUND_COUNT;
		}

		/* generate the cipher and mac keys */
		rcs_secure_expand(ctx, keyparams);
	}
	else if (ctx != NULL)
	{
		qsc_rcs_dispose(ctx);
	}
}

void qsc_rcs_set_associated(qsc_rcs_state* ctx, const uint8_t* data, size_t length)
{
#if defined(QSC_RCS_AUTHENTICATED)
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(data != NULL || length == 0U);
	QSC_ASSERT(length <= UINT32_MAX);

	if (ctx != NULL && rcs_state_valid(ctx) && data != NULL && length != 0U && length <= UINT32_MAX)
	{
		uint8_t code[sizeof(uint32_t)] = { 0U };

		/* add the ad data to the hash */
		rcs_mac_update(ctx, data, length);
		/* add the length of the ad */
		qsc_intutils_le32to8(code, (uint32_t)length);
		rcs_mac_update(ctx, code, sizeof(code));
	}
	else if (ctx != NULL && (length > UINT32_MAX || (data == NULL && length != 0U)))
	{
		qsc_rcs_dispose(ctx);
	}
#else
	(void)ctx;
	(void)data;
	(void)length;
#endif
}

void qsc_rcs_store_nonce(const qsc_rcs_state* ctx, uint8_t nonce[QSC_RCS_NONCE_SIZE])
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(nonce != NULL);

	if (ctx != NULL && nonce != NULL)
	{
		qsc_memutils_copy(nonce, ctx->nonce, QSC_RCS_NONCE_SIZE);
	}
}

bool qsc_rcs_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	bool res;

	res = false;

	if (ctx != NULL && output != NULL && input != NULL && rcs_transform_valid(ctx, length, true))
	{
#if defined(QSC_RCS_AUTHENTICATED)

		/* update the processed bytes counter */
		ctx->counter += length;

		/* update the mac with the current nonce position */
		rcs_mac_update(ctx, ctx->nonce, QSC_RCS_BLOCK_SIZE);

		if (ctx->encrypt)
		{
			/* transform the plain-text with the counter-mode cipher */
			rcs_ctr_transform(ctx, output, input, length);

			/* update the mac with the cipher-text */
			rcs_mac_update(ctx, output, length);

			/* mac the cipher-text appending the code to the end of the array */
			rcs_mac_finalize(ctx, output + length);
			res = true;
		}
		else
		{
			/* update the mac with the cipher-text */
			rcs_mac_update(ctx, input, length);

			if (ctx->ctype == RCS256)
			{
				uint8_t code[QSC_RCS256_MAC_SIZE] = { 0U };

				/* mac the cipher-text to a temp array for comparison */
				rcs_mac_finalize(ctx, code);

				/* test the mac for equality, bypassing the transform if the mac check fails */
				if (qsc_intutils_verify(code, input + length, QSC_RCS256_MAC_SIZE) == 0)
				{
					/* transform the plain-text with the counter-mode cipher */
					rcs_ctr_transform(ctx, output, input, length);
					res = true;
				}
				else
				{
					qsc_rcs_dispose(ctx);
				}

				qsc_memutils_secure_erase(code, sizeof(code));
			}
			else
			{
				uint8_t code[QSC_RCS512_MAC_SIZE] = { 0U };

				rcs_mac_finalize(ctx, code);

				if (qsc_intutils_verify(code, input + length, QSC_RCS512_MAC_SIZE) == 0)
				{
					rcs_ctr_transform(ctx, output, input, length);
					res = true;
				}
				else
				{
					qsc_rcs_dispose(ctx);
				}

				qsc_memutils_secure_erase(code, sizeof(code));
			}
		}

#else

		rcs_ctr_transform(ctx, output, input, length);
		res = true;

#endif
	}

	return res;
}

bool qsc_rcs_extended_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length, bool finalize)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	bool res;

	res = false;

	if (ctx != NULL && output != NULL && input != NULL && rcs_transform_valid(ctx, length, finalize))
	{
#if defined(QSC_RCS_AUTHENTICATED)

		/* update the processed bytes counter */
		ctx->counter += length;

		/* update the mac with the current nonce position */
		rcs_mac_update(ctx, ctx->nonce, QSC_RCS_BLOCK_SIZE);

		if (ctx->encrypt == true)
		{
			/* transform the plain-text with the counter-mode cipher */
			rcs_ctr_transform(ctx, output, input, length);

			/* update the mac with the cipher-text */
			rcs_mac_update(ctx, output, length);

			if (finalize == true)
			{
				/* mac the cipher-text appending the code to the end of the array */
				rcs_mac_finalize(ctx, output + length);
			}

			res = true;
		}
		else
		{
			/* update the mac with the cipher-text */
			rcs_mac_update(ctx, input, length);

			if (finalize == true)
			{
				if (ctx->ctype == RCS256)
				{
					uint8_t code[QSC_RCS256_MAC_SIZE] = { 0U };

					/* mac the cipher-text to a temp array for comparison */
					rcs_mac_finalize(ctx, code);

					/* test the mac for equality, bypassing the transform if the mac check fails */
					if (qsc_intutils_verify(code, input + length, QSC_RCS256_MAC_SIZE) == 0)
					{
						/* transform the plain-text with the counter-mode cipher */
						rcs_ctr_transform(ctx, output, input, length);
						res = true;
					}
					else
					{
						qsc_rcs_dispose(ctx);
					}

					qsc_memutils_secure_erase(code, sizeof(code));
				}
				else
				{
					uint8_t code[QSC_RCS512_MAC_SIZE] = { 0U };

					rcs_mac_finalize(ctx, code);

					if (qsc_intutils_verify(code, input + length, QSC_RCS512_MAC_SIZE) == 0)
					{
						rcs_ctr_transform(ctx, output, input, length);
						res = true;
					}
					else
					{
						qsc_rcs_dispose(ctx);
					}

					qsc_memutils_secure_erase(code, sizeof(code));
				}
			}
			else
			{
				/* transform the plain-text with the counter-mode cipher */
				rcs_ctr_transform(ctx, output, input, length);
				res = true;
			}
		}

#else

		rcs_ctr_transform(ctx, output, input, length);
		res = true;

#endif
	}

	return res;
}
