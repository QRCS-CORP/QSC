/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "poly1305.h"
#include "intutils.h"
#include "memutils.h"
#if defined(QSC_SYSTEM_HAS_AVX2)
#	include "intrinsics.h"
#endif

static void poly1305_block(qsc_poly1305_state* ctx, const uint8_t* message)
{
	/* absorb one complete block or the internally padded final block */
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(message != NULL);

	if (ctx != NULL && message != NULL)
	{
		const uint32_t HIBIT = (ctx->fnl != 0U) ? 0UL : (1U << 24);
		uint64_t b;
		uint64_t t0;
		uint64_t t1;
		uint64_t t2;
		uint64_t t3;
		uint64_t tp0;
		uint64_t tp1;
		uint64_t tp2;
		uint64_t tp3;
		uint64_t tp4;

		t0 = qsc_intutils_le8to32(message);
		t1 = qsc_intutils_le8to32(message + 4U);
		t2 = qsc_intutils_le8to32(message + 8U);
		t3 = qsc_intutils_le8to32(message + 12U);

		ctx->h[0U] += (uint32_t)(t0 & 0x3FFFFFFUL);
		ctx->h[1U] += (uint32_t)((((t1 << 32) | t0) >> 26) & 0x3FFFFFFUL);
		ctx->h[2U] += (uint32_t)((((t2 << 32) | t1) >> 20) & 0x3FFFFFFUL);
		ctx->h[3U] += (uint32_t)((((t3 << 32) | t2) >> 14) & 0x3FFFFFFUL);
		ctx->h[4U] += (uint32_t)(t3 >> 8) | HIBIT;

		tp0 = ((uint64_t)ctx->h[0U] * ctx->r[0U]) + ((uint64_t)ctx->h[1U] * ctx->s[3U]) + ((uint64_t)ctx->h[2U] * ctx->s[2U]) + ((uint64_t)ctx->h[3U] * ctx->s[1U]) + ((uint64_t)ctx->h[4U] * ctx->s[0U]);
		tp1 = ((uint64_t)ctx->h[0U] * ctx->r[1U]) + ((uint64_t)ctx->h[1U] * ctx->r[0U]) + ((uint64_t)ctx->h[2U] * ctx->s[3U]) + ((uint64_t)ctx->h[3U] * ctx->s[2U]) + ((uint64_t)ctx->h[4U] * ctx->s[1U]);
		tp2 = ((uint64_t)ctx->h[0U] * ctx->r[2U]) + ((uint64_t)ctx->h[1U] * ctx->r[1U]) + ((uint64_t)ctx->h[2U] * ctx->r[0U]) + ((uint64_t)ctx->h[3U] * ctx->s[3U]) + ((uint64_t)ctx->h[4U] * ctx->s[2U]);
		tp3 = ((uint64_t)ctx->h[0U] * ctx->r[3U]) + ((uint64_t)ctx->h[1U] * ctx->r[2U]) + ((uint64_t)ctx->h[2U] * ctx->r[1U]) + ((uint64_t)ctx->h[3U] * ctx->r[0U]) + ((uint64_t)ctx->h[4U] * ctx->s[3U]);
		tp4 = ((uint64_t)ctx->h[0U] * ctx->r[4U]) + ((uint64_t)ctx->h[1U] * ctx->r[3U]) + ((uint64_t)ctx->h[2U] * ctx->r[2U]) + ((uint64_t)ctx->h[3U] * ctx->r[1U]) + ((uint64_t)ctx->h[4U] * ctx->r[0U]);

		ctx->h[0U] = (uint32_t)(tp0 & 0x3FFFFFFUL);
		b = (tp0 >> 26);
		tp1 += b;
		ctx->h[1U] = (uint32_t)(tp1 & 0x3FFFFFFUL);
		b = (tp1 >> 26);
		tp2 += b;
		ctx->h[2U] = (uint32_t)(tp2 & 0x3FFFFFFUL);
		b = (tp2 >> 26);
		tp3 += b;
		ctx->h[3U] = (uint32_t)(tp3 & 0x3FFFFFFUL);
		b = (tp3 >> 26);
		tp4 += b;
		ctx->h[4U] = (uint32_t)(tp4 & 0x3FFFFFFUL);
		b = (tp4 >> 26);
		ctx->h[0U] += (uint32_t)(b * 5U);
	}
}

static void poly1305_blocks_register(qsc_poly1305_state* ctx, const uint8_t* message, size_t length)
{
	/* absorb multiple complete Poly1305 blocks with the accumulator held in registers */
	uint64_t h0;
	uint64_t h1;
	uint64_t h2;
	uint64_t h3;
	uint64_t h4;
	uint64_t r0;
	uint64_t r1;
	uint64_t r2;
	uint64_t r3;
	uint64_t r4;
	uint64_t s1;
	uint64_t s2;
	uint64_t s3;
	uint64_t s4;
	uint64_t t0;
	uint64_t t1;
	uint64_t t2;
	uint64_t t3;
	uint64_t d0;
	uint64_t d1;
	uint64_t d2;
	uint64_t d3;
	uint64_t d4;
	uint64_t carry;
	const uint64_t mask = 0x3FFFFFFULL;

	h0 = ctx->h[0U];
	h1 = ctx->h[1U];
	h2 = ctx->h[2U];
	h3 = ctx->h[3U];
	h4 = ctx->h[4U];
	r0 = ctx->r[0U];
	r1 = ctx->r[1U];
	r2 = ctx->r[2U];
	r3 = ctx->r[3U];
	r4 = ctx->r[4U];
	s1 = ctx->s[0U];
	s2 = ctx->s[1U];
	s3 = ctx->s[2U];
	s4 = ctx->s[3U];

	while (length >= QSC_POLY1305_BLOCK_SIZE)
	{
		t0 = qsc_intutils_le8to32(message);
		t1 = qsc_intutils_le8to32(message + 4U);
		t2 = qsc_intutils_le8to32(message + 8U);
		t3 = qsc_intutils_le8to32(message + 12U);

		h0 += t0 & mask;
		h1 += ((t1 << 32U) | t0) >> 26U & mask;
		h2 += ((t2 << 32U) | t1) >> 20U & mask;
		h3 += ((t3 << 32U) | t2) >> 14U & mask;
		h4 += (t3 >> 8U) | (1ULL << 24U);

		d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
		d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
		d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
		d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
		d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

		h0 = d0 & mask;
		carry = d0 >> 26U;
		d1 += carry;
		h1 = d1 & mask;
		carry = d1 >> 26U;
		d2 += carry;
		h2 = d2 & mask;
		carry = d2 >> 26U;
		d3 += carry;
		h3 = d3 & mask;
		carry = d3 >> 26U;
		d4 += carry;
		h4 = d4 & mask;
		carry = d4 >> 26U;
		h0 += carry * 5U;

		message += QSC_POLY1305_BLOCK_SIZE;
		length -= QSC_POLY1305_BLOCK_SIZE;
	}

	ctx->h[0U] = (uint32_t)h0;
	ctx->h[1U] = (uint32_t)h1;
	ctx->h[2U] = (uint32_t)h2;
	ctx->h[3U] = (uint32_t)h3;
	ctx->h[4U] = (uint32_t)h4;
}

#if defined(QSC_SYSTEM_HAS_AVX2)

static void poly1305_multiply26(uint32_t* output, const uint32_t* left, const uint32_t* right)
{
	/* multiply two radix-2^26 Poly1305 field elements modulo 2^130 - 5 */
	uint64_t d[5U];
	size_t i;
	uint64_t carry;
	uint64_t a0;
	uint64_t a1;
	uint64_t a2;
	uint64_t a3;
	uint64_t a4;
	uint64_t b0;
	uint64_t b1;
	uint64_t b2;
	uint64_t b3;
	uint64_t b4;
	const uint64_t mask = 0x3FFFFFFULL;

	a0 = left[0U];
	a1 = left[1U];
	a2 = left[2U];
	a3 = left[3U];
	a4 = left[4U];
	b0 = right[0U];
	b1 = right[1U];
	b2 = right[2U];
	b3 = right[3U];
	b4 = right[4U];
	d[0U] = a0*b0 + a1*b4*5U + a2*b3*5U + a3*b2*5U + a4*b1*5U;
	d[1U] = a0*b1 + a1*b0 + a2*b4*5U + a3*b3*5U + a4*b2*5U;
	d[2U] = a0*b2 + a1*b1 + a2*b0 + a3*b4*5U + a4*b3*5U;
	d[3U] = a0*b3 + a1*b2 + a2*b1 + a3*b0 + a4*b4*5U;
	d[4U] = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;
	carry = d[0U] >> 26U;
	d[0U] &= mask;
	d[1U] += carry;
	carry = d[1U] >> 26U;
	d[1U] &= mask;
	d[2U] += carry;
	carry = d[2U] >> 26U;
	d[2U] &= mask;
	d[3U] += carry;
	carry = d[3U] >> 26U;
	d[3U] &= mask;
	d[4U] += carry;
	carry = d[4U] >> 26U;
	d[4U] &= mask;
	d[0U] += carry * 5U;
	carry = d[0U] >> 26U;
	d[0U] &= mask;
	d[1U] += carry;
	for (i = 0U; i < 5U; ++i)
	{
		output[i] = (uint32_t)d[i];
	}

	qsc_memutils_secure_erase(d, sizeof(d));
}

static void poly1305_blocks4_avx2(qsc_poly1305_state* ctx, const uint8_t* message, size_t length)
{
	/* accumulate full Poly1305 block groups with four persistent AVX2 lanes */
	uint32_t powers[4U][5U] = { { 0U } };
	uint64_t h[5U];
	__m256i r[5U];
	__m256i s[4U];
	__m256i rk[5U];
	__m256i sk[4U];
	__m256i v[5U];
	__m256i m[5U];
	__m256i d[5U];
	__m256i carry;
	__m256i lo;
	__m256i hi;
	__m256i block0;
	__m256i block1;
	__m256i tmp0;
	__m256i tmp1;
	__m128i lane_sum;
	const __m256i hibit = _mm256_set1_epi64x(1LL << 24);
	const __m256i mask = _mm256_set1_epi64x(0x3FFFFFFLL);
	uint64_t sum;
	uint64_t c;
	size_t i;

	for (i = 0U; i < 5U; ++i)
	{
		powers[3U][i] = ctx->r[i];
		h[i] = ctx->h[i];
	}

	poly1305_multiply26(powers[2U], powers[3U], powers[3U]);
	poly1305_multiply26(powers[1U], powers[2U], powers[3U]);
	poly1305_multiply26(powers[0U], powers[1U], powers[3U]);

	/* keep only the common r^4 multiplier active in the bulk loop. */
	for (i = 0U; i < 5U; ++i)
	{
		rk[i] = _mm256_set1_epi64x(powers[0U][i]);
	}

	for (i = 0U; i < 4U; ++i)
	{
		sk[i] = _mm256_add_epi64(_mm256_slli_epi64(rk[i + 1U], 2U), rk[i + 1U]);
	}

	/* read the first group into four accumulator lanes. */

    block0 = _mm256_loadu_si256((const __m256i*)(const void*)message);
    block1 = _mm256_loadu_si256((const __m256i*)(const void*)(message + 32U));
    tmp0 = _mm256_permute2x128_si256(block0, block1, 0x20);
    tmp1 = _mm256_permute2x128_si256(block0, block1, 0x31);
    lo = _mm256_unpacklo_epi64(tmp0, tmp1);
    hi = _mm256_unpackhi_epi64(tmp0, tmp1);
    m[0U] = _mm256_and_si256(lo, mask);
    m[1U] = _mm256_and_si256(_mm256_srli_epi64(lo, 26U), mask);
    m[2U] = _mm256_and_si256(_mm256_or_si256(_mm256_srli_epi64(lo, 52U), _mm256_slli_epi64(hi, 12U)), mask);
    m[3U] = _mm256_and_si256(_mm256_srli_epi64(hi, 14U), mask);
    m[4U] = _mm256_or_si256(_mm256_srli_epi64(hi, 40U), hibit);

	for (i = 0U; i < 5U; ++i)
	{
		v[i] = _mm256_add_epi64(m[i], _mm256_setr_epi64x(h[i], 0, 0, 0));
	}

	message += 4U * QSC_POLY1305_BLOCK_SIZE;
	length -= 4U * QSC_POLY1305_BLOCK_SIZE;

	/* all subsequent groups reuse r^4 and preserve the four lanes. */
	while (length >= 4U * QSC_POLY1305_BLOCK_SIZE)
	{
        block0 = _mm256_loadu_si256((const __m256i*)(const void*)message);
        block1 = _mm256_loadu_si256((const __m256i*)(const void*)(message + 32U));
        tmp0 = _mm256_permute2x128_si256(block0, block1, 0x20);
        tmp1 = _mm256_permute2x128_si256(block0, block1, 0x31);
        lo = _mm256_unpacklo_epi64(tmp0, tmp1);
        hi = _mm256_unpackhi_epi64(tmp0, tmp1);
        m[0U] = _mm256_and_si256(lo, mask);
        m[1U] = _mm256_and_si256(_mm256_srli_epi64(lo, 26U), mask);
        m[2U] = _mm256_and_si256(_mm256_or_si256(_mm256_srli_epi64(lo, 52U), _mm256_slli_epi64(hi, 12U)), mask);
        m[3U] = _mm256_and_si256(_mm256_srli_epi64(hi, 14U), mask);
        m[4U] = _mm256_or_si256(_mm256_srli_epi64(hi, 40U), hibit);

		/* parallel multiplication by r^4, followed by the new messages. */
		d[0U] = _mm256_mul_epu32(v[0U], rk[0U]);
		d[0U] = _mm256_add_epi64(d[0U], _mm256_mul_epu32(v[1U], sk[3U]));
		d[0U] = _mm256_add_epi64(d[0U], _mm256_mul_epu32(v[2U], sk[2U]));
		d[0U] = _mm256_add_epi64(d[0U], _mm256_mul_epu32(v[3U], sk[1U]));
		d[0U] = _mm256_add_epi64(d[0U], _mm256_mul_epu32(v[4U], sk[0U]));
		d[1U] = _mm256_mul_epu32(v[0U], rk[1U]);
		d[1U] = _mm256_add_epi64(d[1U], _mm256_mul_epu32(v[1U], rk[0U]));
		d[1U] = _mm256_add_epi64(d[1U], _mm256_mul_epu32(v[2U], sk[3U]));
		d[1U] = _mm256_add_epi64(d[1U], _mm256_mul_epu32(v[3U], sk[2U]));
		d[1U] = _mm256_add_epi64(d[1U], _mm256_mul_epu32(v[4U], sk[1U]));
		d[2U] = _mm256_mul_epu32(v[0U], rk[2U]);
		d[2U] = _mm256_add_epi64(d[2U], _mm256_mul_epu32(v[1U], rk[1U]));
		d[2U] = _mm256_add_epi64(d[2U], _mm256_mul_epu32(v[2U], rk[0U]));
		d[2U] = _mm256_add_epi64(d[2U], _mm256_mul_epu32(v[3U], sk[3U]));
		d[2U] = _mm256_add_epi64(d[2U], _mm256_mul_epu32(v[4U], sk[2U]));
		d[3U] = _mm256_mul_epu32(v[0U], rk[3U]);
		d[3U] = _mm256_add_epi64(d[3U], _mm256_mul_epu32(v[1U], rk[2U]));
		d[3U] = _mm256_add_epi64(d[3U], _mm256_mul_epu32(v[2U], rk[1U]));
		d[3U] = _mm256_add_epi64(d[3U], _mm256_mul_epu32(v[3U], rk[0U]));
		d[3U] = _mm256_add_epi64(d[3U], _mm256_mul_epu32(v[4U], sk[3U]));
		d[4U] = _mm256_mul_epu32(v[0U], rk[4U]);
		d[4U] = _mm256_add_epi64(d[4U], _mm256_mul_epu32(v[1U], rk[3U]));
		d[4U] = _mm256_add_epi64(d[4U], _mm256_mul_epu32(v[2U], rk[2U]));
		d[4U] = _mm256_add_epi64(d[4U], _mm256_mul_epu32(v[3U], rk[1U]));
		d[4U] = _mm256_add_epi64(d[4U], _mm256_mul_epu32(v[4U], rk[0U]));

		for (i = 0U; i < 4U; ++i)
		{
			carry = _mm256_srli_epi64(d[i], 26U);
			d[i] = _mm256_and_si256(d[i], mask);
			d[i + 1U] = _mm256_add_epi64(d[i + 1U], carry);
		}

		carry = _mm256_srli_epi64(d[4U], 26U);
		d[4U] = _mm256_and_si256(d[4U], mask);
		d[0U] = _mm256_add_epi64(d[0U], _mm256_add_epi64(_mm256_slli_epi64(carry, 2U), carry));
		carry = _mm256_srli_epi64(d[0U], 26U);
		d[0U] = _mm256_and_si256(d[0U], mask);
		d[1U] = _mm256_add_epi64(d[1U], carry);

		for (i = 0U; i < 5U; ++i)
		{
			v[i] = _mm256_add_epi64(d[i], m[i]);
		}

		message += 4U * QSC_POLY1305_BLOCK_SIZE;
		length -= 4U * QSC_POLY1305_BLOCK_SIZE;
	}

	/* construct distinct final-fold powers only after the bulk kernel has
	 * finished, keeping nine YMM registers out of the hot loop's live set. */
	for (i = 0U; i < 5U; ++i)
	{
		r[i] = _mm256_setr_epi64x(powers[0U][i], powers[1U][i], powers[2U][i], powers[3U][i]);
	}

	for (i = 0U; i < 4U; ++i)
	{
		s[i] = _mm256_add_epi64(_mm256_slli_epi64(r[i + 1U], 2U), r[i + 1U]);
	}

	/* fold the lanes once, weighting by r^4, r^3, r^2 and r. */
	d[0U] = _mm256_mul_epu32(v[0U], r[0U]);
	d[0U] = _mm256_add_epi64(d[0U], _mm256_mul_epu32(v[1U], s[3U]));
	d[0U] = _mm256_add_epi64(d[0U], _mm256_mul_epu32(v[2U], s[2U]));
	d[0U] = _mm256_add_epi64(d[0U], _mm256_mul_epu32(v[3U], s[1U]));
	d[0U] = _mm256_add_epi64(d[0U], _mm256_mul_epu32(v[4U], s[0U]));
	d[1U] = _mm256_mul_epu32(v[0U], r[1U]);
	d[1U] = _mm256_add_epi64(d[1U], _mm256_mul_epu32(v[1U], r[0U]));
	d[1U] = _mm256_add_epi64(d[1U], _mm256_mul_epu32(v[2U], s[3U]));
	d[1U] = _mm256_add_epi64(d[1U], _mm256_mul_epu32(v[3U], s[2U]));
	d[1U] = _mm256_add_epi64(d[1U], _mm256_mul_epu32(v[4U], s[1U]));
	d[2U] = _mm256_mul_epu32(v[0U], r[2U]);
	d[2U] = _mm256_add_epi64(d[2U], _mm256_mul_epu32(v[1U], r[1U]));
	d[2U] = _mm256_add_epi64(d[2U], _mm256_mul_epu32(v[2U], r[0U]));
	d[2U] = _mm256_add_epi64(d[2U], _mm256_mul_epu32(v[3U], s[3U]));
	d[2U] = _mm256_add_epi64(d[2U], _mm256_mul_epu32(v[4U], s[2U]));
	d[3U] = _mm256_mul_epu32(v[0U], r[3U]);
	d[3U] = _mm256_add_epi64(d[3U], _mm256_mul_epu32(v[1U], r[2U]));
	d[3U] = _mm256_add_epi64(d[3U], _mm256_mul_epu32(v[2U], r[1U]));
	d[3U] = _mm256_add_epi64(d[3U], _mm256_mul_epu32(v[3U], r[0U]));
	d[3U] = _mm256_add_epi64(d[3U], _mm256_mul_epu32(v[4U], s[3U]));
	d[4U] = _mm256_mul_epu32(v[0U], r[4U]);
	d[4U] = _mm256_add_epi64(d[4U], _mm256_mul_epu32(v[1U], r[3U]));
	d[4U] = _mm256_add_epi64(d[4U], _mm256_mul_epu32(v[2U], r[2U]));
	d[4U] = _mm256_add_epi64(d[4U], _mm256_mul_epu32(v[3U], r[1U]));
	d[4U] = _mm256_add_epi64(d[4U], _mm256_mul_epu32(v[4U], r[0U]));

	for (i = 0U; i < 4U; ++i)
	{
		carry = _mm256_srli_epi64(d[i], 26U);
		d[i] = _mm256_and_si256(d[i], mask);
		d[i + 1U] = _mm256_add_epi64(d[i + 1U], carry);
	}

	carry = _mm256_srli_epi64(d[4U], 26U);
	d[4U] = _mm256_and_si256(d[4U], mask);
	d[0U] = _mm256_add_epi64(d[0U], _mm256_add_epi64(_mm256_slli_epi64(carry, 2U), carry));
	carry = _mm256_srli_epi64(d[0U], 26U);
	d[0U] = _mm256_and_si256(d[0U], mask);
	d[1U] = _mm256_add_epi64(d[1U], carry);

	for (i = 0U; i < 5U; ++i)
	{
		lane_sum = _mm_add_epi64(_mm256_castsi256_si128(d[i]), _mm256_extracti128_si256(d[i], 1));
		sum = (uint64_t)_mm_cvtsi128_si64(lane_sum) + (uint64_t)_mm_cvtsi128_si64(_mm_srli_si128(lane_sum, 8));
		h[i] = sum;
	}

	for (i = 0U; i < 4U; ++i)
	{
		c = h[i] >> 26U;
		h[i] &= 0x3FFFFFFULL;
		h[i + 1U] += c;
	}

	c = h[4U] >> 26U;
	h[4U] &= 0x3FFFFFFULL;
	h[0U] += c * 5U;

	for (i = 0U; i < 5U; ++i)
	{
		ctx->h[i] = (uint32_t)h[i];
	}

	qsc_memutils_secure_erase(powers, sizeof(powers));
	qsc_memutils_secure_erase(h, sizeof(h));
	qsc_memutils_secure_erase(r, sizeof(r));
	qsc_memutils_secure_erase(s, sizeof(s));
	qsc_memutils_secure_erase(rk, sizeof(rk));
	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(v, sizeof(v));
	qsc_memutils_secure_erase(m, sizeof(m));
	qsc_memutils_secure_erase(d, sizeof(d));
	_mm256_zeroupper();
}
#endif

void qsc_poly1305_blockupdate(qsc_poly1305_state* ctx, const uint8_t* message)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(message != NULL);

	if (ctx != NULL && message != NULL)
	{
		if (ctx->rmd == 0U)
		{
			poly1305_block(ctx, message);
		}
		else
		{
			qsc_poly1305_update(ctx, message, QSC_POLY1305_BLOCK_SIZE);
		}
	}
}

void qsc_poly1305_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(message != NULL || msglen == 0U);
	QSC_ASSERT(key != NULL);

	if (output != NULL && (message != NULL || msglen == 0U) && key != NULL)
	{
		qsc_poly1305_state ctx;

		qsc_poly1305_initialize(&ctx, key);

		if (msglen != 0U)
		{
			qsc_poly1305_update(&ctx, message, msglen);
		}

		qsc_poly1305_finalize(&ctx, output);
	}
}

void qsc_poly1305_dispose(qsc_poly1305_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx->h, sizeof(ctx->h));
		qsc_memutils_secure_erase(ctx->k, sizeof(ctx->k));
		qsc_memutils_secure_erase(ctx->r, sizeof(ctx->r));
		qsc_memutils_secure_erase(ctx->s, sizeof(ctx->s));
		qsc_memutils_secure_erase(ctx->buf, sizeof(ctx->buf));
		ctx->fnl = 0U;
		ctx->rmd = 0U;
	}
}

void qsc_poly1305_finalize(qsc_poly1305_state* ctx, uint8_t* output)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	uint64_t f0;
	uint64_t f1;
	uint64_t f2;
	uint64_t f3;
	uint32_t b;
	uint32_t g0;
	uint32_t g1;
	uint32_t g2;
	uint32_t g3;
	uint32_t g4;
	uint32_t nb;

	if (ctx != NULL && output != NULL)
	{
		if (ctx->rmd != 0U)
		{
			ctx->buf[ctx->rmd] = 1U;

			for (size_t i = ctx->rmd + 1U; i < QSC_POLY1305_BLOCK_SIZE; ++i)
			{
				ctx->buf[i] = 0U;
			}

			ctx->fnl = 1U;
			poly1305_block(ctx, ctx->buf);
		}

		b = ctx->h[0U] >> 26;
		ctx->h[0U] = ctx->h[0U] & 0x3FFFFFFUL;
		ctx->h[1U] += b;
		b = ctx->h[1U] >> 26;
		ctx->h[1U] = ctx->h[1U] & 0x3FFFFFFUL;
		ctx->h[2U] += b;
		b = ctx->h[2U] >> 26;
		ctx->h[2U] = ctx->h[2U] & 0x3FFFFFFUL;
		ctx->h[3U] += b;
		b = ctx->h[3U] >> 26;
		ctx->h[3U] = ctx->h[3U] & 0x3FFFFFFUL;
		ctx->h[4U] += b;
		b = ctx->h[4U] >> 26;
		ctx->h[4U] = ctx->h[4U] & 0x3FFFFFFUL;
		ctx->h[0U] += b * 5U;

		g0 = ctx->h[0U] + 5U;
		b = g0 >> 26;
		g0 &= 0x3FFFFFFUL;
		g1 = ctx->h[1U] + b;
		b = g1 >> 26;
		g1 &= 0x3FFFFFFUL;
		g2 = ctx->h[2U] + b;
		b = g2 >> 26;
		g2 &= 0x3FFFFFFUL;
		g3 = ctx->h[3U] + b;
		b = g3 >> 26;
		g3 &= 0x3FFFFFFUL;
		g4 = ctx->h[4U] + b - (1U << 26);

		b = (g4 >> 31) - 1U;
		nb = ~b;

		ctx->h[0U] = (ctx->h[0U] & nb) | (g0 & b);
		ctx->h[1U] = (ctx->h[1U] & nb) | (g1 & b);
		ctx->h[2U] = (ctx->h[2U] & nb) | (g2 & b);
		ctx->h[3U] = (ctx->h[3U] & nb) | (g3 & b);
		ctx->h[4U] = (ctx->h[4U] & nb) | (g4 & b);

		/* jgu: checked */
		/*lint -save -e647 */
		f0 = (ctx->h[0U] | (ctx->h[1U] << 26)) + (uint64_t)ctx->k[0U];
		f1 = ((ctx->h[1U] >> 6) | (ctx->h[2U] << 20)) + (uint64_t)ctx->k[1U];
		f2 = ((ctx->h[2U] >> 12) | (ctx->h[3U] << 14)) + (uint64_t)ctx->k[2U];
		f3 = ((ctx->h[3U] >> 18) | (ctx->h[4U] << 8)) + (uint64_t)ctx->k[3U];
		/*lint -restore */

		qsc_intutils_le32to8(output, (uint32_t)f0);
		f1 += (f0 >> 32);
		qsc_intutils_le32to8(output + 4U, (uint32_t)f1);
		f2 += (f1 >> 32);
		qsc_intutils_le32to8(output + 8U, (uint32_t)f2);
		f3 += (f2 >> 32);
		qsc_intutils_le32to8(output + 12U, (uint32_t)f3);

		qsc_poly1305_reset(ctx);
	}
}

void qsc_poly1305_initialize(qsc_poly1305_state* ctx, const uint8_t key[QSC_POLY1305_KEY_SIZE])
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(key != NULL);

	if (ctx != NULL && key != NULL)
	{
		ctx->r[0U] = (qsc_intutils_le8to32(&key[0U])) & 0x3FFFFFFUL;
		ctx->r[1U] = (qsc_intutils_le8to32(&key[3U]) >> 2) & 0x3FFFF03UL;
		ctx->r[2U] = (qsc_intutils_le8to32(&key[6U]) >> 4) & 0x3FFC0FFUL;
		ctx->r[3U] = (qsc_intutils_le8to32(&key[9U]) >> 6) & 0x3F03FFFUL;
		ctx->r[4U] = (qsc_intutils_le8to32(&key[12U]) >> 8) & 0x00FFFFFUL;
		ctx->s[0U] = ctx->r[1U] * 5U;
		ctx->s[1U] = ctx->r[2U] * 5U;
		ctx->s[2U] = ctx->r[3U] * 5U;
		ctx->s[3U] = ctx->r[4U] * 5U;
		ctx->h[0U] = 0U;
		ctx->h[1U] = 0U;
		ctx->h[2U] = 0U;
		ctx->h[3U] = 0U;
		ctx->h[4U] = 0U;
		ctx->k[0U] = qsc_intutils_le8to32(&key[16U]);
		ctx->k[1U] = qsc_intutils_le8to32(&key[20U]);
		ctx->k[2U] = qsc_intutils_le8to32(&key[24U]);
		ctx->k[3U] = qsc_intutils_le8to32(&key[28U]);
		qsc_memutils_secure_erase(ctx->buf, sizeof(ctx->buf));
		ctx->fnl = 0U;
		ctx->rmd = 0U;
	}
	else if (ctx != NULL)
	{
		qsc_poly1305_dispose(ctx);
	}
}

void qsc_poly1305_reset(qsc_poly1305_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx->h, sizeof(ctx->h));
		qsc_memutils_secure_erase(ctx->k, sizeof(ctx->k));
		qsc_memutils_secure_erase(ctx->r, sizeof(ctx->r));
		qsc_memutils_secure_erase(ctx->s, sizeof(ctx->s));
		qsc_memutils_secure_erase(ctx->buf, sizeof(ctx->buf));
		ctx->rmd = 0U;
		ctx->fnl = 0U;
	}
}

void qsc_poly1305_update(qsc_poly1305_state* ctx, const uint8_t* message, size_t msglen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(message != NULL || msglen == 0U);

	if (ctx != NULL && message != NULL && msglen != 0U)
	{
		size_t i;
		size_t rmd;

		if (ctx->rmd != 0U)
		{
			rmd = (QSC_POLY1305_BLOCK_SIZE - ctx->rmd);

			if (rmd > msglen)
			{
				rmd = msglen;
			}

			for (i = 0U; i < rmd; ++i)
			{
				ctx->buf[ctx->rmd + i] = message[i];
			}

			msglen -= rmd;
			message += rmd;
			ctx->rmd += rmd;

			if (ctx->rmd == QSC_POLY1305_BLOCK_SIZE)
			{
				poly1305_block(ctx, ctx->buf);
				ctx->rmd = 0U;
			}
		}

		if (msglen >= QSC_POLY1305_BLOCK_SIZE)
		{
			rmd = msglen & ~(size_t)(QSC_POLY1305_BLOCK_SIZE - 1U);
#if defined(QSC_SYSTEM_HAS_AVX2)
			if (rmd >= 512U)
			{
				const size_t vlen = rmd & ~(size_t)63U;
				poly1305_blocks4_avx2(ctx, message, vlen);
				message += vlen;
				msglen -= vlen;
				rmd -= vlen;
			}
#endif
			if (rmd != 0U)
			{
				poly1305_blocks_register(ctx, message, rmd);
				message += rmd;
				msglen -= rmd;
			}
		}

		if (msglen != 0U)
		{
			for (i = 0U; i < msglen; ++i)
			{
				ctx->buf[ctx->rmd + i] = message[i];
			}

			ctx->rmd += msglen;
		}
	}
}

int32_t qsc_poly1305_verify(const uint8_t* code, const uint8_t* message, size_t msglen, const uint8_t* key)
{
	QSC_ASSERT(code != NULL);
	QSC_ASSERT(message != NULL || msglen == 0U);
	QSC_ASSERT(key != NULL);

	int32_t res;

	res = -1;

	if (code != NULL && (message != NULL || msglen == 0U) && key != NULL)
	{
		uint8_t hash[QSC_POLY1305_MAC_SIZE] = { 0U };

		qsc_poly1305_compute(hash, message, msglen, key);
		res = qsc_intutils_verify(code, hash, QSC_POLY1305_MAC_SIZE);
		/* Disclose only equality, not the bitwise difference of secret and supplied tags. */
		res = (int32_t)(((uint32_t)res + 255U) >> 8U);
		qsc_memutils_secure_erase(hash, sizeof(hash));
	}

	return res;
}

