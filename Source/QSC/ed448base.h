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

 /* Implementation acknowledgements:
 *
 * This QRCS implementation was developed with reference to the
 * Botan cryptographic library, established cryptographic research,
 * applicable NIST and IETF standards, and published algorithms.
 *
 * The implementation has been adapted and optimized for the QSC
 * architecture, including its arithmetic engines, memory management,
 * platform-specific acceleration, and security requirements.
 *
 * Reference: Botan Cryptographic Library
 * https://botan.randombit.net/
 *
 * Copyright and licensing of third-party derived material remain
 * subject to the applicable original license terms.
 */

#ifndef QSC_ED448BASE_H
#define QSC_ED448BASE_H

#include "qsccommon.h"
#include "memutils.h"
#include "intrinsics.h"

 /* \cond NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/*! \file ed448base.h
 * \brief Private arithmetic shared by X448 and Ed448.
 * \details Based in part on the Botan implementation (curve448_gf.cpp).
 * Seven unsigned 64-bit limbs, native or portable multiplication and carry paths.
 * No shared mutable state. All operands are borrowed, non-NULL fixed-size buffers.
 * This header is internal and does not change the public coordinate types.
 */

#if !defined(QSC_EDDH448_FORCE_PORTABLE) && !defined(QSC_ED448_FORCE_PORTABLE) && !defined(_M_ARM64EC) && (defined(__x86_64__) || (defined(_MSC_VER) && defined(_M_X64)))
#	define ED448_NATIVE_CARRY
#	if defined(_MSC_VER)
#		include <intrin.h>
#	else
#		include <x86intrin.h>
#	endif
#endif

/*! \def ED448_FIELD_WORDS
 * \brief Number of 64-bit words in an internal field element.
 */
#define ED448_FIELD_WORDS 7U

/*! \def ED448_FIELD_BYTES
 * \brief Number of bytes in a serialized X448 coordinate.
 */
#define ED448_FIELD_BYTES 56U

/*! \def ED448_FIELD_A24
 * \brief Curve448 Montgomery ladder constant (A - 2) / 4.
 */
#define ED448_FIELD_A24 39081U

/*! \struct ed448_fe
 * \typedef ed448_fe
 * \brief Private seven-word field representation, little-endian, residues not necessarily canonical.
 */
typedef struct ed448_fe
{
	uint64_t v[ED448_FIELD_WORDS]; /*!< Seven 64-bit limbs, least significant first. */
} ed448_fe;

static inline uint64_t ed448_add_word(uint64_t a, uint64_t b, uint64_t* carry)
{
	uint64_t result;

#if defined(ED448_NATIVE_CARRY)
	unsigned long long output;
	unsigned char c;

	c = _addcarry_u64((unsigned char)*carry, (unsigned long long)a, (unsigned long long)b, &output);
	*carry = (uint64_t)c;
	result = (uint64_t)output;
#else
	uint64_t c;
	uint64_t r;
	uint64_t t;

	t = a + b;
	c = (uint64_t)(t < a);
	r = t + *carry;
	*carry = c | (uint64_t)(r < t);

	result = r;
#endif

	return result;
}

static inline uint64_t ed448_sub_word(uint64_t a, uint64_t b, uint64_t* borrow)
{
	uint64_t result;

#if defined(ED448_NATIVE_CARRY)
	unsigned long long output;
	unsigned char c;

	c = _subborrow_u64((unsigned char)*borrow, (unsigned long long)a, (unsigned long long)b, &output);
	*borrow = (uint64_t)c;
	result = (uint64_t)output;
#else
	uint64_t c;
	uint64_t r;
	uint64_t t;

	t = a - b;
	c = (uint64_t)(a < b);
	r = t - *borrow;
	*borrow = c | (uint64_t)(t < *borrow);

	result = r;
#endif

	return result;
}

static inline void ed448_mul_word(uint64_t a, uint64_t b, uint64_t* low, uint64_t* high)
{
#if !defined(QSC_EDDH448_FORCE_PORTABLE) && !defined(QSC_ED448_FORCE_PORTABLE) && defined(_MSC_VER) && defined(_M_X64) && !defined(_M_ARM64EC)
	*low = _umul128(a, b, high);
#elif defined(__SIZEOF_INT128__) && !defined(QSC_EDDH448_FORCE_PORTABLE) && !defined(QSC_ED448_FORCE_PORTABLE)
	__uint128_t p;

	p = (__uint128_t)a * (__uint128_t)b;
	*low = (uint64_t)p;
	*high = (uint64_t)(p >> 64);
#else
	uint64_t p0;
	uint64_t p1;
	uint64_t p2;
	uint64_t p3;
	uint64_t middle;

	p0 = (a & UINT64_C(0xFFFFFFFF)) * (b & UINT64_C(0xFFFFFFFF));
	p1 = (a & UINT64_C(0xFFFFFFFF)) * (b >> 32);
	p2 = (a >> 32) * (b & UINT64_C(0xFFFFFFFF));
	p3 = (a >> 32) * (b >> 32);
	middle = (p0 >> 32) + (p1 & UINT64_C(0xFFFFFFFF)) + (p2 & UINT64_C(0xFFFFFFFF));
	*low = (p0 & UINT64_C(0xFFFFFFFF)) | (middle << 32);
	*high = p3 + (p1 >> 32) + (p2 >> 32) + (middle >> 32);
#endif
}

static inline void ed448_accumulate(uint64_t acc[3U], uint64_t lo, uint64_t hi)
{
#if defined(ED448_NATIVE_CARRY)
	unsigned long long w0;
	unsigned long long w1;
	unsigned long long w2;
	unsigned char carry;

	w0 = (unsigned long long)acc[0U];
	w1 = (unsigned long long)acc[1U];
	w2 = (unsigned long long)acc[2U];
	carry = _addcarry_u64(0U, w0, (unsigned long long)lo, &w0);
	carry = _addcarry_u64(carry, w1, (unsigned long long)hi, &w1);
	(void)_addcarry_u64(carry, w2, 0U, &w2);
	acc[0U] = (uint64_t)w0;
	acc[1U] = (uint64_t)w1;
	acc[2U] = (uint64_t)w2;
#else
	uint64_t carry;
	uint64_t old;
	uint64_t t;

	old = acc[0U];
	acc[0U] += lo;
	carry = (uint64_t)(acc[0U] < old);
	old = acc[1U];
	t = old + hi;
	acc[1U] = t + carry;
	acc[2U] += (uint64_t)(t < old) + (uint64_t)(acc[1U] < t);
#endif
}

static inline void ed448_comba_mul(uint64_t out[14U], const uint64_t a[7U], const uint64_t b[7U])
{
	uint64_t acc[3U] = {0U, 0U, 0U};
	uint64_t lo;
	uint64_t hi;

	ed448_mul_word(a[0U], b[0U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[0U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], b[1U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], b[0U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[1U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], b[2U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], b[1U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[2U], b[0U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[2U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], b[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], b[2U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[2U], b[1U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[3U], b[0U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[3U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], b[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], b[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[2U], b[2U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[3U], b[1U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[4U], b[0U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[4U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], b[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], b[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[2U], b[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[3U], b[2U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[4U], b[1U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[5U], b[0U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[5U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], b[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], b[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[2U], b[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[3U], b[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[4U], b[2U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[5U], b[1U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[6U], b[0U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[6U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[1U], b[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[2U], b[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[3U], b[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[4U], b[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[5U], b[2U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[6U], b[1U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[7U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[2U], b[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[3U], b[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[4U], b[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[5U], b[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[6U], b[2U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[8U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[3U], b[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[4U], b[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[5U], b[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[6U], b[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[9U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[4U], b[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[5U], b[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[6U], b[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[10U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[5U], b[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[6U], b[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[11U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[6U], b[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[12U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	out[13U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;
}

static inline void ed448_comba_square(uint64_t out[14U], const uint64_t a[7U])
{
	uint64_t acc[3U] = {0U, 0U, 0U};
	uint64_t lo;
	uint64_t hi;

	ed448_mul_word(a[0U], a[0U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[0U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], a[1U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	out[1U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], a[2U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], a[1U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[2U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], a[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], a[2U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	out[3U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], a[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], a[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[2U], a[2U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[4U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], a[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], a[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[2U], a[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	out[5U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[0U], a[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[1U], a[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[2U], a[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[3U], a[3U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[6U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[1U], a[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[2U], a[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[3U], a[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	out[7U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[2U], a[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[3U], a[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[4U], a[4U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[8U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[3U], a[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[4U], a[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	out[9U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[4U], a[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	ed448_mul_word(a[5U], a[5U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[10U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[5U], a[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	ed448_accumulate(acc, lo, hi);
	out[11U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	ed448_mul_word(a[6U], a[6U], &lo, &hi);
	ed448_accumulate(acc, lo, hi);
	out[12U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	out[13U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;
}

static inline void ed448_reduce_add(ed448_fe* out, const uint64_t in[8U])
{
	uint64_t w[8U];
	uint64_t carry;

	carry = 0U;
	w[0U] = ed448_add_word(in[0U], in[7U], &carry);
	w[1U] = ed448_add_word(in[1U], 0U, &carry);
	w[2U] = ed448_add_word(in[2U], 0U, &carry);
	w[3U] = ed448_add_word(in[3U], in[7U] << 32, &carry);
	w[4U] = ed448_add_word(in[4U], 0U, &carry);
	w[5U] = ed448_add_word(in[5U], 0U, &carry);
	w[6U] = ed448_add_word(in[6U], 0U, &carry);
	w[7U] = carry;

	carry = 0U;
	out->v[0U] = ed448_add_word(w[0U], w[7U], &carry);
	out->v[1U] = ed448_add_word(w[1U], 0U, &carry);
	out->v[2U] = ed448_add_word(w[2U], 0U, &carry);
	out->v[3U] = w[3U] + (w[7U] << 32) + carry;
	out->v[4U] = w[4U];
	out->v[5U] = w[5U];
	out->v[6U] = w[6U];
}

static inline void ed448_reduce_mul(ed448_fe* out, const uint64_t in[14U])
{
	uint64_t r[8U];
	uint64_t s[8U];
	uint64_t t[8U];
	uint64_t h[8U];
	uint64_t carry;
	size_t i;

	carry = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		r[i] = ed448_add_word(in[i], in[i + 7U], &carry);
	}

	r[7U] = carry;
	s[0U] = r[0U];
	s[1U] = r[1U];
	s[2U] = r[2U];
	carry = 0U;
	s[3U] = ed448_add_word(r[3U], in[10U] & UINT64_C(0xFFFFFFFF00000000), &carry);
	s[4U] = ed448_add_word(r[4U], in[11U], &carry);
	s[5U] = ed448_add_word(r[5U], in[12U], &carry);
	s[6U] = ed448_add_word(r[6U], in[13U], &carry);
	s[7U] = r[7U] + carry;
	t[0U] = (in[11U] << 32) | (in[10U] >> 32);
	t[1U] = (in[12U] << 32) | (in[11U] >> 32);
	t[2U] = (in[13U] << 32) | (in[12U] >> 32);
	t[3U] = (in[7U] << 32) | (in[13U] >> 32);
	t[4U] = (in[8U] << 32) | (in[7U] >> 32);
	t[5U] = (in[9U] << 32) | (in[8U] >> 32);
	t[6U] = (in[10U] << 32) | (in[9U] >> 32);
	carry = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		h[i] = ed448_add_word(s[i], t[i], &carry);
	}

	h[7U] = s[7U] + carry;
	ed448_reduce_add(out, h);
}

static inline void ed448_load(ed448_fe* out, const uint8_t in[56U])
{
	size_t i;
	size_t j;

	for (i = 0U; i < 7U; ++i)
	{
		out->v[i] = 0U;

		for (j = 0U; j < 8U; ++j)
		{
			out->v[i] |= (uint64_t)in[8U * i + j] << (8U * j);
		}
	}
}

static inline uint64_t ed448_mask_barrier(uint64_t mask)
{
#if defined(_MSC_VER)
	volatile uint64_t guarded;

	guarded = mask;
	mask = guarded;
#elif defined(__GNUC__) || defined(__clang__)
	__asm__("" : "+r"(mask));
#endif
	return mask;
}

static inline void ed448_store(uint8_t out[56U], const ed448_fe* in)
{
	static const uint64_t mod[7U] = {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_C(0xFFFFFFFEFFFFFFFF), UINT64_MAX, UINT64_MAX, UINT64_MAX};
	uint64_t dif[7U];
	uint64_t borrow;
	uint64_t mask;
	uint64_t word;
	size_t i;
	size_t j;

	borrow = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		dif[i] = ed448_sub_word(in->v[i], mod[i], &borrow);
	}

	mask = ed448_mask_barrier(0U - borrow);

	for (i = 0U; i < 7U; ++i)
	{
		word = (in->v[i] & mask) | (dif[i] & ~mask);

		for (j = 0U; j < 8U; ++j)
		{
			out[8U * i + j] = (uint8_t)(word >> (8U * j));
		}
	}
}

static inline void ed448_add(ed448_fe* out, const ed448_fe* a, const ed448_fe* b)
{
	uint64_t w[8U];
	uint64_t carry;
	size_t i;

	carry = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		w[i] = ed448_add_word(a->v[i], b->v[i], &carry);
	}

	w[7U] = carry;
	ed448_reduce_add(out, w);
}

static inline void ed448_sub(ed448_fe* out, const ed448_fe* a, const ed448_fe* b)
{
	uint64_t w[7U];
	uint64_t x[7U];
	uint64_t borrow;
	uint64_t delta;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		w[i] = ed448_sub_word(a->v[i], b->v[i], &borrow);
	}

	delta = borrow;
	borrow = 0U;
	x[0U] = ed448_sub_word(w[0U], delta, &borrow);
	x[1U] = ed448_sub_word(w[1U], 0U, &borrow);
	x[2U] = ed448_sub_word(w[2U], 0U, &borrow);
	x[3U] = ed448_sub_word(w[3U], delta << 32, &borrow);

	for (i = 4U; i < 7U; ++i)
	{
		x[i] = ed448_sub_word(w[i], 0U, &borrow);
	}

	delta = borrow;
	borrow = 0U;
	out->v[0U] = ed448_sub_word(x[0U], delta, &borrow);
	out->v[1U] = ed448_sub_word(x[1U], 0U, &borrow);
	out->v[2U] = ed448_sub_word(x[2U], 0U, &borrow);
	out->v[3U] = ed448_sub_word(x[3U], delta << 32, &borrow);
	out->v[4U] = x[4U];
	out->v[5U] = x[5U];
	out->v[6U] = x[6U];
}

static inline void ed448_mul(ed448_fe* out, const ed448_fe* a, const ed448_fe* b)
{
	uint64_t w[14U];

	ed448_comba_mul(w, a->v, b->v);
	ed448_reduce_mul(out, w);
}

static inline void ed448_square(ed448_fe* out, const ed448_fe* a)
{
	uint64_t w[14U];

	ed448_comba_square(w, a->v);
	ed448_reduce_mul(out, w);
}

static inline void ed448_mul_small(ed448_fe* out, const ed448_fe* a, uint64_t factor)
{
	uint64_t w[8U];
	uint64_t carry;
	uint64_t hi;
	uint64_t lo;
	size_t i;

	carry = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		ed448_mul_word(a->v[i], factor, &lo, &hi);
		w[i] = lo + carry;
		carry = hi + (uint64_t)(w[i] < lo);
	}

	w[7U] = carry;
	ed448_reduce_add(out, w);
}

static inline void ed448_swap(ed448_fe* a, ed448_fe* b, uint64_t bit)
{
	uint64_t mask;
	uint64_t v;
	size_t i;

	mask = ed448_mask_barrier(0U - bit);

	for (i = 0U; i < 7U; ++i)
	{
		v = (a->v[i] ^ b->v[i]) & mask;
		a->v[i] ^= v;
		b->v[i] ^= v;
	}
}

static inline void ed448_square_n(ed448_fe* out, const ed448_fe* a, size_t count)
{
	size_t i;

	ed448_square(out, a);

	for (i = 1U; i < count; ++i)
	{
		ed448_square(out, out);
	}
}

static inline void ed448_pow222(ed448_fe* x222, ed448_fe* x223, const ed448_fe* a)
{
	ed448_fe t;
	ed448_fe a2;
	ed448_fe a3;
	ed448_fe a7;
	ed448_fe a63;
	ed448_fe x12;
	ed448_fe x24;
	ed448_fe i34;
	ed448_fe x30;
	ed448_fe x48;
	ed448_fe x96;
	ed448_fe x192;

	ed448_square(&a2, a);
	ed448_mul(&a3, a, &a2);
	ed448_square(&t, &a3);
	ed448_mul(&a7, a, &t);
	ed448_square_n(&t, &a7, 3U);
	ed448_mul(&a63, &a7, &t);
	ed448_square_n(&t, &a63, 6U);
	ed448_mul(&x12, &a63, &t);
	ed448_square_n(&t, &x12, 12U);
	ed448_mul(&x24, &x12, &t);
	ed448_square_n(&i34, &x24, 6U);
	ed448_mul(&x30, &a63, &i34);
	ed448_square_n(&t, &i34, 18U);
	ed448_mul(&x48, &x24, &t);
	ed448_square_n(&t, &x48, 48U);
	ed448_mul(&x96, &x48, &t);
	ed448_square_n(&t, &x96, 96U);
	ed448_mul(&x192, &x96, &t);
	ed448_square_n(&t, &x192, 30U);
	ed448_mul(x222, &x30, &t);
	ed448_square(&t, x222);
	ed448_mul(x223, a, &t);

	qsc_memutils_secure_erase(&t, sizeof(t));
	qsc_memutils_secure_erase(&a2, sizeof(a2));
	qsc_memutils_secure_erase(&a3, sizeof(a3));
	qsc_memutils_secure_erase(&a7, sizeof(a7));
	qsc_memutils_secure_erase(&a63, sizeof(a63));
	qsc_memutils_secure_erase(&x12, sizeof(x12));
	qsc_memutils_secure_erase(&x24, sizeof(x24));
	qsc_memutils_secure_erase(&i34, sizeof(i34));
	qsc_memutils_secure_erase(&x30, sizeof(x30));
	qsc_memutils_secure_erase(&x48, sizeof(x48));
	qsc_memutils_secure_erase(&x96, sizeof(x96));
	qsc_memutils_secure_erase(&x192, sizeof(x192));
}

static inline void ed448_invert(ed448_fe* out, const ed448_fe* a)
{
	ed448_fe x222;
	ed448_fe x223;
	ed448_fe t;

	ed448_pow222(&x222, &x223, a);
	ed448_square_n(&t, &x223, 223U);
	ed448_mul(&t, &t, &x222);
	ed448_square_n(&t, &t, 2U);
	ed448_mul(out, &t, a);

	qsc_memutils_secure_erase(&x222, sizeof(x222));
	qsc_memutils_secure_erase(&x223, sizeof(x223));
	qsc_memutils_secure_erase(&t, sizeof(t));
}

QSC_CPLUSPLUS_ENABLED_END

/* \endcond NO_DOCUMENT */

#endif
