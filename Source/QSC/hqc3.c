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

/** \file hqc3.c
 * \brief Independently linkable HQC-3 interface using a single shared maintained backend source.
 * \note Compile-time specialization uses object-like symbols only, not function-like macros.
 */
#include "qsccommon.h"
#undef QSC_HQC_S1N2321
#undef QSC_HQC_S3N4602
#undef QSC_HQC_S5N7333
/** \def QSC_HQC_S3N4602
 * \brief Internal compile-time HQC-3 parameter selection.
 */
#define QSC_HQC_S3N4602
#include "hqc_multi.h"

/** \def qsc_hqc_ref_generate_keypair
 * \brief Private compile-time alias to the distinct HQC-3 qsc_hqc3_ref_generate_keypair implementation symbol.
 */
#define qsc_hqc_ref_generate_keypair qsc_hqc3_ref_generate_keypair

/** \def qsc_hqc_ref_generate_seeded_keypair
 * \brief Private compile-time alias to the distinct HQC-3 qsc_hqc3_ref_generate_seeded_keypair implementation symbol.
 */
#define qsc_hqc_ref_generate_seeded_keypair qsc_hqc3_ref_generate_seeded_keypair

/** \def qsc_hqc_ref_encapsulate
 * \brief Private compile-time alias to the distinct HQC-3 qsc_hqc3_ref_encapsulate implementation symbol.
 */
#define qsc_hqc_ref_encapsulate qsc_hqc3_ref_encapsulate

/** \def qsc_hqc_ref_seeded_encapsulate
 * \brief Private compile-time alias to the distinct HQC-3 qsc_hqc3_ref_seeded_encapsulate implementation symbol.
 */
#define qsc_hqc_ref_seeded_encapsulate qsc_hqc3_ref_seeded_encapsulate

/** \def qsc_hqc_ref_decapsulate
 * \brief Private compile-time alias to the distinct HQC-3 qsc_hqc3_ref_decapsulate implementation symbol.
 */
#define qsc_hqc_ref_decapsulate qsc_hqc3_ref_decapsulate

/** \def qsc_hqc_avx2_generate_keypair
 * \brief Private compile-time alias to the distinct HQC-3 qsc_hqc3_avx2_generate_keypair implementation symbol.
 */
#define qsc_hqc_avx2_generate_keypair qsc_hqc3_avx2_generate_keypair

/** \def qsc_hqc_avx2_generate_seeded_keypair
 * \brief Private compile-time alias to the distinct HQC-3 qsc_hqc3_avx2_generate_seeded_keypair implementation symbol.
 */
#define qsc_hqc_avx2_generate_seeded_keypair qsc_hqc3_avx2_generate_seeded_keypair

/** \def qsc_hqc_avx2_encapsulate
 * \brief Private compile-time alias to the distinct HQC-3 qsc_hqc3_avx2_encapsulate implementation symbol.
 */
#define qsc_hqc_avx2_encapsulate qsc_hqc3_avx2_encapsulate

/** \def qsc_hqc_avx2_seeded_encapsulate
 * \brief Private compile-time alias to the distinct HQC-3 qsc_hqc3_avx2_seeded_encapsulate implementation symbol.
 */
#define qsc_hqc_avx2_seeded_encapsulate qsc_hqc3_avx2_seeded_encapsulate

/** \def qsc_hqc_avx2_decapsulate
 * \brief Private compile-time alias to the distinct HQC-3 qsc_hqc3_avx2_decapsulate implementation symbol.
 */
#define qsc_hqc_avx2_decapsulate qsc_hqc3_avx2_decapsulate

#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
#include "hqcbase_avx2.c"
#else
#include "hqcbase.c"
#endif

/** \brief HQC-3 explicit generate_keypair wrapper of the shared compile-time specialized backend.
 * \return True on successful operation for bool functions; void functions perform no operation for null arguments.
 * \note All buffers are caller-owned; the RNG callback controls concurrency safety.
 */
bool qsc_hqc3_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = false;

	if (pk != NULL && sk != NULL && rng_generate != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
		res = qsc_hqc3_avx2_generate_keypair(pk, sk, rng_generate);
#else
		res = qsc_hqc3_ref_generate_keypair(pk, sk, rng_generate);
#endif
	}

	return res;
}

/** \brief HQC-3 explicit generate_seeded_keypair wrapper of the shared compile-time specialized backend.
 * \return True on successful operation for bool functions; void functions perform no operation for null arguments.
 * \note All buffers are caller-owned; the RNG callback controls concurrency safety.
 */
void qsc_hqc3_generate_seeded_keypair(uint8_t* pk, uint8_t* sk, uint8_t* seed)
{
	if (pk != NULL && sk != NULL && seed != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
		qsc_hqc3_avx2_generate_seeded_keypair(pk, sk, seed);
#else
		qsc_hqc3_ref_generate_seeded_keypair(pk, sk, seed);
#endif
	}
}

/** \brief HQC-3 explicit encapsulate wrapper of the shared compile-time specialized backend.
 * \return True on successful operation for bool functions; void functions perform no operation for null arguments.
 * \note All buffers are caller-owned; the RNG callback controls concurrency safety.
 */
bool qsc_hqc3_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* pk, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && pk != NULL && rng_generate != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
		res = qsc_hqc3_avx2_encapsulate(secret, ciphertext, pk, rng_generate);
#else
		res = qsc_hqc3_ref_encapsulate(secret, ciphertext, pk, rng_generate);
#endif
	}

	return res;
}

/** \brief HQC-3 explicit seeded_encapsulate wrapper of the shared compile-time specialized backend.
 * \return True on successful operation for bool functions; void functions perform no operation for null arguments.
 * \note All buffers are caller-owned; the RNG callback controls concurrency safety.
 */
void qsc_hqc3_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* pk, const uint8_t seed[QSC_HQC_SEED_BYTES])
{
	if (secret != NULL && ciphertext != NULL && pk != NULL && seed != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
		qsc_hqc3_avx2_seeded_encapsulate(secret, ciphertext, pk, seed);
#else
		qsc_hqc3_ref_seeded_encapsulate(secret, ciphertext, pk, seed);
#endif
	}
}

/** \brief HQC-3 explicit decapsulate wrapper of the shared compile-time specialized backend.
 * \return True on successful operation for bool functions; void functions perform no operation for null arguments.
 * \note All buffers are caller-owned; the RNG callback controls concurrency safety.
 */
bool qsc_hqc3_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* sk)
{
	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && sk != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
		res = qsc_hqc3_avx2_decapsulate(secret, ciphertext, sk);
#else
		res = qsc_hqc3_ref_decapsulate(secret, ciphertext, sk);
#endif
	}

	return res;
}

