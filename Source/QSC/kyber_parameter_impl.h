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

/*
 * \file kyber_parameter_impl.h
 * \brief Private single-source, parameter-specialized Kyber implementation.
 * \details Each qualified module includes this template exactly once, with
 * a unique prefix and a selected K. The existing default backend is unchanged.
 * This first-stage code specializes shared source for each parameter: it does
 * not yet coalesce specialized machine-code instances into one runtime core.
 * Do not include this template from an ordinary public header.
 */
#ifndef QSC_KYBER_QUALIFIED_PREFIX
#   error "Kyber qualified prefix is required"
#endif

#define QSC_KYBER_IMPL_CONCAT2(a, b) a##b
#define QSC_KYBER_IMPL_CONCAT(a, b) QSC_KYBER_IMPL_CONCAT2(a, b)
#define QSC_KYBER_IMPL_SYM(name) QSC_KYBER_IMPL_CONCAT(QSC_KYBER_QUALIFIED_PREFIX, name)

/* Remap each entry point before parsing the common backend declarations. */
#define qsc_kyber_ref_decapsulate QSC_KYBER_IMPL_SYM(_ref_decapsulate)
#define qsc_kyber_ref_encapsulate QSC_KYBER_IMPL_SYM(_ref_encapsulate)
#define qsc_kyber_ref_seeded_encapsulate QSC_KYBER_IMPL_SYM(_ref_seeded_encapsulate)
#define qsc_kyber_ref_generate_keypair QSC_KYBER_IMPL_SYM(_ref_generate_keypair)
#define qsc_kyber_ref_generate_seeded_keypair QSC_KYBER_IMPL_SYM(_ref_generate_seeded_keypair)
/* Existing AVX2 utility routines have external linkage in the shared source.
 * Give each qualified compilation unit distinct utility symbols so it can
 * coexist with the default AVX2 backend and the other parameter families.
 */
#define kyber_rej_uniform_avx2 QSC_KYBER_IMPL_SYM(_rej_uniform_avx2)
#define kyber_cmov_avx2 QSC_KYBER_IMPL_SYM(_cmov_avx2)
#define kyber_verify_avx2 QSC_KYBER_IMPL_SYM(_verify_avx2)
#define qsc_kyber_avx2_decapsulate QSC_KYBER_IMPL_SYM(_avx2_decapsulate)
#define qsc_kyber_avx2_encapsulate QSC_KYBER_IMPL_SYM(_avx2_encapsulate)
#define qsc_kyber_avx2_seeded_encapsulate QSC_KYBER_IMPL_SYM(_avx2_seeded_encapsulate)
#define qsc_kyber_avx2_generate_keypair QSC_KYBER_IMPL_SYM(_avx2_generate_keypair)
#define qsc_kyber_avx2_generate_seeded_keypair QSC_KYBER_IMPL_SYM(_avx2_generate_seeded_keypair)
#define qsc_kyber_decapsulate QSC_KYBER_IMPL_SYM(_decapsulate)
#define qsc_kyber_encapsulate QSC_KYBER_IMPL_SYM(_encapsulate)
#define qsc_kyber_seeded_encapsulate QSC_KYBER_IMPL_SYM(_seeded_encapsulate)
#define qsc_kyber_generate_keypair QSC_KYBER_IMPL_SYM(_generate_keypair)
#define qsc_kyber_generate_seeded_keypair QSC_KYBER_IMPL_SYM(_generate_seeded_keypair)

#if defined(QSC_SYSTEM_HAS_AVX2)
#   include "kyberbase_avx2.c"
#else
#   include "kyberbase.c"
#endif
#include "kyber.c"

/* Enforce the profile selected by the including parameter-qualified module.
 * The shared base headers resolve QSC_KYBER_K, ETA1 and buffer sizes for
 * the selected implementation, including the AVX2 compilation path.
 */
#if !defined(QSC_KYBER_QUALIFIED_EXPECTED_K) || \
    !defined(QSC_KYBER_QUALIFIED_EXPECTED_ETA1) || \
    !defined(QSC_KYBER_QUALIFIED_EXPECTED_PUBLICKEY_SIZE) || \
    !defined(QSC_KYBER_QUALIFIED_EXPECTED_PRIVATEKEY_SIZE) || \
    !defined(QSC_KYBER_QUALIFIED_EXPECTED_CIPHERTEXT_SIZE) || \
    !defined(QSC_KYBER_QUALIFIED_EXPECTED_SHAREDSECRET_SIZE)
#   error "The Kyber qualified profile must declare its expected dimensions"
#endif
#if (QSC_KYBER_K != QSC_KYBER_QUALIFIED_EXPECTED_K)
#   error "Kyber profile K does not match the qualified module"
#endif
#if (QSC_KYBER_ETA1 != QSC_KYBER_QUALIFIED_EXPECTED_ETA1) || (QSC_KYBER_ETA2 != 2U)
#   error "Kyber CBD eta parameters do not match the qualified module"
#endif
#if (QSC_KYBER_N != 256U) || (QSC_KYBER_Q != 3329U)
#   error "Kyber polynomial parameters are inconsistent"
#endif
#if (QSC_KYBER_PUBLICKEY_BYTES != QSC_KYBER_QUALIFIED_EXPECTED_PUBLICKEY_SIZE) || \
    (QSC_KYBER_SECRETKEY_BYTES != QSC_KYBER_QUALIFIED_EXPECTED_PRIVATEKEY_SIZE) || \
    (QSC_KYBER_CIPHERTEXT_BYTES != QSC_KYBER_QUALIFIED_EXPECTED_CIPHERTEXT_SIZE) || \
    (QSC_KYBER_MSGBYTES != QSC_KYBER_QUALIFIED_EXPECTED_SHAREDSECRET_SIZE)
#   error "Kyber public API buffer sizes do not match its backend"
#endif

#undef kyber_rej_uniform_avx2
#undef kyber_cmov_avx2
#undef kyber_verify_avx2
#undef qsc_kyber_ref_decapsulate
#undef qsc_kyber_ref_encapsulate
#undef qsc_kyber_ref_seeded_encapsulate
#undef qsc_kyber_ref_generate_keypair
#undef qsc_kyber_ref_generate_seeded_keypair
#undef qsc_kyber_avx2_decapsulate
#undef qsc_kyber_avx2_encapsulate
#undef qsc_kyber_avx2_seeded_encapsulate
#undef qsc_kyber_avx2_generate_keypair
#undef qsc_kyber_avx2_generate_seeded_keypair
#undef qsc_kyber_decapsulate
#undef qsc_kyber_encapsulate
#undef qsc_kyber_seeded_encapsulate
#undef qsc_kyber_generate_keypair
#undef qsc_kyber_generate_seeded_keypair
#undef QSC_KYBER_IMPL_SYM
#undef QSC_KYBER_IMPL_CONCAT
#undef QSC_KYBER_IMPL_CONCAT2
