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

/** \file mldsa_parameter_impl.h
 * \brief Private shared source for three explicit ML-DSA compilation units.
 * \details Each module selects a public security level through a plain constant.
 * Public function names and all backend aliases are object-like substitutions;
 * no macro functions, token pasting, or stringification are used.
 */
#ifndef QSC_MLDSA_PARAMETER
#error "ML-DSA profile is required"
#endif

#include "mldsa.h"
#include "memutils.h"

#undef QSC_DILITHIUM_S1P44
#undef QSC_DILITHIUM_S3P65
#undef QSC_DILITHIUM_S5P87
#if QSC_MLDSA_PARAMETER == 44U
#define QSC_DILITHIUM_S1P44
/* Literal public API names; no generated identifiers. */
#define mldsa_export_generate_keypair qsc_mldsa44_generate_keypair
#define mldsa_export_seeded_generate_keypair qsc_mldsa44_seeded_generate_keypair
#define mldsa_export_sign qsc_mldsa44_sign
#define mldsa_export_sign_ex qsc_mldsa44_sign_ex
#define mldsa_export_verify qsc_mldsa44_verify
#define mldsa_export_verify_ex qsc_mldsa44_verify_ex
/* Unique per-parameter backend names, selected as plain aliases. */
#define qsc_dilithium_ref_generate_keypair qsc_mldsa44_ref_generate_keypair
#define qsc_dilithium_ref_seeded_generate_keypair qsc_mldsa44_ref_seeded_generate_keypair
#define qsc_dilithium_ref_sign qsc_mldsa44_ref_sign
#define qsc_dilithium_ref_sign_signature qsc_mldsa44_ref_sign_signature
#define qsc_dilithium_ref_verify qsc_mldsa44_ref_verify
#define qsc_dilithium_ref_open qsc_mldsa44_ref_open
#define qsc_dilithium_avx2_generate_keypair qsc_mldsa44_ref_avx2_generate_keypair
#define qsc_dilithium_avx2_seeded_generate_keypair qsc_mldsa44_ref_avx2_seeded_generate_keypair
#define qsc_dilithium_avx2_sign qsc_mldsa44_ref_avx2_sign
#define qsc_dilithium_avx2_sign_signature qsc_mldsa44_ref_avx2_sign_signature
#define qsc_dilithium_avx2_verify qsc_mldsa44_ref_avx2_verify
#define qsc_dilithium_avx2_open qsc_mldsa44_ref_avx2_open
#define dilithium_avx2_polyw1_pack qsc_mldsa44_ref_avx2_polyw1_pack
#define dilithium_rej_eta_avx qsc_mldsa44_ref_avx2_rej_eta
#elif QSC_MLDSA_PARAMETER == 65U
#define QSC_DILITHIUM_S3P65
/* Literal public API names; no generated identifiers. */
#define mldsa_export_generate_keypair qsc_mldsa65_generate_keypair
#define mldsa_export_seeded_generate_keypair qsc_mldsa65_seeded_generate_keypair
#define mldsa_export_sign qsc_mldsa65_sign
#define mldsa_export_sign_ex qsc_mldsa65_sign_ex
#define mldsa_export_verify qsc_mldsa65_verify
#define mldsa_export_verify_ex qsc_mldsa65_verify_ex
/* Unique per-parameter backend names, selected as plain aliases. */
#define qsc_dilithium_ref_generate_keypair qsc_mldsa65_ref_generate_keypair
#define qsc_dilithium_ref_seeded_generate_keypair qsc_mldsa65_ref_seeded_generate_keypair
#define qsc_dilithium_ref_sign qsc_mldsa65_ref_sign
#define qsc_dilithium_ref_sign_signature qsc_mldsa65_ref_sign_signature
#define qsc_dilithium_ref_verify qsc_mldsa65_ref_verify
#define qsc_dilithium_ref_open qsc_mldsa65_ref_open
#define qsc_dilithium_avx2_generate_keypair qsc_mldsa65_ref_avx2_generate_keypair
#define qsc_dilithium_avx2_seeded_generate_keypair qsc_mldsa65_ref_avx2_seeded_generate_keypair
#define qsc_dilithium_avx2_sign qsc_mldsa65_ref_avx2_sign
#define qsc_dilithium_avx2_sign_signature qsc_mldsa65_ref_avx2_sign_signature
#define qsc_dilithium_avx2_verify qsc_mldsa65_ref_avx2_verify
#define qsc_dilithium_avx2_open qsc_mldsa65_ref_avx2_open
#define dilithium_avx2_polyw1_pack qsc_mldsa65_ref_avx2_polyw1_pack
#define dilithium_rej_eta_avx qsc_mldsa65_ref_avx2_rej_eta
#elif QSC_MLDSA_PARAMETER == 87U
#define QSC_DILITHIUM_S5P87
/* Literal public API names; no generated identifiers. */
#define mldsa_export_generate_keypair qsc_mldsa87_generate_keypair
#define mldsa_export_seeded_generate_keypair qsc_mldsa87_seeded_generate_keypair
#define mldsa_export_sign qsc_mldsa87_sign
#define mldsa_export_sign_ex qsc_mldsa87_sign_ex
#define mldsa_export_verify qsc_mldsa87_verify
#define mldsa_export_verify_ex qsc_mldsa87_verify_ex
/* Unique per-parameter backend names, selected as plain aliases. */
#define qsc_dilithium_ref_generate_keypair qsc_mldsa87_ref_generate_keypair
#define qsc_dilithium_ref_seeded_generate_keypair qsc_mldsa87_ref_seeded_generate_keypair
#define qsc_dilithium_ref_sign qsc_mldsa87_ref_sign
#define qsc_dilithium_ref_sign_signature qsc_mldsa87_ref_sign_signature
#define qsc_dilithium_ref_verify qsc_mldsa87_ref_verify
#define qsc_dilithium_ref_open qsc_mldsa87_ref_open
#define qsc_dilithium_avx2_generate_keypair qsc_mldsa87_ref_avx2_generate_keypair
#define qsc_dilithium_avx2_seeded_generate_keypair qsc_mldsa87_ref_avx2_seeded_generate_keypair
#define qsc_dilithium_avx2_sign qsc_mldsa87_ref_avx2_sign
#define qsc_dilithium_avx2_sign_signature qsc_mldsa87_ref_avx2_sign_signature
#define qsc_dilithium_avx2_verify qsc_mldsa87_ref_avx2_verify
#define qsc_dilithium_avx2_open qsc_mldsa87_ref_avx2_open
#define dilithium_avx2_polyw1_pack qsc_mldsa87_ref_avx2_polyw1_pack
#define dilithium_rej_eta_avx qsc_mldsa87_ref_avx2_rej_eta
#else
#error "Unsupported ML-DSA profile"
#endif

/* Source specialization is retained, as in the qualified Kyber design. */
#if defined(QSC_SYSTEM_HAS_AVX2)
#define mldsa_backend_generate_keypair qsc_dilithium_avx2_generate_keypair
#define mldsa_backend_seeded_generate_keypair qsc_dilithium_avx2_seeded_generate_keypair
#define mldsa_backend_sign qsc_dilithium_avx2_sign
#define mldsa_backend_sign_signature qsc_dilithium_avx2_sign_signature
#define mldsa_backend_verify qsc_dilithium_avx2_verify
#define mldsa_backend_open qsc_dilithium_avx2_open
#include "dilithiumbase_avx2.c"
#else
#define mldsa_backend_generate_keypair qsc_dilithium_ref_generate_keypair
#define mldsa_backend_seeded_generate_keypair qsc_dilithium_ref_seeded_generate_keypair
#define mldsa_backend_sign qsc_dilithium_ref_sign
#define mldsa_backend_sign_signature qsc_dilithium_ref_sign_signature
#define mldsa_backend_verify qsc_dilithium_ref_verify
#define mldsa_backend_open qsc_dilithium_ref_open
#include "dilithiumbase.c"
#endif

/** \brief Generate one qualified parameter's key pair using the common scalar backend.
 * \param pk Output public key, QSC_MLDSA{44|65|87}_PUBLICKEY_SIZE bytes.
 * \param sk Output secret key, QSC_MLDSA{44|65|87}_PRIVATEKEY_SIZE bytes.
 * \param rng_generate Random byte callback; may be stateful and is externally owned.
 * \return True on success, false for invalid input or RNG failure.
 */
bool mldsa_export_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    bool res;

    res = false;

    if (pk != NULL && sk != NULL && rng_generate != NULL)
    {
        res = mldsa_backend_generate_keypair(pk, sk, rng_generate);
    }

    return res;
}

/** \brief Deterministically generate one qualified parameter key pair from seed.
 * \param pk Caller-owned public key output.
 * \param sk Caller-owned secret key output.
 * \param seed Caller-owned 32-byte deterministic seed.
 */
void mldsa_export_seeded_generate_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed)
{
    if (pk != NULL && sk != NULL && seed != NULL)
    {
        mldsa_backend_seeded_generate_keypair(pk, sk, seed);
    }
}

/** \brief Sign with no explicit context using the common parameter backend.
 * \param sm Signed message output, signature size plus msglen bytes.
 * \param smlen Receives length on success.
 * \param msg Input message of msglen bytes.
 * \param msglen Input length.
 * \param sk Secret signing key for selected parameter.
 * \param rng_generate Random generator callback used in hedged builds.
 * \return True on success; false for unsupported arguments, RNG or algorithm failure.
 */
bool mldsa_export_sign(uint8_t* sm, size_t* smlen, const uint8_t* msg, size_t msglen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    bool res;
    bool validrng;

    res = false;

    if (smlen != NULL)
    {
        *smlen = 0U;
    }

#if defined(QSC_DILITHIUM_RANDOMIZED_SIGNING)
    validrng = (rng_generate != NULL);
#else
    validrng = true;
#endif

    if (validrng == true && sm != NULL && smlen != NULL && msg != NULL && sk != NULL && msglen <= SIZE_MAX - DILITHIUM_SIGNATURE_SIZE)
    {
        res = mldsa_backend_sign(sm, smlen, msg, msglen, NULL, 0U, sk, rng_generate);
    }

    return res;
}

/** \brief Sign with explicit context using the common parameter backend.
 * \param sm Signed message output, signature size plus msglen bytes.
 * \param smlen Receives length on success.
 * \param msg Input message of msglen bytes.
 * \param msglen Message length.
 * \param ctx Context, optional when ctxlen is zero.
 * \param ctxlen Context length at most 255 bytes.
 * \param sk Secret signing key.
 * \param rng_generate Random callback for hedged signing.
 * \return True on success; false for malformed parameters or backend failures.
 */
bool mldsa_export_sign_ex(uint8_t* sm, size_t* smlen, const uint8_t* msg, size_t msglen, const uint8_t* ctx, size_t ctxlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    bool res;
    bool validrng;

    res = false;

    if (smlen != NULL)
    {
        *smlen = 0U;
    }

#if defined(QSC_DILITHIUM_RANDOMIZED_SIGNING)
    validrng = (rng_generate != NULL);
#else
    validrng = true;
#endif

    if (validrng == true && sm != NULL && smlen != NULL && msg != NULL && sk != NULL && msglen <= SIZE_MAX - DILITHIUM_SIGNATURE_SIZE && ctxlen <= 255U && (ctx != NULL || ctxlen == 0U))
    {
        res = mldsa_backend_sign(sm, smlen, msg, msglen, ctx, ctxlen, sk, rng_generate);
    }

    return res;
}

/** \brief Verify the signed message without an explicit context.
 * \param msg Recovered message output with sufficient caller-owned capacity.
 * \param msglen Receives output length, zero on invalid signature.
 * \param sm Signature-message input.
 * \param smlen Signed-message input length.
 * \param pk Public key for selected parameter.
 * \return True if verified, false otherwise.
 */
bool mldsa_export_verify(uint8_t* msg, size_t* msglen, const uint8_t* sm, size_t smlen, const uint8_t* pk)
{
    bool res;

    res = false;

    if (msglen != NULL)
    {
        *msglen = 0U;
    }

    if (msg != NULL && msglen != NULL && sm != NULL && pk != NULL)
    {
        res = mldsa_backend_open(msg, msglen, NULL, 0U, sm, smlen, pk);
    }

    return res;
}

/** \brief Verify signed message and context for selected parameter.
 * \param msg Caller-owned recovered message output.
 * \param msglen Receives verified length or zero on failure.
 * \param ctx Optional context when length is zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \param sm Signed message input.
 * \param smlen Signed message length.
 * \param pk Public key of selected parameter.
 * \return True on valid signature and context; false otherwise.
 */
bool mldsa_export_verify_ex(uint8_t* msg, size_t* msglen, const uint8_t* ctx, size_t ctxlen, const uint8_t* sm, size_t smlen, const uint8_t* pk)
{
    bool res;

    res = false;

    if (msglen != NULL)
    {
        *msglen = 0U;
    }

    if (msg != NULL && msglen != NULL && sm != NULL && pk != NULL && ctxlen <= 255U && (ctx != NULL || ctxlen == 0U))
    {
        res = mldsa_backend_open(msg, msglen, ctx, ctxlen, sm, smlen, pk);
    }

    return res;
}
