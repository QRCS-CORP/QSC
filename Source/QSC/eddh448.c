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

#include "eddh448.h"
#include "ed448.h"
#include "memutils.h"

/* ============================================================
 * X448 Montgomery ladder (RFC 7748 5)
 *
 * The curve is: v^2 = u^3 + A*u^2 + u over GF(2^448 - 2^224 - 1)
 * with A = 156326 and A24 = (A - 2) / 4 = 39081.
 * ============================================================ */

#define A24_448 39081U

static const uint8_t X448_BASE_U[56U] =
{
    5U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
};

static void x448_scalarmult(uint8_t out[56U], const uint8_t k[56U], const uint8_t u[56U])
{
    qsc_fe448 a;
    qsc_fe448 b;
    qsc_fe448 aa;
    qsc_fe448 bb;
    qsc_fe448 c;
    qsc_fe448 cb;
    qsc_fe448 d;
    qsc_fe448 da;
    qsc_fe448 e;
    qsc_fe448 t0;
    qsc_fe448 x1;
    qsc_fe448 x2;
    qsc_fe448 z2;
    qsc_fe448 x3;
    qsc_fe448 z3;
    qsc_fe448 zinv;
    uint32_t swap;

    if (out != NULL && k != NULL && u != NULL)
    {
        qsc_fe448_from_bytes(x1, u);
        qsc_fe448_1(x2);
        qsc_fe448_0(z2);
        qsc_fe448_copy(x3, x1);
        qsc_fe448_1(z3);
        swap = 0U;

        for (int32_t i = 447; i >= 0; --i)
        {
            const uint32_t kbit = ((uint32_t)k[(size_t)i >> 3] >> ((uint32_t)i & 7U)) & 1U;

            swap ^= kbit;
            qsc_fe448_cswap(x2, x3, swap);
            qsc_fe448_cswap(z2, z3, swap);
            swap = kbit;

            qsc_fe448_add(a, x2, z2);
            qsc_fe448_sub(b, x2, z2);
            qsc_fe448_sq(aa, a);
            qsc_fe448_sq(bb, b);
            qsc_fe448_sub(e, aa, bb);
            qsc_fe448_add(c, x3, z3);
            qsc_fe448_sub(d, x3, z3);
            qsc_fe448_mul(da, d, a);
            qsc_fe448_mul(cb, c, b);
            qsc_fe448_add(t0, da, cb);
            qsc_fe448_sq(x3, t0);
            qsc_fe448_sub(t0, da, cb);
            qsc_fe448_sq(t0, t0);
            qsc_fe448_mul(z3, x1, t0);
            qsc_fe448_mul(x2, aa, bb);
            qsc_fe448_mul32(t0, e, A24_448);
            qsc_fe448_add(t0, aa, t0);
            qsc_fe448_mul(z2, e, t0);
        }

        qsc_fe448_cswap(x2, x3, swap);
        qsc_fe448_cswap(z2, z3, swap);

        qsc_fe448_invert(zinv, z2);
        qsc_fe448_mul(x2, x2, zinv);
        qsc_fe448_to_bytes(out, x2);
    }
}

void qsc_crypto_scalarmult_curve448_ref10_base(uint8_t* q, const uint8_t* n)
{
    QSC_ASSERT(q != NULL);
    QSC_ASSERT(n != NULL);

    if (q != NULL && n != NULL)
    {
        x448_scalarmult(q, n, X448_BASE_U);
    }
}

void qsc_crypto_scalarmult_curve448_ref10(uint8_t* r, const uint8_t* n, const uint8_t* q)
{
    QSC_ASSERT(r != NULL);
    QSC_ASSERT(n != NULL);
    QSC_ASSERT(q != NULL);

    if (r != NULL && n != NULL && q != NULL)
    {
        x448_scalarmult(r, n, q);
    }
}

void qsc_crypto_sc448_clamp(uint8_t * k)
{
    qsc_sc448_clamp(k);
}

void qsc_crypto_scalarmult_curve448(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
    QSC_ASSERT(q != NULL);
    QSC_ASSERT(n != NULL);
    QSC_ASSERT(p != NULL);

    uint8_t kclamped[QSC_X448_PRIVATEKEY_SIZE] = { 0U };

    if (q != NULL && n != NULL && p != NULL)
    {
        qsc_memutils_copy(kclamped, n, sizeof(kclamped));
        qsc_sc448_clamp(kclamped);
        x448_scalarmult(q, kclamped, p);
        qsc_memutils_secure_erase(kclamped, sizeof(kclamped));
    }
}

void qsc_x448_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(rng_generate != NULL);

    uint8_t ktmp[QSC_X448_PRIVATEKEY_SIZE] = { 0U };

    if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
    {
        if (rng_generate(privatekey, QSC_X448_PRIVATEKEY_SIZE) == true)
        {
            qsc_memutils_copy(ktmp, privatekey, QSC_X448_PRIVATEKEY_SIZE);
            qsc_sc448_clamp(ktmp);
            qsc_crypto_scalarmult_curve448_ref10_base(publickey, ktmp);
            qsc_memutils_secure_erase(ktmp, sizeof(ktmp));
        }
        else
        {
            qsc_memutils_clear(publickey, QSC_X448_PUBLICKEY_SIZE);
            qsc_memutils_clear(privatekey, QSC_X448_PRIVATEKEY_SIZE);
        }
    }
}

void qsc_x448_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(seed != NULL);

    uint8_t ktmp[QSC_X448_PRIVATEKEY_SIZE] = { 0U };

    if (publickey != NULL && privatekey != NULL && seed != NULL)
    {
        qsc_memutils_copy(privatekey, seed, QSC_X448_PRIVATEKEY_SIZE);
        qsc_memutils_copy(ktmp, seed, QSC_X448_PRIVATEKEY_SIZE);
        qsc_sc448_clamp(ktmp);
        qsc_crypto_scalarmult_curve448_ref10_base(publickey, ktmp);
        qsc_memutils_secure_erase(ktmp, sizeof(ktmp));
    }
}

bool qsc_x448_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(secret != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(publickey != NULL);

    uint8_t acc;

    acc = 0U;

    if (secret != NULL && privatekey != NULL && publickey != NULL)
    {
        qsc_crypto_scalarmult_curve448(secret, privatekey, publickey);

        for (size_t i = 0U; i < QSC_X448_SECRET_SIZE; ++i)
        {
            acc |= secret[i];
        }
    }

    return (acc != 0U);
}

/**
 * \brief Derive the RFC 7748 X448 public u-coordinate from a private scalar.
 * \param publickey: Caller-owned output buffer of QSC_X448_PUBLICKEY_SIZE bytes.
 * \param privatekey: Caller-owned private-scalar buffer of QSC_X448_PRIVATEKEY_SIZE bytes.
 * \details Input is not modified, and calls do not use shared mutable state.
 */
void qsc_x448_public_from_private(uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    if (publickey != NULL && privatekey != NULL)
    {
		uint8_t ktmp[QSC_X448_PRIVATEKEY_SIZE] = { 0U };

		qsc_memutils_copy(ktmp, privatekey, sizeof(ktmp));
		qsc_sc448_clamp(ktmp);
		qsc_crypto_scalarmult_curve448_ref10_base(publickey, ktmp);
		qsc_memutils_secure_erase(ktmp, sizeof(ktmp));
	}
}
