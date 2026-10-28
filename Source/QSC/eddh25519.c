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

#include "eddh25519.h"
#include "consoleutils.h"
#include "ed25519.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"

#define ED25519_A24 121666U

static void edwards_to_montgomery(qsc_fe25519 montgomeryX, const qsc_fe25519 edwardsY, const qsc_fe25519 edwardsZ)
{
    qsc_fe25519 tempX;
    qsc_fe25519 tempZ;

    qsc_fe25519_add(tempX, edwardsZ, edwardsY);
    qsc_fe25519_sub(tempZ, edwardsZ, edwardsY);
    qsc_fe25519_invert(tempZ, tempZ);
    qsc_fe25519_mul(montgomeryX, tempX, tempZ);
}

int32_t qsc_crypto_scalarmult_curve25519(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
    QSC_ASSERT(q != NULL);
	QSC_ASSERT(n != NULL);
	QSC_ASSERT(p != NULL);

    uint8_t d;
    int32_t err;
    uint32_t success;

    err = qsc_crypto_scalarmult_curve25519_ref10(q, n, p);
    d = 0U;

    for (size_t i = 0U; i < ED25519_CURVE_SIZE; ++i)
    {
        d |= q[i];
    }

    success = (uint32_t)(err == 0) && (d != 0);

    return -((int32_t)1 - (int32_t)success);
}

int32_t qsc_crypto_scalarmult_curve25519_ref10(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
    QSC_ASSERT(q != NULL);
    QSC_ASSERT(n != NULL);
    QSC_ASSERT(p != NULL);

    uint8_t* t;
    qsc_fe25519 a;
    qsc_fe25519 b;
    qsc_fe25519 aa;
    qsc_fe25519 bb;
    qsc_fe25519 cb;
    qsc_fe25519 da;
    qsc_fe25519 e;
    qsc_fe25519 x1;
    qsc_fe25519 x2;
    qsc_fe25519 x3;
    qsc_fe25519 z2;
    qsc_fe25519 z3;
    uint32_t pos;
    uint32_t swap;
    uint32_t bit;
    uint32_t valid;

    t = q;

    valid = (qsc_ed25519_small_order(p) == 0U);

    for (size_t i = 0U; i < 32U; ++i)
    {
        t[i] = n[i];
    }

    qsc_sc25519_clamp(t);
    qsc_fe25519_from_bytes(x1, p);
    qsc_fe25519_1(x2);
    qsc_fe25519_0(z2);
    qsc_fe25519_copy(x3, x1);
    qsc_fe25519_1(z3);

    swap = 0U;
    pos = 255U;

    do
    {
        --pos;
        bit = (uint32_t)t[pos / 8U] >> (pos & 7U);
        bit &= 1U;
        swap ^= bit;
        qsc_fe25519_cswap(x2, x3, swap);
        qsc_fe25519_cswap(z2, z3, swap);
        swap = bit;
        qsc_fe25519_add(a, x2, z2);
        qsc_fe25519_sub(b, x2, z2);
        qsc_fe25519_sq(aa, a);
        qsc_fe25519_sq(bb, b);
        qsc_fe25519_mul(x2, aa, bb);
        qsc_fe25519_sub(e, aa, bb);
        qsc_fe25519_sub(da, x3, z3);
        qsc_fe25519_mul(da, da, a);
        qsc_fe25519_add(cb, x3, z3);
        qsc_fe25519_mul(cb, cb, b);
        qsc_fe25519_add(x3, da, cb);
        qsc_fe25519_sq(x3, x3);
        qsc_fe25519_sub(z3, da, cb);
        qsc_fe25519_sq(z3, z3);
        qsc_fe25519_mul(z3, z3, x1);
        qsc_fe25519_mul32(z2, e, ED25519_A24);
        qsc_fe25519_add(z2, z2, bb);
        qsc_fe25519_mul(z2, z2, e);
    } while (pos > 0U);

    qsc_fe25519_cswap(x2, x3, swap);
    qsc_fe25519_cswap(z2, z3, swap);
    qsc_fe25519_invert(z2, z2);
    qsc_fe25519_mul(x2, x2, z2);
    qsc_fe25519_to_bytes(q, x2);

    return (valid == 0) ? -1 : 0;
}

int32_t qsc_crypto_scalarmult_curve25519_ref10_base(uint8_t* q, const uint8_t* n)
{
    QSC_ASSERT(q != NULL);
    QSC_ASSERT(n != NULL);

    uint8_t scalar[32] = { 0U };
    qsc_ge25519_p3 A;
    qsc_fe25519 pk;

    qsc_memutils_copy(scalar, n, 32);
    /* RFC 7748 Section 5 clamping */
    qsc_sc25519_clamp(scalar);
    qsc_ge25519_scalarmult_base(&A, scalar);
    edwards_to_montgomery(pk, A.y, A.z);
    qsc_fe25519_to_bytes(q, pk);
    qsc_memutils_secure_erase(scalar, 32);

    return 0;
}

void qsc_x25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(rng_generate != NULL);

    if (rng_generate(privatekey, ED25519_SEED_SIZE) == true)
    {
        /* RFC 7748 compliant method */
        qsc_crypto_scalarmult_curve25519_ref10_base(publickey, privatekey);
    }
    else
    {
        qsc_memutils_clear(publickey, ED25519_SEED_SIZE);
        qsc_memutils_clear(privatekey, ED25519_SEED_SIZE);
    }
}

void qsc_x25519_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(seed != NULL);

    /* RFC 7748 compliant method */
    qsc_memutils_copy(privatekey, seed, ED25519_SEED_SIZE);
    qsc_crypto_scalarmult_curve25519_ref10_base(publickey, privatekey);
}

bool qsc_x25519_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey)
{
	QSC_ASSERT(secret != NULL);
    QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);

    int32_t res;

    res = 0;

    if (secret != NULL && privatekey != NULL && publickey != NULL)
    {
        res = (qsc_crypto_scalarmult_curve25519(secret, privatekey, publickey));
    }

    return (res == 0);
}

/**
 * \brief Derive the RFC 7748 X25519 public u-coordinate from a private scalar.
 * \param publickey: Caller-owned output buffer of QSC_X25519_PUBLICKEY_SIZE bytes.
 * \param privatekey: Caller-owned private-scalar buffer of QSC_X25519_PRIVATEKEY_SIZE bytes.
 * \details Input is not modified, and calls do not use shared mutable state.
 */
void qsc_x25519_public_from_private(uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    if (publickey != NULL && privatekey != NULL)
    {
		(void)qsc_crypto_scalarmult_curve25519_ref10_base(publickey, privatekey);
	}
}
