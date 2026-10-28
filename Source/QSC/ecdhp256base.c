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

#include "ecdhp256base.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"
#if defined(__x86_64__) && defined(__SIZEOF_INT128__) && !defined(_MSC_VER) && !defined(QSC_ECDH_P256_PORTABLE) && !defined(QSC_ECDH_P256_EXCHANGE_LEGACY_REDUCE)
#include <immintrin.h>
#endif


/* 256-bit field element: 8 x uint32_t, little-endian (word 0 is least significant) */
typedef uint32_t fe256[8U];

/* jacobian projective point over P-256 (X:Y:Z), affine = (X/Z^2, Y/Z^3) */
typedef struct { fe256 X; fe256 Y; fe256 Z; } p256_jac_t;

/* affine point over P-256 */
typedef struct { fe256 X; fe256 Y; } p256_aff_t;

/* field prime:  p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
static const uint32_t P256_P[8U] = 
{
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU
};

/* group order: n */
static const uint32_t P256_N[8U] = 
{
    0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU
};

/* base point Gx */
static const uint32_t P256_GX[8U] = 
{
    0xD898C296U, 0xF4A13945U, 0x2DEB33A0U, 0x77037D81U,
    0x63A440F2U, 0xF8BCE6E5U, 0xE12C4247U, 0x6B17D1F2U
};

/* base point Gy */
static const uint32_t P256_GY[8U] = 
{
    0x37BF51F5U, 0xCBB64068U, 0x6B315ECEU, 0x2BCE3357U,
    0x7C0F9E16U, 0x8EE7EB4AU, 0xFE1A7F9BU, 0x4FE342E2U
};

/* curve coefficient b */
static const uint32_t P256_B[8U] = 
{
    0x27D2604BU, 0x3BCE3C3EU, 0xCC53B0F6U, 0x651D06B0U,
    0x769886BCU, 0xB3EBBD55U, 0xAA3A93E7U, 0x5AC635D8U
};

/* Native P-256 field backend is isolated from ECDSA and uses fixed-length
 * Montgomery operations. MSVC and compilers without a double-width unsigned
 * integer retain the established portable 32-bit ECDH backend. */
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER) && !defined(QSC_ECDH_P256_PORTABLE)
#define QSC_ECDH_P256_NATIVE 1

/*! \brief Montgomery field identity, 2^256 modulo the P-256 prime. */
static const uint32_t P256_ECDH_MONT_ONE[8U] =
{
    0x00000001U, 0x00000000U, 0x00000000U, 0xFFFFFFFFU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU, 0x00000000U
};

/*! \brief Square of the Montgomery radix modulo the P-256 prime. */
static const uint32_t P256_ECDH_R2[8U] =
{
    0x00000003U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFBU,
    0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFDU, 0x00000004U
};

/*! \brief Four-limb native representation of the P-256 prime. */
static const uint64_t P256_ECDH_P64[4U] =
{
    UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x00000000FFFFFFFF),
    UINT64_C(0x0000000000000000), UINT64_C(0xFFFFFFFF00000001)
};
#endif

/* Native arithmetic call-boundary specialization. Compiler intrinsics remain
 * selected by the established Montgomery reducer, without inline assembly.
 * The portable and MSVC backends retain their existing function boundaries. */
#if defined(QSC_ECDH_P256_NATIVE) && defined(__x86_64__) && defined(__GNUC__)
#define P256_ECDH_NATIVE_INLINE static inline __attribute__((always_inline))
#if !defined(__clang__)
#define P256_ECDH_GCC_COMBA_INLINE static inline __attribute__((always_inline))
#else
#define P256_ECDH_GCC_COMBA_INLINE static
#endif
#else
#define P256_ECDH_NATIVE_INLINE static
#define P256_ECDH_GCC_COMBA_INLINE static
#endif

/* Use the Botan-style exchange doubling engine on the native backend.
 * Generator and exchange retain separate scalar engines; both use the native field backend.
 * Set QSC_ECDH_P256_EXCHANGE_LEGACY_DBL5 for baseline comparisons. */
#if defined(QSC_ECDH_P256_NATIVE) && !defined(QSC_ECDH_P256_EXCHANGE_LEGACY_DBL5)
#define QSC_ECDH_P256_EXCHANGE_BOTAN_DBL5 1
#endif

static void fe256_select(uint32_t* r, const uint32_t* a, const uint32_t* b, uint32_t mask)
{
    /* mask must be either 0x00000000 or 0xFFFFFFFF */
    for (size_t i = 0U; i < 8U; ++i)
    {
        r[i] = (a[i] & mask) | (b[i] & ~mask);
    }
}

static void fe256_copy(fe256 r, const fe256 a)
{
    for (int32_t i = 0; i < 8; ++i) 
    { 
        r[i] = a[i]; 
    }
}

#if !defined(QSC_ECDH_P256_NATIVE)
static void fe256_zero(fe256 r)
{
    for (int32_t i = 0; i < 8; ++i) 
    { 
        r[i] = 0U; 
    }
}

#endif

static void fe256_one(fe256 r)
{
#if defined(QSC_ECDH_P256_NATIVE)
    fe256_copy(r, P256_ECDH_MONT_ONE);
#else
    r[0U] = 1U;

    for (int32_t i = 1; i < 8; ++i) 
    { 
        r[i] = 0U;
    }
#endif
}

static uint32_t fe256_is_zero(const fe256 a)
{
    /* returns 1 if a == 0, else 0, no data-dependent branches on a. */
    uint32_t t = 0U;

    for (int32_t i = 0; i < 8; ++i) 
    {
        t |= a[i]; 
    }

    /* collapse to 0 or 1 without a branch */
    t = (t | (0U - t)) >> 31U;

    return (1U - t);
}

/*! \brief Reject scalar values at or beyond the NIST P-256 group order.
 * \param scalar: Eight little-endian 32-bit words of a private scalar.
 * \return One if scalar is greater than or equal to the order, zero otherwise.
 * \note The compare executes eight fixed-width subtractions without any
 * early exit on secret scalar words.
 */
static uint32_t p256_private_scalar_ge_order(const uint32_t scalar[8U])
{
    uint64_t difference;
    uint64_t borrow;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 8U; ++i)
    {
        difference = (uint64_t)scalar[i] - (uint64_t)P256_N[i] - borrow;
        borrow = difference >> 63U;
    }

    return (uint32_t)(borrow ^ 1U);
}

static int32_t fe256_cmp(const uint32_t* a, const uint32_t* b)
{
    uint64_t ai;
    uint32_t aigtbi;
    uint32_t ailtbi;
    uint64_t bi;
    uint32_t gt;
    uint32_t lt;
    uint32_t undecided;

    gt = 0U;
    lt = 0U;

    for (int32_t i = 7; i >= 0; --i)
    {
        ai = (uint64_t)a[i];
        bi = (uint64_t)b[i];

        aigtbi = (uint32_t)((bi - ai) >> 63); /* 1 if ai > bi */
        ailtbi = (uint32_t)((ai - bi) >> 63); /* 1 if ai < bi */
        undecided = (uint32_t)(1U ^ (gt | lt));

        gt |= aigtbi & undecided;
        lt |= ailtbi & undecided;
    }

    return (gt != 0U) ? 1 : ((lt != 0U) ? -1 : 0);
}

static uint32_t ct_sel32(uint32_t sel, uint32_t a, uint32_t b)
{
    /* constant-time 32-bit word select: returns a if sel==1, b if sel==0 */
    uint32_t mask;

    /* 0xFFFFFFFF if sel=1, 0x00000000 if sel=0 */
    mask = (uint32_t)(0U - sel);

    return (a & mask) | (b & ~mask);
}

static void fe256_ct_select(fe256 r, uint32_t sel, const fe256 a, const fe256 b)
{
    /* constant-time fe256 select: r = (sel ? a : b) */
    for (int32_t i = 0; i < 8; ++i)
    {
        r[i] = ct_sel32(sel, a[i], b[i]);
    }
}

#if !defined(QSC_ECDH_P256_NATIVE)
static void p256_jac_ct_select(p256_jac_t* r, uint32_t sel, const p256_jac_t* a, const p256_jac_t* b)
{
    /* constant-time Jacobian point select */
    fe256_ct_select(r->X, sel, a->X, b->X);
    fe256_ct_select(r->Y, sel, a->Y, b->Y);
    fe256_ct_select(r->Z, sel, a->Z, b->Z);
}

#endif

static void fe256_from_bytes(fe256 r, const uint8_t* b)
{
    /* convert big-endian 32-byte buffer to little-endian fe256 */
    for (int32_t i = 0; i < 8; ++i)
    {
        const uint8_t* p = b + 4 * (7 - i);

        r[i] = ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U)
             | ((uint32_t)p[2] <<  8U) |  (uint32_t)p[3];
    }
}

static void fe256_to_bytes(uint8_t* b, const fe256 r)
{
    /* convert little-endian fe256 to big-endian 32-byte buffer */
    for (int32_t i = 0; i < 8; ++i)
    {
        uint8_t* p = b + 4 * (7 - i);

        p[0U] = (uint8_t)(r[i] >> 24U);
        p[1U] = (uint8_t)(r[i] >> 16U);
        p[2U] = (uint8_t)(r[i] >>  8U);
        p[3U] = (uint8_t)(r[i]);
    }
}

/* Field arithmetic mod p (Solinas reduction) */

static void fe256_cond_sub(fe256 r, const uint32_t mod[8U])
{
    /* conditional subtraction: if r >= mod, r -= mod */
    uint32_t tmp[8] = { 0U };
    uint64_t borrow;

    borrow = 0U;

    for (int32_t i = 0; i < 8; ++i)
    {
        borrow   = (uint64_t)r[i] - mod[i] - borrow;
        tmp[i]   = (uint32_t)borrow;
        borrow   = (borrow >> 32U) & 1U;
    }

    /* Accept tmp only if there was no borrow (r >= mod) */
    fe256_ct_select(r, (uint32_t)(1U - (uint32_t)borrow), tmp, r);
}

/*! \brief Produce a fresh randomized projective scale and an order-blinded scalar.
 * \details The 64-bit scalar multiplier is independent of the secret scalar.
 * On P-256 (cofactor one), (d + r*n)P = dP for every validated peer point.
 * The scalar is represented as ten little-endian 32-bit words, processed with
 * a fixed 320-bit schedule. A fresh field element masks the Jacobian point.
 * Entropy failure aborts the operation without revealing a derived result.
 * \param blinded: Output ten-word order-blinded scalar.
 * \param projective: Output nonzero canonical field element for point masking.
 * \param rerandomizers: Four independent nonzero field elements used at fixed public window positions.
 * \param scalar: Validated eight-word private scalar.
 * \return True on successful entropy generation, false otherwise.
 */
static bool p256_prepare_blinding(uint32_t blinded[10U], fe256 projective, fe256 rerandomizers[4U], const uint32_t scalar[8U])
{
    uint8_t randomness[168U] = { 0U };
    static const uint32_t ONE[8U] = { 1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
    uint32_t multiplier[2U];
    uint64_t value;
    uint64_t carry;
    size_t i;
    size_t j;
    bool success;

    success = qsc_csp_generate(randomness, sizeof(randomness));

    if (success == true)
    {
        fe256_from_bytes(projective, randomness);
        fe256_cond_sub(projective, P256_P);
        fe256_ct_select(projective, fe256_is_zero(projective), ONE, projective);

        /* A single entropy request supplies independent full-width projective
         * factors for Botan-style accumulator rerandomization. Each public
         * schedule position receives a separate nonzero field element. */
        for (i = 0U; i < 4U; ++i)
        {
            fe256_from_bytes(rerandomizers[i], randomness + 40U + (32U * i));
            fe256_cond_sub(rerandomizers[i], P256_P);
            fe256_ct_select(rerandomizers[i], fe256_is_zero(rerandomizers[i]), ONE, rerandomizers[i]);
        }

        multiplier[0U] = (uint32_t)randomness[32U] | ((uint32_t)randomness[33U] << 8U)
            | ((uint32_t)randomness[34U] << 16U) | ((uint32_t)randomness[35U] << 24U);
        multiplier[1U] = (uint32_t)randomness[36U] | ((uint32_t)randomness[37U] << 8U)
            | ((uint32_t)randomness[38U] << 16U) | ((uint32_t)randomness[39U] << 24U);

        for (i = 0U; i < 10U; ++i)
        {
            blinded[i] = i < 8U ? scalar[i] : 0U;
        }

        for (j = 0U; j < 2U; ++j)
        {
            carry = 0U;

            for (i = 0U; i < 8U; ++i)
            {
                value = (uint64_t)P256_N[i] * multiplier[j] + blinded[i + j] + carry;
                blinded[i + j] = (uint32_t)value;
                carry = value >> 32U;
            }

            blinded[8U + j] = (uint32_t)carry;
        }
    }
    else
    {
        qsc_memutils_clear(blinded, 10U * sizeof(uint32_t));
        qsc_memutils_clear(projective, sizeof(fe256));
        qsc_memutils_clear(rerandomizers, 4U * sizeof(fe256));
    }

    qsc_memutils_secure_erase(randomness, sizeof(randomness));
    qsc_memutils_secure_erase(multiplier, sizeof(multiplier));
    return success;
}

static void fe_add(fe256 r, const fe256 a, const fe256 b)
{
    uint32_t t[8] = { 0U };
    uint32_t u[8] = { 0U };
    uint64_t carry;
    uint32_t csel;

    static const uint32_t P256_C[8U] =
    {
        0x00000001U, 0x00000000U, 0x00000000U, 0xFFFFFFFFU,
        0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU, 0x00000000U
    };

    /* t = a + b mod 2^256, csel = carry */
    carry = 0U;

    for (int32_t i = 0; i < 8; ++i)
    {
        uint64_t x = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        t[i] = (uint32_t)x;
        carry = x >> 32U;
    }

    csel = (uint32_t)carry;

    /* u = t + (carry ? C : 0), where C = 2^256 - p */
    carry = 0U;

    for (int32_t i = 0; i < 8; ++i)
    {
        uint32_t addi = ct_sel32(csel, P256_C[i], 0U);
        uint64_t x = (uint64_t)t[i] + (uint64_t)addi + carry;
        u[i] = (uint32_t)x;
        carry = x >> 32U;
    }

    /* u is now in [0, 2p). Final conditional subtraction. */
    fe256_copy(r, u);
    fe256_cond_sub(r, P256_P);

    qsc_memutils_secure_erase(t, sizeof(t));
    qsc_memutils_secure_erase(u, sizeof(u));
}

static void fe_sub(uint32_t* r, const uint32_t* a, const uint32_t* b)
{
    uint32_t t[8U] = { 0U };
    uint64_t borrow;
    uint64_t carry;
    uint64_t ta;
    uint64_t x;
    uint32_t mask;

    borrow = 0ULL;

    for (size_t i = 0U; i < 8U; ++i)
    {
        ta = (uint64_t)a[i] - b[i] - borrow;
        r[i] = (uint32_t)ta;
        borrow = (ta >> 63) & 1ULL;
    }

    carry = 0ULL;

    for (size_t i = 0U; i < 8U; ++i)
    {
        x = (uint64_t)r[i] + P256_P[i] + carry;
        t[i] = (uint32_t)x;
        carry = x >> 32;
    }

    mask = (uint32_t)-(int32_t)borrow;

    fe256_select(r, t, r, mask);
}

#if !defined(QSC_ECDH_P256_NATIVE)
static void ct_select_8x32(uint32_t dst[8U], const uint32_t a[8U], const uint32_t b[8U], uint32_t mask)
{
    size_t i;

    for (i = 0U; i < 8U; ++i)
    {
        dst[i] = (a[i] & ~mask) | (b[i] & mask);
    }
}

#endif

#if !defined(QSC_ECDH_P256_NATIVE)
static uint32_t ct_select_u32(uint32_t a, uint32_t b, uint32_t mask)
{
    return (a & ~mask) | (b & mask);
}

static uint32_t ct_ge_9x32(const uint32_t a[9U], const uint32_t b[9U])
{
    uint64_t diff;
    uint32_t borrow;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 9U; ++i)
    {
        diff = (uint64_t)a[i] - (uint64_t)b[i] - (uint64_t)borrow;
        borrow = (uint32_t)((diff >> 63) & 1U);
    }

    return (uint32_t)(borrow ^ 1U);
}

static void ct_sub_9x32(uint32_t out[9U], const uint32_t a[9U], const uint32_t b[9U])
{
    uint64_t diff;
    uint32_t borrow;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 9U; ++i)
    {
        diff = (uint64_t)a[i] - (uint64_t)b[i] - (uint64_t)borrow;
        out[i] = (uint32_t)diff;
        borrow = (uint32_t)((diff >> 63) & 1U);
    }
}

static void mod_reduce512_generic(uint32_t out[8U], const uint32_t in[16U], const uint32_t mod[8U])
{
    uint32_t rem[9U];
    uint32_t sub[9U];
    uint32_t mod9[9U];
    uint32_t carry;
    uint32_t bit;
    uint32_t ge;
    uint32_t mask;
    int32_t i;
    size_t j;

    for (j = 0U; j < 8U; ++j)
    {
        mod9[j] = mod[j];
    }

    mod9[8] = 0U;

    for (j = 0U; j < 9U; ++j)
    {
        rem[j] = 0U;
    }

    for (i = 511; i >= 0; --i)
    {
        bit = (in[(size_t)i >> 5] >> ((uint32_t)i & 31U)) & 1U;

        carry = bit;

        for (j = 0U; j < 9U; ++j)
        {
            uint32_t nextcarry;

            nextcarry = rem[j] >> 31;
            rem[j] = (rem[j] << 1) | carry;
            carry = nextcarry;
        }

        ct_sub_9x32(sub, rem, mod9);
        ge = ct_ge_9x32(rem, mod9);
        mask = (uint32_t)(0U - ge);

        for (j = 0U; j < 9U; ++j)
        {
            rem[j] = ct_select_u32(rem[j], sub[j], mask);
        }
    }

    for (j = 0U; j < 8U; ++j)
    {
        out[j] = rem[j];
    }
}

#endif

#if !defined(QSC_ECDH_P256_NATIVE)
static void fe256_reduce512(fe256 r, const uint32_t c[16U])
{
    /* conservative correctness-first reduction of a 512-bit value modulo p.
     * replaces the signed Solinas folding logic with a generic modular reducer. */
    mod_reduce512_generic(r, c, P256_P);
}

#endif

#if !defined(QSC_ECDH_P256_NATIVE)
static void fe256_mul_raw(uint32_t c[16U], const fe256 a, const fe256 b)
{
    /* schoolbook 256x256 -> 512-bit multiplication */
    uint64_t tmp;

    for (int32_t i = 0; i < 16; ++i) { c[i] = 0U; }

    for (int32_t i = 0; i < 8; ++i)
    {
        uint64_t carry = 0U;

        for (int32_t j = 0; j < 8; ++j)
        {
            tmp = (uint64_t)a[i] * b[j] + c[i + j] + carry;
            c[i + j]  = (uint32_t)tmp;
            carry = tmp >> 32U;
        }

        c[i + 8U] = (uint32_t)carry;
    }
}

#endif

#if !defined(QSC_ECDH_P256_NATIVE)
static void fe_copy(uint32_t dst[8U], const uint32_t src[8U])
{
    size_t i;

    for (i = 0U; i < 8U; ++i)
    {
        dst[i] = src[i];
    }
}

#endif

/*! \brief Multiply two P-256 Montgomery field residues in constant-time.
 * \details The fixed-length reduction follows the P-256-specific native-word
 * approach from the existing QSC ECDSA P-256 signing engine, itself adapted
 * from Botan's Secp256r1MontgomeryRep (Botan Simplified BSD license).
 * The implementation is private to this ECDH module.
 * \param r: Eight-word output residue; may alias either operand.
 * \param a: First canonical Montgomery residue.
 * \param b: Second canonical Montgomery residue.
 * \note Execution path and memory access do not depend on field values.
 */
#if defined(QSC_ECDH_P256_NATIVE)
static void ecdh_p256_native_mont_mul(fe256 r, const fe256 a, const fe256 b)
{
    uint64_t left[4U] = { 0U };
    uint64_t right[4U] = { 0U };
    uint64_t product[8U] = { 0U };
    uint64_t reduced[4U] = { 0U };
    __uint128_t value;
    uint64_t carry;
    uint64_t borrow;
    uint64_t pending;
    uint64_t m;
    uint64_t q0;
    uint64_t q1;
    uint64_t q2;
    uint64_t q3;
    uint64_t selected;
    uint64_t mask;
    size_t i;
    size_t j;

    for (i = 0U; i < 4U; ++i)
    {
        left[i] = (uint64_t)a[2U * i] | ((uint64_t)a[2U * i + 1U] << 32U);
        right[i] = (uint64_t)b[2U * i] | ((uint64_t)b[2U * i + 1U] << 32U);
    }

    for (i = 0U; i < 4U; ++i)
    {
        carry = 0U;

        for (j = 0U; j < 4U; ++j)
        {
            value = ((__uint128_t)left[i] * right[j]) + product[i + j] + carry;
            product[i + j] = (uint64_t)value;
            carry = (uint64_t)(value >> 64U);
        }

        for (j = i + 4U; j < 8U; ++j)
        {
            value = (__uint128_t)product[j] + carry;
            product[j] = (uint64_t)value;
            carry = (uint64_t)(value >> 64U);
        }
    }

    pending = 0U;

    for (i = 0U; i < 4U; ++i)
    {
        m = product[i];
        q0 = m << 32U;
        q1 = m >> 32U;
        borrow = (uint64_t)(m < q0);
        q2 = m - q0;
        q3 = m - q1 - borrow;
        q3 += pending;
        carry = 0U;

        value = (__uint128_t)product[i + 1U] + q0 + carry;
        product[i + 1U] = (uint64_t)value;
        carry = (uint64_t)(value >> 64U);
        value = (__uint128_t)product[i + 2U] + q1 + carry;
        product[i + 2U] = (uint64_t)value;
        carry = (uint64_t)(value >> 64U);
        value = (__uint128_t)product[i + 3U] + q2 + carry;
        product[i + 3U] = (uint64_t)value;
        carry = (uint64_t)(value >> 64U);
        value = (__uint128_t)product[i + 4U] + q3 + carry;
        product[i + 4U] = (uint64_t)value;
        pending = (uint64_t)(value >> 64U);
    }

    borrow = 0U;

    for (i = 0U; i < 4U; ++i)
    {
        value = (__uint128_t)product[i + 4U] - P256_ECDH_P64[i] - borrow;
        reduced[i] = (uint64_t)value;
        borrow = (uint64_t)(value >> 127U);
    }

    mask = (uint64_t)(0U - (uint64_t)(borrow & (pending ^ 1U)));

    for (i = 0U; i < 4U; ++i)
    {
        selected = (product[i + 4U] & mask) | (reduced[i] & ~mask);
        r[2U * i] = (uint32_t)selected;
        r[2U * i + 1U] = (uint32_t)(selected >> 32U);
    }

    qsc_memutils_secure_erase(left, sizeof(left));
    qsc_memutils_secure_erase(right, sizeof(right));
    qsc_memutils_secure_erase(product, sizeof(product));
    qsc_memutils_secure_erase(reduced, sizeof(reduced));
}

/*! \brief Encode an external field element into Montgomery representation. */
static void ecdh_p256_encode(fe256 r, const fe256 a)
{
    ecdh_p256_native_mont_mul(r, a, P256_ECDH_R2);
}

/*! \brief Decode a Montgomery field residue for the public wire format. */
static void ecdh_p256_decode(fe256 r, const fe256 a)
{
    static const uint32_t one[8U] = { 1U };
    ecdh_p256_native_mont_mul(r, a, one);
}
#endif

static void fe_mul(fe256 r, const fe256 a, const fe256 b)
{
#if defined(QSC_ECDH_P256_NATIVE)
    ecdh_p256_native_mont_mul(r, a, b);
#else
    uint32_t c[16U] = { 0U };

    fe256_mul_raw(c, a, b);
    fe256_reduce512(r, c);
    qsc_memutils_secure_erase(c, sizeof(c));
#endif
}

static void fe_sqr(fe256 r, const fe256 a)
{
    /* r = a^2 mod p */
    fe_mul(r, a, a);
}

static void fe_mul_small(fe256 r, const fe256 a, uint32_t k)
{
#if defined(QSC_ECDH_P256_NATIVE)
    fe256 twice;
    fe256 four;

    fe_add(twice, a, a);
    fe_add(four, twice, twice);

    if (k == 3U)
    {
        fe_add(r, twice, a);
    }
    else if (k == 8U)
    {
        fe_add(r, four, four);
    }
    else if (k == 4U)
    {
        fe256_copy(r, four);
    }
    else
    {
        fe256_copy(r, twice);
    }

    qsc_memutils_secure_erase(twice, sizeof(twice));
    qsc_memutils_secure_erase(four, sizeof(four));
#else
    /*
     * r = a * k mod p
     *
     * This replacement avoids:
     * 1. the data-dependent while (carry) loop
     * 2. right shifts of signed intermediate values
     *
     * The product a * k is at most 288 bits, so it is represented as a
     * 512-bit intermediate with only the low 9 limbs populated, then
     * reduced with the existing generic 512-bit field reducer.
     */
    uint32_t c[16U] = { 0U };
    uint64_t carry;
    size_t i;

    carry = 0U;

    for (i = 0U; i < 8U; ++i)
    {
        const uint64_t w = ((uint64_t)a[i] * (uint64_t)k) + carry;
        c[i] = (uint32_t)w;
        carry = w >> 32U;
    }

    c[8U] = (uint32_t)carry;

    fe256_reduce512(r, c);

    qsc_memutils_secure_erase(c, sizeof(c));
#endif
}

static void fe_inv(uint32_t r[8U], const uint32_t a[8U])
{
    static const uint32_t p_minus_2[8U] =
    {
        0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
        0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU
    };

#if defined(QSC_ECDH_P256_NATIVE)
    fe256 powers[16U] = { { 0U } };
    fe256 accumulator = { 0U };
    uint32_t digit;
    size_t window;
    size_t j;

    fe256_one(powers[0U]);
    fe256_copy(powers[1U], a);

    for (window = 2U; window < 16U; ++window)
    {
        fe_mul(powers[window], powers[window - 1U], a);
    }

    fe256_one(accumulator);

    /* The exponent is public and constant (p - 2). All secret operands
     * follow the same number of multiplications and squarings. */
    for (window = 64U; window > 0U; --window)
    {
        for (j = 0U; j < 4U; ++j)
        {
            fe_sqr(accumulator, accumulator);
        }

        digit = (p_minus_2[(window - 1U) / 8U] >> (4U * ((window - 1U) % 8U))) & 15U;
        fe_mul(accumulator, accumulator, powers[digit]);
    }

    fe256_copy(r, accumulator);
    qsc_memutils_secure_erase(powers, sizeof(powers));
    qsc_memutils_secure_erase(accumulator, sizeof(accumulator));
#else
    uint32_t base[8U] = { 0U };
    uint32_t acc[8U] = { 0U };
    uint32_t tmp[8U] = { 0U };
    uint32_t mask;
    uint32_t bit;
    int32_t i;
    int32_t j;

    fe_copy(base, a);
    fe256_one(acc);

    for (i = 7; i >= 0; --i)
    {
        for (j = 31; j >= 0; --j)
        {
            fe_sqr(acc, acc);
            fe_mul(tmp, acc, base);

            bit = (p_minus_2[i] >> (uint32_t)j) & 1U;
            mask = (uint32_t)(0U - bit);
            ct_select_8x32(acc, acc, tmp, mask);
        }
    }

    fe_copy(r, acc);
    qsc_memutils_secure_erase(base, sizeof(base));
    qsc_memutils_secure_erase(acc, sizeof(acc));
    qsc_memutils_secure_erase(tmp, sizeof(tmp));
#endif
}

/* Scalar arithmetic mod n (Barrett reduction) */

static void sc_from_bytes_reduce(uint32_t r[8U], const uint8_t b[32U])
{
    /* reduce a 256-bit big-endian byte array mod n into a little-endian fe256 */
    fe256_from_bytes(r, b);
    fe256_cond_sub(r, P256_N);
}

/* Elliptic curve point arithmetic (Jacobian projective coordinates) */

static uint32_t p256_is_infinity(const p256_jac_t* P)
{
    /* return 1 if the Jacobian point is the point at infinity (Z == 0) */
    return fe256_is_zero(P->Z);
}

#if !defined(QSC_ECDH_P256_NATIVE)
static void p256_aff_to_jac(p256_jac_t* R, const p256_aff_t* P)
{
    /* lift an affine point to Jacobian (Z = 1) */
    fe256_copy(R->X, P->X);
    fe256_copy(R->Y, P->Y);
    fe256_one(R->Z);
}

#if !defined(QSC_ECDH_P256_NATIVE)
static void p256_set_infinity(p256_jac_t* R)
{
    /* set Jacobian point to the point at infinity */
    fe256_zero(R->X);
    fe256_one(R->Y);
    fe256_zero(R->Z);
}

#endif

static void p256_dbl(p256_jac_t* R, const p256_jac_t* P)
{
    /*
     * Branch-free Jacobian doubling.
     * For the Jacobian point-at-infinity representation used here, a result
     * with Z == 0 is treated as infinity by the rest of the code.
     */
    fe256 delta;
    fe256 gamma;
    fe256 beta;
    fe256 alpha;
    fe256 tmp;
    fe256 x3;
    fe256 y3;
    fe256 z3;

    /* delta = Z1^2 */
    fe_sqr(delta, P->Z);

    /* gamma = Y1^2 */
    fe_sqr(gamma, P->Y);

    /* beta = X1 * gamma */
    fe_mul(beta, P->X, gamma);

    /* alpha = 3 * (X1 - delta) * (X1 + delta) */
    fe_sub(alpha, P->X, delta);
    fe_add(tmp, P->X, delta);
    fe_mul(alpha, alpha, tmp);
    fe_mul_small(alpha, alpha, 3U);

    /* X3 = alpha^2 - 8*beta */
    fe_sqr(x3, alpha);
    fe_mul_small(tmp, beta, 8U);
    fe_sub(x3, x3, tmp);

    /* Z3 = (Y1 + Z1)^2 - gamma - delta */
    fe_add(z3, P->Y, P->Z);
    fe_sqr(z3, z3);
    fe_sub(z3, z3, gamma);
    fe_sub(z3, z3, delta);

    /* Y3 = alpha * (4*beta - X3) - 8*gamma^2 */
    fe_mul_small(tmp, beta, 4U);
    fe_sub(tmp, tmp, x3);
    fe_mul(y3, alpha, tmp);
    fe_sqr(tmp, gamma);
    fe_mul_small(tmp, tmp, 8U);
    fe_sub(y3, y3, tmp);

    fe256_copy(R->X, x3);
    fe256_copy(R->Y, y3);
    fe256_copy(R->Z, z3);
}

static void p256_add(p256_jac_t* R, const p256_jac_t* P, const p256_jac_t* Q)
{
    /*
     * Constant-time Jacobian addition for distinct points in the ECDH ladder.
     * The ladder invariant ensures that P and Q differ by the non-identity
     * peer point, so the equal-point doubling case cannot occur.
     * An opposite-point sum naturally produces Z = 0 (infinity); input
     * infinity points are selected using word masks, not branches.
     */

    fe256 z1z1;
    fe256 z2z2;
    fe256 u1;
    fe256 u2;
    fe256 s1;
    fe256 s2;
    fe256 h;
    fe256 r2;
    fe256 i;
    fe256 j;
    fe256 v;
    fe256 x3;
    fe256 y3;
    fe256 z3;
    fe256 tmp;
    p256_jac_t Radd;
    uint32_t pinf;
    uint32_t qinf;
    p256_jac_t T;

    /* generic add candidate */
    fe_sqr(z1z1, P->Z);
    fe_sqr(z2z2, Q->Z);

    fe_mul(u1, P->X, z2z2);
    fe_mul(u2, Q->X, z1z1);

    fe_mul(s1, P->Y, Q->Z);
    fe_mul(s1, s1, z2z2);

    fe_mul(s2, Q->Y, P->Z);
    fe_mul(s2, s2, z1z1);

    fe_sub(h, u2, u1);
    fe_sub(r2, s2, s1);
    fe_mul_small(r2, r2, 2U);

    fe_mul_small(i, h, 2U);
    fe_sqr(i, i);
    fe_mul(j, h, i);
    fe_mul(v, u1, i);

    fe_sqr(x3, r2);
    fe_sub(x3, x3, j);
    fe_sub(x3, x3, v);
    fe_sub(x3, x3, v);

    fe_sub(tmp, v, x3);
    fe_mul(y3, r2, tmp);

    fe_mul(tmp, s1, j);
    fe_mul_small(tmp, tmp, 2U);
    fe_sub(y3, y3, tmp);

    fe_add(z3, P->Z, Q->Z);
    fe_sqr(z3, z3);
    fe_sub(z3, z3, z1z1);
    fe_sub(z3, z3, z2z2);
    fe_mul(z3, z3, h);

    fe256_copy(Radd.X, x3);
    fe256_copy(Radd.Y, y3);
    fe256_copy(Radd.Z, z3);

    pinf = p256_is_infinity(P);
    qinf = p256_is_infinity(Q);

    /* The normal formula also represents opposite points as infinity.
     * Lift the two legitimate input-infinity cases without scalar branching. */
    T = Radd;
    p256_jac_ct_select(&T, qinf, P, &T);
    p256_jac_ct_select(&T, pinf, Q, &T);

    *R = T;

    qsc_memutils_secure_erase(&Radd, sizeof(Radd));
    qsc_memutils_secure_erase(&T, sizeof(T));
}

#endif /* QSC_ECDH_P256_NATIVE */

#if defined(QSC_ECDH_P256_NATIVE)
/* Reused four-limb native Montgomery arithmetic from the frozen QSC P-256
 * signing implementation, derived from Botan's P-256 native-field approach.
 * Botan Simplified BSD license; original QRCS license notice applies.
 * This independent ECDH point engine never calls or modifies ECDSA. */
/*! \brief One P-256 Montgomery residue, least significant word first. */
typedef uint64_t p256_native_fe[4U];

/*! \brief One P-256 Jacobian point over the native Montgomery representation. */
typedef struct
{
	/*! \brief Montgomery projective X coordinate. */
	p256_native_fe x;
	/*! \brief Montgomery projective Y coordinate. */
	p256_native_fe y;
	/*! \brief Montgomery projective Z coordinate, zero for infinity. */
	p256_native_fe z;
} p256_native_point;

/*! \brief P-256 field modulus as four little-endian words. */
static const uint64_t P256_NATIVE_PRIME[4U] =
{
	UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x00000000FFFFFFFF),
	UINT64_C(0x0000000000000000), UINT64_C(0xFFFFFFFF00000001)
};

/*! \brief The Montgomery representation of field identity. */
static const uint64_t P256_NATIVE_ONE[4U] =
{
	UINT64_C(0x0000000000000001), UINT64_C(0xFFFFFFFF00000000),
	UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x00000000FFFFFFFE)
};

/*! \brief Convert QSC's eight 32-bit words to a four-word native residue.
 * \param output: Destination of four 64-bit words; aliasing unsupported.
 * \param input: Source of eight 32-bit words; no ownership transfer.
 * \note Fixed word order, independent of CPU endianness, thread safe.
 */
static void p256_native_load(p256_native_fe output, const uint32_t input[8U])
{
	size_t i;

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (uint64_t)input[2U * i] | ((uint64_t)input[2U * i + 1U] << 32U);
	}
}

/*! \brief Convert four native words to QSC's eight-word representation.
 * \param output: Destination of eight 32-bit words; no aliasing with input.
 * \param input: Source of four 64-bit words; read-only and caller-owned.
 * \note Fixed instruction schedule and no shared state.
 */
static void p256_native_store(uint32_t output[8U], const p256_native_fe input)
{
	size_t i;

	for (i = 0U; i < 4U; ++i)
	{
		output[2U * i] = (uint32_t)input[i];
		output[2U * i + 1U] = (uint32_t)(input[i] >> 32U);
	}
}

/*! \brief Return whether a native Montgomery element equals zero.
 * \param input: Four little-endian words, caller-owned.
 * \return 1 if zero, 0 otherwise, without data-dependent branching.
 */
static uint64_t p256_native_is_zero(const p256_native_fe input)
{
	uint64_t bits;

	bits = input[0U] | input[1U] | input[2U] | input[3U];
	return (uint64_t)(1U ^ ((bits | (UINT64_C(0) - bits)) >> 63U));
}

/*! \brief Copy one Montgomery residue using four fixed native assignments.
 * \param output: Caller-owned four-word destination, may alias input.
 * \param input: Caller-owned four-word source.
 */
static void p256_native_copy(p256_native_fe output, const p256_native_fe input)
{
	output[0U] = input[0U];
	output[1U] = input[1U];
	output[2U] = input[2U];
	output[3U] = input[3U];
}

/*! \brief Add two canonical native P-256 field elements modulo p.
 * \param output: Four-word canonical result, aliasing permitted.
 * \param a: Four-word canonical Montgomery operand.
 * \param b: Four-word canonical Montgomery operand.
 * \note Fixed iteration counts and masked correction; heap free.
 */
static void p256_native_add(p256_native_fe output, const p256_native_fe a, const p256_native_fe b, uint64_t scratch[15U])
{
#if defined(__x86_64__) && defined(QSC_ECDH_P256_NATIVE) && !defined(QSC_ECDH_P256_NATIVE_LEGACY_ADDSUB)
	uint64_t* sum;
	uint64_t* reduced;
	uint64_t mask;
	unsigned long long word;
	unsigned char carry;
	unsigned char borrow;
	size_t i;

	sum = scratch;
	reduced = scratch + 4U;
	carry = 0U;
	for (i = 0U; i < 4U; ++i)
	{
		carry = _addcarry_u64(carry, (unsigned long long)a[i], (unsigned long long)b[i], &word);
		sum[i] = (uint64_t)word;
	}
	borrow = 0U;
	for (i = 0U; i < 4U; ++i)
	{
		borrow = _subborrow_u64(borrow, (unsigned long long)sum[i], (unsigned long long)P256_NATIVE_PRIME[i], &word);
		reduced[i] = (uint64_t)word;
	}
	mask = UINT64_C(0) - ((uint64_t)carry | ((uint64_t)borrow ^ UINT64_C(1)));
	for (i = 0U; i < 4U; ++i)
	{
		output[i] = reduced[i] ^ ((sum[i] ^ reduced[i]) & ~mask);
	}
#else
	uint64_t* sum;
	uint64_t* reduced;
	__uint128_t value;
	uint64_t carry;
	uint64_t borrow;
	uint64_t mask;
	size_t i;

	sum = scratch;
	reduced = scratch + 4U;
	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)a[i] + b[i] + carry;
		sum[i] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)sum[i] - P256_NATIVE_PRIME[i] - borrow;
		reduced[i] = (uint64_t)value;
		borrow = (uint64_t)(value >> 127U);
	}

	mask = UINT64_C(0) - (carry | (borrow ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (reduced[i] & mask) | (sum[i] & ~mask);
	}

#endif
}

/*! \brief Subtract two canonical native P-256 field elements modulo p.
 * \param output: Four-word canonical result, aliasing permitted.
 * \param a: Four-word first Montgomery operand.
 * \param b: Four-word second Montgomery operand.
 * \note Public modulus correction is masked, with no secret branch.
 */
static void p256_native_sub(p256_native_fe output, const p256_native_fe a, const p256_native_fe b, uint64_t scratch[15U])
{
#if defined(__x86_64__) && defined(QSC_ECDH_P256_NATIVE) && !defined(QSC_ECDH_P256_NATIVE_LEGACY_ADDSUB)
	uint64_t* difference;
	uint64_t mask;
	unsigned long long word;
	unsigned char borrow;
	unsigned char carry;
	size_t i;

	difference = scratch;
	borrow = 0U;
	for (i = 0U; i < 4U; ++i)
	{
		borrow = _subborrow_u64(borrow, (unsigned long long)a[i], (unsigned long long)b[i], &word);
		difference[i] = (uint64_t)word;
	}
	mask = UINT64_C(0) - (uint64_t)borrow;
	carry = 0U;
	for (i = 0U; i < 4U; ++i)
	{
		carry = _addcarry_u64(carry, (unsigned long long)difference[i], (unsigned long long)(P256_NATIVE_PRIME[i] & mask), &word);
		output[i] = (uint64_t)word;
	}
#else
	uint64_t* difference;
	__uint128_t value;
	uint64_t borrow;
	uint64_t carry;
	uint64_t mask;
	size_t i;

	difference = scratch;
	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)a[i] - b[i] - borrow;
		difference[i] = (uint64_t)value;
		borrow = (uint64_t)(value >> 127U);
	}

	mask = UINT64_C(0) - borrow;
	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)difference[i] + (P256_NATIVE_PRIME[i] & mask) + carry;
		output[i] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
	}
#endif
}

/*! \brief Accumulate one precomputed 128-bit product in a three-word Comba column.
 * \param accumulator: Three-word column carry state.
 * \param product: Fixed-width 128-bit operand.
 * \note The high carry is bounded for the four-limb Comba construction.
 */
P256_ECDH_GCC_COMBA_INLINE void p256_native_comba_acc_product(uint64_t accumulator[3U], __uint128_t product)
{
	__uint128_t value;

	value = (__uint128_t)accumulator[0U] + (uint64_t)product;
	accumulator[0U] = (uint64_t)value;
	value = (__uint128_t)accumulator[1U] + (uint64_t)(product >> 64U) + (uint64_t)(value >> 64U);
	accumulator[1U] = (uint64_t)value;
	accumulator[2U] += (uint64_t)(value >> 64U);
}

/*! \brief Accumulate one 64-by-64 product in the Comba column.
 * \param accumulator: Three-word bounded column accumulator.
 * \param a: First native multiplier word.
 * \param b: Second native multiplier word.
 */
P256_ECDH_GCC_COMBA_INLINE void p256_native_comba_acc(uint64_t accumulator[3U], uint64_t a, uint64_t b)
{
	p256_native_comba_acc_product(accumulator, (__uint128_t)a * b);
}

/*! \brief Accumulate the doubled cross-product with one carry chain.
 * \param accumulator: Three fixed-width Comba accumulator words.
 * \param product: One 128-bit off-diagonal square term.
 * \note All carries are derived using fixed-width unsigned arithmetic.
 */
P256_ECDH_GCC_COMBA_INLINE void p256_native_comba_acc_double(uint64_t accumulator[3U], __uint128_t product)
{
	uint64_t doubled_low;
	uint64_t doubled_high;
	uint64_t high_carry;
	__uint128_t sum;

	doubled_low = (uint64_t)product << 1U;
	doubled_high = ((uint64_t)(product >> 64U) << 1U) | ((uint64_t)product >> 63U);
	high_carry = (uint64_t)(product >> 127U);
	sum = (__uint128_t)accumulator[0U] + doubled_low;
	accumulator[0U] = (uint64_t)sum;
	sum = (__uint128_t)accumulator[1U] + doubled_high + (uint64_t)(sum >> 64U);
	accumulator[1U] = (uint64_t)sum;
	accumulator[2U] += high_carry + (uint64_t)(sum >> 64U);
}

/*! \brief Form a 512-bit Comba product of two four-word operands.
 * \param result: Operation-local scratch of 15 64-bit words; low eight hold the output.
 * \param a: First four-word operand.
 * \param b: Second four-word operand.
 * \note Fixed column traversal, no variable memory indices from secret operands.
 */
static void p256_native_comba_mul(uint64_t result[15U], const p256_native_fe a, const p256_native_fe b)
{
	uint64_t accumulator[3U];

	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[0U], b[0U]);
	result[0U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[0U], b[1U]);
	p256_native_comba_acc(accumulator, a[1U], b[0U]);
	result[1U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[0U], b[2U]);
	p256_native_comba_acc(accumulator, a[1U], b[1U]);
	p256_native_comba_acc(accumulator, a[2U], b[0U]);
	result[2U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[0U], b[3U]);
	p256_native_comba_acc(accumulator, a[1U], b[2U]);
	p256_native_comba_acc(accumulator, a[2U], b[1U]);
	p256_native_comba_acc(accumulator, a[3U], b[0U]);
	result[3U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[1U], b[3U]);
	p256_native_comba_acc(accumulator, a[2U], b[2U]);
	p256_native_comba_acc(accumulator, a[3U], b[1U]);
	result[4U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[2U], b[3U]);
	p256_native_comba_acc(accumulator, a[3U], b[2U]);
	result[5U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[3U], b[3U]);
	result[6U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	result[7U] = accumulator[0U];
	qsc_memutils_secure_erase(accumulator, sizeof(accumulator));

}

/*! \brief Form a 512-bit Comba square using ten 64-bit products.
 * \param result: Fifteen-word workspace; low eight words receive the square.
 * \param a: Canonical four-limb Montgomery input.
 * \note Fixed unrolled arithmetic with no data-dependent branches or indices.
 */
static void p256_native_comba_square(uint64_t result[15U], const p256_native_fe a)
{
	uint64_t accumulator[3U];
	__uint128_t product;

	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[0U];
	p256_native_comba_acc_product(accumulator, product);
	result[0U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[1U];
	p256_native_comba_acc_double(accumulator, product);
	result[1U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[2U];
	p256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[1U] * a[1U];
	p256_native_comba_acc_product(accumulator, product);
	result[2U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[3U];
	p256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[1U] * a[2U];
	p256_native_comba_acc_double(accumulator, product);
	result[3U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[1U] * a[3U];
	p256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[2U] * a[2U];
	p256_native_comba_acc_product(accumulator, product);
	result[4U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[2U] * a[3U];
	p256_native_comba_acc_double(accumulator, product);
	result[5U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[3U] * a[3U];
	p256_native_comba_acc_product(accumulator, product);
	result[6U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	result[7U] = accumulator[0U];
	qsc_memutils_secure_erase(accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&product, sizeof(product));

}

/*! \brief Reduce eight product words using Botan's specialized P-256 Montgomery formula.
 * \param output: Four-word Montgomery result, independent from input.
 * \param scratch: In/out workspace of 15 native words; first eight hold the product.
 * \note The specialization exploits p[0] = -1 modulo 2^64.
 * \note Strictly fixed four-step reduction and masked final subtraction.
 */
static void p256_native_reduce(p256_native_fe output, uint64_t scratch[15U])
{
	uint64_t* words;
	uint64_t* reduced;
	__uint128_t value;
	uint64_t pending;
	uint64_t carry;
	uint64_t borrow;
	uint64_t m;
	uint64_t q0;
	uint64_t q1;
	uint64_t q2;
	uint64_t q3;
	uint64_t selected;
	uint64_t mask;
	size_t i;

	words = scratch;
	reduced = scratch + 8U;
	pending = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		m = words[i];
		q0 = m << 32U;
		q1 = m >> 32U;
		borrow = (uint64_t)(m < q0);
		q2 = m - q0;
		q3 = m - q1 - borrow + pending;
		carry = 0U;

		value = (__uint128_t)words[i + 1U] + q0 + carry;
		words[i + 1U] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
		value = (__uint128_t)words[i + 2U] + q1 + carry;
		words[i + 2U] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
		value = (__uint128_t)words[i + 3U] + q2 + carry;
		words[i + 3U] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
		value = (__uint128_t)words[i + 4U] + q3 + carry;
		words[i + 4U] = (uint64_t)value;
		pending = (uint64_t)(value >> 64U);
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)words[i + 4U] - P256_NATIVE_PRIME[i] - borrow;
		reduced[i] = (uint64_t)value;
		borrow = (uint64_t)(value >> 127U);
	}

	mask = UINT64_C(0) - (borrow & (pending ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		selected = reduced[i] ^ ((words[i + 4U] ^ reduced[i]) & mask);
		output[i] = selected;
	}
}

/*! \brief Shared native P-256 reduction optimized for carry-chain instructions.
 * \param output: Four-word reduced field output; does not overlap scratch.
 * \param scratch: Operation-owned 15-word reduction workspace.
 * \note Field operand/output aliasing is supported by multiplication/squaring wrappers.
 */
static void p256_native_reduce_intrinsic(uint64_t* restrict output, uint64_t* restrict scratch);

/*! \brief Multiply two Montgomery-native P-256 field elements.
 * \param output: Canonical four-word Montgomery result; aliasing allowed.
 * \param a: Canonical Montgomery operand, four words.
 * \param b: Canonical Montgomery operand, four words.
 * \note Arithmetic workspace is erased by its owning scalar multiplication.
 * \param scratch: Reused 15-word operation-local product/reduction workspace.
 */
static void p256_native_mul(p256_native_fe output, const p256_native_fe a, const p256_native_fe b, uint64_t scratch[15U])
{
	p256_native_comba_mul(scratch, a, b);
	p256_native_reduce_intrinsic(output, scratch);
}

/*! \brief Square one native P-256 Montgomery element.
 * \param output: Four-word result; aliasing allowed.
 * \param a: Four-word canonical Montgomery input.
 * \note Dedicated Comba square with the same reduction as field multiplication.
 * \param scratch: Reused 15-word operation-local product/reduction workspace.
 */
static void p256_native_square(p256_native_fe output, const p256_native_fe a, uint64_t scratch[15U])
{
	p256_native_comba_square(scratch, a);
	p256_native_reduce_intrinsic(output, scratch);
}


/*! \brief Apply a fixed number of native field squarings.
 * \param value: Four-word in/out Montgomery field element.
 * \param rounds: Public iteration count, deterministic control flow.
 * \param scratch: Caller-owned 15-word scratch buffer.
 */
static void p256_native_square_n(p256_native_fe value, size_t rounds, uint64_t scratch[15U])
{
	size_t i;

	for (i = 0U; i < rounds; ++i)
	{
		p256_native_square(value, value, scratch);
	}
}

/*! \brief Compute Z^-2 using Botan's fixed P-256 p-3 addition chain.
 * \param output: Montgomery four-word inverse square; aliasing allowed.
 * \param z: Nonzero canonical four-word Montgomery field input.
 * \note Caller-owned stack operands; zero is rejected by point-level callers.
 * \param scratch: Caller-owned 15-word scratch buffer.
 */
static void p256_native_inverse_square(p256_native_fe output, const p256_native_fe z, uint64_t scratch[15U])
{
	p256_native_fe t[2U] = { { 0U } };
	p256_native_fe r = { 0U };

	p256_native_square(r, z, scratch);
	p256_native_mul(r, r, z, scratch);
	p256_native_square(r, r, scratch);
	p256_native_mul(r, r, z, scratch);
	p256_native_copy(t[0U], r);
	p256_native_square_n(t[0U], 3U, scratch);
	p256_native_mul(t[0U], t[0U], r, scratch);
	p256_native_copy(t[1U], t[0U]);
	p256_native_square_n(t[1U], 6U, scratch);
	p256_native_mul(t[0U], t[0U], t[1U], scratch);
	p256_native_square_n(t[0U], 3U, scratch);
	p256_native_mul(r, r, t[0U], scratch);
	p256_native_square(t[0U], r, scratch);
	p256_native_mul(t[0U], t[0U], z, scratch);
	p256_native_copy(t[1U], t[0U]);
	p256_native_square_n(t[1U], 16U, scratch);
	p256_native_mul(t[0U], t[0U], t[1U], scratch);
	p256_native_square_n(t[0U], 15U, scratch);
	p256_native_mul(r, r, t[0U], scratch);
	p256_native_square_n(t[0U], 17U, scratch);
	p256_native_mul(t[0U], t[0U], z, scratch);
	p256_native_square_n(t[0U], 143U, scratch);
	p256_native_mul(t[0U], t[0U], r, scratch);
	p256_native_square_n(t[0U], 47U, scratch);
	p256_native_mul(r, r, t[0U], scratch);
	p256_native_square_n(r, 2U, scratch);
	p256_native_copy(output, r);

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(r, sizeof(r));
}


/*! \brief Compute affine X for one non-infinity P-256 native Montgomery point.
 * \param output: Canonical affine X coordinate as eight QSC 32-bit words.
 * \param point: QSC eight-word projective point from fixed-base multiplication.
 * \note Fixed inversion addition chain; only X is recovered, not Y.
 */
static void p256_native_affine_x(fe256 output, const p256_jac_t* point)
{
	uint64_t scratch[15U] = { 0U };
	p256_native_fe x = { 0U };
	p256_native_fe z = { 0U };
	p256_native_fe inverse2 = { 0U };
	p256_native_fe product = { 0U };

	p256_native_load(x, point->X);
	p256_native_load(z, point->Z);
	p256_native_inverse_square(inverse2, z, scratch);
	p256_native_mul(product, x, inverse2, scratch);
	p256_native_mul(product, product, (const uint64_t[4U]){ 1U, 0U, 0U, 0U }, scratch);
	p256_native_store(output, product);
	qsc_memutils_secure_erase(x, sizeof(x));
	qsc_memutils_secure_erase(z, sizeof(z));
	qsc_memutils_secure_erase(inverse2, sizeof(inverse2));
	qsc_memutils_secure_erase(product, sizeof(product));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
}


/*! \brief Reusable native-width Jacobian mixed-add workspace.
 * \note Owned by one scalar multiplication and securely erased at its completion.
 */
typedef struct
{
	/*! \brief Projective Z square. */
	p256_native_fe zz;
	/*! \brief Second X scaled by first Z square. */
	p256_native_fe u;
	/*! \brief Second Y scaled by first Z cube. */
	p256_native_fe s;
	/*! \brief Jacobian X coordinate difference. */
	p256_native_fe h;
	/*! \brief Jacobian Y coordinate difference. */
	p256_native_fe delta;
	/*! \brief Square of X difference. */
	p256_native_fe hh;
	/*! \brief Cube of X difference. */
	p256_native_fe hhh;
	/*! \brief First X times squared X difference. */
	p256_native_fe v;
	/*! \brief Temporary intermediate field value. */
	p256_native_fe tmp;
	/*! \brief Candidate sum point before constant-time infinity selection. */
	p256_native_point added;
} p256_native_window_workspace;

/*! \brief Compute the finite mixed-add candidate with a fixed arithmetic schedule.
 * \param first: Current Jacobian accumulator.
 * \param second: Selected isomorphic public-table point.
 * \param work: Owned point workspace including the candidate output.
 * \param scratch: Reusable multiplication and reduction workspace.
 * \note Exceptional points are resolved by the caller with constant-time masks.
 */
static void p256_native_add_candidate(const p256_native_point* first,
    const p256_native_point* second, p256_native_window_workspace* work,
    uint64_t scratch[15U])
{
	p256_native_square(work->zz, first->z, scratch);
	p256_native_mul(work->u, second->x, work->zz, scratch);
	p256_native_mul(work->s, second->y, first->z, scratch);
	p256_native_mul(work->s, work->s, work->zz, scratch);
	p256_native_sub(work->h, work->u, first->x, scratch);
	p256_native_sub(work->delta, work->s, first->y, scratch);
	p256_native_square(work->hh, work->h, scratch);
	p256_native_mul(work->hhh, work->h, work->hh, scratch);
	p256_native_mul(work->v, first->x, work->hh, scratch);
	p256_native_square(work->added.x, work->delta, scratch);
	p256_native_sub(work->added.x, work->added.x, work->hhh, scratch);
	p256_native_add(work->tmp, work->v, work->v, scratch);
	p256_native_sub(work->added.x, work->added.x, work->tmp, scratch);
	p256_native_sub(work->tmp, work->v, work->added.x, scratch);
	p256_native_mul(work->added.y, work->delta, work->tmp, scratch);
	p256_native_mul(work->tmp, first->y, work->hhh, scratch);
	p256_native_sub(work->added.y, work->added.y, work->tmp, scratch);
	p256_native_mul(work->added.z, first->z, work->h, scratch);
}

/*! \brief Complete mixed point addition for public-point table generation.
 * \param output: Computed sum, which may alias either input point.
 * \param first: Jacobian input point.
 * \param second: Affine or infinity input point.
 * \param work: Caller-owned arithmetic workspace.
 * \param scratch: Caller-owned native field scratch.
 * \note Zero-Z inputs are handled with masked selection.
 */
static void p256_native_add_generator(p256_native_point* output, const p256_native_point* first,
    const p256_native_point* second, p256_native_window_workspace* work, uint64_t scratch[15U])
{
    uint64_t first_inf;
    uint64_t second_inf;

    p256_native_add_candidate(first, second, work, scratch);
    first_inf = p256_native_is_zero(first->z);
    second_inf = p256_native_is_zero(second->z);
    qsc_intutils_cmov((uint8_t*)&work->added, (const uint8_t*)first,
        sizeof(work->added), (uint8_t)second_inf);
    qsc_intutils_cmov((uint8_t*)&work->added, (const uint8_t*)second,
        sizeof(work->added), (uint8_t)first_inf);
    *output = work->added;
}

/*! \brief Reusable secret-point doubling workspace, cleared after the operation. */
typedef struct
{
    p256_native_fe delta;
    p256_native_fe gamma;
    p256_native_fe beta;
    p256_native_fe alpha;
    p256_native_fe tmp;
    p256_native_point next;
} p256_ecdh_double_workspace;

static void p256_ecdh_native_double(p256_native_point* result, const p256_native_point* first,
    p256_ecdh_double_workspace* work, uint64_t scratch[15U])
{
    p256_native_square(work->delta, first->z, scratch);
    p256_native_square(work->gamma, first->y, scratch);
    p256_native_mul(work->beta, first->x, work->gamma, scratch);
    p256_native_sub(work->alpha, first->x, work->delta, scratch);
    p256_native_add(work->tmp, first->x, work->delta, scratch);
    p256_native_mul(work->alpha, work->alpha, work->tmp, scratch);
    p256_native_add(work->tmp, work->alpha, work->alpha, scratch);
    p256_native_add(work->alpha, work->tmp, work->alpha, scratch);

    p256_native_square(work->next.x, work->alpha, scratch);
    p256_native_add(work->tmp, work->beta, work->beta, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_sub(work->next.x, work->next.x, work->tmp, scratch);

    p256_native_mul(work->next.z, first->y, first->z, scratch);
    p256_native_add(work->next.z, work->next.z, work->next.z, scratch);

    p256_native_add(work->tmp, work->beta, work->beta, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_sub(work->tmp, work->tmp, work->next.x, scratch);
    p256_native_mul(work->next.y, work->alpha, work->tmp, scratch);
    p256_native_square(work->tmp, work->gamma, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_sub(work->next.y, work->next.y, work->tmp, scratch);
    *result = work->next;
}

/*! \brief Double an isomorphic P-256 point with a = -3*scale^4.
 * \param scale_squared: Square of shared nonzero projective scale.
 * \note The scalar path is fixed schedule and never indexes by secret digits.
 */
static void p256_ecdh_native_double_iso(p256_native_point* result, const p256_native_point* first,
    p256_ecdh_double_workspace* work, const p256_native_fe scale_squared, uint64_t scratch[15U])
{
    p256_native_square(work->delta, first->z, scratch);
    p256_native_square(work->gamma, first->y, scratch);
    p256_native_mul(work->beta, first->x, work->gamma, scratch);
    p256_native_mul(work->tmp, work->delta, scale_squared, scratch);
    p256_native_sub(work->alpha, first->x, work->tmp, scratch);
    p256_native_add(work->tmp, first->x, work->tmp, scratch);
    p256_native_mul(work->alpha, work->alpha, work->tmp, scratch);
    p256_native_add(work->tmp, work->alpha, work->alpha, scratch);
    p256_native_add(work->alpha, work->tmp, work->alpha, scratch);

    p256_native_square(work->next.x, work->alpha, scratch);
    p256_native_add(work->tmp, work->beta, work->beta, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_sub(work->next.x, work->next.x, work->tmp, scratch);

    p256_native_mul(work->next.z, first->y, first->z, scratch);
    p256_native_add(work->next.z, work->next.z, work->next.z, scratch);

    p256_native_add(work->tmp, work->beta, work->beta, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_sub(work->tmp, work->tmp, work->next.x, scratch);
    p256_native_mul(work->next.y, work->alpha, work->tmp, scratch);
    p256_native_square(work->tmp, work->gamma, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_sub(work->next.y, work->next.y, work->tmp, scratch);
    *result = work->next;
}

#if !defined(QSC_ECDH_P256_EXCHANGE_BOTAN_DBL5)
/*! \brief Double a point using a cached scaled Z square.
 * \param result: Destination point, may alias first.
 * \param first: Current Jacobian point on the randomized isomorphic curve.
 * \param work: Owned workspace with work->delta=(scale*Z)^2 at entry.
 * \param scratch: Reused field-arithmetic workspace.
 * \param update_delta: Public schedule flag; recompute cached delta for next doubling.
 * \note A group of five doubles saves four field squarings.
 */
static void p256_ecdh_native_double_iso_cached(p256_native_point* result, const p256_native_point* first,
    p256_ecdh_double_workspace* work, uint64_t scratch[15U], bool update_delta)
{
    p256_native_square(work->gamma, first->y, scratch);
    p256_native_mul(work->beta, first->x, work->gamma, scratch);
    p256_native_sub(work->alpha, first->x, work->delta, scratch);
    p256_native_add(work->tmp, first->x, work->delta, scratch);
    p256_native_mul(work->alpha, work->alpha, work->tmp, scratch);
    p256_native_add(work->tmp, work->alpha, work->alpha, scratch);
    p256_native_add(work->alpha, work->tmp, work->alpha, scratch);

    p256_native_square(work->next.x, work->alpha, scratch);
    /* Preserve 4*beta across the X and Y formulas. The previous sequence
     * computed it twice, requiring two unnecessary field additions per
     * doubling. Both temporaries are already in the operation workspace. */
    p256_native_add(work->tmp, work->beta, work->beta, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_add(work->next.y, work->tmp, work->tmp, scratch);
    p256_native_sub(work->next.x, work->next.x, work->next.y, scratch);

    p256_native_mul(work->next.z, first->y, first->z, scratch);
    p256_native_add(work->next.z, work->next.z, work->next.z, scratch);

    p256_native_sub(work->tmp, work->tmp, work->next.x, scratch);
    p256_native_mul(work->next.y, work->alpha, work->tmp, scratch);
    p256_native_square(work->tmp, work->gamma, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_add(work->tmp, work->tmp, work->tmp, scratch);
    p256_native_sub(work->next.y, work->next.y, work->tmp, scratch);
    if (update_delta)
    {
        /* Z' = 2YZ, so (scale*Z')^2 = 4*Y^2*(scale*Z)^2. */
        p256_native_mul(work->delta, work->delta, work->gamma, scratch);
        p256_native_add(work->delta, work->delta, work->delta, scratch);
        p256_native_add(work->delta, work->delta, work->delta, scratch);
    }
    *result = work->next;
}


#endif /* !QSC_ECDH_P256_EXCHANGE_BOTAN_DBL5 */

#if defined(QSC_ECDH_P256_EXCHANGE_BOTAN_DBL5)
/*! \brief Owned scratch for the fixed five-doubling isomorphic recurrence. */
typedef struct
{
    p256_native_point current;
    p256_native_fe twice_y;
    p256_native_fe y2;
    p256_native_fe y4;
    p256_native_fe w;
    p256_native_fe z2;
    p256_native_fe t1;
    p256_native_fe t2;
    p256_native_fe tmp;
    p256_native_fe half_tmp;
    __uint128_t carry_sum;
    uint64_t carry;
    uint64_t odd_mask;
} p256_botan5_workspace;

/*! \brief Multiply two native P-256 residues in exchange-owned Comba scratch.
 * \param result: Fifteen-word caller-owned scratch and product, with carry state in words 12 through 14.
 * \param a: First four-word Montgomery field operand.
 * \param b: Second four-word Montgomery field operand.
 * \note Carry state is erased at the group boundary and again at exchange exit.
 */
P256_ECDH_GCC_COMBA_INLINE void p256_ecdh_group_comba_mul(uint64_t result[15U], const p256_native_fe a, const p256_native_fe b)
{
	uint64_t* accumulator;

	accumulator = result + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[0U], b[0U]);
	result[0U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[0U], b[1U]);
	p256_native_comba_acc(accumulator, a[1U], b[0U]);
	result[1U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[0U], b[2U]);
	p256_native_comba_acc(accumulator, a[1U], b[1U]);
	p256_native_comba_acc(accumulator, a[2U], b[0U]);
	result[2U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[0U], b[3U]);
	p256_native_comba_acc(accumulator, a[1U], b[2U]);
	p256_native_comba_acc(accumulator, a[2U], b[1U]);
	p256_native_comba_acc(accumulator, a[3U], b[0U]);
	result[3U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[1U], b[3U]);
	p256_native_comba_acc(accumulator, a[2U], b[2U]);
	p256_native_comba_acc(accumulator, a[3U], b[1U]);
	result[4U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[2U], b[3U]);
	p256_native_comba_acc(accumulator, a[3U], b[2U]);
	result[5U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	p256_native_comba_acc(accumulator, a[3U], b[3U]);
	result[6U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	result[7U] = accumulator[0U];
}

/*! \brief Square a native P-256 residue in exchange-owned Comba scratch.
 * \param result: Fifteen-word caller-owned scratch and product, with carry state in words 12 through 14.
 * \param a: Four-word Montgomery field operand.
 * \note The 128-bit cross-product temporary retains explicit erasure at function exit.
 */
P256_ECDH_GCC_COMBA_INLINE void p256_ecdh_group_comba_square(uint64_t result[15U], const p256_native_fe a)
{
	uint64_t* accumulator;
	__uint128_t product;

	accumulator = result + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[0U];
	p256_native_comba_acc_product(accumulator, product);
	result[0U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[1U];
	p256_native_comba_acc_double(accumulator, product);
	result[1U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[2U];
	p256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[1U] * a[1U];
	p256_native_comba_acc_product(accumulator, product);
	result[2U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[3U];
	p256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[1U] * a[2U];
	p256_native_comba_acc_double(accumulator, product);
	result[3U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[1U] * a[3U];
	p256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[2U] * a[2U];
	p256_native_comba_acc_product(accumulator, product);
	result[4U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[2U] * a[3U];
	p256_native_comba_acc_double(accumulator, product);
	result[5U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[3U] * a[3U];
	p256_native_comba_acc_product(accumulator, product);
	result[6U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	result[7U] = accumulator[0U];
	qsc_memutils_secure_erase(&product, sizeof(product));
}

/*! \brief Shared intrinsic Montgomery reduction for P-256 native multiplication/squaring.
 * \param output: Four canonical Montgomery output limbs; may alias the field inputs.
 * \param scratch: Operation-owned, non-overlapping 15-word Comba and reduction buffer.
 * \details Matches the four fixed P-256 reduction rounds and final masked subtraction.
 * \note Output and scratch must not overlap. Operand/output aliasing remains supported.
 * \note The owning scalar multiplication clears scratch; no assembly is used.
 * \note Either QSC_ECDH_P256_NATIVE_LEGACY_REDUCE or the historical
 *       QSC_ECDH_P256_EXCHANGE_LEGACY_REDUCE selects the original native reducer.
 */
P256_ECDH_NATIVE_INLINE void p256_native_reduce_intrinsic(uint64_t* restrict output, uint64_t* restrict scratch)
{
#if defined(__x86_64__) && defined(QSC_ECDH_P256_NATIVE) && !defined(QSC_ECDH_P256_EXCHANGE_LEGACY_REDUCE) && !defined(QSC_ECDH_P256_NATIVE_LEGACY_REDUCE)
    uint64_t* words;
    uint64_t* reduced;
    uint64_t m;
    uint64_t q0;
    uint64_t q1;
    uint64_t q2;
    uint64_t q3;
    uint64_t pending;
    uint64_t borrow_word;
    uint64_t mask;
    unsigned long long result_word;
    unsigned char carry;
    unsigned char borrow;
    size_t i;

    words = scratch;
    reduced = scratch + 8U;
    pending = 0U;

    for (i = 0U; i < 4U; ++i)
    {
        m = words[i];
        q0 = m << 32U;
        q1 = m >> 32U;
        borrow_word = (uint64_t)(m < q0);
        q2 = m - q0;
        q3 = m - q1 - borrow_word + pending;

        carry = _addcarry_u64(0U, (unsigned long long)words[i + 1U], (unsigned long long)q0, &result_word);
        words[i + 1U] = (uint64_t)result_word;
        carry = _addcarry_u64(carry, (unsigned long long)words[i + 2U], (unsigned long long)q1, &result_word);
        words[i + 2U] = (uint64_t)result_word;
        carry = _addcarry_u64(carry, (unsigned long long)words[i + 3U], (unsigned long long)q2, &result_word);
        words[i + 3U] = (uint64_t)result_word;
        carry = _addcarry_u64(carry, (unsigned long long)words[i + 4U], (unsigned long long)q3, &result_word);
        words[i + 4U] = (uint64_t)result_word;
        pending = (uint64_t)carry;
    }

    borrow = 0U;
    for (i = 0U; i < 4U; ++i)
    {
        borrow = _subborrow_u64(borrow, (unsigned long long)words[i + 4U], (unsigned long long)P256_NATIVE_PRIME[i], &result_word);
        reduced[i] = (uint64_t)result_word;
    }

    mask = UINT64_C(0) - ((uint64_t)borrow & (pending ^ 1U));
    for (i = 0U; i < 4U; ++i)
    {
        output[i] = reduced[i] ^ ((words[i + 4U] ^ reduced[i]) & mask);
    }
#else
    p256_native_reduce(output, scratch);
#endif
}

/*! \brief Exchange doubling-group Montgomery product using shared-end-life scratch.
 * \param output: Result; aliasing with either operand supported.
 * \param a: Canonical Montgomery multiplicand.
 * \param b: Canonical Montgomery multiplicand.
 * \param scratch: Operation-owned 15-word buffer; carry state erased per group, entire buffer at exchange exit.
 */
P256_ECDH_NATIVE_INLINE void p256_ecdh_group_mul(p256_native_fe output, const p256_native_fe a, const p256_native_fe b, uint64_t scratch[15U])
{
    p256_ecdh_group_comba_mul(scratch, a, b);
    p256_native_reduce_intrinsic(output, scratch);
}

/*! \brief Exchange doubling-group Montgomery square using shared-end-life scratch.
 * \param output: Result; aliasing with operand supported.
 * \param a: Canonical Montgomery operand.
 * \param scratch: Operation-owned 15-word buffer; carry state erased per group, entire buffer at exchange exit.
 */
P256_ECDH_NATIVE_INLINE void p256_ecdh_group_square(p256_native_fe output, const p256_native_fe a, uint64_t scratch[15U])
{
    p256_ecdh_group_comba_square(scratch, a);
    p256_native_reduce_intrinsic(output, scratch);
}

/*! \brief Compute five isomorphic point doublings using Botan's Y-doubled recurrence.
 * \param output: Result point; may alias input.
 * \param input: Valid Jacobian point on the randomized isomorphic curve.
 * \param shared_z_squared: Square of the table's randomized common scale.
 * \param scratch: Owned native Montgomery field workspace.
 * \param bw: Caller-owned temporary state, erased at scalar-operation exit.
 * \details The curve coefficient is -3*shared_z^4. The intermediate
 *  w = a*Z^4 is advanced after each doubling as w *= (2*Y)^4.
 *  All five iterations and the final modular halving are fixed schedule.
 */
static void p256_ecdh_native_double_iso_botan5(p256_native_point* output,
    const p256_native_point* input, const p256_native_fe shared_z_squared,
    uint64_t scratch[15U], p256_botan5_workspace* bw)
{
    p256_native_fe zero = { 0U };
    size_t i;

    bw->current = *input;
    p256_ecdh_group_square(bw->z2, bw->current.z, scratch);
    p256_ecdh_group_mul(bw->z2, bw->z2, shared_z_squared, scratch);
    p256_ecdh_group_square(bw->w, bw->z2, scratch);
    p256_native_add(bw->tmp, bw->w, bw->w, scratch);
    p256_native_add(bw->tmp, bw->tmp, bw->w, scratch);
    p256_native_sub(bw->w, zero, bw->tmp, scratch);
    p256_native_add(bw->twice_y, bw->current.y, bw->current.y, scratch);

    for (i = 0U; i < 5U; ++i)
    {
        p256_ecdh_group_square(bw->y2, bw->twice_y, scratch);
        p256_ecdh_group_square(bw->y4, bw->y2, scratch);
        p256_ecdh_group_square(bw->t1, bw->current.x, scratch);
        p256_native_add(bw->tmp, bw->t1, bw->t1, scratch);
        p256_native_add(bw->t1, bw->tmp, bw->t1, scratch);
        p256_native_add(bw->t1, bw->t1, bw->w, scratch);
        p256_ecdh_group_mul(bw->t2, bw->current.x, bw->y2, scratch);
        p256_ecdh_group_square(bw->current.x, bw->t1, scratch);
        p256_native_add(bw->tmp, bw->t2, bw->t2, scratch);
        p256_native_sub(bw->current.x, bw->current.x, bw->tmp, scratch);
        p256_ecdh_group_mul(bw->current.z, bw->current.z, bw->twice_y, scratch);
        p256_native_sub(bw->tmp, bw->t2, bw->current.x, scratch);
        p256_native_add(bw->tmp, bw->tmp, bw->tmp, scratch);
        p256_ecdh_group_mul(bw->twice_y, bw->t1, bw->tmp, scratch);
        p256_native_sub(bw->twice_y, bw->twice_y, bw->y4, scratch);
        if (i < 4U)
        {
            p256_ecdh_group_mul(bw->w, bw->w, bw->y4, scratch);
        }
    }

    /* Montgomery residues can be halved directly modulo P using
     * (v + (v&1)*P) / 2. Preserve the 257th carry bit. */
    bw->odd_mask = UINT64_C(0) - (bw->twice_y[0U] & UINT64_C(1));
    bw->carry = 0U;
    for (i = 0U; i < 4U; ++i)
    {
        bw->carry_sum = (__uint128_t)bw->twice_y[i] + (P256_ECDH_P64[i] & bw->odd_mask) + bw->carry;
        bw->half_tmp[i] = (uint64_t)bw->carry_sum;
        bw->carry = (uint64_t)(bw->carry_sum >> 64U);
    }
    for (i = 0U; i < 3U; ++i)
    {
        bw->current.y[i] = (bw->half_tmp[i] >> 1U) | (bw->half_tmp[i + 1U] << 63U);
    }
    bw->current.y[3U] = (bw->half_tmp[3U] >> 1U) | (bw->carry << 63U);
    *output = bw->current;
    /* End the accumulator carry-state lifetime after each public five-doubling group.
     * The owning exchange also securely erases the entire scratch buffer at exit. */
    qsc_memutils_secure_erase(scratch + 12U, 3U * sizeof(uint64_t));
}
#endif /* QSC_ECDH_P256_EXCHANGE_BOTAN_DBL5 */

/*! \brief Select one of four point-coordinate candidates without a secret branch.
 * \param output: Four-limb output coordinate.
 * \param sum: Finite mixed-add candidate.
 * \param first: Prior accumulator coordinate.
 * \param second: Selected public-table coordinate.
 * \param doubled: Precomputed double of the selected public point.
 * \param first_mask: Mask selecting the prior accumulator.
 * \param second_mask: Mask selecting the public point.
 * \param double_mask: Mask selecting the point double.
 * \param sum_mask: Mask selecting the mixed-add candidate.
 * \note Masks are exclusively zero or UINT64_MAX; all inputs are secret-derived.
 */
static void p256_native_masked_coordinate(p256_native_fe output,
    const p256_native_fe sum, const p256_native_fe first,
    const p256_native_fe second, const p256_native_fe doubled,
    uint64_t first_mask, uint64_t second_mask, uint64_t double_mask, uint64_t sum_mask)
{
    size_t i;

    for (i = 0U; i < 4U; ++i)
    {
        output[i] = (sum[i] & sum_mask) | (first[i] & first_mask)
            | (second[i] & second_mask) | (doubled[i] & double_mask);
    }
}

/*! \brief Complete blinded mixed addition through one masked point selection.
 * \param output: Resulting isomorphic Jacobian point.
 * \param first: Current secret-derived accumulator.
 * \param second: Selected randomized shared-Z public-table point.
 * \param doubled: Preselected double of the public-table point.
 * \param work: Caller-owned candidate-addition workspace.
 * \param scratch: Caller-owned native field scratch.
 * \details Retains equal, inverse, infinity and absent-digit handling.
 * \note Output must not alias either input point.
 */
static void p256_native_add_generator_safe(p256_native_point* output,
    const p256_native_point* first, const p256_native_point* second,
    const p256_native_point* doubled, p256_native_window_workspace* work,
    uint64_t scratch[15U])
{
    uint64_t first_inf;
    uint64_t second_inf;
    uint64_t equal_points;
    uint64_t use_first;
    uint64_t use_second;
    uint64_t use_double;
    uint64_t use_sum;

    p256_native_add_candidate(first, second, work, scratch);
    first_inf = p256_native_is_zero(first->z);
    second_inf = p256_native_is_zero(second->z);
    equal_points = p256_native_is_zero(work->h) & p256_native_is_zero(work->delta);
    equal_points &= (first_inf ^ 1U) & (second_inf ^ 1U);

    use_first = UINT64_C(0) - ((first_inf ^ 1U) & second_inf);
    use_second = UINT64_C(0) - first_inf;
    use_double = UINT64_C(0) - equal_points;
    use_sum = ~(use_first | use_second | use_double);

    p256_native_masked_coordinate(output->x, work->added.x, first->x,
        second->x, doubled->x, use_first, use_second, use_double, use_sum);
    p256_native_masked_coordinate(output->y, work->added.y, first->y,
        second->y, doubled->y, use_first, use_second, use_double, use_sum);
    p256_native_masked_coordinate(output->z, work->added.z, first->z,
        second->z, doubled->z, use_first, use_second, use_double, use_sum);
}

/*! \brief Exchange-only alias-free masked coordinate selection.
 * \param output: Four-limb output coordinate.
 * \param sum: Finite mixed-add candidate.
 * \param first: Prior accumulator coordinate.
 * \param second: Selected public-table coordinate.
 * \param doubled: Precomputed double of the selected public point.
 * \param first_mask: Mask selecting the prior accumulator.
 * \param second_mask: Mask selecting the public point.
 * \param double_mask: Mask selecting the point double.
 * \param sum_mask: Mask selecting the mixed-add candidate.
 * \note Masks are exclusively zero or UINT64_MAX; all inputs are secret-derived.
 */
static void p256_native_masked_coordinate_exchange(uint64_t* restrict output,
    const uint64_t* restrict sum, const uint64_t* restrict first,
    const uint64_t* restrict second, const uint64_t* restrict doubled,
    uint64_t first_mask, uint64_t second_mask, uint64_t double_mask, uint64_t sum_mask)
{
    size_t i;

    for (i = 0U; i < 4U; ++i)
    {
        output[i] = (sum[i] & sum_mask) | (first[i] & first_mask)
            | (second[i] & second_mask) | (doubled[i] & double_mask);
    }
}

/*! \brief Exchange-only complete blinded addition with alias-free coordinate selection.
 * \param output: Resulting isomorphic Jacobian point.
 * \param first: Current secret-derived accumulator.
 * \param second: Selected randomized shared-Z public-table point.
 * \param doubled: Preselected double of the public-table point.
 * \param work: Caller-owned candidate-addition workspace.
 * \param scratch: Caller-owned native field scratch.
 * \details Retains equal, inverse, infinity and absent-digit handling.
 * \note Output must not alias either input point.
 */
static QSC_NO_INLINE void p256_native_add_exchange_safe(p256_native_point* output,
    const p256_native_point* first, const p256_native_point* second,
    const p256_native_point* doubled, p256_native_window_workspace* work,
    uint64_t scratch[15U])
{
    uint64_t first_inf;
    uint64_t second_inf;
    uint64_t equal_points;
    uint64_t use_first;
    uint64_t use_second;
    uint64_t use_double;
    uint64_t use_sum;

    p256_native_add_candidate(first, second, work, scratch);
    first_inf = p256_native_is_zero(first->z);
    second_inf = p256_native_is_zero(second->z);
    equal_points = p256_native_is_zero(work->h) & p256_native_is_zero(work->delta);
    equal_points &= (first_inf ^ 1U) & (second_inf ^ 1U);

    use_first = UINT64_C(0) - ((first_inf ^ 1U) & second_inf);
    use_second = UINT64_C(0) - first_inf;
    use_double = UINT64_C(0) - equal_points;
    use_sum = ~(use_first | use_second | use_double);

    p256_native_masked_coordinate_exchange(output->x, work->added.x, first->x,
        second->x, doubled->x, use_first, use_second, use_double, use_sum);
    p256_native_masked_coordinate_exchange(output->y, work->added.y, first->y,
        second->y, doubled->y, use_first, use_second, use_double, use_sum);
    p256_native_masked_coordinate_exchange(output->z, work->added.z, first->z,
        second->z, doubled->z, use_first, use_second, use_double, use_sum);
}

/*! \brief Precompute sixteen public multiples on an isomorphic shared-Z curve.
 * \details Each table entry is scaled to the common Jacobian Z coordinate;
 * the table then acts as affine input to isomorphic mixed additions without
 * requiring modular inversion during setup. The isomorphism scale is
 * deterministic and does not substitute for random projective blinding.
 * \param table: Output sixteen Montgomery-isomorphic affine coordinates.
 * \param shared_z: Output common projective Z for the mapping back.
 * \param shared_z_squared: Output square of the common projective Z.
 * \param point: Validated public peer affine point.
 * \param scratch: Owned fifteen-word field arithmetic workspace.
 * \note The precomputation operates exclusively on public peer points.
 */
static void p256_native_precompute_window5(p256_native_point table[16U],
    p256_native_fe shared_z, p256_native_fe shared_z_squared,
    const p256_aff_t* point, uint64_t scratch[15U])
{
    p256_native_point multiples[16U];
    p256_native_point base;
    p256_native_fe prefix[16U];
    p256_native_fe suffix;
    p256_native_fe factor;
    p256_native_fe factor_squared;
    p256_native_fe factor_cubed;
    p256_native_window_workspace adding;
    p256_ecdh_double_workspace doubling;
    size_t i;

    p256_native_load(base.x, point->X);
    p256_native_load(base.y, point->Y);
    p256_native_copy(base.z, P256_NATIVE_ONE);
    multiples[0U] = base;
    p256_ecdh_native_double(&multiples[1U], &base, &doubling, scratch);

    for (i = 2U; i < 16U; ++i)
    {
        p256_native_add_generator(&multiples[i], &multiples[i - 1U],
            &base, &adding, scratch);
    }

    p256_native_copy(prefix[0U], multiples[0U].z);
    for (i = 1U; i < 16U; ++i)
    {
        p256_native_mul(prefix[i], prefix[i - 1U], multiples[i].z, scratch);
    }

    p256_native_copy(shared_z, prefix[15U]);
    p256_native_square(shared_z_squared, shared_z, scratch);
    p256_native_copy(suffix, P256_NATIVE_ONE);

    for (i = 16U; i > 0U; --i)
    {
        if (i > 1U)
        {
            p256_native_mul(factor, prefix[i - 2U], suffix, scratch);
        }
        else
        {
            p256_native_copy(factor, suffix);
        }

        p256_native_square(factor_squared, factor, scratch);
        p256_native_mul(factor_cubed, factor_squared, factor, scratch);
        p256_native_mul(table[i - 1U].x, multiples[i - 1U].x, factor_squared, scratch);
        p256_native_mul(table[i - 1U].y, multiples[i - 1U].y, factor_cubed, scratch);
        p256_native_copy(table[i - 1U].z, P256_NATIVE_ONE);
        p256_native_mul(suffix, suffix, multiples[i - 1U].z, scratch);
    }

    qsc_memutils_secure_erase(multiples, sizeof(multiples));
    qsc_memutils_secure_erase(&base, sizeof(base));
    qsc_memutils_secure_erase(prefix, sizeof(prefix));
    qsc_memutils_secure_erase(suffix, sizeof(suffix));
    qsc_memutils_secure_erase(factor, sizeof(factor));
    qsc_memutils_secure_erase(factor_squared, sizeof(factor_squared));
    qsc_memutils_secure_erase(factor_cubed, sizeof(factor_cubed));
    qsc_memutils_secure_erase(&adding, sizeof(adding));
    qsc_memutils_secure_erase(&doubling, sizeof(doubling));
}

/*! \brief Signed five-bit window ECDH scalar multiplication with native limbs.
 * \details Sixteen validated public-point multiples share one projective
 * scale. All signed Booth digits scan the complete table and select using
 * masks; the native point loop executes a fixed five-doubling schedule.
 * \param result: QSC standard internal eight-word projective result.
 * \param point: Canonical Montgomery affine curve point.
 * \param scalar: Ten-word order-blinded scalar, processed in fixed time.
 * \param projective: Fresh nonzero field scale for Jacobian randomization.
 * \param rerandomizers: Four freshly generated nonzero factors applied at fixed public window positions.
 */
static void p256_scalar_mult(p256_jac_t* result, const p256_aff_t* point,
    const uint32_t scalar[10U], const fe256 projective, const fe256 rerandomizers[4U])
{
    p256_native_point table[16U];
    /* Public-point doubles avoid a secret-dependent exceptional-path
     * recomputation in each blinded scalar window. */
    p256_native_point doubled_table[16U];
    p256_native_point selected;
    p256_native_point selected_twice;
    p256_native_point accumulator;
    p256_native_point added;
    p256_native_fe shared_z;
    p256_native_fe shared_z_squared;
    p256_native_window_workspace work;
    p256_ecdh_double_workspace doubling;
#if defined(QSC_ECDH_P256_EXCHANGE_BOTAN_DBL5)
    p256_botan5_workspace botan5_work;
#endif
    uint64_t scratch[15U] = { 0U };
    uint32_t digit;
    uint32_t digits[65U];
    uint32_t digit_signs[65U];
    fe256 projective_mont;
    p256_native_fe blind_z;
    p256_native_fe blind_z2;
    p256_native_fe blind_z3;
    p256_native_fe random_z[4U];
    p256_native_fe random_z2[4U];
    p256_native_fe random_z3[4U];
    fe256 random_encoded;
    uint32_t carry;
    uint32_t unsigned_digit;
    uint32_t index;
    uint32_t shift;
    p256_native_fe zero = { 0U };
    p256_native_fe neg_y;
    p256_native_fe neg_twice_y;
    uint32_t difference;
    uint32_t equal;
    uint32_t present;
    size_t i;
    size_t j;

    p256_native_precompute_window5(table, shared_z, shared_z_squared, point, scratch);
    ecdh_p256_encode(projective_mont, projective);
    p256_native_load(blind_z, projective_mont);
    p256_native_square(blind_z2, blind_z, scratch);
    p256_native_mul(blind_z3, blind_z2, blind_z, scratch);

    /* Randomize the entire shared-Z isomorphism before processing any secret
     * window. Scaling every table point preserves its affine interpretation
     * while ensuring that leading zero digits and infinity transitions cannot
     * discard projective randomization. */
    for (i = 0U; i < 16U; ++i)
    {
        p256_native_mul(table[i].x, table[i].x, blind_z2, scratch);
        p256_native_mul(table[i].y, table[i].y, blind_z3, scratch);
    }

    p256_native_mul(shared_z, shared_z, blind_z, scratch);
    p256_native_square(shared_z_squared, shared_z, scratch);

    for (i = 0U; i < 4U; ++i)
    {
        ecdh_p256_encode(random_encoded, rerandomizers[i]);
        p256_native_load(random_z[i], random_encoded);
        p256_native_square(random_z2[i], random_z[i], scratch);
        p256_native_mul(random_z3[i], random_z2[i], random_z[i], scratch);
    }

    /* The first eight doubles are already present in the shared-Z table.
     * Reuse the isomorphic affine representation without leaking a scalar.
     * The remaining doubles are computed once, before scalar recoding. */
    for (i = 0U; i < 8U; ++i)
    {
        doubled_table[i] = table[(2U * i) + 1U];
    }

    for (i = 8U; i < 16U; ++i)
    {
        p256_ecdh_native_double_iso(&doubled_table[i], &table[i],
            &doubling, shared_z_squared, scratch);
    }

    carry = 0U;
    for (i = 0U; i < 65U; ++i)
    {
        index = (uint32_t)((5U * i) / 32U);
        shift = (uint32_t)((5U * i) % 32U);
        unsigned_digit = index < 10U ? scalar[index] >> shift : 0U;
        if (shift > 27U && index < 9U)
        {
            unsigned_digit |= scalar[index + 1U] << (32U - shift);
        }
        unsigned_digit = (unsigned_digit & 31U) + carry;
        carry = (unsigned_digit + 15U) >> 5U;
        digit_signs[i] = carry;
        digit = unsigned_digit - (carry << 5U);
        digits[i] = (digit ^ (0U - carry)) + carry;
    }

    qsc_memutils_clear(&selected, sizeof(selected));
    qsc_memutils_clear(&selected_twice, sizeof(selected_twice));
    qsc_memutils_clear(&accumulator, sizeof(accumulator));
    qsc_memutils_clear(&work, sizeof(work));
    qsc_memutils_clear(&doubling, sizeof(doubling));
    p256_native_copy(accumulator.y, P256_NATIVE_ONE);

    for (i = 65U; i > 0U; --i)
    {
        /* The leading five-bit window needs no preceding doublings.
         * The window index is public; the digit remains masked and secret. */
        if (i != 65U)
        {
#if defined(QSC_ECDH_P256_EXCHANGE_BOTAN_DBL5)
            p256_ecdh_native_double_iso_botan5(&accumulator, &accumulator,
                shared_z_squared, scratch, &botan5_work);
#else
            p256_native_square(doubling.delta, accumulator.z, scratch);
            p256_native_mul(doubling.delta, doubling.delta, shared_z_squared, scratch);

            for (j = 0U; j < 5U; ++j)
            {
                p256_ecdh_native_double_iso_cached(&accumulator, &accumulator,
                    &doubling, scratch, j != 4U);
            }
#endif
        }

        digit = digits[i - 1U];
        present = ((digit | (0U - digit)) >> 31U);

        /* Volatile mask materialization prevents the optimizer from
         * rewriting the secret digit lookup as a branch cascade. */
        {
            volatile uint64_t opaque_mask;
            uint64_t mask;
            size_t word;

            opaque_mask = UINT64_C(0) - (uint64_t)present;
            mask = opaque_mask;

            for (word = 0U; word < 4U; ++word)
            {
                selected.x[word] = 0U;
                selected.y[word] = 0U;
                selected.z[word] = P256_NATIVE_ONE[word] & mask;
                selected_twice.x[word] = 0U;
                selected_twice.y[word] = 0U;
                selected_twice.z[word] = 0U;
            }

            for (j = 0U; j < 16U; ++j)
            {
                difference = digit ^ (uint32_t)(j + 1U);
                equal = 1U ^ ((difference | (0U - difference)) >> 31U);
                opaque_mask = UINT64_C(0) - (uint64_t)equal;
                mask = opaque_mask;

                for (word = 0U; word < 4U; ++word)
                {
                    selected.x[word] |= table[j].x[word] & mask;
                    selected.y[word] |= table[j].y[word] & mask;
                    selected_twice.x[word] |= doubled_table[j].x[word] & mask;
                    selected_twice.y[word] |= doubled_table[j].y[word] & mask;
                    selected_twice.z[word] |= doubled_table[j].z[word] & mask;
                }
            }
        }

        /* Initial accumulator selection is public-position control flow;
         * no secret-window digit is ever used as a branch condition. */
        p256_native_sub(neg_y, zero, selected.y, scratch);
        qsc_intutils_cmov((uint8_t*)selected.y, (const uint8_t*)neg_y,
            sizeof(neg_y), (uint8_t)digit_signs[i - 1U]);
        p256_native_sub(neg_twice_y, zero, selected_twice.y, scratch);
        qsc_intutils_cmov((uint8_t*)selected_twice.y, (const uint8_t*)neg_twice_y,
            sizeof(neg_twice_y), (uint8_t)digit_signs[i - 1U]);

        if (i == 65U)
        {
            accumulator = selected;
        }
        else
        {
            p256_native_add_exchange_safe(&added, &accumulator, &selected,
                &selected_twice, &work, scratch);
            accumulator = added;
        }

        /* Fixed public positions, independent of scalar digits and point
         * equality. Preserve the isomorphic representation as in Botan. */
        if (i > 61U)
        {
            size_t ridx;

            ridx = 65U - i;
            p256_native_mul(accumulator.x, accumulator.x, random_z2[ridx], scratch);
            p256_native_mul(accumulator.y, accumulator.y, random_z3[ridx], scratch);
            p256_native_mul(accumulator.z, accumulator.z, random_z[ridx], scratch);
        }
    }

    p256_native_store(result->X, accumulator.x);
    p256_native_store(result->Y, accumulator.y);
    p256_native_mul(accumulator.z, accumulator.z, shared_z, scratch);
    p256_native_store(result->Z, accumulator.z);
    qsc_memutils_secure_erase(projective_mont, sizeof(projective_mont));
    qsc_memutils_secure_erase(blind_z, sizeof(blind_z));
    qsc_memutils_secure_erase(blind_z2, sizeof(blind_z2));
    qsc_memutils_secure_erase(blind_z3, sizeof(blind_z3));
    qsc_memutils_secure_erase(random_z, sizeof(random_z));
    qsc_memutils_secure_erase(random_z2, sizeof(random_z2));
    qsc_memutils_secure_erase(random_z3, sizeof(random_z3));
    qsc_memutils_secure_erase(random_encoded, sizeof(random_encoded));
    qsc_memutils_secure_erase(neg_y, sizeof(neg_y));
    qsc_memutils_secure_erase(neg_twice_y, sizeof(neg_twice_y));
    qsc_memutils_secure_erase(digits, sizeof(digits));
    qsc_memutils_secure_erase(digit_signs, sizeof(digit_signs));
    qsc_memutils_secure_erase(shared_z, sizeof(shared_z));
    qsc_memutils_secure_erase(shared_z_squared, sizeof(shared_z_squared));
    qsc_memutils_secure_erase(table, sizeof(table));
    qsc_memutils_secure_erase(doubled_table, sizeof(doubled_table));
    qsc_memutils_secure_erase(&selected, sizeof(selected));
    qsc_memutils_secure_erase(&selected_twice, sizeof(selected_twice));
    qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
    qsc_memutils_secure_erase(&added, sizeof(added));
    qsc_memutils_secure_erase(&work, sizeof(work));
    qsc_memutils_secure_erase(&doubling, sizeof(doubling));
#if defined(QSC_ECDH_P256_EXCHANGE_BOTAN_DBL5)
    qsc_memutils_secure_erase(&botan5_work, sizeof(botan5_work));
#endif
    qsc_memutils_secure_erase(scratch, sizeof(scratch));
}

#if defined(QSC_ECDH_P256_GENERATOR_W6)
#include "p256generatorw6.h"

/*! \brief Protected fixed-generator P-256 multiplication using Botan's W6 Booth structure.
 * \param result: Writable Montgomery Jacobian result, owned by caller.
 * \param scalar: Exactly 320 bits of independently order-blinded scalar.
 * \param projective: Fresh nonzero canonical projective scale.
 * \param rerandomizers: Four independent nonzero canonical projective scales.
 * \details 54 public-position windows; each secret digit scans all 32 immutable
 * generator multiples. Exceptional additions use the existing QSC masked
 * complete point selection. All projective masking remains fail-closed at caller.
 * \note This is an isolated no-ASM candidate; not enabled in production by default.
 */
static void p256_scalar_mult_fixed_generator(p256_jac_t* result, const uint32_t scalar[10U],
    const fe256 projective, const fe256 rerandomizers[4U])
{
    p256_native_point accumulator;
    p256_native_point selected;
    p256_native_point selected_twice;
    p256_native_point added;
    p256_native_window_workspace work;
    p256_ecdh_double_workspace doubling;
    uint64_t scratch[15U] = { 0U };
    p256_native_fe neg_y;
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
    p256_native_fe neg_twice_y;
#endif
    p256_native_fe first_z;
    p256_native_fe first_z2;
    p256_native_fe first_z3;
    p256_native_fe random_z[4U];
    p256_native_fe random_z2[4U];
    p256_native_fe random_z3[4U];
    p256_native_fe zero = { 0U };
    fe256 encoded;
    uint64_t opaque;
    uint64_t mask;
    uint64_t present_mask;
    uint64_t words;
    uint32_t raw;
    uint32_t inverted;
    uint32_t sign;
    uint32_t signmask;
    uint32_t canonical;
    uint32_t digit;
    uint32_t difference;
    uint32_t equal;
    uint32_t bitpos;
    uint32_t wordindex;
    uint32_t shift;
    size_t i;
    size_t j;
    size_t m;

    /* Fresh projective and accumulator masks, independent of table contents. */
    ecdh_p256_encode(encoded, projective);
    p256_native_load(first_z, encoded);
    p256_native_square(first_z2, first_z, scratch);
    p256_native_mul(first_z3, first_z2, first_z, scratch);

    for (i = 0U; i < 4U; ++i)
    {
        ecdh_p256_encode(encoded, rerandomizers[i]);
        p256_native_load(random_z[i], encoded);
        p256_native_square(random_z2[i], random_z[i], scratch);
        p256_native_mul(random_z3[i], random_z2[i], random_z[i], scratch);
    }

    qsc_memutils_clear(&accumulator, sizeof(accumulator));
    qsc_memutils_clear(&selected, sizeof(selected));
    qsc_memutils_clear(&selected_twice, sizeof(selected_twice));
    qsc_memutils_clear(&added, sizeof(added));
    qsc_memutils_clear(&work, sizeof(work));
    qsc_memutils_clear(&doubling, sizeof(doubling));

    for (i = 0U; i < 54U; ++i)
    {
        /* W+1 overlapping digits exactly reproduce Botan's Booth recoding. */
        if (i == 0U)
        {
            raw = (scalar[0U] & 63U) << 1U;
        }
        else
        {
            bitpos = (uint32_t)(6U * i - 1U);
            wordindex = bitpos / 32U;
            shift = bitpos % 32U;
            words = (uint64_t)scalar[wordindex] >> shift;

            if (wordindex < 9U)
            {
                words |= (uint64_t)scalar[wordindex + 1U] << (32U - shift);
            }

            raw = (uint32_t)words & 127U;
        }

        sign = raw >> 6U;
        inverted = 127U - raw;
        signmask = 0U - sign;
        canonical = raw ^ ((raw ^ inverted) & signmask);
        digit = (canonical >> 1U) + (canonical & 1U);
        present_mask = UINT64_C(0) - (uint64_t)((digit | (0U - digit)) >> 31U);

        for (m = 0U; m < 4U; ++m)
        {
            selected.x[m] = 0U;
            selected.y[m] = 0U;
            selected.z[m] = P256_NATIVE_ONE[m] & present_mask;
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
            selected_twice.x[m] = 0U;
            selected_twice.y[m] = 0U;
            selected_twice.z[m] = P256_NATIVE_ONE[m] & present_mask;
#endif
        }

        /* Fixed 32-entry scan; only public window i determines table location. */
        for (j = 0U; j < 32U; ++j)
        {
            difference = digit ^ (uint32_t)(j + 1U);
            equal = 1U ^ ((difference | (0U - difference)) >> 31U);
            opaque = UINT64_C(0) - (uint64_t)equal;
            {
                volatile uint64_t protected_mask;
                protected_mask = opaque;
                mask = protected_mask;
            }

            for (m = 0U; m < 4U; ++m)
            {
                selected.x[m] |= P256_GENERATOR_W6_MONT[i][j][0U][m] & mask;
                selected.y[m] |= P256_GENERATOR_W6_MONT[i][j][1U][m] & mask;
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
                selected_twice.x[m] |= P256_GENERATOR_W6_DOUBLE_MONT[i][j][0U][m] & mask;
                selected_twice.y[m] |= P256_GENERATOR_W6_DOUBLE_MONT[i][j][1U][m] & mask;
#endif
            }
        }

        p256_native_sub(neg_y, zero, selected.y, scratch);
        qsc_intutils_cmov((uint8_t*)selected.y, (const uint8_t*)neg_y,
            sizeof(neg_y), (uint8_t)sign);
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
        p256_native_sub(neg_twice_y, zero, selected_twice.y, scratch);
        qsc_intutils_cmov((uint8_t*)selected_twice.y, (const uint8_t*)neg_twice_y,
            sizeof(neg_twice_y), (uint8_t)sign);
#endif

        if (i == 0U)
        {
            accumulator = selected;
            p256_native_mul(accumulator.x, accumulator.x, first_z2, scratch);
            p256_native_mul(accumulator.y, accumulator.y, first_z3, scratch);
            p256_native_mul(accumulator.z, accumulator.z, first_z, scratch);
        }
        else
        {
            /* The public selected-point double must also be computed for
             * zero/equal/inverse cases; no secret-dependent shortcut is allowed. */
#if !defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
            p256_ecdh_native_double(&selected_twice, &selected, &doubling, scratch);
#endif
            p256_native_add_generator_safe(&added, &accumulator, &selected,
                &selected_twice, &work, scratch);
            accumulator = added;
        }

        /* The positions are public and fixed, independent of secret digits. */
        if (i < 4U)
        {
            p256_native_mul(accumulator.x, accumulator.x, random_z2[i], scratch);
            p256_native_mul(accumulator.y, accumulator.y, random_z3[i], scratch);
            p256_native_mul(accumulator.z, accumulator.z, random_z[i], scratch);
        }
    }

    p256_native_store(result->X, accumulator.x);
    p256_native_store(result->Y, accumulator.y);
    p256_native_store(result->Z, accumulator.z);

    qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
    qsc_memutils_secure_erase(&selected, sizeof(selected));
    qsc_memutils_secure_erase(&selected_twice, sizeof(selected_twice));
    qsc_memutils_secure_erase(&added, sizeof(added));
    qsc_memutils_secure_erase(&work, sizeof(work));
    qsc_memutils_secure_erase(&doubling, sizeof(doubling));
    qsc_memutils_secure_erase(scratch, sizeof(scratch));
    qsc_memutils_secure_erase(neg_y, sizeof(neg_y));
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
    qsc_memutils_secure_erase(neg_twice_y, sizeof(neg_twice_y));
#endif
    qsc_memutils_secure_erase(first_z, sizeof(first_z));
    qsc_memutils_secure_erase(first_z2, sizeof(first_z2));
    qsc_memutils_secure_erase(first_z3, sizeof(first_z3));
    qsc_memutils_secure_erase(random_z, sizeof(random_z));
    qsc_memutils_secure_erase(random_z2, sizeof(random_z2));
    qsc_memutils_secure_erase(random_z3, sizeof(random_z3));
    qsc_memutils_secure_erase(encoded, sizeof(encoded));
    qsc_memutils_secure_erase(&raw, sizeof(raw));
    qsc_memutils_secure_erase(&inverted, sizeof(inverted));
    qsc_memutils_secure_erase(&sign, sizeof(sign));
    qsc_memutils_secure_erase(&canonical, sizeof(canonical));
    qsc_memutils_secure_erase(&digit, sizeof(digit));
    qsc_memutils_secure_erase(&words, sizeof(words));
}
#endif /* QSC_ECDH_P256_GENERATOR_W6 */

#else
/*! \brief Swap two projective points without a secret-dependent branch.
 * \param first: Writable first point.
 * \param second: Writable second point.
 * \param select: Secret scalar bit (zero or one).
 */
static void p256_ladder_cswap(p256_jac_t* first, p256_jac_t* second, uint32_t select)
{
    uint32_t mask;
    uint32_t t;
    size_t i;

    mask = (uint32_t)(0U - select);

    for (i = 0U; i < 8U; ++i)
    {
        t = (first->X[i] ^ second->X[i]) & mask;
        first->X[i] ^= t;
        second->X[i] ^= t;
        t = (first->Y[i] ^ second->Y[i]) & mask;
        first->Y[i] ^= t;
        second->Y[i] ^= t;
        t = (first->Z[i] ^ second->Z[i]) & mask;
        first->Z[i] ^= t;
        second->Z[i] ^= t;
    }
}

/*! \brief Perform fixed-schedule secret-scalar multiplication on a validated point.
 * \details Uses a Montgomery-style differential-invariant ladder with one
 * Jacobian doubling and one addition for each of the 320 blinded bits.
 * Both point operands and bit transitions are masked; no secret-bit branches.
 * \param R: Caller-owned result point.
 * \param P: Validated affine input, Montgomery encoded on the native path.
 * \param k: Ten-word order-blinded secret scalar.
 * \param projective: Nonzero random affine-field masking factor.
 * \param rerandomizers: Four fresh projective factors for fixed public bit positions.
 */
static void p256_scalar_mult(p256_jac_t* R, const p256_aff_t* P, const uint32_t k[10U], const fe256 projective, const fe256 rerandomizers[4U])
{
    p256_jac_t r0;
    p256_jac_t r1;
    p256_jac_t added;
    p256_jac_t doubled;
    uint32_t swap;
    uint32_t bit;
    fe256 z2;
    fe256 z3;
    fe256 mask2;
    fe256 mask3;
    size_t ridx;
    int32_t i;

    p256_set_infinity(&r0);
    p256_aff_to_jac(&r1, P);
    fe_sqr(z2, projective);
    fe_mul(z3, z2, projective);
    fe_mul(r1.X, r1.X, z2);
    fe_mul(r1.Y, r1.Y, z3);
    fe256_copy(r1.Z, projective);
    swap = 0U;

    for (i = 319; i >= 0; --i)
    {
        bit = (k[(size_t)i / 32U] >> ((uint32_t)i % 32U)) & 1U;
        swap ^= bit;
        p256_ladder_cswap(&r0, &r1, swap);
        swap = bit;

        p256_add(&added, &r0, &r1);
        p256_dbl(&doubled, &r0);
        r1 = added;
        r0 = doubled;

        if (i >= 316)
        {
            ridx = 319U - (size_t)i;
            fe_sqr(mask2, rerandomizers[ridx]);
            fe_mul(mask3, mask2, rerandomizers[ridx]);
            fe_mul(r0.X, r0.X, mask2);
            fe_mul(r0.Y, r0.Y, mask3);
            fe_mul(r0.Z, r0.Z, rerandomizers[ridx]);
            fe_mul(r1.X, r1.X, mask2);
            fe_mul(r1.Y, r1.Y, mask3);
            fe_mul(r1.Z, r1.Z, rerandomizers[ridx]);
        }
    }

    p256_ladder_cswap(&r0, &r1, swap);
    *R = r0;
    qsc_memutils_secure_erase(z2, sizeof(z2));
    qsc_memutils_secure_erase(z3, sizeof(z3));
    qsc_memutils_secure_erase(mask2, sizeof(mask2));
    qsc_memutils_secure_erase(mask3, sizeof(mask3));
    qsc_memutils_secure_erase(&r0, sizeof(r0));
    qsc_memutils_secure_erase(&r1, sizeof(r1));
    qsc_memutils_secure_erase(&added, sizeof(added));
    qsc_memutils_secure_erase(&doubled, sizeof(doubled));
}

#endif /* QSC_ECDH_P256_NATIVE */

/*! \brief Convert a Jacobian point to affine without branching on its Z coordinate.
 * \param R: Caller-owned affine output.
 * \param P: Caller-owned Jacobian input, potentially derived from a private scalar.
 * \return True for a finite point; false if the input represents infinity.
 * \note The field inversion schedule is fixed, including for an infinity input.
 */
static bool p256_jac_to_aff(p256_aff_t* R, const p256_jac_t* P)
{
    fe256 zinv;
    fe256 zinv2;
    fe256 zinv3;
    uint32_t finite;

    finite = p256_is_infinity(P) ^ 1U;
    fe_inv(zinv, P->Z);
    fe_sqr(zinv2, zinv);
    fe_mul(zinv3, zinv2, zinv);
    fe_mul(R->X, P->X, zinv2);
    fe_mul(R->Y, P->Y, zinv3);

    qsc_memutils_secure_erase(zinv, sizeof(zinv));
    qsc_memutils_secure_erase(zinv2, sizeof(zinv2));
    qsc_memutils_secure_erase(zinv3, sizeof(zinv3));

    return (finite != 0U);
}

static bool p256_point_is_on_curve(const p256_aff_t* Q)
{
    /* verify that a public key point lies on the curve.
     * checks the Weierstrass equation:  Y^2 = X^3 - 3X + b  (mod p)
     * and that the point is not the identity. */
    fe256 y2, x3, ax, rhs;

    /* y^2 mod p */
    fe_sqr(y2, Q->Y);

    /* x^3 mod p */
    fe_sqr(x3, Q->X);
    fe_mul(x3, x3, Q->X);

    /* -3*x mod p (a = -3) */
    fe_mul_small(ax, Q->X, 3U);
    fe_sub(rhs, x3, ax);

    /* rhs = x^3 - 3x + b */
#if defined(QSC_ECDH_P256_NATIVE)
    {
        fe256 bm;

        ecdh_p256_encode(bm, P256_B);
        fe_add(rhs, rhs, bm);
        qsc_memutils_secure_erase(bm, sizeof(bm));
    }
#else
    fe_add(rhs, rhs, P256_B);
#endif

    return (fe256_cmp(y2, rhs) == 0);
}

/*! \brief Validate and prepare a canonical external peer point for scalar multiplication.
 * \param Q: Writable affine peer point, already range checked in [0, p).
 * \return True only for a point on NIST P-256.
 * \note Montgomery conversion is fixed-time; validation may reject public data.
 */
static bool p256_prepare_peer_point(p256_aff_t* Q)
{
#if defined(QSC_ECDH_P256_NATIVE)
    ecdh_p256_encode(Q->X, Q->X);
    ecdh_p256_encode(Q->Y, Q->Y);
#endif
    return p256_point_is_on_curve(Q);
}

/* RFC 6979 deterministic k generation */

static void sc_from_bytes(uint32_t r[8U], const uint8_t s[32U])
{
    int32_t i;
    int32_t j;

    for (i = 0, j = 28; i < 8; ++i, j -= 4)
    {
        r[i] =
            ((uint32_t)s[j] << 24) |
            ((uint32_t)s[j + 1U] << 16) |
            ((uint32_t)s[j + 2U] << 8) |
            ((uint32_t)s[j + 3U]);
    }
}

static bool p256_private_scalar_from_seed(uint8_t scalar[32U], const uint8_t seed[32U])
{
    uint8_t hash[32U] = { 0U };
    uint32_t d[8U] = { 0U };
    bool res;

    qsc_sha256_compute(hash, seed, QSC_ECDHP256_SEED_SIZE);
    sc_from_bytes_reduce(d, hash);

    res = (fe256_is_zero(d) == 0U);

    if (res == true)
    {
        fe256_to_bytes(scalar, d);
    }
    else
    {
        qsc_memutils_clear(scalar, QSC_ECDHP256_PRIVATEKEY_SIZE);
    }

    qsc_memutils_secure_erase(hash, sizeof(hash));
    qsc_memutils_secure_erase(d, sizeof(d));

    return res;
}

int32_t qsc_crypto_scalarmult_secp256r1_base(uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    p256_aff_t G;
    p256_aff_t Q;
    p256_jac_t R;
    uint32_t d[8U] = { 0U };
    uint32_t blinded[10U] = { 0U };
    fe256 projective = { 0U };
    fe256 rerandomizers[4U] = { { 0U } };
    int32_t ret;

    ret = -1;

    if (publickey != NULL && privatekey != NULL)
    {
        qsc_memutils_clear(publickey, QSC_ECDHP256_PUBLICKEY_SIZE);
        sc_from_bytes(d, privatekey);

        if (fe256_is_zero(d) != 0U)
        {
            ret = -2;
        }
        else if (p256_private_scalar_ge_order(d) != 0U)
        {
            ret = -3;
        }
        else if (p256_prepare_blinding(blinded, projective, rerandomizers, d) == false)
        {
            ret = -9;
        }
        else
        {
            fe256_copy(G.X, P256_GX);
            fe256_copy(G.Y, P256_GY);
#if defined(QSC_ECDH_P256_NATIVE)
            ecdh_p256_encode(G.X, G.X);
            ecdh_p256_encode(G.Y, G.Y);
#endif
#if defined(QSC_ECDH_P256_NATIVE) && defined(QSC_ECDH_P256_GENERATOR_W6)
            p256_scalar_mult_fixed_generator(&R, blinded, projective, rerandomizers);
#else
            p256_scalar_mult(&R, &G, blinded, projective, rerandomizers);
#endif

            if (p256_is_infinity(&R) != 0U)
            {
                ret = -4;
            }
            else if (p256_jac_to_aff(&Q, &R) != true)
            {
                ret = -5;
            }
            else
            {
#if defined(QSC_ECDH_P256_NATIVE)
                ecdh_p256_decode(Q.X, Q.X);
                ecdh_p256_decode(Q.Y, Q.Y);
#endif
                fe256_to_bytes(publickey, Q.X);
                fe256_to_bytes(publickey + 32U, Q.Y);
                ret = 0;
            }
        }
    }

    qsc_memutils_secure_erase(blinded, sizeof(blinded));
    qsc_memutils_secure_erase(projective, sizeof(projective));
    qsc_memutils_secure_erase(rerandomizers, sizeof(rerandomizers));
    qsc_memutils_secure_erase(d, sizeof(d));
    qsc_memutils_secure_erase(&Q, sizeof(Q));
    qsc_memutils_secure_erase(&R, sizeof(R));
    qsc_memutils_secure_erase(&G, sizeof(G));

    return ret;
}

int32_t qsc_crypto_scalarmult_secp256r1(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey)
{
    QSC_ASSERT(secret != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(publickey != NULL);

    uint32_t d[8U] = { 0U };
    uint32_t blinded[10U] = { 0U };
    fe256 projective = { 0U };
    fe256 rerandomizers[4U] = { { 0U } };
    p256_aff_t Q;
    p256_aff_t S;
    p256_jac_t J;
    int32_t ret;

    ret = -1;

    if (secret != NULL && privatekey != NULL && publickey != NULL)
    {
        qsc_memutils_clear(secret, QSC_ECDHP256_SHAREDSECRET_SIZE);
        sc_from_bytes(d, privatekey);

        if (fe256_is_zero(d) != 0U)
        {
            ret = -2;
        }
        else if (p256_private_scalar_ge_order(d) != 0U)
        {
            ret = -3;
        }
        else
        {
            fe256_from_bytes(Q.X, publickey);
            fe256_from_bytes(Q.Y, publickey + 32U);

            if (fe256_cmp(Q.X, P256_P) >= 0 || fe256_cmp(Q.Y, P256_P) >= 0)
            {
                ret = -4;
            }
            else if (p256_prepare_peer_point(&Q) == false)
            {
                ret = -5;
            }
            else if (p256_prepare_blinding(blinded, projective, rerandomizers, d) == false)
            {
                ret = -9;
            }
            else
            {
                p256_scalar_mult(&J, &Q, blinded, projective, rerandomizers);

                if (p256_is_infinity(&J) != 0U)
                {
                    ret = -6;
                }
#if defined(QSC_ECDH_P256_NATIVE)
                else
                {
                    p256_native_affine_x(S.X, &J);

                    fe256_to_bytes(secret, S.X);
                    ret = 0;
                }
#else
                else if (p256_jac_to_aff(&S, &J) != true)
                {
                    ret = -7;
                }
                else
                {
#if defined(QSC_ECDH_P256_NATIVE)
                    ecdh_p256_decode(S.X, S.X);
#endif
                    fe256_to_bytes(secret, S.X);
                    ret = 0;
                }
#endif
            }
        }
    }

    qsc_memutils_secure_erase(blinded, sizeof(blinded));
    qsc_memutils_secure_erase(projective, sizeof(projective));
    qsc_memutils_secure_erase(rerandomizers, sizeof(rerandomizers));
    qsc_memutils_secure_erase(d, sizeof(d));
    qsc_memutils_secure_erase(&Q, sizeof(Q));
    qsc_memutils_secure_erase(&S, sizeof(S));
    qsc_memutils_secure_erase(&J, sizeof(J));

    return ret;
}

void qsc_p256_public_from_private(uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    if (publickey != NULL && privatekey != NULL)
    {
        (void)qsc_crypto_scalarmult_secp256r1_base(publickey, privatekey);
    }
}

void qsc_p256_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(seed != NULL);

    if (publickey != NULL && privatekey != NULL && seed != NULL)
    {
        qsc_memutils_clear(publickey, QSC_ECDHP256_PUBLICKEY_SIZE);
        qsc_memutils_clear(privatekey, QSC_ECDHP256_PRIVATEKEY_SIZE);

        if (p256_private_scalar_from_seed(privatekey, seed) == true)
        {
            if (qsc_crypto_scalarmult_secp256r1_base(publickey, privatekey) != 0)
            {
                qsc_memutils_clear(publickey, QSC_ECDHP256_PUBLICKEY_SIZE);
                qsc_memutils_clear(privatekey, QSC_ECDHP256_PRIVATEKEY_SIZE);
            }
        }
    }
}

void qsc_p256_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(rng_generate != NULL);

    uint8_t seed[QSC_ECDHP256_SEED_SIZE] = { 0U };

    if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
    {
        qsc_memutils_clear(publickey, QSC_ECDHP256_PUBLICKEY_SIZE);
        qsc_memutils_clear(privatekey, QSC_ECDHP256_PRIVATEKEY_SIZE);

        if (rng_generate(seed, sizeof(seed)) == true)
        {
            qsc_p256_generate_seeded_keypair(publickey, privatekey, seed);
        }
    }

    qsc_memutils_secure_erase(seed, sizeof(seed));
}

bool qsc_p256_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(secret != NULL);
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    int32_t ret;

    ret = -1;

    if (secret != NULL && publickey != NULL && privatekey != NULL)
    {
        ret = qsc_crypto_scalarmult_secp256r1(secret, privatekey, publickey);

    }

    return (ret == 0);
}
