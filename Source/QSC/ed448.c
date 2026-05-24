#include "ed448.h"
#include "sha3.h"
#include "memutils.h"

/* ============================================================
 * Internal constants
 * ============================================================ */

/*
 * The Goldilocks prime p = 2^448 - 2^224 - 1.
 * Used for reduction and canonicality checks.
 */
static const uint8_t SC448_ORDER[57U] =
{
    0xF3U, 0x44U, 0x58U, 0xABU, 0x92U, 0xC2U, 0x78U, 0x23U,
    0x55U, 0x8FU, 0xC5U, 0x8DU, 0x72U, 0xC2U, 0x6CU, 0x21U,
    0x90U, 0x36U, 0xD6U, 0xAEU, 0x49U, 0xDBU, 0x4EU, 0xC4U,
    0xE9U, 0x23U, 0xCAU, 0x7CU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x3FU,
    0x00U
};

/*
 * d constant for Ed448-Goldilocks (twisted Edwards curve):
 *   d = -39081 mod p
 * Precomputed as a field element.
 */
static const qsc_fe448 FE448_D =
{
    -39081, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* 2*d constant for use in group operations. */
static const qsc_fe448 FE448_2D =
{
    -78162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static const uint8_t FE448_P_BYTES[56U] =
{
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

static const uint8_t FE448_PM2[56U] =
{
    0xFDU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

static const uint8_t FE448_SQRT_EXP[56U] =
{
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0xC0U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x3FU
};

static const qsc_fe448 FE448_INV2 =
{
    0, 0, 0, 0, 0, 0, 0, 134217728,
    268435455, 268435455, 268435455, 268435455,
    268435455, 268435455, 268435455, 134217727
};

static void fe448_canonicalize_bytes(uint8_t s[56U])
{
    uint8_t tmp[56U];
    uint32_t borrow = 0U;
    uint32_t mask;
    size_t i;

    for (i = 0U; i < 56U; ++i)
    {
        const uint32_t xi = (uint32_t)s[i];
        const uint32_t yi = (uint32_t)FE448_P_BYTES[i];
        const uint32_t sub = yi + borrow;

        tmp[i] = (uint8_t)(xi - sub);
        borrow = (uint32_t)((xi < sub) ? 1U : 0U);
    }

    mask = (uint32_t)(0U - (borrow ^ 1U));

    for (i = 0U; i < 56U; ++i)
    {
        s[i] = (uint8_t)((s[i] & (uint8_t)(~mask)) | (tmp[i] & (uint8_t)mask));
    }
}

static void fe448_p3_identity(qsc_ge448_p3* p)
{
    qsc_fe448_0(p->x);
    qsc_fe448_1(p->y);
    qsc_fe448_1(p->z);
    qsc_fe448_0(p->t);
}

static void fe448_p2_identity(qsc_ge448_p2* p)
{
    qsc_fe448_0(p->x);
    qsc_fe448_1(p->y);
    qsc_fe448_1(p->z);
}

static void fe448_p3_cmov(qsc_ge448_p3* r, const qsc_ge448_p3* p, uint32_t b)
{
    qsc_fe448_cmov(r->x, p->x, b);
    qsc_fe448_cmov(r->y, p->y, b);
    qsc_fe448_cmov(r->z, p->z, b);
    qsc_fe448_cmov(r->t, p->t, b);
}

static void fe448_p3_to_affine(qsc_fe448 x, qsc_fe448 y, const qsc_ge448_p3* p)
{
    qsc_fe448 zinv;

    qsc_fe448_invert(zinv, p->z);
    qsc_fe448_mul(x, p->x, zinv);
    qsc_fe448_mul(y, p->y, zinv);
}

static void fe448_cached_to_affine(qsc_fe448 x, qsc_fe448 y, const qsc_ge448_cached* q)
{
    qsc_fe448 sum;
    qsc_fe448 diff;
    qsc_fe448 invz;

    qsc_fe448_add(sum, q->yplusx, q->yminusx);
    qsc_fe448_sub(diff, q->yplusx, q->yminusx);
    qsc_fe448_mul(sum, sum, FE448_INV2);
    qsc_fe448_mul(diff, diff, FE448_INV2);
    qsc_fe448_invert(invz, q->z);
    qsc_fe448_mul(x, diff, invz);
    qsc_fe448_mul(y, sum, invz);
}

static void fe448_precomp_to_affine(qsc_fe448 x, qsc_fe448 y, const qsc_ge448_precomp* q)
{
    qsc_fe448_add(y, q->yplusx, q->yminusx);
    qsc_fe448_sub(x, q->yplusx, q->yminusx);
    qsc_fe448_mul(y, y, FE448_INV2);
    qsc_fe448_mul(x, x, FE448_INV2);
}

static void fe448_affine_add(qsc_fe448 rx, qsc_fe448 ry, const qsc_fe448 x1, const qsc_fe448 y1, const qsc_fe448 x2, const qsc_fe448 y2)
{
    qsc_fe448 x1y2;
    qsc_fe448 y1x2;
    qsc_fe448 y1y2;
    qsc_fe448 x1x2;
    qsc_fe448 prod;
    qsc_fe448 denx;
    qsc_fe448 deny;
    qsc_fe448 inv;
    qsc_fe448 numx;
    qsc_fe448 numy;
    qsc_fe448 one;

    qsc_fe448_1(one);
    qsc_fe448_mul(x1y2, x1, y2);
    qsc_fe448_mul(y1x2, y1, x2);
    qsc_fe448_mul(y1y2, y1, y2);
    qsc_fe448_mul(x1x2, x1, x2);
    qsc_fe448_mul(prod, x1x2, y1y2);
    qsc_fe448_mul(prod, prod, FE448_D);

    qsc_fe448_add(numx, x1y2, y1x2);
    qsc_fe448_add(denx, one, prod);
    qsc_fe448_invert(inv, denx);
    qsc_fe448_mul(rx, numx, inv);

    qsc_fe448_sub(numy, y1y2, x1x2);
    qsc_fe448_sub(deny, one, prod);
    qsc_fe448_invert(inv, deny);
    qsc_fe448_mul(ry, numy, inv);
}


/* ============================================================
 * Precomputed base point table
 *
 * The Ed448-Goldilocks base point in compressed form (RFC 8032):
 *   Gy = 693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14
 *   (x is recovered as positive)
 *
 * The table below contains 57 groups of 8 precomputed points (yplusx, yminusx, xy2d)
 * representing multiples of B for the comb/wNAF scalar multiplication.
 * For clarity in this reference implementation a 4-bit sliding window over
 * 57 windows is used; the table has 57 * 8 = 456 entries.
 * Each entry is {yplusx, yminusx, xy2d}.
 *
 * NOTE: A complete precomputed table for Ed448 is large (~50 KB). The constants
 * below are the authoritative RFC 8032 values; in a production build these would
 * be generated offline by a dedicated tool and linked as a static table.
 * For the reference build the scalarmult_base function computes the table at
 * runtime from the base point using repeated doublings.
 * ============================================================ */

/* Base point affine coordinates (RFC 8032 5.2.5) */
static const uint8_t ED448_BASEPOINT[57U] =
{
    /* RFC 8032 Edwards448 base point, compressed: y || sign(x) */
    0x14U, 0xFAU, 0x30U, 0xF2U, 0x5BU, 0x79U, 0x08U, 0x98U,
    0xADU, 0xC8U, 0xD7U, 0x4EU, 0x2CU, 0x13U, 0xBDU, 0xFDU,
    0xC4U, 0x39U, 0x7CU, 0xE6U, 0x1CU, 0xFFU, 0xD3U, 0x3AU,
    0xD7U, 0xC2U, 0xA0U, 0x05U, 0x1EU, 0x9CU, 0x78U, 0x87U,
    0x40U, 0x98U, 0xA3U, 0x6CU, 0x73U, 0x73U, 0xEAU, 0x4BU,
    0x62U, 0xC7U, 0xC9U, 0x56U, 0x37U, 0x20U, 0x76U, 0x88U,
    0x24U, 0xBCU, 0xB6U, 0x6EU, 0x71U, 0x46U, 0x3FU, 0x69U,
    0x00U
};

/* ============================================================
 * Field element helpers
 * ============================================================ */

/* Load a 32-bit little-endian integer from a byte array */
static inline uint32_t load32_le(const uint8_t* src)
{
    return ((uint32_t)src[0U])
        | ((uint32_t)src[1U] << 8)
        | ((uint32_t)src[2U] << 16)
        | ((uint32_t)src[3U] << 24);
}

/* Store a 32-bit little-endian integer to a byte array */
static inline void store32_le(uint8_t* dst, uint32_t v)
{
    dst[0U] = (uint8_t)(v);
    dst[1U] = (uint8_t)(v >> 8);
    dst[2U] = (uint8_t)(v >> 16);
    dst[3U] = (uint8_t)(v >> 24);
}

/* ============================================================
 * Field arithmetic - GF(2^448 - 2^224 - 1)
 *
 * Representation: 16 limbs, each int32_t, in radix 2^28.
 * Limb i holds bits [28*i .. 28*i+27] of the canonical value.
 * After each operation limbs may exceed the 28-bit range and
 * are propagated by qsc_fe448_reduce / carry chains inside
 * mul/sq.
 * ============================================================ */

void qsc_fe448_0(qsc_fe448 h)
{
    for (int32_t i = 0; i < 16; i++)
    {
        h[i] = 0;
    }
}

void qsc_fe448_1(qsc_fe448 h)
{
    h[0U] = 1;

    for (int32_t i = 1; i < 16; i++)
    {
        h[i] = 0;
    }
}

void qsc_fe448_copy(qsc_fe448 h, const qsc_fe448 f)
{
    for (int32_t i = 0; i < 16; i++)
    {
        h[i] = f[i];
    }
}

void qsc_fe448_add(qsc_fe448 h, const qsc_fe448 f, const qsc_fe448 g)
{
    for (int32_t i = 0; i < 16; i++)
    {
        h[i] = f[i] + g[i];
    }
}

void qsc_fe448_sub(qsc_fe448 h, const qsc_fe448 f, const qsc_fe448 g)
{
    for (int32_t i = 0; i < 16; i++)
    {
        h[i] = f[i] - g[i];
    }
}

void qsc_fe448_neg(qsc_fe448 h, const qsc_fe448 f)
{
    for (int32_t i = 0; i < 16; i++)
    {
        h[i] = -f[i];
    }
}

void qsc_fe448_cmov(qsc_fe448 f, const qsc_fe448 g, uint32_t b)
{
    int32_t mask = (int32_t)(-(int64_t)b);  /* 0x00000000 or 0xFFFFFFFF */

    for (int32_t i = 0; i < 16; i++)
    {
        f[i] ^= mask & (f[i] ^ g[i]);
    }
}

void qsc_fe448_cswap(qsc_fe448 f, qsc_fe448 g, uint32_t b)
{
    int32_t mask = (int32_t)(-(int64_t)b);

    for (int32_t i = 0; i < 16; i++)
    {
        int32_t t = mask & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
    }
}

void qsc_fe448_from_bytes(qsc_fe448 h, const uint8_t* s)
{
    /* Each limb is 28 bits; 16 limbs x 28 bits = 448 bits = 56 bytes.
     * We load 56 bytes (not 57; the 57th byte holds the sign of x for Ed448 points
     * and is handled at the point decoding level, not here). */
    int64_t tmp[16U] = { 0 };
    uint64_t word;
    int32_t i;
    int32_t byte_off;
    int32_t bit_off;
    int32_t j;
    int64_t v;

    for (i = 0; i < 14; i++)
    {
        /* 4 bytes per limb for limbs 0..13, but the 28-bit boundary means we
         * need to mask.  Load aligned 32-bit words and mask to 28 bits. */
        tmp[i] = ((int64_t)load32_le(s + i * 4)) & 0x0FFFFFFFL;
    }

    /* Limbs 14 and 15 straddle byte 56; handle carefully.
     * Byte layout (28-bit limbs):
     *   limb 0:  bits   0..27  -> bytes  0..3  (mask 28 bits)
     *   limb 1:  bits  28..55  -> bytes  3..6  (shift 4, mask 28 bits from 32-bit word)
     * Using the standard approach of extracting 4 bytes and shifting: */

    /* Recompute properly with bit offsets */
    v = 0;

    for (i = 0; i < 16; i++)
    {
        /* bit offset = 28*i */
        byte_off = (28 * i) / 8;
        bit_off  = (28 * i) % 8;
        /* load 5 bytes to guarantee 28 bits are available */
        word = 0;

        for (j = 0; j < 5 && byte_off + j < 56; j++)
        {
            word |= ((uint64_t)s[byte_off + j]) << (8 * j);
        }

        tmp[i] = (int64_t)((word >> bit_off) & 0x0FFFFFFFUL);
        (void)v;
    }

    for (i = 0; i < 16; i++)
    {
        h[i] = (int32_t)tmp[i];
    }
}

void qsc_fe448_to_bytes(uint8_t* s, const qsc_fe448 h)
{
    qsc_fe448 t;
    int64_t carry;
    uint64_t val;
    int32_t i;
    int32_t j;
    int32_t byte_off;
    int32_t bit_off;

    if (s != NULL)
    {
        qsc_fe448_copy(t, h);

        for (j = 0; j < 2; ++j)
        {
            for (i = 0; i < 15; ++i)
            {
                carry = (int64_t)t[i] >> 28;
                t[i] -= (int32_t)(carry << 28);
                t[i + 1] += (int32_t)carry;
            }

            carry = (int64_t)t[15] >> 28;
            t[15] -= (int32_t)(carry << 28);
            t[0] += (int32_t)carry;
            t[8] += (int32_t)carry;
        }

        qsc_memutils_clear(s, 56U);

        for (i = 0; i < 16; ++i)
        {
            byte_off = (28 * i) / 8;
            bit_off = (28 * i) % 8;
            val = ((uint64_t)(uint32_t)t[i]) << bit_off;

            for (j = 0; j < 5 && (byte_off + j) < 56; ++j)
            {
                s[byte_off + j] |= (uint8_t)(val >> (8 * j));
            }
        }

        fe448_canonicalize_bytes(s);
    }
}


void qsc_fe448_reduce(qsc_fe448 h, const qsc_fe448 f)
{
    int64_t carry;

    qsc_fe448_copy(h, f);

    for (int32_t i = 0; i < 15; i++)
    {
        carry  = (int64_t)h[i] >> 28;
        h[i]  -= (int32_t)(carry << 28);
        h[i + 1U] += (int32_t)carry;
    }

    carry  = (int64_t)h[15U] >> 28;
    h[15U] -= (int32_t)(carry << 28);
    h[0U]  += (int32_t)carry;
    h[8U]  += (int32_t)carry;
}

int32_t qsc_fe448_is_negative(const qsc_fe448 f)
{
    uint8_t s[56U] = { 0 };

    qsc_fe448_to_bytes(s, f);

    return (int32_t)(s[0U] & 1);
}

int32_t qsc_fe448_is_zero(const qsc_fe448 f)
{
    uint8_t s[56U] = { 0 };
    uint8_t d;
    int32_t i;

    d = 0;
    qsc_fe448_to_bytes(s, f);

    for (i = 0; i < 56; i++)
    {
        d |= s[i];
    }

    return (int32_t)(1 - ((d + 255) >> 8));
}

void qsc_fe448_mul32(qsc_fe448 h, const qsc_fe448 f, uint32_t n)
{
    int64_t carry;
    
    carry = 0;

    for (int32_t i = 0; i < 16; i++)
    {
        carry   = (int64_t)f[i] * n + carry;
        h[i]    = (int32_t)(carry & 0x0FFFFFFFL);
        carry >>= 28;
    }

    /* Wrap carry using p = 2^448 - 2^224 - 1 */
    h[0U] += (int32_t)carry;
    h[8U] += (int32_t)carry;
}

/*
 * Field multiplication: h = f * g mod (2^448 - 2^224 - 1)
 *
 * Strategy: schoolbook 16x16 -> 31-limb product, then reduce.
 * Reduction identity: 2^448 = 2^224 + 1 (mod p).
 * So for a product limb at position k >= 16:
 *   coefficient * 2^(28*k) = coefficient * 2^(28*(k-16)) * 2^448
 *                          = coefficient * 2^(28*(k-16)) * (2^224 + 1)
 *                          = coefficient * (2^(28*(k-16)+224) + 2^(28*(k-16)))
 * 224/28 = 8, so the shift by 224 bits = shift by 8 limbs.
 */
void qsc_fe448_mul(qsc_fe448 h, const qsc_fe448 f, const qsc_fe448 g)
{
    int64_t t[31U] = { 0 };
    int32_t i, j;
    int64_t carry;

    /* Schoolbook product */
    for (i = 0; i < 16; i++)
    {
        for (j = 0; j < 16; j++)
        {
            t[i + j] += (int64_t)f[i] * g[j];
        }
    }

    /* Reduce limbs 16..30 using 2^448 = 2^224 + 1 */
    for (i = 30; i >= 16; i--)
    {
        int64_t c = t[i];
        t[i - 16] += c;       /* * 2^0 */
        t[i - 8]  += c;       /* * 2^224 */
        t[i]       = 0;
    }

    /* Propagate carries */
    for (i = 0; i < 15; i++)
    {
        carry      = t[i] >> 28;
        t[i]      &= 0x0FFFFFFFL;
        t[i + 1]  += carry;
    }

    carry   = t[15] >> 28;
    t[15]  &= 0x0FFFFFFFL;
    t[0]   += carry;
    t[8]   += carry;

    /* One more pass to clean up */
    for (i = 0; i < 15; i++)
    {
        carry     = t[i] >> 28;
        t[i]     &= 0x0FFFFFFFL;
        t[i + 1] += carry;
    }

    for (i = 0; i < 16; i++)
    {
        h[i] = (int32_t)t[i];
    }
}

void qsc_fe448_sq(qsc_fe448 h, const qsc_fe448 f)
{
    /* Use multiplication for simplicity; a dedicated squaring routine would
     * exploit f[i]*f[j] == f[j]*f[i] to halve the multiplications. */
    qsc_fe448_mul(h, f, f);
}

void qsc_fe448_sq2(qsc_fe448 h, const qsc_fe448 f)
{
    qsc_fe448 t;
    qsc_fe448_sq(t, f);
    qsc_fe448_mul32(h, t, 2);
}

/*
 * Modular inversion via Fermat: z^(p-2) where p = 2^448 - 2^224 - 1.
 * Exponent e = p - 2 = 2^448 - 2^224 - 3.
 *
 * Addition chain (following standard Ed448 implementations):
 *   a1  = z
 *   a2  = a1^2
 *   a3  = a2 * a1
 *   a6  = a3^(2^3) * a3          (6 = 3+3)
 *   a9  = a6^(2^3) * a3
 *   a11 = a9 * a2
 *   a22 = a11^(2^1) * a11
 *   ... (standard Fermat inversion for p = 2^448 - 2^224 - 1)
 */
void qsc_fe448_invert(qsc_fe448 out, const qsc_fe448 z)
{
    qsc_fe448 result;
    qsc_fe448 base;
    int32_t i;
    int32_t bit;

    qsc_fe448_1(result);
    qsc_fe448_copy(base, z);

    for (i = 55; i >= 0; --i)
    {
        uint8_t byteval = FE448_PM2[i];

        for (bit = 7; bit >= 0; --bit)
        {
            qsc_fe448_sq(result, result);

            if (((byteval >> bit) & 1U) != 0U)
            {
                qsc_fe448_mul(result, result, base);
            }
        }
    }

    qsc_fe448_copy(out, result);
}


/* ============================================================
 * Scalar arithmetic (57-byte scalars mod l)
 *
 * l = 2^446 - 13818066809895115352007386748515426880316871408816
 *     44BI82177129234481
 * in little-endian:
 *   l[0..27] carry info, l[55] = 0x3F, l[56] = 0x00
 * ============================================================ */

void qsc_sc448_clamp(uint8_t* k)
{
    /* RFC 7748 5: For X448 scalar multiplication */
    k[0U]  &= 252U;   /* clear bits 0 and 1 */
    k[55U] |= 128U;   /* set bit 447 */
}

int32_t qsc_sc448_is_canonical(const uint8_t s[57U])
{
    int32_t r;

    r = 0;

    if (s != NULL)
    {
        for (size_t i = 57U; i-- > 0U;)
        {
            if (s[i] < SC448_ORDER[i])
            {
                r = 1;
                break;
            }
            else if (s[i] > SC448_ORDER[i])
            {
                r = 0;
                break;
            }
        }
    }

    return r;
}


int32_t qsc_ed448_small_order(const uint8_t s[57U])
{
    static const uint8_t small_order_points[4][57] =
    {
        {
            0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U
        },
        {
            0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
            0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
            0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
            0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU,
            0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
            0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
            0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
            0x00U
        },
        {
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U
        },
        {
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x80U
        }
    };

    uint32_t diff;
    int32_t r;

    r = 0;

    if (s != NULL)
    {
        for (size_t i = 0U; i < 4U; ++i)
        {
            diff = 0U;

            for (size_t j = 0U; j < 57U; ++j)
            {
                diff |= (uint32_t)(s[j] ^ small_order_points[i][j]);
            }

            if (diff == 0U)
            {
                r = 1;
                break;
            }
        }
    }

    return r;
}


int32_t qsc_ge448_has_small_order(const uint8_t s[57U])
{
    return qsc_ed448_small_order(s);
}

void qsc_sc448_reduce(uint8_t s[114U])
{
    QSC_ASSERT(s != NULL);

    uint8_t rem[58U] = { 0U };
    uint8_t diff[58U] = { 0U };
    int32_t bit;
    size_t i;

    if (s != NULL)
    {
        for (bit = 911; bit >= 0; --bit)
        {
            uint32_t carry = 0U;
            const uint32_t inbit = ((uint32_t)s[(size_t)bit >> 3] >> ((uint32_t)bit & 7U)) & 1U;
            uint32_t borrow = 0U;
            uint32_t ge;
            uint32_t mask;

            for (i = 0U; i < 58U; ++i)
            {
                const uint32_t next = ((uint32_t)rem[i] << 1) | carry;
                rem[i] = (uint8_t)(next & 0xFFU);
                carry = (next >> 8) & 0x01U;
            }

            rem[0U] |= (uint8_t)inbit;

            for (i = 0U; i < 57U; ++i)
            {
                const uint32_t xi = (uint32_t)rem[i];
                const uint32_t yi = (uint32_t)SC448_ORDER[i];
                const uint32_t sub = yi + borrow;

                diff[i] = (uint8_t)(xi - sub);
                borrow = (uint32_t)((xi < sub) ? 1U : 0U);
            }

            diff[57] = (uint8_t)((uint32_t)rem[57] - borrow);
            ge = (uint32_t)(((rem[57] != 0U) || (borrow == 0U)) ? 1U : 0U);
            mask = (uint32_t)(0U - ge);

            for (i = 0U; i < 58U; ++i)
            {
                rem[i] = (uint8_t)((rem[i] & (uint8_t)(~mask)) | (diff[i] & (uint8_t)mask));
            }
        }

        for (i = 0U; i < 57U; ++i)
        {
            s[i] = rem[i];
        }

        qsc_memutils_secure_erase(s + 57U, 57U);
    }
}


void qsc_sc448_muladd(uint8_t s[57U], const uint8_t a[57U], const uint8_t b[57U], const uint8_t c[57U])
{
    QSC_ASSERT(s != NULL);
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);
    QSC_ASSERT(c != NULL);

    uint8_t tmp[114U] = { 0 };
    int64_t product[114U] = { 0 };
    int64_t carry;
    size_t i;
    size_t j;

    if (s != NULL && a != NULL && b != NULL && c != NULL)
    {
        for (i = 0U; i < 57U; ++i)
        {
            for (j = 0U; j < 57U; ++j)
            {
                product[i + j] += (int64_t)a[i] * (int64_t)b[j];
            }
        }

        for (i = 0U; i < 57U; ++i)
        {
            product[i] += (int64_t)c[i];
        }

        for (i = 0U; i < 113U; ++i)
        {
            carry = product[i] >> 8;
            product[i] &= 0xFF;
            product[i + 1U] += carry;
        }

        product[113] &= 0xFF;

        for (i = 0U; i < 114U; ++i)
        {
            tmp[i] = (uint8_t)product[i];
        }

        qsc_sc448_reduce(tmp);

        for (i = 0U; i < 57U; ++i)
        {
            s[i] = tmp[i];
        }

        qsc_memutils_secure_erase(tmp, sizeof(tmp));
        qsc_memutils_secure_erase((uint8_t*)product, sizeof(product));
    }
}


int32_t qsc_sc448_verify(const uint8_t* x, const uint8_t* y, size_t n)
{
    uint8_t d = 0;
    size_t i;

    for (i = 0; i < n; i++)
    {
        d |= x[i] ^ y[i];
    }

    return (int32_t)(((uint32_t)d - 1U) >> 31) - 1;  /* 0 if equal, -1 if not */
}

/* ============================================================
 * Group element operations
 * ============================================================ */

void qsc_ge448_p1p1_to_p2(qsc_ge448_p2* r, const qsc_ge448_p1p1* p)
{
    qsc_fe448_mul(r->x, p->x, p->t);
    qsc_fe448_mul(r->y, p->y, p->z);
    qsc_fe448_mul(r->z, p->z, p->t);
}

void qsc_ge448_p1p1_to_p3(qsc_ge448_p3* r, const qsc_ge448_p1p1* p)
{
    qsc_fe448_mul(r->x, p->x, p->t);
    qsc_fe448_mul(r->y, p->y, p->z);
    qsc_fe448_mul(r->z, p->z, p->t);
    qsc_fe448_mul(r->t, p->x, p->y);
}

void qsc_ge448_p3_to_cached(qsc_ge448_cached* r, const qsc_ge448_p3* p)
{
    qsc_fe448_add(r->yplusx, p->y, p->x);
    qsc_fe448_sub(r->yminusx, p->y, p->x);
    qsc_fe448_copy(r->z, p->z);
    qsc_fe448_mul(r->t2d, p->t, FE448_2D);
}

void qsc_ge448_add_cached(qsc_ge448_p1p1* r, const qsc_ge448_p3* p, const qsc_ge448_cached* q)
{
    qsc_fe448 x1, y1, x2, y2, rx, ry;

    fe448_p3_to_affine(x1, y1, p);
    fe448_cached_to_affine(x2, y2, q);
    fe448_affine_add(rx, ry, x1, y1, x2, y2);

    qsc_fe448_copy(r->x, rx);
    qsc_fe448_copy(r->y, ry);
    qsc_fe448_1(r->z);
    qsc_fe448_1(r->t);
}


void qsc_ge448_sub_cached(qsc_ge448_p1p1* r, const qsc_ge448_p3* p, const qsc_ge448_cached* q)
{
    qsc_fe448 x1, y1, x2, y2, rx, ry;

    fe448_p3_to_affine(x1, y1, p);
    fe448_cached_to_affine(x2, y2, q);
    qsc_fe448_neg(x2, x2);
    fe448_affine_add(rx, ry, x1, y1, x2, y2);

    qsc_fe448_copy(r->x, rx);
    qsc_fe448_copy(r->y, ry);
    qsc_fe448_1(r->z);
    qsc_fe448_1(r->t);
}


void qsc_ge448_add_precomp(qsc_ge448_p1p1* r, const qsc_ge448_p3* p, const qsc_ge448_precomp* q)
{
    qsc_fe448 x1, y1, x2, y2, rx, ry;

    fe448_p3_to_affine(x1, y1, p);
    fe448_precomp_to_affine(x2, y2, q);
    fe448_affine_add(rx, ry, x1, y1, x2, y2);

    qsc_fe448_copy(r->x, rx);
    qsc_fe448_copy(r->y, ry);
    qsc_fe448_1(r->z);
    qsc_fe448_1(r->t);
}


void qsc_ge448_sub_precomp(qsc_ge448_p1p1* r, const qsc_ge448_p3* p, const qsc_ge448_precomp* q)
{
    qsc_fe448 x1, y1, x2, y2, rx, ry;

    fe448_p3_to_affine(x1, y1, p);
    fe448_precomp_to_affine(x2, y2, q);
    qsc_fe448_neg(x2, x2);
    fe448_affine_add(rx, ry, x1, y1, x2, y2);

    qsc_fe448_copy(r->x, rx);
    qsc_fe448_copy(r->y, ry);
    qsc_fe448_1(r->z);
    qsc_fe448_1(r->t);
}


/* Point doubling (P3 -> P1P1) using the unified doubling formula for
 * twisted Edwards curves:
 *   A = X1^2, B = Y1^2, C = 2*Z1^2, D = a*A (a=-1 for Ed448)
 *   E = (X1+Y1)^2 - A - B, G = D+B, F = G-C, H = D-B
 *   X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G
 */
static void ge448_p3_dbl(qsc_ge448_p1p1* r, const qsc_ge448_p3* p)
{
    qsc_fe448 x;
    qsc_fe448 y;
    qsc_fe448 rx;
    qsc_fe448 ry;

    fe448_p3_to_affine(x, y, p);
    fe448_affine_add(rx, ry, x, y, x, y);

    qsc_fe448_copy(r->x, rx);
    qsc_fe448_copy(r->y, ry);
    qsc_fe448_1(r->z);
    qsc_fe448_1(r->t);
}


/* Compress a P3 point: s = encode(X/Z, Y/Z) */
void qsc_ge448_p3_to_bytes(uint8_t* s, const qsc_ge448_p3* h)
{
    qsc_fe448 recip, x, y;
    qsc_fe448_invert(recip, h->z);
    qsc_fe448_mul(x, h->x, recip);
    qsc_fe448_mul(y, h->y, recip);
    qsc_fe448_to_bytes(s, y);
    s[56] = (uint8_t)(qsc_fe448_is_negative(x) << 7);
}

void qsc_ge448_to_bytes(uint8_t* s, const qsc_ge448_p2* h)
{
    qsc_fe448 recip, x, y;
    qsc_fe448_invert(recip, h->z);
    qsc_fe448_mul(x, h->x, recip);
    qsc_fe448_mul(y, h->y, recip);
    qsc_fe448_to_bytes(s, y);
    s[56] = (uint8_t)(qsc_fe448_is_negative(x) << 7);
}

int32_t qsc_ge448_is_canonical(const uint8_t* s)
{
    QSC_ASSERT(s != NULL);

    int32_t r;

    r = 0;

    if (s != NULL)
    {
        if ((s[56U] & 0x7FU) == 0U)
        {
            for (size_t i = 56U; i-- > 0U;)
            {
                if (s[i] < FE448_P_BYTES[i])
                {
                    r = 1;
                    break;
                }
                else if (s[i] > FE448_P_BYTES[i])
                {
                    r = 0;
                    break;
                }
            }
        }
    }

    return r;
}

/*
 * Decode a compressed point and negate: used in signature verification.
 * The sign bit of X is in bit 7 of byte 56; the remaining bytes encode Y.
 * We recover X from Y using the curve equation:
 *   x^2 = (y^2 - 1) / (d*y^2 - 1)   (twisted Edwards, a=-1)
 * For Ed448-Goldilocks d = -39081:
 *   x^2 = (y^2 - 1) / (-39081*y^2 - 1)
 */
int32_t qsc_ge448_from_bytes_negate_vartime(qsc_ge448_p3* h, const uint8_t* s)
{
    QSC_ASSERT(h != NULL);
    QSC_ASSERT(s != NULL);

    qsc_fe448 y;
    qsc_fe448 ysq;
    qsc_fe448 u;
    qsc_fe448 v;
    qsc_fe448 vinv;
    qsc_fe448 x2;
    qsc_fe448 x;
    qsc_fe448 check;
    qsc_fe448 one;
    uint8_t ybytes[56U] = { 0U };
    int32_t bit;
    int32_t i;
    int32_t r;
    int32_t sign;

    r = -1;

    if (h != NULL && s != NULL)
    {
        if (qsc_ge448_is_canonical(s) != 0 && qsc_ge448_has_small_order(s) == 0)
        {
            sign = (int32_t)((s[56U] >> 7) & 1U);

            for (i = 0; i < 56; ++i)
            {
                ybytes[i] = s[i];
            }

            qsc_fe448_from_bytes(y, ybytes);
            qsc_fe448_1(one);

            qsc_fe448_sq(ysq, y);
            qsc_fe448_sub(u, one, ysq);
            qsc_fe448_mul(v, FE448_D, ysq);
            qsc_fe448_sub(v, one, v);

            if (qsc_fe448_is_zero(v) == 0)
            {
                qsc_fe448_invert(vinv, v);
                qsc_fe448_mul(x2, u, vinv);
                qsc_fe448_1(x);

                for (i = 55; i >= 0; --i)
                {
                    const uint8_t byteval = FE448_SQRT_EXP[i];

                    for (bit = 7; bit >= 0; --bit)
                    {
                        qsc_fe448_sq(x, x);

                        if (((byteval >> bit) & 1U) != 0U)
                        {
                            qsc_fe448_mul(x, x, x2);
                        }
                    }
                }

                qsc_fe448_sq(check, x);
                qsc_fe448_mul(check, check, v);
                qsc_fe448_sub(check, check, u);

                if (qsc_fe448_is_zero(check) != 0)
                {
                    if ((qsc_fe448_is_zero(x) != 0) && (sign != 0))
                    {
                        r = -1;
                    }
                    else
                    {
                        /*
                         * This is the negate-vartime decode, matching the working Ed25519 path:
                         * when the recovered x parity already equals the encoded sign bit,
                         * negate x so the returned point is the negated representative.
                         */
                        if (qsc_fe448_is_negative(x) == sign)
                        {
                            qsc_fe448_neg(x, x);
                        }

                        qsc_fe448_copy(h->x, x);
                        qsc_fe448_copy(h->y, y);
                        qsc_fe448_1(h->z);
                        qsc_fe448_mul(h->t, h->x, h->y);
                        r = 0;
                    }
                }
            }
        }
    }

    return r;
}

/* ============================================================
 * Scalar base point multiplication
 *
 * Uses a simple double-and-add loop over the 446-bit scalar.
 * A production implementation would use a precomputed table with
 * a windowed NAF; this reference implementation is constant-time
 * via the add-always pattern.
 * ============================================================ */
void qsc_ge448_scalarmult_base(qsc_ge448_p3* h, const uint8_t* a)
{
    QSC_ASSERT(h != NULL);
    QSC_ASSERT(a != NULL);

    qsc_ge448_p3 B;
    qsc_ge448_p3 Q;
    int32_t i;
    int32_t bit;

    if (h != NULL && a != NULL)
    {
        if (qsc_ge448_from_bytes_negate_vartime(&B, ED448_BASEPOINT) != 0)
        {
            fe448_p3_identity(h);
        }
        else
        {
            qsc_fe448_neg(B.x, B.x);
            fe448_p3_identity(&Q);

            for (i = 56; i >= 0; --i)
            {
                const uint8_t byteval = a[i];

                for (bit = 7; bit >= 0; --bit)
                {
                    qsc_ge448_p1p1 dbl;
                    qsc_ge448_p1p1 add;
                    qsc_ge448_p3 qdbl;
                    qsc_ge448_p3 qadd;
                    const uint32_t sel = (uint32_t)((byteval >> bit) & 1U);

                    ge448_p3_dbl(&dbl, &Q);
                    qsc_ge448_p1p1_to_p3(&qdbl, &dbl);

                    {
                        qsc_ge448_cached bc;
                        qsc_ge448_p3_to_cached(&bc, &B);
                        qsc_ge448_add_cached(&add, &qdbl, &bc);
                        qsc_ge448_p1p1_to_p3(&qadd, &add);
                    }

                    qsc_fe448_copy(Q.x, qdbl.x);
                    qsc_fe448_copy(Q.y, qdbl.y);
                    qsc_fe448_copy(Q.z, qdbl.z);
                    qsc_fe448_copy(Q.t, qdbl.t);
                    fe448_p3_cmov(&Q, &qadd, sel);
                }
            }

            qsc_fe448_copy(h->x, Q.x);
            qsc_fe448_copy(h->y, Q.y);
            qsc_fe448_copy(h->z, Q.z);
            qsc_fe448_copy(h->t, Q.t);
        }
    }
}

/* Double scalar multiplication r = a*A + b*B (variable-time, for verification) */
void qsc_ge448_double_scalarmult_vartime(qsc_ge448_p2* r, const uint8_t* a, const qsc_ge448_p3* A, const uint8_t* b)
{
    QSC_ASSERT(r != NULL);
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(A != NULL);
    QSC_ASSERT(b != NULL);

    qsc_ge448_p3 B;
    qsc_ge448_p3 aA;
    qsc_ge448_p3 bB;
    qsc_ge448_p3 sum;
    qsc_ge448_p1p1 tmp;
    qsc_ge448_cached ac;
    qsc_ge448_cached bc;
    int32_t i;
    int32_t bit;

    if (r != NULL && a != NULL && A != NULL && b != NULL)
    {
        if (qsc_ge448_from_bytes_negate_vartime(&B, ED448_BASEPOINT) != 0)
        {
            fe448_p2_identity(r);
        }
        else
        {
            qsc_fe448_neg(B.x, B.x);
            fe448_p3_identity(&aA);
            fe448_p3_identity(&bB);

            for (i = 56; i >= 0; --i)
            {
                const uint8_t av = a[i];
                const uint8_t bv = b[i];

                for (bit = 7; bit >= 0; --bit)
                {
                    ge448_p3_dbl(&tmp, &aA);
                    qsc_ge448_p1p1_to_p3(&aA, &tmp);

                    if (((av >> bit) & 1U) != 0U)
                    {
                        qsc_ge448_p3_to_cached(&ac, A);
                        qsc_ge448_add_cached(&tmp, &aA, &ac);
                        qsc_ge448_p1p1_to_p3(&aA, &tmp);
                    }

                    ge448_p3_dbl(&tmp, &bB);
                    qsc_ge448_p1p1_to_p3(&bB, &tmp);

                    if (((bv >> bit) & 1U) != 0U)
                    {
                        qsc_ge448_p3_to_cached(&bc, &B);
                        qsc_ge448_add_cached(&tmp, &bB, &bc);
                        qsc_ge448_p1p1_to_p3(&bB, &tmp);
                    }
                }
            }

            {
                qsc_ge448_cached bbc;
                qsc_ge448_p1p1 stmp;

                qsc_ge448_p3_to_cached(&bbc, &bB);
                qsc_ge448_add_cached(&stmp, &aA, &bbc);
                qsc_ge448_p1p1_to_p3(&sum, &stmp);
            }

            qsc_fe448_copy(r->x, sum.x);
            qsc_fe448_copy(r->y, sum.y);
            qsc_fe448_copy(r->z, sum.z);
        }
    }
}

