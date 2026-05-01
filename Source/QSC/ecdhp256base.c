#include "ecdhp256base.h"
#include "memutils.h"
#include "sha2.h"


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

static void fe256_zero(fe256 r)
{
    for (int32_t i = 0; i < 8; ++i) 
    { 
        r[i] = 0U; 
    }
}

static void fe256_one(fe256 r)
{
    r[0U] = 1U;

    for (int32_t i = 1; i < 8; ++i) 
    { 
        r[i] = 0U; 
    }
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

static void p256_jac_ct_select(p256_jac_t* r, uint32_t sel, const p256_jac_t* a, const p256_jac_t* b)
{
    /* constant-time Jacobian point select */
    fe256_ct_select(r->X, sel, a->X, b->X);
    fe256_ct_select(r->Y, sel, a->Y, b->Y);
    fe256_ct_select(r->Z, sel, a->Z, b->Z);
}

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

static uint32_t ct_select_u32(uint32_t a, uint32_t b, uint32_t mask)
{
    return (a & ~mask) | (b & mask);
}

static void ct_select_8x32(uint32_t dst[8U], const uint32_t a[8U], const uint32_t b[8U], uint32_t mask)
{
    size_t i;

    for (i = 0U; i < 8U; ++i)
    {
        dst[i] = (a[i] & ~mask) | (b[i] & mask);
    }
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

static void fe256_reduce512(fe256 r, const uint32_t c[16U])
{
    /* conservative correctness-first reduction of a 512-bit value modulo p.
     * replaces the signed Solinas folding logic with a generic modular reducer. */
    mod_reduce512_generic(r, c, P256_P);
}

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

static void fe_set_one(uint32_t x[8U])
{
    size_t i;

    x[0] = 1U;

    for (i = 1U; i < 8U; ++i)
    {
        x[i] = 0U;
    }
}

static void fe_copy(uint32_t dst[8U], const uint32_t src[8U])
{
    size_t i;

    for (i = 0U; i < 8U; ++i)
    {
        dst[i] = src[i];
    }
}

static void fe_mul(fe256 r, const fe256 a, const fe256 b)
{
    /* r = a * b mod p */
    uint32_t c[16U] = { 0U };

    fe256_mul_raw(c, a, b);
    fe256_reduce512(r, c);
}

static void fe_sqr(fe256 r, const fe256 a)
{
    /* r = a^2 mod p */
    fe_mul(r, a, a);
}

static void fe_mul_small(fe256 r, const fe256 a, uint32_t k)
{
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
}

static void fe_inv(uint32_t r[8U], const uint32_t a[8U])
{
    static const uint32_t p_minus_2[8U] =
    {
        0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
        0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU
    };

    uint32_t base[8U] = { 0U };
    uint32_t acc[8U] = { 0U };
    uint32_t tmp[8U] = { 0U };
    uint32_t mask;
    uint32_t bit;
    int32_t i;
    int32_t j;

    fe_copy(base, a);
    fe_set_one(acc);

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
}

/* Scalar arithmetic mod n (Barrett reduction) */

static void sc256_mul_raw(uint32_t c[16U], const uint32_t a[8U], const uint32_t b[8U])
{
    /* 256x256 -> 512-bit schoolbook multiplication (same as fe256_mul_raw,
     * reused for scalar field - separate alias for clarity). */
    fe256_mul_raw(c, a, b);
}

static void sc256_reduce512(uint32_t r[8U], const uint32_t c[16U])
{
    /*
     * conservative correctness-first reduction of a 512-bit value modulo n.
     * replaces the previous Barrett reduction implementation.
     */
    mod_reduce512_generic(r, c, P256_N);
}

static void sc_set_one(uint32_t x[8U])
{
    size_t i;

    x[0U] = 1U;

    for (i = 1U; i < 8U; ++i)
    {
        x[i] = 0U;
    }
}

static void sc_copy(uint32_t dst[8U], const uint32_t src[8U])
{
    size_t i;

    for (i = 0U; i < 8U; ++i)
    {
        dst[i] = src[i];
    }
}

static void sc_mul(uint32_t r[8U], const uint32_t a[8U], const uint32_t b[8U])
{
    /* r = a * b mod n */
    uint32_t c[16U] = { 0U };

    sc256_mul_raw(c, a, b);
    sc256_reduce512(r, c);
}

static void sc_sqr(uint32_t r[8U], const uint32_t a[8U])
{
    uint32_t t[8U] = { 0U };

    sc_mul(t, a, a);
    sc_copy(r, t);
}

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

static void p256_aff_to_jac(p256_jac_t* R, const p256_aff_t* P)
{
    /* lift an affine point to Jacobian (Z = 1) */
    fe256_copy(R->X, P->X);
    fe256_copy(R->Y, P->Y);
    fe256_one(R->Z);
}

static void p256_set_infinity(p256_jac_t* R)
{
    /* set Jacobian point to the point at infinity */
    fe256_zero(R->X);
    fe256_one(R->Y);
    fe256_zero(R->Z);
}

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
     * Constant-time Jacobian addition with masked exceptional-case handling.
     *
     * Cases handled without branches:
     *   1. P = inf  -> R = Q
     *   2. Q = inf  -> R = P
     *   3. P = Q    -> R = 2P
     *   4. P = -Q   -> R = inf
     *   5. general  -> standard add-2007-bl result
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
    p256_jac_t Rdbl;
    p256_jac_t Rinf;
    uint32_t pinf;
    uint32_t qinf;
    uint32_t h_zero;
    uint32_t r_zero;
    uint32_t same_point;
    uint32_t opposite_point;
    uint32_t general_case;
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

    /* doubling candidate */
    p256_dbl(&Rdbl, P);

    /* infinity candidate */
    p256_set_infinity(&Rinf);

    /* masks */
    pinf = p256_is_infinity(P);
    qinf = p256_is_infinity(Q);
    h_zero = fe256_is_zero(h);
    r_zero = fe256_is_zero(r2);

    same_point = h_zero & r_zero;
    opposite_point = h_zero & (r_zero ^ 1U);

    /* general case is only selected when no exceptional case applies */
    general_case = (pinf | qinf | same_point | opposite_point) ^ 1U;

    /* start from infinity so all paths are explicit */
    p256_set_infinity(&T);

    /* general add */
    p256_jac_ct_select(&T, general_case, &Radd, &T);

    /* P == Q */
    p256_jac_ct_select(&T, same_point, &Rdbl, &T);

    /* P == -Q */
    p256_jac_ct_select(&T, opposite_point, &Rinf, &T);

    /* Q = inf => R = P */
    p256_jac_ct_select(&T, qinf, P, &T);

    /* P = inf => R = Q */
    p256_jac_ct_select(&T, pinf, Q, &T);

    *R = T;

    qsc_memutils_secure_erase(&Radd, sizeof(Radd));
    qsc_memutils_secure_erase(&Rdbl, sizeof(Rdbl));
    qsc_memutils_secure_erase(&Rinf, sizeof(Rinf));
    qsc_memutils_secure_erase(&T, sizeof(T));
}

static void p256_scalar_mult(p256_jac_t* R, const p256_aff_t* P, const uint32_t k[8U])
{
    /*
     * Montgomery ladder style scalar multiplication.
     *
     * Invariant before each bit step:
     *   R1 = R0 + P
     *
     * For each scalar bit b:
     *   if b == 0:
     *       R1 <- R0 + R1
     *       R0 <- 2 * R0
     *   else
     *       R0 <- R0 + R1
     *       R1 <- 2 * R1
     */

    p256_jac_t R0;
    p256_jac_t R1;
    p256_jac_t A;
    p256_jac_t D0;
    p256_jac_t D1;

    p256_set_infinity(&R0);
    p256_aff_to_jac(&R1, P);

    for (int32_t i = 255; i >= 0; --i)
    {
        uint32_t bit;

        /* A  = R0 + R1 */
        p256_add(&A, &R0, &R1);

        /* D0 = 2 * R0 */
        p256_dbl(&D0, &R0);

        /* D1 = 2 * R1 */
        p256_dbl(&D1, &R1);

        bit = (k[i / 32] >> (i % 32)) & 1U;

        /* if bit == 0: R0 = D0, R1 = A
         * if bit == 1: R0 = A,  R1 = D1
         */
        p256_jac_ct_select(&R0, bit, &A, &D0);
        p256_jac_ct_select(&R1, bit, &D1, &A);
    }

    *R = R0;

    qsc_memutils_secure_erase(&R0, sizeof(R0));
    qsc_memutils_secure_erase(&R1, sizeof(R1));
    qsc_memutils_secure_erase(&A, sizeof(A));
    qsc_memutils_secure_erase(&D0, sizeof(D0));
    qsc_memutils_secure_erase(&D1, sizeof(D1));
}

static bool p256_jac_to_aff(p256_aff_t* R, const p256_jac_t* P)
{
    /* convert Jacobian to affine: (X:Y:Z) -> (X/Z^2, Y/Z^3) */
    fe256 zinv, zinv2, zinv3;

    if (p256_is_infinity(P)) { return false; }

    fe_inv(zinv, P->Z);
    fe_sqr(zinv2, zinv);
    fe_mul(zinv3, zinv2, zinv);

    fe_mul(R->X, P->X, zinv2);
    fe_mul(R->Y, P->Y, zinv3);

    return true;
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
    fe_add(rhs, rhs, (const uint32_t*)P256_B);

    return (fe256_cmp(y2, rhs) == 0);
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
        else if (fe256_cmp(d, P256_N) >= 0)
        {
            ret = -3;
        }
        else
        {
            fe256_copy(G.X, P256_GX);
            fe256_copy(G.Y, P256_GY);
            p256_scalar_mult(&R, &G, d);

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
                fe256_to_bytes(publickey, Q.X);
                fe256_to_bytes(publickey + 32U, Q.Y);
                ret = 0;
            }
        }
    }

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
        else if (fe256_cmp(d, P256_N) >= 0)
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
            else if (p256_point_is_on_curve(&Q) == false)
            {
                ret = -5;
            }
            else
            {
                p256_scalar_mult(&J, &Q, d);

                if (p256_is_infinity(&J) != 0U)
                {
                    ret = -6;
                }
                else if (p256_jac_to_aff(&S, &J) != true)
                {
                    ret = -7;
                }
                else if (fe256_is_zero(S.X) != 0U)
                {
                    ret = -8;
                }
                else
                {
                    fe256_to_bytes(secret, S.X);
                    ret = 0;
                }
            }
        }
    }

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

    uint8_t acc;
    int32_t ret;

    acc = 0U;
    ret = -1;

    if (secret != NULL && publickey != NULL && privatekey != NULL)
    {
        ret = qsc_crypto_scalarmult_secp256r1(secret, privatekey, publickey);

        if (ret == 0)
        {
            for (size_t i = 0U; i < QSC_ECDHP256_SHAREDSECRET_SIZE; ++i)
            {
                acc |= secret[i];
            }
        }
    }

    return (ret == 0 && acc != 0U);
}
