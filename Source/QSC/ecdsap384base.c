
#include "ecdsap384base.h"
#include "memutils.h"
#include "sha2.h"

/* 384-bit field element: 12 x uint32_t, little-endian (word 0 is least significant) */
typedef uint32_t fe384[12U];

/* jacobian projective point over P-384 (X:Y:Z), affine = (X/Z^2, Y/Z^3) */
typedef struct { fe384 X; fe384 Y; fe384 Z; } p384_jac_t;

/* affine point over P-384 */
typedef struct { fe384 X; fe384 Y; } p384_aff_t;

/* field prime: p = 2^384 - 2^128 - 2^96 + 2^32 - 1 */
static const uint32_t P384_P[12U] =
{
    0xFFFFFFFFU, 0x00000000U, 0x00000000U, 0xFFFFFFFFU,
    0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU
};

/* group order: n */
static const uint32_t P384_N[12U] =
{
    0xCCC52973U, 0xECEC196AU, 0x48B0A77AU, 0x581A0DB2U,
    0xF4372DDFU, 0xC7634D81U, 0xFFFFFFFFU, 0xFFFFFFFFU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU
};

/* n-2 (for Fermat modular inverse mod n) */
static const uint32_t P384_N2[12U] =
{
    0xCCC52971U, 0xECEC196AU, 0x48B0A77AU, 0x581A0DB2U,
    0xF4372DDFU, 0xC7634D81U, 0xFFFFFFFFU, 0xFFFFFFFFU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU
};

/* p-2 (for Fermat field inversion mod p) */
static const uint32_t P384_P2[12U] =
{
    0xFFFFFFFDU, 0x00000000U, 0x00000000U, 0xFFFFFFFFU,
    0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU
};

/* base point Gx */
static const uint32_t P384_GX[12U] =
{
    0x72760AB7U, 0x3A545E38U, 0xBF55296CU, 0x5502F25DU,
    0x82542A38U, 0x59F741E0U, 0x8BA79B98U, 0x6E1D3B62U,
    0xF320AD74U, 0x8EB1C71EU, 0xBE8B0537U, 0xAA87CA22U
};

/* base point Gy */
static const uint32_t P384_GY[12U] =
{
    0x90EA0E5FU, 0x7A431D7CU, 0x1D7E819DU, 0x0A60B1CEU,
    0xB5F0B8C0U, 0xE9DA3113U, 0x289A147CU, 0xF8F41DBDU,
    0x9292DC29U, 0x5D9E98BFU, 0x96262C6FU, 0x3617DE4AU
};

/* curve coefficient b */
static const uint32_t P384_B[12U] =
{
    0xD3EC2AEFU, 0x2A85C8EDU, 0x8A2ED19DU, 0xC656398DU,
    0x5013875AU, 0x0314088FU, 0xFE814112U, 0x181D9C6EU,
    0xE3F82D19U, 0x988E056BU, 0xE23EE7E4U, 0xB3312FA7U
};

static void fe384_select(uint32_t* r, const uint32_t* a, const uint32_t* b, uint32_t mask)
{
    size_t i;

    for (i = 0U; i < 12U; ++i)
    {
        r[i] = (a[i] & mask) | (b[i] & ~mask);
    }
}

static void fe384_copy(fe384 r, const fe384 a)
{
    size_t i;

    for (i = 0U; i < 12U; ++i)
    {
        r[i] = a[i];
    }
}

static void fe384_zero(fe384 r)
{
    size_t i;

    for (i = 0U; i < 12U; ++i)
    {
        r[i] = 0U;
    }
}

static void fe384_one(fe384 r)
{
    r[0U] = 1U;

    for (size_t i = 1U; i < 12U; ++i)
    {
        r[i] = 0U;
    }
}

static uint32_t fe384_is_zero(const fe384 a)
{
    uint32_t t;
    size_t i;

    t = 0U;

    for (i = 0U; i < 12U; ++i)
    {
        t |= a[i];
    }

    t = (t | (0U - t)) >> 31U;

    return (1U - t);
}

static int32_t fe384_cmp(const uint32_t* a, const uint32_t* b)
{
    uint64_t ai;
    uint32_t aigtbi;
    uint32_t ailtbi;
    uint64_t bi;
    uint32_t gt;
    uint32_t lt;
    uint32_t undecided;
    int32_t i;

    gt = 0U;
    lt = 0U;

    for (i = 11; i >= 0; --i)
    {
        ai = (uint64_t)a[i];
        bi = (uint64_t)b[i];

        aigtbi = (uint32_t)((bi - ai) >> 63);
        ailtbi = (uint32_t)((ai - bi) >> 63);
        undecided = (uint32_t)(1U ^ (gt | lt));

        gt |= aigtbi & undecided;
        lt |= ailtbi & undecided;
    }

    return (gt != 0U) ? 1 : ((lt != 0U) ? -1 : 0);
}

static uint32_t ct_sel32(uint32_t sel, uint32_t a, uint32_t b)
{
    uint32_t mask;

    mask = (uint32_t)(0U - sel);

    return (a & mask) | (b & ~mask);
}

static void fe384_ct_select(fe384 r, uint32_t sel, const fe384 a, const fe384 b)
{
    size_t i;

    for (i = 0U; i < 12U; ++i)
    {
        r[i] = ct_sel32(sel, a[i], b[i]);
    }
}

static void p384_jac_ct_select(p384_jac_t* r, uint32_t sel, const p384_jac_t* a, const p384_jac_t* b)
{
    fe384_ct_select(r->X, sel, a->X, b->X);
    fe384_ct_select(r->Y, sel, a->Y, b->Y);
    fe384_ct_select(r->Z, sel, a->Z, b->Z);
}

static void fe384_from_bytes(fe384 r, const uint8_t* b)
{
    size_t i;

    for (i = 0U; i < 12U; ++i)
    {
        const uint8_t* p = b + (4U * (11U - i));

        r[i] = ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U)
             | ((uint32_t)p[2] << 8U)  |  (uint32_t)p[3];
    }
}

static void fe384_to_bytes(uint8_t* b, const fe384 r)
{
    size_t i;

    for (i = 0U; i < 12U; ++i)
    {
        uint8_t* p = b + (4U * (11U - i));

        p[0U] = (uint8_t)(r[i] >> 24U);
        p[1U] = (uint8_t)(r[i] >> 16U);
        p[2U] = (uint8_t)(r[i] >> 8U);
        p[3U] = (uint8_t)(r[i]);
    }
}

static void fe384_cond_sub(uint32_t r[12U], const uint32_t mod[12U])
{
    uint32_t tmp[12U] = { 0U };
    uint64_t borrow;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 12U; ++i)
    {
        borrow = (uint64_t)r[i] - mod[i] - borrow;
        tmp[i] = (uint32_t)borrow;
        borrow = (borrow >> 32U) & 1U;
    }

    fe384_ct_select(r, (uint32_t)(1U - (uint32_t)borrow), tmp, r);
}

static void fe_sub(uint32_t* r, const uint32_t* a, const uint32_t* b)
{
    uint32_t t[12U] = { 0U };
    uint64_t borrow;
    uint64_t carry;
    uint64_t ta;
    uint64_t x;
    uint32_t mask;
    size_t i;

    borrow = 0ULL;

    for (i = 0U; i < 12U; ++i)
    {
        ta = (uint64_t)a[i] - b[i] - borrow;
        r[i] = (uint32_t)ta;
        borrow = (ta >> 63U) & 1ULL;
    }

    carry = 0ULL;

    for (i = 0U; i < 12U; ++i)
    {
        x = (uint64_t)r[i] + P384_P[i] + carry;
        t[i] = (uint32_t)x;
        carry = x >> 32U;
    }

    mask = (uint32_t)-(int32_t)borrow;

    fe384_select(r, t, r, mask);
}

static uint32_t ct_ge_13x32(const uint32_t a[13U], const uint32_t b[13U])
{
    uint64_t diff;
    uint32_t borrow;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 13U; ++i)
    {
        diff = (uint64_t)a[i] - (uint64_t)b[i] - (uint64_t)borrow;
        borrow = (uint32_t)((diff >> 63U) & 1U);
    }

    return (uint32_t)(borrow ^ 1U);
}

static void ct_sub_13x32(uint32_t out[13U], const uint32_t a[13U], const uint32_t b[13U])
{
    uint64_t diff;
    uint32_t borrow;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 13U; ++i)
    {
        diff = (uint64_t)a[i] - (uint64_t)b[i] - (uint64_t)borrow;
        out[i] = (uint32_t)diff;
        borrow = (uint32_t)((diff >> 63U) & 1U);
    }
}

static void mod_reduce768_generic(uint32_t out[12U], const uint32_t in[24U], const uint32_t mod[12U])
{
    uint32_t rem[13U];
    uint32_t sub[13U];
    uint32_t mod13[13U];
    uint32_t carry;
    uint32_t bit;
    uint32_t ge;
    uint32_t mask;
    int32_t i;
    size_t j;

    for (j = 0U; j < 12U; ++j)
    {
        mod13[j] = mod[j];
    }

    mod13[12U] = 0U;

    for (j = 0U; j < 13U; ++j)
    {
        rem[j] = 0U;
    }

    for (i = 767; i >= 0; --i)
    {
        bit = (in[(size_t)i >> 5] >> ((uint32_t)i & 31U)) & 1U;
        carry = bit;

        for (j = 0U; j < 13U; ++j)
        {
            uint32_t nextcarry;

            nextcarry = rem[j] >> 31U;
            rem[j] = (rem[j] << 1U) | carry;
            carry = nextcarry;
        }

        ct_sub_13x32(sub, rem, mod13);
        ge = ct_ge_13x32(rem, mod13);
        mask = (uint32_t)(0U - ge);

        for (j = 0U; j < 13U; ++j)
        {
            rem[j] = (rem[j] & ~mask) | (sub[j] & mask);
        }
    }

    for (j = 0U; j < 12U; ++j)
    {
        out[j] = rem[j];
    }

    qsc_memutils_secure_erase(rem, sizeof(rem));
    qsc_memutils_secure_erase(sub, sizeof(sub));
    qsc_memutils_secure_erase(mod13, sizeof(mod13));
}

static void fe384_reduce768(fe384 r, const uint32_t c[24U])
{
    mod_reduce768_generic(r, c, P384_P);
}

static void fe384_mul_raw(uint32_t c[24U], const fe384 a, const fe384 b)
{
    size_t i;
    size_t j;

    qsc_memutils_clear(c, 24U * sizeof(uint32_t));

    for (i = 0U; i < 12U; ++i)
    {
        uint64_t carry;

        carry = 0U;

        for (j = 0U; j < 12U; ++j)
        {
            uint64_t x;

            x = (uint64_t)c[i + j] + ((uint64_t)a[i] * (uint64_t)b[j]) + carry;
            c[i + j] = (uint32_t)x;
            carry = x >> 32U;
        }

        c[i + 12U] = (uint32_t)((uint64_t)c[i + 12U] + carry);
    }
}

static void sc384_mul_raw(uint32_t c[24U], const uint32_t a[12U], const uint32_t b[12U])
{
    fe384_mul_raw(c, a, b);
}

static void sc384_reduce768(uint32_t r[12U], const uint32_t c[24U])
{
    mod_reduce768_generic(r, c, P384_N);
}

static void fe_add(fe384 r, const fe384 a, const fe384 b)
{
    uint32_t t[13U] = { 0U };
    uint32_t mod13[13U] = { 0U };
    uint32_t sub[13U] = { 0U };
    uint64_t carry;
    uint32_t ge;
    uint32_t mask;
    size_t i;

    carry = 0U;

    for (i = 0U; i < 12U; ++i)
    {
        uint64_t x;

        x = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        t[i] = (uint32_t)x;
        carry = x >> 32U;
    }

    t[12U] = (uint32_t)carry;

    for (i = 0U; i < 12U; ++i)
    {
        mod13[i] = P384_P[i];
    }

    ct_sub_13x32(sub, t, mod13);
    ge = ct_ge_13x32(t, mod13);
    mask = (uint32_t)(0U - ge);

    for (i = 0U; i < 12U; ++i)
    {
        r[i] = (t[i] & ~mask) | (sub[i] & mask);
    }

    fe384_cond_sub(r, P384_P);
}

static void fe_mul(fe384 r, const fe384 a, const fe384 b)
{
    uint32_t c[24U] = { 0U };

    fe384_mul_raw(c, a, b);
    fe384_reduce768(r, c);
    qsc_memutils_secure_erase(c, sizeof(c));
}

static void fe_sqr(fe384 r, const fe384 a)
{
    fe_mul(r, a, a);
}

static void fe_mul_small(fe384 r, const fe384 a, uint32_t k)
{
    uint32_t c[24U] = { 0U };
    uint64_t carry;
    size_t i;

    carry = 0U;

    for (i = 0U; i < 12U; ++i)
    {
        uint64_t x;

        x = ((uint64_t)a[i] * (uint64_t)k) + carry;
        c[i] = (uint32_t)x;
        carry = x >> 32U;
    }

    c[12U] = (uint32_t)carry;
    fe384_reduce768(r, c);
    qsc_memutils_secure_erase(c, sizeof(c));
}

static void fe_inv(uint32_t r[12U], const uint32_t a[12U])
{
    fe384 base;
    fe384 acc;
    int32_t i;
    int32_t j;

    fe384_copy(base, a);
    fe384_one(acc);

    for (i = 11; i >= 0; --i)
    {
        for (j = 31; j >= 0; --j)
        {
            fe_sqr(acc, acc);

            if (((P384_P2[i] >> (uint32_t)j) & 1U) != 0U)
            {
                fe_mul(acc, acc, base);
            }
        }
    }

    fe384_copy(r, acc);
    qsc_memutils_secure_erase(base, sizeof(base));
    qsc_memutils_secure_erase(acc, sizeof(acc));
}

static void sc_set_one(uint32_t x[12U])
{
    x[0U] = 1U;

    for (size_t i = 1U; i < 12U; ++i)
    {
        x[i] = 0U;
    }
}

static void sc_copy(uint32_t dst[12U], const uint32_t src[12U])
{
    size_t i;

    for (i = 0U; i < 12U; ++i)
    {
        dst[i] = src[i];
    }
}

static void sc_sub(uint32_t r[12U], const uint32_t a[12U], const uint32_t b[12U])
{
    uint32_t t[12U] = { 0U };
    uint64_t borrow;
    uint64_t carry;
    uint64_t x;
    uint32_t mask;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 12U; ++i)
    {
        x = (uint64_t)a[i] - (uint64_t)b[i] - borrow;
        r[i] = (uint32_t)x;
        borrow = (x >> 63U) & 1U;
    }

    carry = 0U;

    for (i = 0U; i < 12U; ++i)
    {
        x = (uint64_t)r[i] + (uint64_t)P384_N[i] + carry;
        t[i] = (uint32_t)x;
        carry = x >> 32U;
    }

    mask = (uint32_t)-(int32_t)borrow;
    fe384_select(r, t, r, mask);
}

static void sc_add(uint32_t r[12U], const uint32_t a[12U], const uint32_t b[12U])
{
    uint32_t t[13U] = { 0U };
    uint32_t mod13[13U] = { 0U };
    uint32_t sub[13U] = { 0U };
    uint64_t carry;
    uint32_t ge;
    uint32_t mask;
    size_t i;

    carry = 0U;

    for (i = 0U; i < 12U; ++i)
    {
        uint64_t x;

        x = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        t[i] = (uint32_t)x;
        carry = x >> 32U;
    }

    t[12U] = (uint32_t)carry;

    for (i = 0U; i < 12U; ++i)
    {
        mod13[i] = P384_N[i];
    }

    ct_sub_13x32(sub, t, mod13);
    ge = ct_ge_13x32(t, mod13);
    mask = (uint32_t)(0U - ge);

    for (i = 0U; i < 12U; ++i)
    {
        r[i] = (t[i] & ~mask) | (sub[i] & mask);
    }

    fe384_cond_sub(r, P384_N);
}

static void sc_mul(uint32_t r[12U], const uint32_t a[12U], const uint32_t b[12U])
{
    uint32_t c[24U] = { 0U };

    sc384_mul_raw(c, a, b);
    sc384_reduce768(r, c);
    qsc_memutils_secure_erase(c, sizeof(c));
}

static void sc_sqr(uint32_t r[12U], const uint32_t a[12U])
{
    sc_mul(r, a, a);
}

static void sc_inv(uint32_t r[12U], const uint32_t a[12U])
{
    uint32_t base[12U] = { 0U };
    uint32_t acc[12U] = { 0U };
    int32_t i;
    int32_t j;

    sc_copy(base, a);
    sc_set_one(acc);

    for (i = 11; i >= 0; --i)
    {
        for (j = 31; j >= 0; --j)
        {
            sc_sqr(acc, acc);

            if (((P384_N2[i] >> (uint32_t)j) & 1U) != 0U)
            {
                sc_mul(acc, acc, base);
            }
        }
    }

    sc_copy(r, acc);
    qsc_memutils_secure_erase(base, sizeof(base));
    qsc_memutils_secure_erase(acc, sizeof(acc));
}

static void sc_from_bytes_reduce(uint32_t r[12U], const uint8_t b[48U])
{
    fe384_from_bytes(r, b);
    fe384_cond_sub(r, P384_N);
}

static uint32_t p384_is_infinity(const p384_jac_t* P)
{
    return fe384_is_zero(P->Z);
}

static void p384_aff_to_jac(p384_jac_t* R, const p384_aff_t* P)
{
    fe384_copy(R->X, P->X);
    fe384_copy(R->Y, P->Y);
    fe384_one(R->Z);
}

static void p384_set_infinity(p384_jac_t* R)
{
    fe384_zero(R->X);
    fe384_one(R->Y);
    fe384_zero(R->Z);
}

static void p384_dbl(p384_jac_t* R, const p384_jac_t* P)
{
    fe384 delta;
    fe384 gamma;
    fe384 beta;
    fe384 alpha;
    fe384 tmp;
    fe384 x3;
    fe384 y3;
    fe384 z3;

    fe_sqr(delta, P->Z);
    fe_sqr(gamma, P->Y);
    fe_mul(beta, P->X, gamma);

    fe_sub(alpha, P->X, delta);
    fe_add(tmp, P->X, delta);
    fe_mul(alpha, alpha, tmp);
    fe_mul_small(alpha, alpha, 3U);

    fe_sqr(x3, alpha);
    fe_mul_small(tmp, beta, 8U);
    fe_sub(x3, x3, tmp);

    fe_add(z3, P->Y, P->Z);
    fe_sqr(z3, z3);
    fe_sub(z3, z3, gamma);
    fe_sub(z3, z3, delta);

    fe_mul_small(tmp, beta, 4U);
    fe_sub(tmp, tmp, x3);
    fe_mul(y3, alpha, tmp);
    fe_sqr(tmp, gamma);
    fe_mul_small(tmp, tmp, 8U);
    fe_sub(y3, y3, tmp);

    fe384_copy(R->X, x3);
    fe384_copy(R->Y, y3);
    fe384_copy(R->Z, z3);
}

static void p384_add(p384_jac_t* R, const p384_jac_t* P, const p384_jac_t* Q)
{
    fe384 z1z1;
    fe384 z2z2;
    fe384 u1;
    fe384 u2;
    fe384 s1;
    fe384 s2;
    fe384 h;
    fe384 r2;
    fe384 i;
    fe384 j;
    fe384 v;
    fe384 x3;
    fe384 y3;
    fe384 z3;
    fe384 tmp;
    p384_jac_t Radd;
    p384_jac_t Rdbl;
    p384_jac_t Rinf;
    uint32_t pinf;
    uint32_t qinf;
    uint32_t h_zero;
    uint32_t r_zero;
    uint32_t same_point;
    uint32_t opposite_point;
    uint32_t general_case;
    p384_jac_t T;

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

    fe384_copy(Radd.X, x3);
    fe384_copy(Radd.Y, y3);
    fe384_copy(Radd.Z, z3);

    p384_dbl(&Rdbl, P);
    p384_set_infinity(&Rinf);

    pinf = p384_is_infinity(P);
    qinf = p384_is_infinity(Q);
    h_zero = fe384_is_zero(h);
    r_zero = fe384_is_zero(r2);

    same_point = h_zero & r_zero;
    opposite_point = h_zero & (r_zero ^ 1U);
    general_case = (pinf | qinf | same_point | opposite_point) ^ 1U;

    p384_set_infinity(&T);
    p384_jac_ct_select(&T, general_case, &Radd, &T);
    p384_jac_ct_select(&T, same_point, &Rdbl, &T);
    p384_jac_ct_select(&T, opposite_point, &Rinf, &T);
    p384_jac_ct_select(&T, qinf, P, &T);
    p384_jac_ct_select(&T, pinf, Q, &T);

    *R = T;

    qsc_memutils_secure_erase(&Radd, sizeof(Radd));
    qsc_memutils_secure_erase(&Rdbl, sizeof(Rdbl));
    qsc_memutils_secure_erase(&Rinf, sizeof(Rinf));
    qsc_memutils_secure_erase(&T, sizeof(T));
}

static void p384_scalar_mult(p384_jac_t* R, const p384_aff_t* P, const uint32_t k[12U])
{
    p384_jac_t R0;
    p384_jac_t R1;
    p384_jac_t A;
    p384_jac_t D0;
    p384_jac_t D1;
    int32_t i;

    p384_set_infinity(&R0);
    p384_aff_to_jac(&R1, P);

    for (i = 383; i >= 0; --i)
    {
        uint32_t bit;

        p384_add(&A, &R0, &R1);
        p384_dbl(&D0, &R0);
        p384_dbl(&D1, &R1);

        bit = (k[(size_t)i / 32U] >> ((uint32_t)i % 32U)) & 1U;

        p384_jac_ct_select(&R0, bit, &A, &D0);
        p384_jac_ct_select(&R1, bit, &D1, &A);
    }

    *R = R0;

    qsc_memutils_secure_erase(&R0, sizeof(R0));
    qsc_memutils_secure_erase(&R1, sizeof(R1));
    qsc_memutils_secure_erase(&A, sizeof(A));
    qsc_memutils_secure_erase(&D0, sizeof(D0));
    qsc_memutils_secure_erase(&D1, sizeof(D1));
}

static bool p384_jac_to_aff(p384_aff_t* R, const p384_jac_t* P)
{
    fe384 zinv;
    fe384 zinv2;
    fe384 zinv3;

    if (p384_is_infinity(P))
    {
        return false;
    }

    fe_inv(zinv, P->Z);
    fe_sqr(zinv2, zinv);
    fe_mul(zinv3, zinv2, zinv);

    fe_mul(R->X, P->X, zinv2);
    fe_mul(R->Y, P->Y, zinv3);

    qsc_memutils_secure_erase(zinv, sizeof(zinv));
    qsc_memutils_secure_erase(zinv2, sizeof(zinv2));
    qsc_memutils_secure_erase(zinv3, sizeof(zinv3));

    return true;
}

static bool p384_point_is_on_curve(const p384_aff_t* Q)
{
    fe384 y2;
    fe384 x3;
    fe384 ax;
    fe384 rhs;

    fe_sqr(y2, Q->Y);
    fe_sqr(x3, Q->X);
    fe_mul(x3, x3, Q->X);

    fe_mul_small(ax, Q->X, 3U);
    fe_sub(rhs, x3, ax);
    fe_add(rhs, rhs, (const uint32_t*)P384_B);

    return (fe384_cmp(y2, rhs) == 0);
}

static void rfc6979_bits2octets_p384(uint8_t out[48U], const uint8_t hash_be[48U])
{
    uint32_t z[12U] = { 0U };

    sc_from_bytes_reduce(z, hash_be);
    fe384_to_bytes(out, z);
    qsc_memutils_secure_erase(z, sizeof(z));
}

static void rfc6979_generate_k(uint32_t k_out[12U], const uint8_t priv_be[48U], const uint8_t h1_be[48U])
{
    uint8_t V[48U] = { 0U };
    uint8_t K[48U] = { 0U };
    uint8_t bh[48U] = { 0U };
    uint8_t blob[97U] = { 0U };
    uint8_t T[48U] = { 0U };
    uint8_t msg[145U] = { 0U };
    uint8_t mac[48U] = { 0U };
    size_t i;

    rfc6979_bits2octets_p384(bh, h1_be);

    for (i = 0U; i < 48U; ++i)
    {
        V[i] = 0x01U;
        K[i] = 0x00U;
    }

    blob[0U] = 0x00U;
    qsc_memutils_copy(blob + 1U, priv_be, 48U);
    qsc_memutils_copy(blob + 49U, bh, 48U);

    qsc_memutils_copy(msg, V, 48U);
    qsc_memutils_copy(msg + 48U, blob, 97U);
    qsc_hmac384_compute(mac, msg, sizeof(msg), K, sizeof(K));
    qsc_memutils_copy(K, mac, 48U);

    qsc_hmac384_compute(mac, V, sizeof(V), K, sizeof(K));
    qsc_memutils_copy(V, mac, 48U);

    blob[0U] = 0x01U;
    qsc_memutils_copy(msg, V, 48U);
    qsc_memutils_copy(msg + 48U, blob, 97U);
    qsc_hmac384_compute(mac, msg, sizeof(msg), K, sizeof(K));
    qsc_memutils_copy(K, mac, 48U);

    qsc_hmac384_compute(mac, V, sizeof(V), K, sizeof(K));
    qsc_memutils_copy(V, mac, 48U);

    for (;;)
    {
        qsc_hmac384_compute(T, V, sizeof(V), K, sizeof(K));
        qsc_memutils_copy(V, T, 48U);
        fe384_from_bytes(k_out, T);

        if ((fe384_is_zero(k_out) == 0U) && (fe384_cmp(k_out, P384_N) < 0))
        {
            break;
        }

        msg[0U] = 0x00U;
        qsc_memutils_copy(msg + 1U, V, 48U);
        qsc_hmac384_compute(mac, msg, 49U, K, sizeof(K));
        qsc_memutils_copy(K, mac, 48U);

        qsc_hmac384_compute(mac, V, sizeof(V), K, sizeof(K));
        qsc_memutils_copy(V, mac, 48U);
    }

    qsc_memutils_secure_erase(V, sizeof(V));
    qsc_memutils_secure_erase(K, sizeof(K));
    qsc_memutils_secure_erase(bh, sizeof(bh));
    qsc_memutils_secure_erase(blob, sizeof(blob));
    qsc_memutils_secure_erase(T, sizeof(T));
    qsc_memutils_secure_erase(msg, sizeof(msg));
    qsc_memutils_secure_erase(mac, sizeof(mac));
}

static void sc_from_bytes(uint32_t r[12U], const uint8_t s[48U])
{
    int32_t i;
    int32_t j;

    for (i = 0, j = 44; i < 12; ++i, j -= 4)
    {
        r[i] =
            ((uint32_t)s[j] << 24U) |
            ((uint32_t)s[j + 1U] << 16U) |
            ((uint32_t)s[j + 2U] << 8U) |
            ((uint32_t)s[j + 3U]);
    }
}

int32_t qsc_p384_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{
    p384_aff_t G;
    p384_aff_t Q;
    p384_jac_t R;
    uint32_t d[12U] = { 0U };
    int32_t ret;

    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    ret = -1;
    sc_from_bytes(d, privatekey);

    if (fe384_is_zero(d) != 0U)
    {
        ret = -2;
    }
    else if (fe384_cmp(d, P384_N) >= 0)
    {
        ret = -3;
    }
    else
    {
        fe384_copy(G.X, P384_GX);
        fe384_copy(G.Y, P384_GY);
        p384_scalar_mult(&R, &G, d);

        if (p384_is_infinity(&R) != 0U)
        {
            ret = -4;
        }
        else if (p384_jac_to_aff(&Q, &R) != true)
        {
            ret = -5;
        }
        else
        {
            fe384_to_bytes(publickey, Q.X);
            fe384_to_bytes(publickey + 48U, Q.Y);
            ret = 0;
        }
    }

    return ret;
}

int32_t qsc_p384_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    uint8_t hash[48U] = { 0U };
    uint32_t d[12U] = { 0U };
    p384_aff_t Q;
    p384_jac_t Q_jac;
    p384_aff_t G_init;
    int32_t ret;

    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(seed != NULL);

    ret = -1;

    qsc_memutils_clear(publickey, EC_NISTP384_PUBLICKEY_SIZE);
    qsc_memutils_clear(privatekey, EC_NISTP384_PRIVATEKEY_SIZE);

    qsc_sha384_compute(hash, seed, EC_NISTP384_SEED_SIZE);
    sc_from_bytes_reduce(d, hash);

    if (fe384_is_zero(d) != 0U)
    {
        ret = -2;
    }
    else
    {
        fe384_copy(G_init.X, P384_GX);
        fe384_copy(G_init.Y, P384_GY);

        p384_scalar_mult(&Q_jac, &G_init, d);

        if (p384_jac_to_aff(&Q, &Q_jac) != true)
        {
            ret = -3;
        }
        else
        {
            fe384_to_bytes(publickey, Q.X);
            fe384_to_bytes(publickey + 48U, Q.Y);

            qsc_memutils_copy(privatekey, seed, EC_NISTP384_SEED_SIZE);
            qsc_memutils_copy(privatekey + 48U, publickey, EC_NISTP384_PUBLICKEY_SIZE);

            ret = 0;
        }
    }

    qsc_memutils_secure_erase(hash, sizeof(hash));
    qsc_memutils_secure_erase(d, sizeof(d));
    qsc_memutils_secure_erase(&Q, sizeof(Q));
    qsc_memutils_secure_erase(&Q_jac, sizeof(Q_jac));
    qsc_memutils_secure_erase(&G_init, sizeof(G_init));

    return ret;
}

int32_t qsc_p384_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    uint8_t hash[48U] = { 0U };
    uint8_t d_be[48U] = { 0U };
    uint8_t dhash[48U] = { 0U };
    uint32_t d[12U] = { 0U };
    uint32_t k[12U] = { 0U };
    uint32_t r[12U] = { 0U };
    uint32_t s[12U] = { 0U };
    uint32_t e[12U] = { 0U };
    uint32_t tmp[12U] = { 0U };
    p384_aff_t kG;
    p384_jac_t kG_jac;
    p384_aff_t G;
    int32_t res;

    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    res = -1;

    qsc_sha384_compute(hash, message, msglen);
    qsc_sha384_compute(dhash, privatekey, EC_NISTP384_SEED_SIZE);
    sc_from_bytes_reduce(d, dhash);

    if (fe384_is_zero(d) != 0U)
    {
        res = -2;
    }
    else if (fe384_cmp(d, P384_N) < 0)
    {
        sc_from_bytes_reduce(e, hash);
        fe384_to_bytes(d_be, d);
        rfc6979_generate_k(k, d_be, hash);

        fe384_copy(G.X, P384_GX);
        fe384_copy(G.Y, P384_GY);

        p384_scalar_mult(&kG_jac, &G, k);
        p384_jac_to_aff(&kG, &kG_jac);

        fe384_copy(r, kG.X);
        fe384_cond_sub(r, P384_N);

        if (fe384_is_zero(r) == 0U)
        {
            sc_mul(tmp, r, d);
            sc_add(tmp, tmp, e);
            sc_inv(s, k);
            sc_mul(s, s, tmp);

            if (fe384_is_zero(s) == 0U)
            {
                fe384_to_bytes(signedmsg, r);
                fe384_to_bytes(signedmsg + 48U, s);
                qsc_memutils_copy(signedmsg + EC_NISTP384_SIGNATURE_SIZE, message, msglen);
                *smsglen = EC_NISTP384_SIGNATURE_SIZE + msglen;
                res = 0;
            }
        }
    }

    qsc_memutils_secure_erase(hash, sizeof(hash));
    qsc_memutils_secure_erase(dhash, sizeof(dhash));
    qsc_memutils_secure_erase(d_be, sizeof(d_be));
    qsc_memutils_secure_erase(d, sizeof(d));
    qsc_memutils_secure_erase(k, sizeof(k));
    qsc_memutils_secure_erase(tmp, sizeof(tmp));
    qsc_memutils_secure_erase(r, sizeof(r));
    qsc_memutils_secure_erase(s, sizeof(s));
    qsc_memutils_secure_erase(e, sizeof(e));
    qsc_memutils_secure_erase(&kG, sizeof(kG));
    qsc_memutils_secure_erase(&kG_jac, sizeof(kG_jac));
    qsc_memutils_secure_erase(&G, sizeof(G));

    if (res != 0 && smsglen != NULL)
    {
        *smsglen = 0U;
    }

    return res;
}

int32_t qsc_p384_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    uint8_t hash[48U] = { 0U };
    uint8_t d_be[48U] = { 0U };
    uint32_t d[12U] = { 0U };
    uint32_t k[12U] = { 0U };
    uint32_t r[12U] = { 0U };
    uint32_t s[12U] = { 0U };
    uint32_t e[12U] = { 0U };
    uint32_t tmp[12U] = { 0U };
    p384_aff_t kG;
    p384_jac_t kG_jac;
    p384_aff_t G;
    int32_t res;

    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    res = -1;

    qsc_sha384_compute(hash, message, msglen);
    sc_from_bytes(d, privatekey);

    if (fe384_is_zero(d) != 0U)
    {
        res = -2;
    }
    else if (fe384_cmp(d, P384_N) < 0)
    {
        sc_from_bytes_reduce(e, hash);
        fe384_to_bytes(d_be, d);
        rfc6979_generate_k(k, d_be, hash);

        fe384_copy(G.X, P384_GX);
        fe384_copy(G.Y, P384_GY);

        p384_scalar_mult(&kG_jac, &G, k);
        p384_jac_to_aff(&kG, &kG_jac);

        fe384_copy(r, kG.X);
        fe384_cond_sub(r, P384_N);

        if (fe384_is_zero(r) == 0U)
        {
            sc_mul(tmp, r, d);
            sc_add(tmp, tmp, e);
            sc_inv(s, k);
            sc_mul(s, s, tmp);

            if (fe384_is_zero(s) == 0U)
            {
                fe384_to_bytes(signedmsg, r);
                fe384_to_bytes(signedmsg + 48U, s);
                qsc_memutils_copy(signedmsg + EC_NISTP384_SIGNATURE_SIZE, message, msglen);
                *smsglen = EC_NISTP384_SIGNATURE_SIZE + msglen;
                res = 0;
            }
        }
    }

    qsc_memutils_secure_erase(hash, sizeof(hash));
    qsc_memutils_secure_erase(d_be, sizeof(d_be));
    qsc_memutils_secure_erase(d, sizeof(d));
    qsc_memutils_secure_erase(k, sizeof(k));
    qsc_memutils_secure_erase(tmp, sizeof(tmp));
    qsc_memutils_secure_erase(r, sizeof(r));
    qsc_memutils_secure_erase(s, sizeof(s));
    qsc_memutils_secure_erase(e, sizeof(e));
    qsc_memutils_secure_erase(&kG, sizeof(kG));
    qsc_memutils_secure_erase(&kG_jac, sizeof(kG_jac));
    qsc_memutils_secure_erase(&G, sizeof(G));

    if (res != 0 && smsglen != NULL)
    {
        *smsglen = 0U;
    }

    return res;
}

bool qsc_p384_verify(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
    uint8_t hash[48U] = { 0U };
    uint32_t r[12U] = { 0U };
    uint32_t s[12U] = { 0U };
    uint32_t e[12U] = { 0U };
    uint32_t w[12U] = { 0U };
    uint32_t u1[12U] = { 0U };
    uint32_t u2[12U] = { 0U };
    uint32_t xr[12U] = { 0U };
    p384_aff_t Q = { 0U };
    p384_aff_t G_init = { 0U };
    p384_aff_t Rsum = { 0U };
    p384_jac_t J1 = { 0U };
    p384_jac_t J2 = { 0U };
    p384_jac_t Jsum = { 0U };
    bool res;
    size_t mlen;

    QSC_ASSERT(msgout != NULL);
    QSC_ASSERT(msglen != NULL);
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(publickey != NULL);

    res = false;

    if (smsglen >= EC_NISTP384_SIGNATURE_SIZE)
    {
        mlen = smsglen - EC_NISTP384_SIGNATURE_SIZE;

        fe384_from_bytes((uint32_t*)Q.X, publickey);
        fe384_from_bytes((uint32_t*)Q.Y, publickey + 48U);

        if (fe384_cmp((uint32_t*)Q.X, P384_P) < 0 &&
            fe384_cmp((uint32_t*)Q.Y, P384_P) < 0 &&
            p384_point_is_on_curve(&Q) == true)
        {
            fe384_from_bytes(r, signedmsg);
            fe384_from_bytes(s, signedmsg + 48U);

            if (fe384_is_zero(r) == 0U &&
                fe384_cmp(r, P384_N) < 0 &&
                fe384_is_zero(s) == 0U &&
                fe384_cmp(s, P384_N) < 0)
            {
                qsc_sha384_compute(hash, signedmsg + EC_NISTP384_SIGNATURE_SIZE, mlen);
                sc_from_bytes_reduce(e, hash);
                sc_inv(w, s);
                sc_mul(u1, e, w);
                sc_mul(u2, r, w);

                fe384_copy((uint32_t*)G_init.X, P384_GX);
                fe384_copy((uint32_t*)G_init.Y, P384_GY);

                p384_scalar_mult(&J1, &G_init, u1);
                p384_scalar_mult(&J2, &Q, u2);
                p384_add(&Jsum, &J1, &J2);

                if (p384_jac_to_aff(&Rsum, &Jsum) == true)
                {
                    fe384_copy(xr, (const uint32_t*)Rsum.X);

                    if (fe384_cmp(xr, P384_N) >= 0)
                    {
                        sc_sub(xr, xr, P384_N);
                    }

                    if (fe384_cmp(xr, r) == 0)
                    {
                        qsc_memutils_copy(msgout, signedmsg + EC_NISTP384_SIGNATURE_SIZE, mlen);
                        *msglen = mlen;
                        res = true;
                    }
                }
            }
        }

        if (res == false)
        {
            *msglen = 0U;
        }

        qsc_memutils_secure_erase(hash, sizeof(hash));
        qsc_memutils_secure_erase(r, sizeof(r));
        qsc_memutils_secure_erase(s, sizeof(s));
        qsc_memutils_secure_erase(e, sizeof(e));
        qsc_memutils_secure_erase(w, sizeof(w));
        qsc_memutils_secure_erase(u1, sizeof(u1));
        qsc_memutils_secure_erase(u2, sizeof(u2));
        qsc_memutils_secure_erase(xr, sizeof(xr));
        qsc_memutils_secure_erase(&Q, sizeof(Q));
        qsc_memutils_secure_erase(&G_init, sizeof(G_init));
        qsc_memutils_secure_erase(&Rsum, sizeof(Rsum));
        qsc_memutils_secure_erase(&J1, sizeof(J1));
        qsc_memutils_secure_erase(&J2, sizeof(J2));
        qsc_memutils_secure_erase(&Jsum, sizeof(Jsum));
    }

    return res;
}
