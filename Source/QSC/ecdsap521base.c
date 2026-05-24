#include "ecdsap521base.h"
#include "memutils.h"
#include "sha2.h"

typedef uint32_t fe521[17U];

typedef struct
{
    fe521 X;
    fe521 Y;
    fe521 Z;
} p521_jac_t;

typedef struct
{
    fe521 X;
    fe521 Y;
} p521_aff_t;

/* field prime p = 2^521 - 1 */
static const uint32_t P521_P[17U] =
{
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
    0x000001FFU
};

/* subgroup order n */
static const uint32_t P521_N[17U] =
{
    0x91386409U, 0xBB6FB71EU, 0x899C47AEU, 0x3BB5C9B8U,
    0xF709A5D0U, 0x7FCC0148U, 0xBF2F966BU, 0x51868783U,
    0xFFFFFFFAU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
    0x000001FFU
};

/* curve coefficient b */
static const uint32_t P521_B[17U] =
{
    0x6B503F00U, 0xEF451FD4U, 0x3D2C34F1U, 0x3573DF88U,
    0x3BB1BF07U, 0x1652C0BDU, 0xEC7E937BU, 0x56193951U,
    0x8EF109E1U, 0xB8B48991U, 0x99B315F3U, 0xA2DA725BU,
    0xB68540EEU, 0x929A21A0U, 0x8E1C9A1FU, 0x953EB961U,
    0x00000051U
};

/* base point Gx */
static const uint32_t P521_GX[17U] =
{
    0xC2E5BD66U, 0xF97E7E31U, 0x856A429BU, 0x3348B3C1U,
    0xA2FFA8DEU, 0xFE1DC127U, 0xEFE75928U, 0xA14B5E77U,
    0x6B4D3DBAU, 0xF828AF60U, 0x053FB521U, 0x9C648139U,
    0x2395B442U, 0x9E3ECB66U, 0x0404E9CDU, 0x858E06B7U,
    0x000000C6U
};

/* base point Gy */
static const uint32_t P521_GY[17U] =
{
    0x9FD16650U, 0x88BE9476U, 0xA272C240U, 0x353C7086U,
    0x3FAD0761U, 0xC550B901U, 0x5EF42640U, 0x97EE7299U,
    0x273E662CU, 0x17AFBD17U, 0x579B4468U, 0x98F54449U,
    0x2C7D1BD9U, 0x5C8A5FB4U, 0x9A3BC004U, 0x39296A78U,
    0x00000118U
};

static void fe521_copy(fe521 r, const fe521 a)
{
    size_t i;

    for (i = 0U; i < 17U; ++i)
    {
        r[i] = a[i];
    }
}

static void fe521_zero(fe521 r)
{
    size_t i;

    for (i = 0U; i < 17U; ++i)
    {
        r[i] = 0U;
    }
}

static void fe521_one(fe521 r)
{
    size_t i;

    r[0U] = 1U;

    for (i = 1U; i < 17U; ++i)
    {
        r[i] = 0U;
    }
}

static uint32_t fe521_is_zero(const fe521 a)
{
    uint32_t t;
    size_t i;

    t = 0U;

    for (i = 0U; i < 17U; ++i)
    {
        t |= a[i];
    }

    t = (t | (0U - t)) >> 31U;

    return (uint32_t)(1U - t);
}

static uint32_t fe521_is_one(const fe521 a)
{
    uint32_t t;
    size_t i;

    t = a[0U] ^ 1U;

    for (i = 1U; i < 17U; ++i)
    {
        t |= a[i];
    }

    t = (t | (0U - t)) >> 31U;

    return (uint32_t)(1U - t);
}

static uint32_t fe521_is_even(const fe521 a)
{
    return (uint32_t)((a[0U] & 1U) ^ 1U);
}

static int32_t fe521_cmp(const uint32_t* a, const uint32_t* b)
{
    uint64_t ai;
    uint32_t aigtbi;
    uint32_t ailtbi;
    uint64_t bi;
    uint32_t gt;
    int32_t i;
    uint32_t lt;
    uint32_t undecided;

    gt = 0U;
    lt = 0U;

    for (i = 16; i >= 0; --i)
    {
        ai = (uint64_t)a[i];
        bi = (uint64_t)b[i];

        aigtbi = (uint32_t)((bi - ai) >> 63U);
        ailtbi = (uint32_t)((ai - bi) >> 63U);
        undecided = (uint32_t)(1U ^ (gt | lt));

        gt |= aigtbi & undecided;
        lt |= ailtbi & undecided;
    }

    return (gt != 0U) ? 1 : ((lt != 0U) ? -1 : 0);
}

static void fe521_from_bytes(fe521 r, const uint8_t* b)
{
    int32_t i;
    int32_t j;

    for (i = 0, j = 62; i < 16; ++i, j -= 4)
    {
        r[i] = ((uint32_t)b[j] << 24U) |
               ((uint32_t)b[j + 1] << 16U) |
               ((uint32_t)b[j + 2] << 8U) |
               ((uint32_t)b[j + 3]);
    }

    r[16] = ((uint32_t)b[0] << 8U) | (uint32_t)b[1];
}

static void fe521_to_bytes(uint8_t* b, const fe521 r)
{
    int32_t i;
    int32_t j;

    b[0] = (uint8_t)(r[16] >> 8U);
    b[1] = (uint8_t)(r[16]);

    for (i = 0, j = 62; i < 16; ++i, j -= 4)
    {
        b[j] = (uint8_t)(r[i] >> 24U);
        b[j + 1] = (uint8_t)(r[i] >> 16U);
        b[j + 2] = (uint8_t)(r[i] >> 8U);
        b[j + 3] = (uint8_t)(r[i]);
    }
}

static void bn_rshift1(fe521 r)
{
    size_t i;
    uint32_t carry;

    carry = 0U;

    for (i = 17U; i-- > 0U;)
    {
        uint32_t next;

        next = r[i] << 31U;
        r[i] = (r[i] >> 1U) | carry;
        carry = next;
    }

}

static void bn_add_raw(fe521 r, const fe521 a, const fe521 b)
{
    uint64_t t;
    uint64_t carry;
    size_t i;

    carry = 0U;

    for (i = 0U; i < 17U; ++i)
    {
        t = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        r[i] = (uint32_t)t;
        carry = t >> 32U;
    }
}

static uint32_t bn_sub_raw(fe521 r, const fe521 a, const fe521 b)
{
    uint64_t t;
    uint32_t borrow;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 17U; ++i)
    {
        t = (uint64_t)a[i] - (uint64_t)b[i] - (uint64_t)borrow;
        r[i] = (uint32_t)t;
        borrow = (uint32_t)((t >> 63U) & 1U);
    }

    return borrow;
}

static void bn_add_inplace(fe521 r, const fe521 a)
{
    uint64_t t;
    uint64_t carry;
    size_t i;

    carry = 0U;

    for (i = 0U; i < 17U; ++i)
    {
        t = (uint64_t)r[i] + (uint64_t)a[i] + carry;
        r[i] = (uint32_t)t;
        carry = t >> 32U;
    }
}

static void bn_sub_mod(fe521 r, const fe521 a, const fe521 b, const fe521 mod)
{
    fe521 t;

    if (bn_sub_raw(t, a, b) != 0U)
    {
        bn_add_inplace(t, mod);
    }

    fe521_copy(r, t);
    qsc_memutils_secure_erase(t, sizeof(t));
}

static void bn_half_mod(fe521 r, const fe521 mod)
{
    if ((r[0U] & 1U) != 0U)
    {
        bn_add_inplace(r, mod);
    }

    bn_rshift1(r);
}

static void mod_p_cond_sub(fe521 r)
{
    fe521 t;

    if (fe521_cmp(r, P521_P) >= 0)
    {
        (void)bn_sub_raw(t, r, P521_P);
        fe521_copy(r, t);
    }

    r[16] &= 0x000001FFU;
    qsc_memutils_secure_erase(t, sizeof(t));
}

static void mod_p_add_small(fe521 r, uint32_t x)
{
    uint64_t t;
    uint64_t carry;
    size_t i;

    t = (uint64_t)r[0U] + (uint64_t)x;
    r[0U] = (uint32_t)t;
    carry = t >> 32U;

    for (i = 1U; i < 17U && carry != 0U; ++i)
    {
        t = (uint64_t)r[i] + carry;
        r[i] = (uint32_t)t;
        carry = t >> 32U;
    }

    if ((r[16] >> 9U) != 0U)
    {
        x = r[16] >> 9U;
        r[16] &= 0x000001FFU;

        t = (uint64_t)r[0U] + (uint64_t)x;
        r[0U] = (uint32_t)t;
        carry = t >> 32U;

        for (i = 1U; i < 17U && carry != 0U; ++i)
        {
            t = (uint64_t)r[i] + carry;
            r[i] = (uint32_t)t;
            carry = t >> 32U;
        }
    }

    mod_p_cond_sub(r);
}

static void fe_add(fe521 r, const fe521 a, const fe521 b)
{
    uint64_t t;
    uint64_t carry;
    uint32_t extra;
    size_t i;

    carry = 0U;

    for (i = 0U; i < 17U; ++i)
    {
        t = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        r[i] = (uint32_t)t;
        carry = t >> 32U;
    }

    extra = (uint32_t)(r[16] >> 9U);
    r[16] &= 0x000001FFU;
    extra += (uint32_t)(carry << 23U);

    if (extra != 0U)
    {
        mod_p_add_small(r, extra);
    }
    else
    {
        mod_p_cond_sub(r);
    }
}

static void fe_sub(fe521 r, const fe521 a, const fe521 b)
{
    fe521 t;

    if (bn_sub_raw(t, a, b) != 0U)
    {
        bn_add_inplace(t, P521_P);
    }

    fe521_copy(r, t);
    mod_p_cond_sub(r);
    qsc_memutils_secure_erase(t, sizeof(t));
}

static void fe_mul_raw(uint32_t c[34U], const fe521 a, const fe521 b)
{
    uint64_t t;
    uint64_t carry;
    size_t i;
    size_t j;
    size_t k;

    for (i = 0U; i < 34U; ++i)
    {
        c[i] = 0U;
    }

    for (i = 0U; i < 17U; ++i)
    {
        carry = 0U;

        for (j = 0U; j < 17U; ++j)
        {
            t = (uint64_t)a[i] * (uint64_t)b[j] + (uint64_t)c[i + j] + carry;
            c[i + j] = (uint32_t)t;
            carry = t >> 32U;
        }

        k = i + 17U;

        while (carry != 0U && k < 34U)
        {
            t = (uint64_t)c[k] + carry;
            c[k] = (uint32_t)t;
            carry = t >> 32U;
            ++k;
        }
    }
}

static void fe_reduce_p(fe521 r, const uint32_t c[34U])
{
    fe521 low;
    fe521 high;
    uint64_t t;
    uint64_t carry;
    uint32_t extra;
    size_t i;

    for (i = 0U; i < 16U; ++i)
    {
        low[i] = c[i];
    }

    low[16] = c[16U] & 0x000001FFU;

    for (i = 0U; i < 17U; ++i)
    {
        uint64_t v;
        size_t s;

        s = i + 16U;
        v = 0U;

        if (s < 34U)
        {
            v = (uint64_t)(c[s] >> 9U);
        }

        if ((s + 1U) < 34U)
        {
            v |= ((uint64_t)c[s + 1U] << 23U);
        }

        high[i] = (uint32_t)v;
    }

    carry = 0U;

    for (i = 0U; i < 17U; ++i)
    {
        t = (uint64_t)low[i] + (uint64_t)high[i] + carry;
        r[i] = (uint32_t)t;
        carry = t >> 32U;
    }

    extra = (uint32_t)(r[16] >> 9U);
    r[16] &= 0x000001FFU;
    extra += (uint32_t)(carry << 23U);

    if (extra != 0U)
    {
        mod_p_add_small(r, extra);
    }
    else
    {
        mod_p_cond_sub(r);
    }

    qsc_memutils_secure_erase(low, sizeof(low));
    qsc_memutils_secure_erase(high, sizeof(high));
}

static void fe_mul(fe521 r, const fe521 a, const fe521 b)
{
    uint32_t c[34U];

    fe_mul_raw(c, a, b);
    fe_reduce_p(r, c);

    qsc_memutils_secure_erase(c, sizeof(c));
}

static void fe_sqr(fe521 r, const fe521 a)
{
    fe_mul(r, a, a);
}

static void fe_mul_small(fe521 r, const fe521 a, uint32_t k)
{
    fe521 t;
    uint32_t i;

    fe521_zero(t);

    for (i = 0U; i < k; ++i)
    {
        fe_add(t, t, a);
    }

    fe521_copy(r, t);
    qsc_memutils_secure_erase(t, sizeof(t));
}

static void mod_n_cond_sub(fe521 r)
{
    fe521 t;

    if (fe521_cmp(r, P521_N) >= 0)
    {
        (void)bn_sub_raw(t, r, P521_N);
        fe521_copy(r, t);
    }

    qsc_memutils_secure_erase(t, sizeof(t));
}

static void sc_add(fe521 r, const fe521 a, const fe521 b);

static void sc_add_one(fe521 r);

static void sc_from_bytes(fe521 r, const uint8_t s[66U])
{
    fe521_from_bytes(r, s);
}

static void sc_add_one(fe521 r)
{
    uint64_t t;
    uint64_t carry;
    size_t i;

    t = (uint64_t)r[0U] + 1U;
    r[0U] = (uint32_t)t;
    carry = t >> 32U;

    for (i = 1U; i < 17U && carry != 0U; ++i)
    {
        t = (uint64_t)r[i] + carry;
        r[i] = (uint32_t)t;
        carry = t >> 32U;
    }

    mod_n_cond_sub(r);
}

static void sc_from_bytes_reduce(fe521 r, const uint8_t* b, size_t blen)
{
    size_t i;
    int32_t j;

    fe521_zero(r);

    for (i = 0U; i < blen; ++i)
    {
        for (j = 7; j >= 0; --j)
        {
            sc_add(r, r, r);

            if (((b[i] >> (uint32_t)j) & 1U) != 0U)
            {
                sc_add_one(r);
            }
        }
    }
}

static void sc_mul(fe521 r, const fe521 a, const fe521 b)
{
    uint32_t c[34U];
    fe521 rem;
    int32_t bit;

    fe_mul_raw(c, a, b);
    fe521_zero(rem);

    for (bit = 1087; bit >= 0; --bit)
    {
        uint32_t word;
        uint32_t bpos;

        sc_add(rem, rem, rem);

        word = c[(uint32_t)bit >> 5U];
        bpos = (uint32_t)bit & 31U;

        if (((word >> bpos) & 1U) != 0U)
        {
            sc_add_one(rem);
        }
    }

    fe521_copy(r, rem);

    qsc_memutils_secure_erase(c, sizeof(c));
    qsc_memutils_secure_erase(rem, sizeof(rem));
}

static void sc_add(fe521 r, const fe521 a, const fe521 b)
{
    bn_add_raw(r, a, b);

    if ((r[16] > 0x000001FFU) || (fe521_cmp(r, P521_N) >= 0))
    {
        (void)bn_sub_raw(r, r, P521_N);
    }
}

static void sc_sub(fe521 r, const fe521 a, const fe521 b)
{
    bn_sub_mod(r, a, b, P521_N);
    mod_n_cond_sub(r);
}

static void sc_inv(fe521 r, const fe521 a)
{
    fe521 u;
    fe521 v;
    fe521 x1;
    fe521 x2;

    fe521_copy(u, a);
    fe521_copy(v, P521_N);
    fe521_one(x1);
    fe521_zero(x2);

    while ((fe521_is_one(u) == 0U) && (fe521_is_one(v) == 0U))
    {
        while (fe521_is_even(u) != 0U)
        {
            bn_rshift1(u);
            bn_half_mod(x1, P521_N);
        }

        while (fe521_is_even(v) != 0U)
        {
            bn_rshift1(v);
            bn_half_mod(x2, P521_N);
        }

        if (fe521_cmp(u, v) >= 0)
        {
            (void)bn_sub_raw(u, u, v);
            bn_sub_mod(x1, x1, x2, P521_N);
        }
        else
        {
            (void)bn_sub_raw(v, v, u);
            bn_sub_mod(x2, x2, x1, P521_N);
        }
    }

    if (fe521_is_one(u) != 0U)
    {
        fe521_copy(r, x1);
    }
    else
    {
        fe521_copy(r, x2);
    }

    mod_n_cond_sub(r);

    qsc_memutils_secure_erase(u, sizeof(u));
    qsc_memutils_secure_erase(v, sizeof(v));
    qsc_memutils_secure_erase(x1, sizeof(x1));
    qsc_memutils_secure_erase(x2, sizeof(x2));
}

static void fe_inv(fe521 r, const fe521 a)
{
    fe521 u;
    fe521 v;
    fe521 x1;
    fe521 x2;

    fe521_copy(u, a);
    fe521_copy(v, P521_P);
    fe521_one(x1);
    fe521_zero(x2);

    while ((fe521_is_one(u) == 0U) && (fe521_is_one(v) == 0U))
    {
        while (fe521_is_even(u) != 0U)
        {
            bn_rshift1(u);
            bn_half_mod(x1, P521_P);
        }

        while (fe521_is_even(v) != 0U)
        {
            bn_rshift1(v);
            bn_half_mod(x2, P521_P);
        }

        if (fe521_cmp(u, v) >= 0)
        {
            (void)bn_sub_raw(u, u, v);
            bn_sub_mod(x1, x1, x2, P521_P);
        }
        else
        {
            (void)bn_sub_raw(v, v, u);
            bn_sub_mod(x2, x2, x1, P521_P);
        }
    }

    if (fe521_is_one(u) != 0U)
    {
        fe521_copy(r, x1);
    }
    else
    {
        fe521_copy(r, x2);
    }

    mod_p_cond_sub(r);

    qsc_memutils_secure_erase(u, sizeof(u));
    qsc_memutils_secure_erase(v, sizeof(v));
    qsc_memutils_secure_erase(x1, sizeof(x1));
    qsc_memutils_secure_erase(x2, sizeof(x2));
}

static uint32_t ct_sel32(uint32_t sel, uint32_t a, uint32_t b)
{
    uint32_t mask;

    mask = (uint32_t)(0U - sel);

    return (a & mask) | (b & ~mask);
}

static void fe521_ct_select(fe521 r, uint32_t sel, const fe521 a, const fe521 b)
{
    size_t i;

    for (i = 0U; i < 17U; ++i)
    {
        r[i] = ct_sel32(sel, a[i], b[i]);
    }
}

static void p521_jac_ct_select(p521_jac_t* r, uint32_t sel, const p521_jac_t* a, const p521_jac_t* b)
{
    fe521_ct_select(r->X, sel, a->X, b->X);
    fe521_ct_select(r->Y, sel, a->Y, b->Y);
    fe521_ct_select(r->Z, sel, a->Z, b->Z);
}

static void p521_aff_to_jac(p521_jac_t* R, const p521_aff_t* P)
{
    fe521_copy(R->X, P->X);
    fe521_copy(R->Y, P->Y);
    fe521_one(R->Z);
}

static void p521_set_infinity(p521_jac_t* R)
{
    fe521_zero(R->X);
    fe521_one(R->Y);
    fe521_zero(R->Z);
}

static uint32_t p521_is_infinity(const p521_jac_t* P)
{
    return fe521_is_zero(P->Z);
}

static void p521_dbl(p521_jac_t* R, const p521_jac_t* P)
{
    fe521 delta;
    fe521 gamma;
    fe521 beta;
    fe521 alpha;
    fe521 tmp;
    fe521 x3;
    fe521 y3;
    fe521 z3;

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

    fe521_copy(R->X, x3);
    fe521_copy(R->Y, y3);
    fe521_copy(R->Z, z3);
}

static void p521_add(p521_jac_t* R, const p521_jac_t* P, const p521_jac_t* Q)
{
    fe521 z1z1;
    fe521 z2z2;
    fe521 u1;
    fe521 u2;
    fe521 s1;
    fe521 s2;
    fe521 h;
    fe521 r2;
    fe521 i;
    fe521 j;
    fe521 v;
    fe521 x3;
    fe521 y3;
    fe521 z3;
    fe521 tmp;
    p521_jac_t Radd;
    p521_jac_t Rdbl;
    p521_jac_t Rinf;
    p521_jac_t T;
    uint32_t general_case;
    uint32_t h_zero;
    uint32_t opposite_point;
    uint32_t pinf;
    uint32_t qinf;
    uint32_t r_zero;
    uint32_t same_point;

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

    fe521_copy(Radd.X, x3);
    fe521_copy(Radd.Y, y3);
    fe521_copy(Radd.Z, z3);

    p521_dbl(&Rdbl, P);
    p521_set_infinity(&Rinf);

    pinf = p521_is_infinity(P);
    qinf = p521_is_infinity(Q);
    h_zero = fe521_is_zero(h);
    r_zero = fe521_is_zero(r2);

    same_point = h_zero & r_zero;
    opposite_point = h_zero & (uint32_t)(r_zero ^ 1U);
    general_case = (uint32_t)((pinf | qinf | same_point | opposite_point) ^ 1U);

    p521_set_infinity(&T);
    p521_jac_ct_select(&T, general_case, &Radd, &T);
    p521_jac_ct_select(&T, same_point, &Rdbl, &T);
    p521_jac_ct_select(&T, opposite_point, &Rinf, &T);
    p521_jac_ct_select(&T, qinf, P, &T);
    p521_jac_ct_select(&T, pinf, Q, &T);

    *R = T;

    qsc_memutils_secure_erase(&Radd, sizeof(Radd));
    qsc_memutils_secure_erase(&Rdbl, sizeof(Rdbl));
    qsc_memutils_secure_erase(&Rinf, sizeof(Rinf));
    qsc_memutils_secure_erase(&T, sizeof(T));
}

static void p521_scalar_mult(p521_jac_t* R, const p521_aff_t* P, const fe521 k)
{
    p521_jac_t R0;
    p521_jac_t R1;
    p521_jac_t A;
    p521_jac_t D0;
    p521_jac_t D1;
    int32_t i;

    p521_set_infinity(&R0);
    p521_aff_to_jac(&R1, P);

    for (i = 520; i >= 0; --i)
    {
        uint32_t bit;

        p521_add(&A, &R0, &R1);
        p521_dbl(&D0, &R0);
        p521_dbl(&D1, &R1);

        bit = (k[(uint32_t)i >> 5U] >> ((uint32_t)i & 31U)) & 1U;

        p521_jac_ct_select(&R0, bit, &A, &D0);
        p521_jac_ct_select(&R1, bit, &D1, &A);
    }

    *R = R0;

    qsc_memutils_secure_erase(&R0, sizeof(R0));
    qsc_memutils_secure_erase(&R1, sizeof(R1));
    qsc_memutils_secure_erase(&A, sizeof(A));
    qsc_memutils_secure_erase(&D0, sizeof(D0));
    qsc_memutils_secure_erase(&D1, sizeof(D1));
}

static bool p521_jac_to_aff(p521_aff_t* R, const p521_jac_t* P)
{
    fe521 zinv;
    fe521 zinv2;
    fe521 zinv3;

    if (p521_is_infinity(P) != 0U)
    {
        return false;
    }

    fe_inv(zinv, P->Z);
    fe_sqr(zinv2, zinv);
    fe_mul(zinv3, zinv2, zinv);

    fe_mul(R->X, P->X, zinv2);
    fe_mul(R->Y, P->Y, zinv3);

    qsc_memutils_secure_erase(zinv, sizeof(fe521));
    qsc_memutils_secure_erase(zinv2, sizeof(fe521));
    qsc_memutils_secure_erase(zinv3, sizeof(fe521));

    return true;
}

static bool p521_point_is_on_curve(const p521_aff_t* Q)
{
    fe521 y2;
    fe521 x3;
    fe521 ax;
    fe521 rhs;

    fe_sqr(y2, Q->Y);
    fe_sqr(x3, Q->X);
    fe_mul(x3, x3, Q->X);

    fe_mul_small(ax, Q->X, 3U);
    fe_sub(rhs, x3, ax);
    fe_add(rhs, rhs, P521_B);

    return (fe521_cmp(y2, rhs) == 0);
}

static void rfc6979_bits2octets_p521(uint8_t out[66U], const uint8_t hash_be[64U])
{
    fe521 z;

    sc_from_bytes_reduce(z, hash_be, 64U);
    fe521_to_bytes(out, z);

    qsc_memutils_secure_erase(z, sizeof(z));
}

static void rfc6979_generate_k(fe521 k_out, const uint8_t priv_be[66U], const uint8_t h1_be[64U])
{
    uint8_t V[64U];
    uint8_t K[64U];
    uint8_t bh[66U];
    uint8_t blob[133U];
    uint8_t T[66U];
    uint8_t msg[197U];
    uint8_t mac[64U];
    uint32_t i;

    rfc6979_bits2octets_p521(bh, h1_be);

    for (i = 0U; i < 64U; ++i)
    {
        V[i] = 0x01U;
        K[i] = 0x00U;
    }

    blob[0U] = 0x00U;
    qsc_memutils_copy(blob + 1U, priv_be, 66U);
    qsc_memutils_copy(blob + 67U, bh, 66U);

    qsc_memutils_copy(msg, V, 64U);
    qsc_memutils_copy(msg + 64U, blob, 133U);
    qsc_hmac512_compute(mac, msg, sizeof(msg), K, sizeof(K));
    qsc_memutils_copy(K, mac, 64U);

    qsc_hmac512_compute(mac, V, sizeof(V), K, sizeof(K));
    qsc_memutils_copy(V, mac, 64U);

    blob[0U] = 0x01U;
    qsc_memutils_copy(msg, V, 64U);
    qsc_memutils_copy(msg + 64U, blob, 133U);
    qsc_hmac512_compute(mac, msg, sizeof(msg), K, sizeof(K));
    qsc_memutils_copy(K, mac, 64U);

    qsc_hmac512_compute(mac, V, sizeof(V), K, sizeof(K));
    qsc_memutils_copy(V, mac, 64U);

    for (;;)
    {
        qsc_hmac512_compute(mac, V, sizeof(V), K, sizeof(K));
        qsc_memutils_copy(V, mac, 64U);
        qsc_memutils_copy(T, V, 64U);

        qsc_hmac512_compute(mac, V, sizeof(V), K, sizeof(K));
        qsc_memutils_copy(V, mac, 64U);
        T[64U] = V[0U];
        T[65U] = V[1U];

        /*
         * RFC 6979 bits2int(T) for qlen = 521 and tlen = 528
         * is the leftmost 521 bits of T, which is equivalent to
         * shifting the 528-bit candidate right by 7 bits.
         */
        {
            uint8_t t521[66U];
            uint32_t carry;

            carry = 0U;

            for (i = 0U; i < 66U; ++i)
            {
                uint32_t cur;

                cur = T[i];
                t521[i] = (uint8_t)((cur >> 7U) | carry);
                carry = (cur & 0x7FU) << 1U;
            }

            sc_from_bytes(k_out, t521);
            qsc_memutils_secure_erase(t521, sizeof(t521));
        }

        if ((fe521_is_zero(k_out) == 0U) && (fe521_cmp(k_out, P521_N) < 0))
        {
            break;
        }

        msg[0U] = 0x00U;
        qsc_memutils_copy(msg + 1U, V, 64U);
        qsc_hmac512_compute(mac, msg, 65U, K, sizeof(K));
        qsc_memutils_copy(K, mac, 64U);

        qsc_hmac512_compute(mac, V, sizeof(V), K, sizeof(K));
        qsc_memutils_copy(V, mac, 64U);
    }

    qsc_memutils_secure_erase(V, sizeof(V));
    qsc_memutils_secure_erase(K, sizeof(K));
    qsc_memutils_secure_erase(bh, sizeof(bh));
    qsc_memutils_secure_erase(blob, sizeof(blob));
    qsc_memutils_secure_erase(T, sizeof(T));
    qsc_memutils_secure_erase(msg, sizeof(msg));
    qsc_memutils_secure_erase(mac, sizeof(mac));
}

int32_t qsc_p521_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{
    fe521 d;
    p521_aff_t G;
    p521_aff_t Q;
    p521_jac_t Qj;
    int32_t res;

    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    res = -1;

    if (publickey != NULL && privatekey != NULL)
    {
        sc_from_bytes(d, privatekey);

        if ((fe521_is_zero(d) == 0U) && (fe521_cmp(d, P521_N) < 0))
        {
            fe521_copy(G.X, P521_GX);
            fe521_copy(G.Y, P521_GY);

            p521_scalar_mult(&Qj, &G, d);

            if (p521_jac_to_aff(&Q, &Qj) == true)
            {
                fe521_to_bytes(publickey, Q.X);
                fe521_to_bytes(publickey + 66U, Q.Y);
                res = 0;
            }

            qsc_memutils_secure_erase(&Q, sizeof(Q));
            qsc_memutils_secure_erase(&Qj, sizeof(Qj));
        }

        qsc_memutils_secure_erase(d, sizeof(d));
        qsc_memutils_secure_erase(&G, sizeof(G));
    }

    return res;
}

int32_t qsc_p521_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    uint8_t dhash[64U];
    uint8_t d_be[66U];
    fe521 d;
    int32_t res;

    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(seed != NULL);

    res = -1;

    if (publickey != NULL && privatekey != NULL && seed != NULL)
    {
        qsc_sha512_compute(dhash, seed, EC_NISTP521_SEED_SIZE);
        sc_from_bytes_reduce(d, dhash, sizeof(dhash));

        if (fe521_is_zero(d) != 0U)
        {
            fe521_one(d);
        }

        fe521_to_bytes(d_be, d);
        res = qsc_p521_publickey_from_privatekey(publickey, d_be);

        if (res == 0)
        {
            qsc_memutils_copy(privatekey, seed, EC_NISTP521_SEED_SIZE);
            qsc_memutils_copy(privatekey + EC_NISTP521_SEED_SIZE, publickey, EC_NISTP521_PUBLICKEY_SIZE);
        }

        qsc_memutils_secure_erase(dhash, sizeof(dhash));
        qsc_memutils_secure_erase(d_be, sizeof(d_be));
        qsc_memutils_secure_erase(d, sizeof(d));
    }

    return res;
}

int32_t qsc_p521_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    uint8_t hash[64U];
    uint8_t dhash[64U];
    uint8_t d_be[66U];
    fe521 d;
    fe521 e;
    fe521 k;
    fe521 r;
    fe521 s;
    fe521 tmp;
    p521_aff_t G;
    p521_aff_t kG;
    p521_jac_t kG_jac;
    int32_t res;

    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    res = -1;

    qsc_sha512_compute(hash, message, msglen);
    qsc_sha512_compute(dhash, privatekey, EC_NISTP521_SEED_SIZE);
    sc_from_bytes_reduce(d, dhash, sizeof(dhash));

    if (fe521_is_zero(d) != 0U)
    {
        res = -2;
    }
    else if (fe521_cmp(d, P521_N) < 0)
    {
        sc_from_bytes_reduce(e, hash, sizeof(hash));
        fe521_to_bytes(d_be, d);
        rfc6979_generate_k(k, d_be, hash);

        fe521_copy(G.X, P521_GX);
        fe521_copy(G.Y, P521_GY);

        p521_scalar_mult(&kG_jac, &G, k);
        p521_jac_to_aff(&kG, &kG_jac);

        fe521_copy(r, kG.X);
        mod_n_cond_sub(r);

        if (fe521_is_zero(r) == 0U)
        {
            sc_mul(tmp, r, d);
            sc_add(tmp, tmp, e);
            sc_inv(s, k);
            sc_mul(s, s, tmp);

            if (fe521_is_zero(s) == 0U)
            {
                fe521_to_bytes(signedmsg, r);
                fe521_to_bytes(signedmsg + 66U, s);
                qsc_memutils_copy(signedmsg + EC_NISTP521_SIGNATURE_SIZE, message, msglen);
                *smsglen = EC_NISTP521_SIGNATURE_SIZE + msglen;
                res = 0;
            }
        }
    }

    qsc_memutils_secure_erase(hash, sizeof(hash));
    qsc_memutils_secure_erase(dhash, sizeof(dhash));
    qsc_memutils_secure_erase(d_be, sizeof(d_be));
    qsc_memutils_secure_erase(d, sizeof(d));
    qsc_memutils_secure_erase(e, sizeof(e));
    qsc_memutils_secure_erase(k, sizeof(k));
    qsc_memutils_secure_erase(r, sizeof(r));
    qsc_memutils_secure_erase(s, sizeof(s));
    qsc_memutils_secure_erase(tmp, sizeof(tmp));
    qsc_memutils_secure_erase(&G, sizeof(G));
    qsc_memutils_secure_erase(&kG, sizeof(kG));
    qsc_memutils_secure_erase(&kG_jac, sizeof(kG_jac));

    if (res != 0 && smsglen != NULL)
    {
        *smsglen = 0U;
    }

    return res;
}

int32_t qsc_p521_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    uint8_t hash[64U];
    uint8_t d_be[66U];
    fe521 d;
    fe521 e;
    fe521 k;
    fe521 r;
    fe521 s;
    fe521 tmp;
    p521_aff_t G;
    p521_aff_t kG;
    p521_jac_t kG_jac;
    int32_t res;

    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    res = -1;

    qsc_sha512_compute(hash, message, msglen);
    sc_from_bytes(d, privatekey);

    if (fe521_is_zero(d) != 0U)
    {
        res = -2;
    }
    else if (fe521_cmp(d, P521_N) < 0)
    {
        sc_from_bytes_reduce(e, hash, sizeof(hash));
        fe521_to_bytes(d_be, d);
        rfc6979_generate_k(k, d_be, hash);

        fe521_copy(G.X, P521_GX);
        fe521_copy(G.Y, P521_GY);

        p521_scalar_mult(&kG_jac, &G, k);
        p521_jac_to_aff(&kG, &kG_jac);

        fe521_copy(r, kG.X);
        mod_n_cond_sub(r);

        if (fe521_is_zero(r) == 0U)
        {
            sc_mul(tmp, r, d);
            sc_add(tmp, tmp, e);
            sc_inv(s, k);
            sc_mul(s, s, tmp);

            if (fe521_is_zero(s) == 0U)
            {
                fe521_to_bytes(signedmsg, r);
                fe521_to_bytes(signedmsg + 66U, s);
                qsc_memutils_copy(signedmsg + EC_NISTP521_SIGNATURE_SIZE, message, msglen);
                *smsglen = EC_NISTP521_SIGNATURE_SIZE + msglen;
                res = 0;
            }
        }
    }

    qsc_memutils_secure_erase(hash, sizeof(hash));
    qsc_memutils_secure_erase(d_be, sizeof(d_be));
    qsc_memutils_secure_erase(d, sizeof(d));
    qsc_memutils_secure_erase(e, sizeof(e));
    qsc_memutils_secure_erase(k, sizeof(k));
    qsc_memutils_secure_erase(r, sizeof(r));
    qsc_memutils_secure_erase(s, sizeof(s));
    qsc_memutils_secure_erase(tmp, sizeof(tmp));
    qsc_memutils_secure_erase(&G, sizeof(G));
    qsc_memutils_secure_erase(&kG, sizeof(kG));
    qsc_memutils_secure_erase(&kG_jac, sizeof(kG_jac));

    if (res != 0 && smsglen != NULL)
    {
        *smsglen = 0U;
    }

    return res;
}

bool qsc_p521_verify(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
    uint8_t hash[64U];
    fe521 r;
    fe521 s;
    fe521 e;
    fe521 w;
    fe521 u1;
    fe521 u2;
    fe521 xr;
    p521_aff_t Q;
    p521_aff_t G_init;
    p521_aff_t Rsum;
    p521_jac_t J1;
    p521_jac_t J2;
    p521_jac_t Jsum;
    bool res;
    size_t mlen;

    QSC_ASSERT(msgout != NULL);
    QSC_ASSERT(msglen != NULL);
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(publickey != NULL);

    res = false;

    if (smsglen >= EC_NISTP521_SIGNATURE_SIZE)
    {
        mlen = smsglen - EC_NISTP521_SIGNATURE_SIZE;

        fe521_from_bytes(Q.X, publickey);
        fe521_from_bytes(Q.Y, publickey + 66U);

        if (fe521_cmp(Q.X, P521_P) < 0 && fe521_cmp(Q.Y, P521_P) < 0 && p521_point_is_on_curve(&Q) == true)
        {
            fe521_from_bytes(r, signedmsg);
            fe521_from_bytes(s, signedmsg + 66U);

            if (fe521_is_zero(r) == 0U && fe521_cmp(r, P521_N) < 0 && 
                fe521_is_zero(s) == 0U && fe521_cmp(s, P521_N) < 0)
            {
                qsc_sha512_compute(hash, signedmsg + EC_NISTP521_SIGNATURE_SIZE, mlen);
                sc_from_bytes_reduce(e, hash, sizeof(hash));
                sc_inv(w, s);
                sc_mul(u1, e, w);
                sc_mul(u2, r, w);

                fe521_copy(G_init.X, P521_GX);
                fe521_copy(G_init.Y, P521_GY);

                p521_scalar_mult(&J1, &G_init, u1);
                p521_scalar_mult(&J2, &Q, u2);
                p521_add(&Jsum, &J1, &J2);

                if (p521_jac_to_aff(&Rsum, &Jsum) == true)
                {
                    fe521_copy(xr, Rsum.X);

                    if (fe521_cmp(xr, P521_N) >= 0)
                    {
                        sc_sub(xr, xr, P521_N);
                    }

                    if (fe521_cmp(xr, r) == 0)
                    {
                        qsc_memutils_copy(msgout, signedmsg + EC_NISTP521_SIGNATURE_SIZE, mlen);
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
