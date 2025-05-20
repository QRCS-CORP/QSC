#include "dilithiumbase.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

/* params.h */

#if defined(QSC_DILITHIUM_S1P2544)
#   define DILITHIUM_MODE 2
#elif defined(QSC_DILITHIUM_S3P4016) 
#   define DILITHIUM_MODE 3
#elif defined(QSC_DILITHIUM_S5P4880)
#   define DILITHIUM_MODE 5
#else
#error The dilithium mode is not supported!
#endif

#define DILITHIUM_CRHBYTES 64ULL
#define DILITHIUM_CONTEXT_SIZE 257
#define DILITHIUM_D 13LL
#define DILITHIUM_Q 8380417LL
#define DILITHIUM_MONT -4186625LL /* 2^32 % DILITHIUM_Q */
#define DILITHIUM_N 256LL
#define DILITHIUM_QINV 58728449LL /* q^(-1) mod 2^32 */
#define DILITHIUM_RNDBYTES 32
#define DILITHIUM_ROOT_OF_UNITY 1753LL
#define DILITHIUM_SEEDBYTES 32ULL
#define DILITHIUM_TRBYTES 64

#if (DILITHIUM_MODE == 2)
#   define DILITHIUM_K 4
#   define DILITHIUM_L 4
#   define DILITHIUM_ETA 2
#   define DILITHIUM_TAU 39
#   define DILITHIUM_BETA 78
#   define DILITHIUM_GAMMA1 (1 << 17)
#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1) / 88)
#   define DILITHIUM_OMEGA 80
#   define DILITHIUM_CTILDEBYTES 32
#elif (DILITHIUM_MODE == 3)
#   define DILITHIUM_K 6
#   define DILITHIUM_L 5
#   define DILITHIUM_ETA 4
#   define DILITHIUM_TAU 49
#   define DILITHIUM_BETA 196
#   define DILITHIUM_GAMMA1 (1 << 19)
#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1) / 32)
#   define DILITHIUM_OMEGA 55
#   define DILITHIUM_CTILDEBYTES 48
#elif (DILITHIUM_MODE == 5)
#   define DILITHIUM_K 8
#   define DILITHIUM_L 7
#   define DILITHIUM_ETA 2
#   define DILITHIUM_TAU 60
#   define DILITHIUM_BETA 120
#   define DILITHIUM_GAMMA1 (1 << 19)
#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q - 1) / 32)
#   define DILITHIUM_OMEGA 75
#   define DILITHIUM_CTILDEBYTES 64
#endif

#define DILITHIUM_POLYT1_PACKEDBYTES  320ULL
#define DILITHIUM_POLYT0_PACKEDBYTES  416ULL
#define DILITHIUM_POLYVECH_PACKEDBYTES (DILITHIUM_OMEGA + DILITHIUM_K)

#if (DILITHIUM_GAMMA1 == (1 << 17))
#   define DILITHIUM_POLYZ_PACKEDBYTES 576
#elif (DILITHIUM_GAMMA1 == (1 << 19))
#   define DILITHIUM_POLYZ_PACKEDBYTES 640ULL
#endif

#if (DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 88)
#   define DILITHIUM_POLYW1_PACKEDBYTES 192
#elif (DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 32)
#   define DILITHIUM_POLYW1_PACKEDBYTES  128ULL
#endif

#if (DILITHIUM_ETA == 2)
#   define DILITHIUM_POLYETA_PACKEDBYTES 96ULL
#elif (DILITHIUM_ETA == 4)
#   define DILITHIUM_POLYETA_PACKEDBYTES 128ULL
#endif

#define DILITHIUM_PUBLICKEY_SIZE (DILITHIUM_SEEDBYTES + DILITHIUM_K * DILITHIUM_POLYT1_PACKEDBYTES)
#define DILITHIUM_PRIVATEKEY_SIZE (2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES \
                               + DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES \
                               + DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES \
                               + DILITHIUM_K * DILITHIUM_POLYT0_PACKEDBYTES)
#define DILITHIUM_SIGNATURE_SIZE (DILITHIUM_CTILDEBYTES + DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES + DILITHIUM_POLYVECH_PACKEDBYTES)

#define DILITHIUM_POLY_UNIFORM_NBLOCKS ((768ULL + QSC_KECCAK_128_RATE - 1) / QSC_KECCAK_128_RATE)

#if (DILITHIUM_ETA == 2)
#   define DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS ((136ULL + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
#elif (DILITHIUM_ETA == 4)
#   define DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS ((227ULL + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
#endif

#define DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS ((576 + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)

/*!
* \struct dilithium_poly
* \brief Array of coefficients of length N
*/
typedef struct
{
    int32_t coeffs[DILITHIUM_N];            /*!< The coefficients  */
} dilithium_poly;

/*!
* \struct dilithium_polyvecl
* \brief Vectors of polynomials of length L
*/
typedef struct
{
    dilithium_poly vec[DILITHIUM_L];    /*!< The poly vector of L  */
} dilithium_polyvecl;

/*!
* \struct dilithium_polyveck
* \brief Vectors of polynomials of length K
*/
typedef struct
{
    dilithium_poly vec[DILITHIUM_K];    /*!< The poly vector of K  */
} dilithium_polyveck;

static const int32_t dilithium_zetas[DILITHIUM_N] =
{
            0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
    1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
    2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
    2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
    -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
    -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
    -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
    3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
    -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
    -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
    -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
    1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
    2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
    -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
    2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
    -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
    -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
    -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
    -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
    -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
    -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
    -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
    -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
    -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
    -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/* reduce.c */

static int32_t dilithium_montgomery_reduce(int64_t a)
{
    int32_t t;

    t = (int64_t)(int32_t)a * DILITHIUM_QINV;
    t = (a - (int64_t)t * DILITHIUM_Q) >> 32;

    return t;
}

static int32_t dilithium_reduce32(int32_t a)
{
    int32_t t;

    t = (a + (1 << 22)) >> 23;
    t = a - t * DILITHIUM_Q;

    return t;
}

static int32_t dilithium_caddq(int32_t a)
{
    a += ((int32_t)(uint32_t)a >> 31) & DILITHIUM_Q;

    return a;
}

/* rounding.c */

static int32_t dilithium_power2_round(int32_t* a0, int32_t a)
{
    int32_t a1;

    a1 = (a + (1 << (DILITHIUM_D - 1)) - 1) >> DILITHIUM_D;
    *a0 = a - (a1 << DILITHIUM_D);

    return a1;
}

static int32_t dilithium_decompose(int32_t* a0, int32_t a)
{
    int32_t a1;

    a1 = (a + 127) >> 7;
#if (DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32)
    a1 = ((a1 * 1025) + (1 << 21)) >> 22;
    a1 &= 15;
#elif (DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88)
    a1 = ((a1 * 11275) + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;
#endif

    *a0 = a - (a1 * 2 * DILITHIUM_GAMMA2);
    *a0 -= ((((DILITHIUM_Q - 1) / 2) - *a0) >> 31) & DILITHIUM_Q;

    return a1;
}

static uint32_t dilithium_make_hint(int32_t a0, int32_t a1)
{
    uint32_t res;

    res = 0;

    if (a0 > DILITHIUM_GAMMA2 || a0 < -DILITHIUM_GAMMA2 || (a0 == -DILITHIUM_GAMMA2 && a1 != 0))
    {
        res = 1;
    }

    return res;
}

static int32_t dilithium_use_hint(int32_t a, uint32_t hint)
{
    int32_t a0;
    int32_t a1;
    int32_t res;

    a1 = dilithium_decompose(&a0, a);

    if (hint == 0)
    {
        res = a1;
    }
    else
    {
#if (DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32)
        if (a0 > 0)
        {
            res = (a1 + 1) & 15;
        }
        else
        {
            res = (a1 - 1) & 15;
        }
#elif (DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88)
        if (a0 > 0)
        {
            res = (a1 == 43) ? 0 : a1 + 1;
        }
        else
        {
            res = (a1 == 0) ? 43 : a1 - 1;
        }
#endif
    }

    return res;
}

/* poly.c */

static void dilithium_shake128_stream_init(qsc_keccak_state* kctx, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce)
{
    uint8_t tn[2];
    tn[0] = (uint8_t)nonce;
    tn[1] = nonce >> 8;

    qsc_keccak_initialize_state(kctx);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_128_RATE, seed, DILITHIUM_SEEDBYTES);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_128_RATE, tn, sizeof(tn));
    qsc_keccak_incremental_finalize(kctx, QSC_KECCAK_128_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
}

static void dilithium_shake256_stream_init(qsc_keccak_state* kctx, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
    uint8_t tn[2];
    tn[0] = (uint8_t)nonce;
    tn[1] = nonce >> 8;

    qsc_keccak_initialize_state(kctx);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_256_RATE, seed, DILITHIUM_CRHBYTES);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_256_RATE, tn, sizeof(tn));
    qsc_keccak_incremental_finalize(kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
}

/* ntt.c */

static void dilithium_ntt(int32_t a[DILITHIUM_N])
{
    size_t j;
    size_t k;
    int32_t zeta;
    int32_t t;

    k = 0;

    for (size_t len = 128; len > 0; len >>= 1)
    {
        for (size_t start = 0; start < DILITHIUM_N; start = j + len)
        {
            ++k;
            zeta = dilithium_zetas[k];

            for (j = start; j < start + len; ++j)
            {
                t = dilithium_montgomery_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

static void dilithium_invntt_to_mont(int32_t a[DILITHIUM_N])
{
    size_t j;
    size_t k;
    int32_t t;
    int32_t zeta;
    const int32_t F = 41978; /* mont ^ 2 / 256 */

    k = 256;

    for (size_t len = 1; len < DILITHIUM_N; len <<= 1)
    {
        for (size_t start = 0; start < DILITHIUM_N; start = j + len)
        {
            --k;
            zeta = -dilithium_zetas[k];

            for (j = start; j < start + len; ++j)
            {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = dilithium_montgomery_reduce((int64_t)zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < DILITHIUM_N; ++j)
    {
        a[j] = dilithium_montgomery_reduce((int64_t)F * a[j]);
    }
}

static void dilithium_poly_reduce(dilithium_poly* a)
{
    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        a->coeffs[i] = dilithium_reduce32(a->coeffs[i]);
    }
}

static void dilithium_poly_caddq(dilithium_poly* a)
{
    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        a->coeffs[i] = dilithium_caddq(a->coeffs[i]);
    }
}

static void dilithium_poly_add(dilithium_poly* c, const dilithium_poly* a, const dilithium_poly* b)
{
    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

static void dilithium_poly_sub(dilithium_poly* c, const dilithium_poly* a, const dilithium_poly* b)
{
    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

static void dilithium_poly_shiftl(dilithium_poly* a)
{
    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        a->coeffs[i] <<= DILITHIUM_D;
    }
}

static void dilithium_poly_ntt(dilithium_poly* a)
{
    dilithium_ntt(a->coeffs);
}

static void dilithium_poly_invntt_to_mont(dilithium_poly* a)
{
    dilithium_invntt_to_mont(a->coeffs);
}

static void dilithium_poly_pointwise_montgomery(dilithium_poly* c, const dilithium_poly* a, const dilithium_poly* b)
{
    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = dilithium_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

static void dilithium_poly_power2_round(dilithium_poly* a1, dilithium_poly* a0, const dilithium_poly* a)
{
    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        a1->coeffs[i] = dilithium_power2_round(&a0->coeffs[i], a->coeffs[i]);
    }
}

static void dilithium_poly_decompose(dilithium_poly* a1, dilithium_poly* a0, const dilithium_poly* a)
{
    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        a1->coeffs[i] = dilithium_decompose(&a0->coeffs[i], a->coeffs[i]);
    }
}

static uint32_t dilithium_poly_make_hint(dilithium_poly* h, const dilithium_poly* a0, const dilithium_poly* a1)
{
    uint32_t s;

    s = 0;

    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        h->coeffs[i] = dilithium_make_hint(a0->coeffs[i], a1->coeffs[i]);
        s += h->coeffs[i];
    }

    return s;
}

static void dilithium_poly_use_hint(dilithium_poly* b, const dilithium_poly* a, const dilithium_poly* h)
{
    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        b->coeffs[i] = dilithium_use_hint(a->coeffs[i], h->coeffs[i]);
    }
}

static int32_t dilithium_poly_chknorm(const dilithium_poly* a, int32_t B)
{
    int32_t t;
    int32_t res;

    res = 0;

    if (B > (DILITHIUM_Q - 1) / 8)
    {
        res = 1;
    }
    else
    {
        /* It is ok to leak which coefficient violates the bound since
           the probability for each coefficient is independent of secret
           data but we must not leak the sign of the centralized representative. */
        for (size_t i = 0; i < DILITHIUM_N; ++i)
        {
            /* Absolute value */
            t = a->coeffs[i] >> 31;
            t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

            if (t >= B)
            {
                res = 1;
                break;
            }
        }
    }

    return res;
}

static size_t dilithium_rej_uniform(int32_t* a, size_t len, const uint8_t* buf, size_t buflen)
{
    size_t ctr;
    size_t pos;
    uint32_t t;

    ctr = pos = 0;

    while (ctr < len && pos + 3 <= buflen)
    {
        t = buf[pos];
        ++pos;
        t |= (uint32_t)buf[pos] << 8;
        ++pos;
        t |= (uint32_t)buf[pos] << 16;
        ++pos;
        t &= 0x007FFFFF;

        if (t < DILITHIUM_Q)
        {
            a[ctr] = t;
            ++ctr;
        }
    }

    return ctr;
}

static void dilithium_poly_uniform(dilithium_poly* a, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce)
{
    uint8_t buf[DILITHIUM_POLY_UNIFORM_NBLOCKS * QSC_KECCAK_128_RATE + 2];
    qsc_keccak_state kctx;
    size_t ctr;
    size_t off;
    size_t buflen;

    buflen = DILITHIUM_POLY_UNIFORM_NBLOCKS * QSC_KECCAK_128_RATE;
    dilithium_shake128_stream_init(&kctx, seed, nonce);
    qsc_keccak_squeezeblocks(&kctx, buf, DILITHIUM_POLY_UNIFORM_NBLOCKS, QSC_KECCAK_128_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
    ctr = dilithium_rej_uniform(a->coeffs, DILITHIUM_N, buf, buflen);

    while (ctr < DILITHIUM_N)
    {
        off = buflen % 3;

        for (size_t i = 0; i < off; ++i)
        {
            buf[i] = buf[buflen - off + i];
        }

        qsc_keccak_squeezeblocks(&kctx, buf + off, 1, QSC_KECCAK_128_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
        buflen = QSC_KECCAK_128_RATE + off;
        ctr += dilithium_rej_uniform(a->coeffs + ctr, DILITHIUM_N - ctr, buf, buflen);
    }
}

static size_t dilithium_rej_eta(int32_t* a, size_t len, const uint8_t* buf, size_t buflen)
{
    size_t ctr;
    size_t pos;
    uint32_t t0;
    uint32_t t1;

    ctr = 0;
    pos = 0;

    while (ctr < len && pos < buflen)
    {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos] >> 4;
        ++pos;

#if (DILITHIUM_ETA == 2)
        if (t0 < 15)
        {
            t0 = t0 - (205 * t0 >> 10) * 5;
            a[ctr] = 2 - t0;
            ++ctr;
        }

        if (t1 < 15 && ctr < len)
        {
            t1 = t1 - (205 * t1 >> 10) * 5;
            a[ctr] = 2 - t1;
            ++ctr;
        }
#elif (DILITHIUM_ETA == 4)
        if (t0 < 9)
        {
            a[ctr] = 4 - t0;
            ++ctr;
        }

        if (t1 < 9 && ctr < len)
        {
            a[ctr] = 4 - t1;
            ++ctr;
        }
#endif
    }

    return ctr;
}

static void dilithium_poly_challenge(dilithium_poly* c, const uint8_t seed[DILITHIUM_CTILDEBYTES])
{
    uint8_t buf[QSC_KECCAK_256_RATE];
    qsc_keccak_state kctx;
    uint64_t signs;
    size_t i;
    size_t b;
    size_t pos;

    qsc_keccak_initialize_state(&kctx);

    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, seed, DILITHIUM_CTILDEBYTES);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_squeezeblocks(&kctx, buf, 1, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
    signs = 0;
    pos = 8;

    for (i = 0; i < 8; ++i)
    {
        signs |= (uint64_t)buf[i] << (8 * i);
    }

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = 0;
    }

    for (i = DILITHIUM_N - DILITHIUM_TAU; i < DILITHIUM_N; ++i)
    {
        do
        {
            if (pos >= QSC_KECCAK_256_RATE)
            {
                qsc_keccak_squeezeblocks(&kctx, buf, 1, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
                pos = 0;
            }

            b = buf[pos];
            ++pos;
        } 
        while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - (2 * (signs & 1));
        signs >>= 1;
    }
}

static void dilithium_polyeta_pack(uint8_t* r, const dilithium_poly* a)
{
    uint8_t t[8];

#if DILITHIUM_ETA == 2
    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        t[0] = (uint8_t)(DILITHIUM_ETA - a->coeffs[8 * i]);
        t[1] = (uint8_t)(DILITHIUM_ETA - a->coeffs[(8 * i) + 1]);
        t[2] = (uint8_t)(DILITHIUM_ETA - a->coeffs[(8 * i) + 2]);
        t[3] = (uint8_t)(DILITHIUM_ETA - a->coeffs[(8 * i) + 3]);
        t[4] = (uint8_t)(DILITHIUM_ETA - a->coeffs[(8 * i) + 4]);
        t[5] = (uint8_t)(DILITHIUM_ETA - a->coeffs[(8 * i) + 5]);
        t[6] = (uint8_t)(DILITHIUM_ETA - a->coeffs[(8 * i) + 6]);
        t[7] = (uint8_t)(DILITHIUM_ETA - a->coeffs[(8 * i) + 7]);

        r[3 * i] = (uint8_t)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
        r[(3 * i) + 1] = (uint8_t)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
        r[(3 * i) + 2] = (uint8_t)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
    }
#elif DILITHIUM_ETA == 4
    for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
    {
        t[0] = (uint8_t)(DILITHIUM_ETA - a->coeffs[2 * i]);
        t[1] = (uint8_t)(DILITHIUM_ETA - a->coeffs[(2 * i) + 1]);
        r[i] = (uint8_t)(t[0] | (t[1] << 4));
    }
#endif
}

static void dilithium_polyeta_unpack(dilithium_poly* r, const uint8_t* a)
{
#if (DILITHIUM_ETA == 2)
    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        r->coeffs[8 * i] = (a[3 * i] >> 0) & 7;
        r->coeffs[(8 * i) + 1] = (a[3 * i] >> 3) & 7;
        r->coeffs[(8 * i) + 2] = ((a[3 * i] >> 6) | (a[(3 * i) + 1] << 2)) & 7;
        r->coeffs[(8 * i) + 3] = (a[(3 * i) + 1] >> 1) & 7;
        r->coeffs[(8 * i) + 4] = (a[(3 * i) + 1] >> 4) & 7;
        r->coeffs[(8 * i) + 5] = ((a[(3 * i) + 1] >> 7) | (a[(3 * i) + 2] << 1)) & 7;
        r->coeffs[(8 * i) + 6] = (a[(3 * i) + 2] >> 2) & 7;
        r->coeffs[(8 * i) + 7] = (a[(3 * i) + 2] >> 5) & 7;

        r->coeffs[8 * i] = DILITHIUM_ETA - r->coeffs[8 * i];
        r->coeffs[(8 * i) + 1] = DILITHIUM_ETA - r->coeffs[(8 * i) + 1];
        r->coeffs[(8 * i) + 2] = DILITHIUM_ETA - r->coeffs[(8 * i) + 2];
        r->coeffs[(8 * i) + 3] = DILITHIUM_ETA - r->coeffs[(8 * i) + 3];
        r->coeffs[(8 * i) + 4] = DILITHIUM_ETA - r->coeffs[(8 * i) + 4];
        r->coeffs[(8 * i) + 5] = DILITHIUM_ETA - r->coeffs[(8 * i) + 5];
        r->coeffs[(8 * i) + 6] = DILITHIUM_ETA - r->coeffs[(8 * i) + 6];
        r->coeffs[(8 * i) + 7] = DILITHIUM_ETA - r->coeffs[(8 * i) + 7];
    }
#elif (DILITHIUM_ETA == 4)
    for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
    {
        r->coeffs[2 * i] = a[i] & 0x0F;
        r->coeffs[(2 * i) + 1] = a[i] >> 4;
        r->coeffs[2 * i] = DILITHIUM_ETA - r->coeffs[2 * i];
        r->coeffs[(2 * i) + 1] = DILITHIUM_ETA - r->coeffs[(2 * i) + 1];
    }
#endif
}

static void dilithium_polyt1_pack(uint8_t* r, const dilithium_poly* a)
{
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
    {
        r[5 * i] = (uint8_t)(a->coeffs[4 * i] >> 0);
        r[(5 * i) + 1] = (uint8_t)((a->coeffs[4 * i] >> 8) | (a->coeffs[(4 * i) + 1] << 2));
        r[(5 * i) + 2] = (uint8_t)((a->coeffs[(4 * i) + 1] >> 6) | (a->coeffs[(4 * i) + 2] << 4));
        r[(5 * i) + 3] = (uint8_t)((a->coeffs[(4 * i) + 2] >> 4) | (a->coeffs[(4 * i) + 3] << 6));
        r[(5 * i) + 4] = (uint8_t)(a->coeffs[(4 * i) + 3] >> 2);
    }
}

static void dilithium_polyt1_unpack(dilithium_poly* r, const uint8_t* a)
{
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
    {
        r->coeffs[4 * i] = ((a[5 * i] >> 0) | ((uint32_t)a[(5 * i) + 1] << 8)) & 0x000003FF;
        r->coeffs[(4 * i) + 1] = ((a[(5 * i) + 1] >> 2) | ((uint32_t)a[(5 * i) + 2] << 6)) & 0x000003FF;
        r->coeffs[(4 * i) + 2] = ((a[(5 * i) + 2] >> 4) | ((uint32_t)a[(5 * i) + 3] << 4)) & 0x000003FF;
        r->coeffs[(4 * i) + 3] = ((a[(5 * i) + 3] >> 6) | ((uint32_t)a[(5 * i) + 4] << 2)) & 0x000003FF;
    }
}

static void dilithium_polyt0_pack(uint8_t* r, const dilithium_poly* a)
{
    uint32_t t[8];

    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        t[0] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i];
        t[1] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 1];
        t[2] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 2];
        t[3] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 3];
        t[4] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 4];
        t[5] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 5];
        t[6] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 6];
        t[7] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 7];

        r[13 * i] = (uint8_t)t[0];
        r[(13 * i) + 1] = (uint8_t)(t[0] >> 8);
        r[(13 * i) + 1] |= (uint8_t)(t[1] << 5);
        r[(13 * i) + 2] = (uint8_t)(t[1] >> 3);
        r[(13 * i) + 3] = (uint8_t)(t[1] >> 11);
        r[(13 * i) + 3] |= (uint8_t)(t[2] << 2);
        r[(13 * i) + 4] = (uint8_t)(t[2] >> 6);
        r[(13 * i) + 4] |= (uint8_t)(t[3] << 7);
        r[(13 * i) + 5] = (uint8_t)(t[3] >> 1);
        r[(13 * i) + 6] = (uint8_t)(t[3] >> 9);
        r[(13 * i) + 6] |= (uint8_t)(t[4] << 4);
        r[(13 * i) + 7] = (uint8_t)(t[4] >> 4);
        r[(13 * i) + 8] = (uint8_t)(t[4] >> 12);
        r[(13 * i) + 8] |= (uint8_t)(t[5] << 1);
        r[(13 * i) + 9] = (uint8_t)(t[5] >> 7);
        r[(13 * i) + 9] |= (uint8_t)(t[6] << 6);
        r[(13 * i) + 10] = (uint8_t)(t[6] >> 2);
        r[(13 * i) + 11] = (uint8_t)(t[6] >> 10);
        r[(13 * i) + 11] |= (uint8_t)(t[7] << 3);
        r[(13 * i) + 12] = (uint8_t)(t[7] >> 5);
    }
}

static void dilithium_polyt0_unpack(dilithium_poly* r, const uint8_t* a)
{
    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        r->coeffs[8 * i] = a[13 * i];
        r->coeffs[8 * i] |= (uint32_t)a[(13 * i) + 1] << 8;
        r->coeffs[8 * i] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 1] = a[(13 * i) + 1] >> 5;
        r->coeffs[(8 * i) + 1] |= (uint32_t)a[(13 * i) + 2] << 3;
        r->coeffs[(8 * i) + 1] |= (uint32_t)a[(13 * i) + 3] << 11;
        r->coeffs[(8 * i) + 1] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 2] = a[(13 * i) + 3] >> 2;
        r->coeffs[(8 * i) + 2] |= (uint32_t)a[(13 * i) + 4] << 6;
        r->coeffs[(8 * i) + 2] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 3] = a[(13 * i) + 4] >> 7;
        r->coeffs[(8 * i) + 3] |= (uint32_t)a[(13 * i) + 5] << 1;
        r->coeffs[(8 * i) + 3] |= (uint32_t)a[(13 * i) + 6] << 9;
        r->coeffs[(8 * i) + 3] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 4] = a[(13 * i) + 6] >> 4;
        r->coeffs[(8 * i) + 4] |= (uint32_t)a[(13 * i) + 7] << 4;
        r->coeffs[(8 * i) + 4] |= (uint32_t)a[(13 * i) + 8] << 12;
        r->coeffs[(8 * i) + 4] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 5] = a[(13 * i) + 8] >> 1;
        r->coeffs[(8 * i) + 5] |= (uint32_t)a[(13 * i) + 9] << 7;
        r->coeffs[(8 * i) + 5] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 6] = a[(13 * i) + 9] >> 6;
        r->coeffs[(8 * i) + 6] |= (uint32_t)a[(13 * i) + 10] << 2;
        r->coeffs[(8 * i) + 6] |= (uint32_t)a[(13 * i) + 11] << 10;
        r->coeffs[(8 * i) + 6] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 7] = a[(13 * i) + 11] >> 3;
        r->coeffs[(8 * i) + 7] |= (uint32_t)a[(13 * i) + 12] << 5;
        r->coeffs[(8 * i) + 7] &= 0x00001FFFL;

        r->coeffs[8 * i] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i];
        r->coeffs[(8 * i) + 1] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 1];
        r->coeffs[(8 * i) + 2] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 2];
        r->coeffs[(8 * i) + 3] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 3];
        r->coeffs[(8 * i) + 4] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 4];
        r->coeffs[(8 * i) + 5] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 5];
        r->coeffs[(8 * i) + 6] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 6];
        r->coeffs[(8 * i) + 7] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 7];
    }
}

static void dilithium_polyz_pack(uint8_t* r, const dilithium_poly* a)
{
    uint32_t t[4];

#if (DILITHIUM_GAMMA1 == (1 << 17))
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
    {
        t[0] = DILITHIUM_GAMMA1 - a->coeffs[4 * i];
        t[1] = DILITHIUM_GAMMA1 - a->coeffs[(4 * i) + 1];
        t[2] = DILITHIUM_GAMMA1 - a->coeffs[(4 * i) + 2];
        t[3] = DILITHIUM_GAMMA1 - a->coeffs[(4 * i) + 3];

        r[9 * i] = (uint8_t)t[0];
        r[(9 * i) + 1] = (uint8_t)(t[0] >> 8);
        r[(9 * i) + 2] = (uint8_t)(t[0] >> 16);
        r[(9 * i) + 2] |= (uint8_t)(t[1] << 2);
        r[(9 * i) + 3] = (uint8_t)(t[1] >> 6);
        r[(9 * i) + 4] = (uint8_t)(t[1] >> 14);
        r[(9 * i) + 4] |= (uint8_t)(t[2] << 4);
        r[(9 * i) + 5] = (uint8_t)(t[2] >> 4);
        r[(9 * i) + 6] = (uint8_t)(t[2] >> 12);
        r[(9 * i) + 6] |= (uint8_t)(t[3] << 6);
        r[(9 * i) + 7] = (uint8_t)(t[3] >> 2);
        r[(9 * i) + 8] = (uint8_t)(t[3] >> 10);
    }
#elif (DILITHIUM_GAMMA1 == (1 << 19))
    for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
    {
        t[0] = DILITHIUM_GAMMA1 - a->coeffs[2 * i];
        t[1] = DILITHIUM_GAMMA1 - a->coeffs[(2 * i) + 1];

        r[5 * i] = (uint8_t)t[0];
        r[(5 * i) + 1] = (uint8_t)(t[0] >> 8);
        r[(5 * i) + 2] = (uint8_t)(t[0] >> 16);
        r[(5 * i) + 2] |= (uint8_t)(t[1] << 4);
        r[(5 * i) + 3] = (uint8_t)(t[1] >> 4);
        r[(5 * i) + 4] = (uint8_t)(t[1] >> 12);
    }
#endif
}

static void dilithium_polyz_unpack(dilithium_poly* r, const uint8_t* a)
{
#if (DILITHIUM_GAMMA1 == (1 << 17))
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
    {
        r->coeffs[4 * i] = a[9 * i];
        r->coeffs[4 * i] |= (uint32_t)a[(9 * i) + 1] << 8;
        r->coeffs[4 * i] |= (uint32_t)a[(9 * i) + 2] << 16;
        r->coeffs[4 * i] &= 0x0003FFFF;

        r->coeffs[(4 * i) + 1] = a[(9 * i) + 2] >> 2;
        r->coeffs[(4 * i) + 1] |= (uint32_t)a[(9 * i) + 3] << 6;
        r->coeffs[(4 * i) + 1] |= (uint32_t)a[(9 * i) + 4] << 14;
        r->coeffs[(4 * i) + 1] &= 0x0003FFFF;

        r->coeffs[(4 * i) + 2] = a[(9 * i) + 4] >> 4;
        r->coeffs[(4 * i) + 2] |= (uint32_t)a[(9 * i) + 5] << 4;
        r->coeffs[(4 * i) + 2] |= (uint32_t)a[(9 * i) + 6] << 12;
        r->coeffs[(4 * i) + 2] &= 0x0003FFFF;

        r->coeffs[(4 * i) + 3] = a[(9 * i) + 6] >> 6;
        r->coeffs[(4 * i) + 3] |= (uint32_t)a[(9 * i) + 7] << 2;
        r->coeffs[(4 * i) + 3] |= (uint32_t)a[(9 * i) + 8] << 10;
        r->coeffs[(4 * i) + 3] &= 0x0003FFFF;

        r->coeffs[4 * i] = DILITHIUM_GAMMA1 - r->coeffs[4 * i];
        r->coeffs[(4 * i) + 1] = DILITHIUM_GAMMA1 - r->coeffs[(4 * i) + 1];
        r->coeffs[(4 * i) + 2] = DILITHIUM_GAMMA1 - r->coeffs[(4 * i) + 2];
        r->coeffs[(4 * i) + 3] = DILITHIUM_GAMMA1 - r->coeffs[(4 * i) + 3];
    }
#elif (DILITHIUM_GAMMA1 == (1 << 19))
    for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
    {
        r->coeffs[2 * i] = a[5 * i];
        r->coeffs[2 * i] |= (uint32_t)a[(5 * i) + 1] << 8;
        r->coeffs[2 * i] |= (uint32_t)a[(5 * i) + 2] << 16;
        r->coeffs[2 * i] &= 0x000FFFFFL;

        r->coeffs[(2 * i) + 1] = a[(5 * i) + 2] >> 4;
        r->coeffs[(2 * i) + 1] |= (uint32_t)a[(5 * i) + 3] << 4;
        r->coeffs[(2 * i) + 1] |= (uint32_t)a[(5 * i) + 4] << 12;
        r->coeffs[2 * i] &= 0x000FFFFFL;

        r->coeffs[2 * i] = DILITHIUM_GAMMA1 - r->coeffs[2 * i];
        r->coeffs[(2 * i) + 1] = DILITHIUM_GAMMA1 - r->coeffs[(2 * i) + 1];
    }
#endif
}

static void dilithium_polyw1_pack(uint8_t* r, const dilithium_poly* a)
{
#if (DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88)
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
    {
        r[3 * i] = (uint8_t)a->coeffs[4 * i];
        r[3 * i] |= (uint8_t)(a->coeffs[(4 * i) + 1] << 6);
        r[(3 * i) + 1] = (uint8_t)(a->coeffs[(4 * i) + 1] >> 2);
        r[(3 * i) + 1] |= (uint8_t)(a->coeffs[(4 * i) + 2] << 4);
        r[(3 * i) + 2] = (uint8_t)(a->coeffs[(4 * i) + 2] >> 4);
        r[(3 * i) + 2] |= (uint8_t)(a->coeffs[(4 * i) + 3] << 2);
    }
#elif (DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32)
    for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
    {
        r[i] = (uint8_t)(a->coeffs[2 * i] | (a->coeffs[(2 * i) + 1] << 4));
    }
#endif
}

static void dilithium_poly_uniform_eta(dilithium_poly* a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
    uint8_t buf[DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS * QSC_KECCAK_256_RATE];
    qsc_keccak_state kctx;
    size_t ctr;
    size_t buflen;

    buflen = DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS * QSC_KECCAK_256_RATE;
    dilithium_shake256_stream_init(&kctx, seed, nonce);
    qsc_keccak_squeezeblocks(&kctx, buf, DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);

    ctr = dilithium_rej_eta(a->coeffs, DILITHIUM_N, buf, buflen); // Check: is rej_eta processing the last 4 bytes?

    while (ctr < DILITHIUM_N)
    {
        qsc_keccak_squeezeblocks(&kctx, buf, 1, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
        ctr += dilithium_rej_eta(a->coeffs + ctr, DILITHIUM_N - ctr, buf, QSC_KECCAK_256_RATE);
    }
}

static void dilithium_poly_uniform_gamma1(dilithium_poly* a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
    uint8_t buf[DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS * QSC_KECCAK_256_RATE];
    qsc_keccak_state kctx;

    dilithium_shake256_stream_init(&kctx, seed, nonce);
    qsc_keccak_squeezeblocks(&kctx, buf, DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
    dilithium_polyz_unpack(a, buf);
}

/* polyvec.c */

static void dilithium_polyvec_matrix_expand(dilithium_polyvecl mat[DILITHIUM_K], const uint8_t rho[DILITHIUM_SEEDBYTES])
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        for (size_t j = 0; j < DILITHIUM_L; ++j)
        {
            dilithium_poly_uniform(&mat[i].vec[j], rho, (uint16_t)((i << 8) + j));
        }
    }
}

static void dilithium_polyvecl_pointwise_acc_montgomery(dilithium_poly* w, const dilithium_polyvecl* u, const dilithium_polyvecl* v)
{
    dilithium_poly t;

    dilithium_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);

    for (size_t i = 1; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        dilithium_poly_add(w, w, &t);
    }
}

static void dilithium_polyvec_matrix_pointwise_montgomery(dilithium_polyveck* t, const dilithium_polyvecl mat[DILITHIUM_K], const dilithium_polyvecl* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
    }
}

static void dilithium_polyvecl_uniform_eta(dilithium_polyvecl* v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
    for (size_t i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_uniform_eta(&v->vec[i], seed, nonce);
        ++nonce;
    }
}

static void dilithium_polyvecl_uniform_gamma1(dilithium_polyvecl* v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
    for (size_t i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_uniform_gamma1(&v->vec[i], seed, (uint16_t)((DILITHIUM_L * nonce) + i));
    }
}

static void dilithium_polyvecl_reduce(dilithium_polyvecl* v)
{
    for (size_t i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_reduce(&v->vec[i]);
    }
}

static void dilithium_polyvecl_add(dilithium_polyvecl* w, const dilithium_polyvecl* u, const dilithium_polyvecl* v)
{
    for (size_t i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void dilithium_polyvecl_ntt(dilithium_polyvecl* v)
{
    for (size_t i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

static void dilithium_polyvecl_invntt_to_mont(dilithium_polyvecl* v)
{
    for (size_t i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_invntt_to_mont(&v->vec[i]);
    }
}

static void dilithium_polyvecl_pointwise_poly_montgomery(dilithium_polyvecl* r, const dilithium_poly* a, const dilithium_polyvecl* v)
{
    for (size_t i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

static int32_t dilithium_polyvecl_chknorm(const dilithium_polyvecl* v, int32_t bound)
{
    int32_t res;

    res = 0;

    for (size_t i = 0; i < DILITHIUM_L; ++i)
    {
        if (dilithium_poly_chknorm(&v->vec[i], bound) != 0)
        {
            res = 1;
            break;
        }
    }

    return res;
}

static void dilithium_polyveck_uniform_eta(dilithium_polyveck* v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_uniform_eta(&v->vec[i], seed, nonce);
        ++nonce;
    }
}

static void dilithium_polyveck_reduce(dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_reduce(&v->vec[i]);
    }
}

static void dilithium_polyveck_caddq(dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_caddq(&v->vec[i]);
    }
}

static void dilithium_polyveck_add(dilithium_polyveck* w, const dilithium_polyveck* u, const dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void dilithium_polyveck_sub(dilithium_polyveck* w, const dilithium_polyveck* u, const dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void dilithium_polyveck_shiftl(dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_shiftl(&v->vec[i]);
    }
}

static void dilithium_polyveck_ntt(dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

static void dilithium_polyveck_invntt_to_mont(dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_invntt_to_mont(&v->vec[i]);
    }
}

static void dilithium_polyveck_pointwise_poly_montgomery(dilithium_polyveck* r, const dilithium_poly* a, const dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

static int32_t dilithium_polyveck_chknorm(const dilithium_polyveck* v, int32_t bound)
{
    int32_t res;

    res = 0;

    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        if (dilithium_poly_chknorm(&v->vec[i], bound) != 0)
        {
            res = 1;
            break;
        }
    }

    return res;
}

static void dilithium_polyveck_power2_round(dilithium_polyveck* v1, dilithium_polyveck* v0, const dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_power2_round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

static void dilithium_polyveck_decompose(dilithium_polyveck* v1, dilithium_polyveck* v0, const dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

static uint32_t dilithium_polyveck_make_hint(dilithium_polyveck* h, const dilithium_polyveck* v0, const dilithium_polyveck* v1)
{
    uint32_t s;

    s = 0;

    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        s += dilithium_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    }

    return s;
}

static void dilithium_polyveck_use_hint(dilithium_polyveck* w, const dilithium_polyveck* u, const dilithium_polyveck* h)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
    }
}

static void dilithium_polyveck_pack_w1(uint8_t r[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES], const dilithium_polyveck* w1)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_polyw1_pack(&r[i * DILITHIUM_POLYW1_PACKEDBYTES], &w1->vec[i]);
    }
}

/* packing.c */

static void dilithium_pack_pk(uint8_t pk[DILITHIUM_PUBLICKEY_SIZE], const uint8_t rho[DILITHIUM_SEEDBYTES], const dilithium_polyveck* t1)
{
    size_t i;

    for (i = 0; i < DILITHIUM_SEEDBYTES; ++i)
    {
        pk[i] = rho[i];
    }

    pk += DILITHIUM_SEEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_polyt1_pack(pk + i * DILITHIUM_POLYT1_PACKEDBYTES, &t1->vec[i]);
    }
}

static void dilithium_unpack_pk(uint8_t rho[DILITHIUM_SEEDBYTES], dilithium_polyveck* t1, const uint8_t pk[DILITHIUM_PUBLICKEY_SIZE])
{
    size_t i;

    for (i = 0; i < DILITHIUM_SEEDBYTES; ++i)
    {
        rho[i] = pk[i];
    }

    pk += DILITHIUM_SEEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_polyt1_unpack(&t1->vec[i], pk + i * DILITHIUM_POLYT1_PACKEDBYTES);
    }
}

static void dilithium_pack_sk(uint8_t sk[DILITHIUM_PRIVATEKEY_SIZE], const uint8_t rho[DILITHIUM_SEEDBYTES], const uint8_t tr[DILITHIUM_CRHBYTES],
    const uint8_t key[DILITHIUM_SEEDBYTES], const dilithium_polyveck* t0, const dilithium_polyvecl* s1, const dilithium_polyveck* s2)
{
    size_t  i;

    qsc_memutils_copy(sk, rho, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    qsc_memutils_copy(sk, key, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    qsc_memutils_copy(sk, tr, DILITHIUM_TRBYTES);
    sk += DILITHIUM_TRBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_polyeta_pack(sk + i * DILITHIUM_POLYETA_PACKEDBYTES, &s1->vec[i]);
    }

    sk += DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_polyeta_pack(sk + i * DILITHIUM_POLYETA_PACKEDBYTES, &s2->vec[i]);
    }

    sk += DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_polyt0_pack(sk + i * DILITHIUM_POLYT0_PACKEDBYTES, &t0->vec[i]);
    }
}

static void dilithium_unpack_sk(uint8_t rho[DILITHIUM_SEEDBYTES], uint8_t tr[DILITHIUM_CRHBYTES], uint8_t key[DILITHIUM_SEEDBYTES],
    dilithium_polyveck* t0, dilithium_polyvecl* s1, dilithium_polyveck* s2, const uint8_t sk[DILITHIUM_PRIVATEKEY_SIZE])
{
    size_t  i;

    qsc_memutils_copy(rho, sk, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    qsc_memutils_copy(key, sk, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    qsc_memutils_copy(tr, sk, DILITHIUM_TRBYTES);
    sk += DILITHIUM_TRBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_polyeta_unpack(&s1->vec[i], sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
    }

    sk += DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_polyeta_unpack(&s2->vec[i], sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
    }

    sk += DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_polyt0_unpack(&t0->vec[i], sk + i * DILITHIUM_POLYT0_PACKEDBYTES);
    }
}

static void dilithium_pack_sig(uint8_t sig[DILITHIUM_SIGNATURE_SIZE], const uint8_t c[DILITHIUM_CTILDEBYTES], const dilithium_polyvecl* z, const dilithium_polyveck* h)
{
    size_t i;
    size_t j;
    size_t k;

    for (i = 0; i < DILITHIUM_CTILDEBYTES; ++i)
    {
        sig[i] = c[i];
    }

    sig += DILITHIUM_CTILDEBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_polyz_pack(sig + i * DILITHIUM_POLYZ_PACKEDBYTES, &z->vec[i]);
    }

    sig += DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;

    /* Encode h */
    qsc_memutils_clear(sig, DILITHIUM_OMEGA + DILITHIUM_K);
    k = 0;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        for (j = 0; j < DILITHIUM_N; ++j)
        {
            if (h->vec[i].coeffs[j] != 0)
            {
                sig[k] = (uint8_t)j;
                ++k;
            }
        }

        sig[DILITHIUM_OMEGA + i] = (uint8_t)k;
    }
}

static int32_t dilithium_unpack_sig(uint8_t c[DILITHIUM_CTILDEBYTES], dilithium_polyvecl* z, dilithium_polyveck* h, const uint8_t sig[DILITHIUM_SIGNATURE_SIZE])
{
    size_t i;
    size_t j;
    size_t k;
    int32_t res;

    res = 0;

    qsc_memutils_copy(c, sig, DILITHIUM_CTILDEBYTES);
    sig += DILITHIUM_CTILDEBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_polyz_unpack(&z->vec[i], sig + i * DILITHIUM_POLYZ_PACKEDBYTES);
    }

    sig += DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;

    /* Decode h */
    k = 0;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        for (j = 0; j < DILITHIUM_N; ++j)
        {
            h->vec[i].coeffs[j] = 0;
        }

        if (sig[DILITHIUM_OMEGA + i] < k || sig[DILITHIUM_OMEGA + i] > DILITHIUM_OMEGA)
        {
            res = 1;
            break;
        }

        for (j = k; j < sig[DILITHIUM_OMEGA + i]; ++j)
        {
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[j] <= sig[j - 1])
            {
                res = 1;
                break;
            }

            h->vec[i].coeffs[sig[j]] = 1;
        }

        if (res != 0)
        {
            break;
        }

        k = sig[DILITHIUM_OMEGA + i];
    }

    if (res == 0)
    {
        /* Extra indices are zero for strong unforgeability */
        for (j = k; j < DILITHIUM_OMEGA; ++j)
        {
            if (sig[j] != 0)
            {
                res = 1;
                break;
            }
        }
    }

    return res;
}

/* sign.c */

void qsc_dilithium_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl s1;
    dilithium_polyvecl s1hat;
    dilithium_polyveck s2;
    dilithium_polyveck t1;
    dilithium_polyveck t0;
    uint8_t seedbuf[2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES];
    uint8_t tr[DILITHIUM_TRBYTES];
    const uint8_t* rho;
    const uint8_t* rhoprime;
    const uint8_t* key;

    /* Get randomness for rho, rhoprime and key */
    rng_generate(seedbuf, DILITHIUM_SEEDBYTES);
    seedbuf[DILITHIUM_SEEDBYTES] = DILITHIUM_K;
    seedbuf[DILITHIUM_SEEDBYTES + 1] = DILITHIUM_L;
    qsc_shake256_compute(seedbuf, 2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES, seedbuf, DILITHIUM_SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = seedbuf + DILITHIUM_SEEDBYTES;
    key = rhoprime + DILITHIUM_CRHBYTES;

    /* Expand matrix */
    dilithium_polyvec_matrix_expand(mat, rho);

    /* Sample short vectors s1 and s2 */
    dilithium_polyvecl_uniform_eta(&s1, rhoprime, 0);
    dilithium_polyveck_uniform_eta(&s2, rhoprime, DILITHIUM_L);

    /* Matrix-vector multiplication */
    s1hat = s1;
    dilithium_polyvecl_ntt(&s1hat);
    dilithium_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    dilithium_polyveck_reduce(&t1);
    dilithium_polyveck_invntt_to_mont(&t1);

    /* Add error vector s2 */
    dilithium_polyveck_add(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    dilithium_polyveck_caddq(&t1);
    dilithium_polyveck_power2_round(&t1, &t0, &t1);
    dilithium_pack_pk(pk, rho, &t1);

    /* Compute CRH(rho, t1) and write secret key */
    qsc_shake256_compute(tr, DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);
    dilithium_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
}

void qsc_dilithium_ref_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* context, size_t contextlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    uint8_t seedbuf[(2 * DILITHIUM_SEEDBYTES) + DILITHIUM_TRBYTES + (2 * DILITHIUM_CRHBYTES)];
    dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl s1;
    dilithium_polyvecl y;
    dilithium_polyvecl z;
    dilithium_polyveck h;
    dilithium_polyveck s2;
    dilithium_polyveck t0;
    dilithium_polyveck w1;
    dilithium_polyveck w0;
    dilithium_poly cp;
    qsc_keccak_state kctx;
    uint8_t rnd[DILITHIUM_RNDBYTES] = { 0 };
    uint8_t* rho;
    uint8_t* tr;
    uint8_t* key;
    uint8_t* mu;
    uint8_t* rhoprime;
    uint32_t n;
    uint16_t nonce;

    nonce = 0;
    rho = seedbuf;
    tr = rho + DILITHIUM_SEEDBYTES;
    key = tr + DILITHIUM_TRBYTES;
    mu = key + DILITHIUM_SEEDBYTES;
    rhoprime = mu + DILITHIUM_CRHBYTES;

    dilithium_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* compute CRH(tr, msg) */
    qsc_keccak_initialize_state(&kctx);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, tr, DILITHIUM_TRBYTES);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, context, contextlen);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, m, mlen);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);

#if defined(QSC_DILITHIUM_RANDOMIZED_SIGNING)
    rng_generate(rnd, DILITHIUM_CRHBYTES);
#endif

    /* compute rhoprime = CRH(key, rnd, mu) */
    qsc_keccak_initialize_state(&kctx);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, key, DILITHIUM_SEEDBYTES);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, rnd, DILITHIUM_RNDBYTES);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, rhoprime, DILITHIUM_CRHBYTES);

    /* expand matrix and transform vectors */
    dilithium_polyvec_matrix_expand(mat, rho);
    dilithium_polyvecl_ntt(&s1);
    dilithium_polyveck_ntt(&s2);
    dilithium_polyveck_ntt(&t0);

    while (true)
    {
        /* sample intermediate vector y */
        dilithium_polyvecl_uniform_gamma1(&y, rhoprime, nonce);
        ++nonce;
        z = y;
        dilithium_polyvecl_ntt(&z);

        /* matrix-vector multiplication */
        dilithium_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
        dilithium_polyveck_reduce(&w1);
        dilithium_polyveck_invntt_to_mont(&w1);

        /* decompose w and call the random oracle */
        dilithium_polyveck_caddq(&w1);
        dilithium_polyveck_decompose(&w1, &w0, &w1);
        dilithium_polyveck_pack_w1(sig, &w1);

        qsc_keccak_initialize_state(&kctx);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, sig, DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
        qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
        qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, sig, DILITHIUM_CTILDEBYTES);

        dilithium_poly_challenge(&cp, sig);
        dilithium_poly_ntt(&cp);

        /* compute z, reject if it reveals secret */
        dilithium_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
        dilithium_polyvecl_invntt_to_mont(&z);
        dilithium_polyvecl_add(&z, &z, &y);
        dilithium_polyvecl_reduce(&z);

        if (dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA) != 0)
        {
            continue;
        }

        /* check that subtracting cs2 does not change high bits of w and low bits
           do not reveal secret information */
        dilithium_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
        dilithium_polyveck_invntt_to_mont(&h);
        dilithium_polyveck_sub(&w0, &w0, &h);
        dilithium_polyveck_reduce(&w0);

        if (dilithium_polyveck_chknorm(&w0, DILITHIUM_GAMMA2 - DILITHIUM_BETA) != 0)
        {
            continue;
        }

        /* compute hints for w1 */
        dilithium_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
        dilithium_polyveck_invntt_to_mont(&h);
        dilithium_polyveck_reduce(&h);

        if (dilithium_polyveck_chknorm(&h, DILITHIUM_GAMMA2) != 0)
        {
            continue;
        }

        dilithium_polyveck_add(&w0, &w0, &h);
        n = dilithium_polyveck_make_hint(&h, &w0, &w1);

        if (n > DILITHIUM_OMEGA)
        {
            continue;
        }

        break;
    }

    /* write signature */
    dilithium_pack_sig(sig, sig, &z, &h);
    *siglen = DILITHIUM_SIGNATURE_SIZE;
}

void qsc_dilithium_ref_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen, const uint8_t* context, size_t contextlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    if (contextlen <= 255)
    {
        uint8_t prec[DILITHIUM_CONTEXT_SIZE] = { 0 };

        /* prepare pre = (0, contextlen, ctx) */
        prec[0] = 0;
        prec[1] = (uint8_t)contextlen;

        if (context != NULL)
        {
            qsc_memutils_copy(prec + 2, context, contextlen);
        }

        for (size_t i = 0; i < mlen; ++i)
        {
            sm[DILITHIUM_SIGNATURE_SIZE + mlen - 1 - i] = m[mlen - 1 - i];
        }

        qsc_dilithium_ref_sign_signature(sm, smlen, sm + DILITHIUM_SIGNATURE_SIZE, mlen, prec, contextlen + 2, sk, rng_generate);
        *smlen += mlen;
    }
}

bool qsc_dilithium_ref_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* context, size_t contextlen, const uint8_t* pk)
{
    uint8_t buf[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES];
    uint8_t rho[DILITHIUM_SEEDBYTES];
    uint8_t mu[DILITHIUM_CRHBYTES];
    uint8_t c[DILITHIUM_CTILDEBYTES];
    uint8_t c2[DILITHIUM_CTILDEBYTES];
    dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl z;
    dilithium_polyveck h;
    dilithium_polyveck t1;
    dilithium_polyveck w1;
    dilithium_poly cp;
    qsc_keccak_state kctx = { 0 };
    bool res;

    res = false;

    if (siglen >= DILITHIUM_SIGNATURE_SIZE)
    {
        dilithium_unpack_pk(rho, &t1, pk);

        if (dilithium_unpack_sig(c, &z, &h, sig) == 0)
        {
            if (dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA) == 0)
            {
                /* Compute CRH(CRH(rho, t1), msg) */
                qsc_shake256_compute(mu, DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);

                qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
                qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, context, contextlen);
                qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, m, mlen);
                qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
                qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);

                /* Matrix-vector multiplication; compute Az - c2^dt1 */
                dilithium_poly_challenge(&cp, c);
                dilithium_polyvec_matrix_expand(mat, rho);

                dilithium_polyvecl_ntt(&z);
                dilithium_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

                dilithium_poly_ntt(&cp);
                dilithium_polyveck_shiftl(&t1);
                dilithium_polyveck_ntt(&t1);
                dilithium_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

                dilithium_polyveck_sub(&w1, &w1, &t1);
                dilithium_polyveck_reduce(&w1);
                dilithium_polyveck_invntt_to_mont(&w1);

                /* Reconstruct w1 */
                dilithium_polyveck_caddq(&w1);
                dilithium_polyveck_use_hint(&w1, &w1, &h);
                dilithium_polyveck_pack_w1(buf, &w1);

                /* Call random oracle and verify challenge */
                qsc_keccak_initialize_state(&kctx);
                qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
                qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, buf, DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
                qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
                qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, c2, DILITHIUM_SEEDBYTES);

                res = (qsc_intutils_verify(c, c2, DILITHIUM_SEEDBYTES) == 0);
            }
        }
    }

    return res;
}

bool qsc_dilithium_ref_open(uint8_t* m, size_t* mlen, const uint8_t* sm, size_t smlen, const uint8_t* context, size_t contextlen, const uint8_t* pk)
{
    bool res;

    *mlen = 0;
    res = false;

    if (contextlen <= 255)
    {
        uint8_t prec[DILITHIUM_CONTEXT_SIZE] = { 0 };

        /* prepare pre = (0, ctxlen, ctx) */
        prec[0] = 0;
        prec[1] = (uint8_t)contextlen;

        if (context != NULL)
        {
            qsc_memutils_copy(prec + 2, context, contextlen);
        }

        if (smlen >= DILITHIUM_SIGNATURE_SIZE)
        {
            *mlen = smlen - DILITHIUM_SIGNATURE_SIZE;
            res = qsc_dilithium_ref_verify(sm, DILITHIUM_SIGNATURE_SIZE, sm + DILITHIUM_SIGNATURE_SIZE, *mlen, prec, contextlen + 2, pk);

            if (res == true)
            {
                /* All good, copy msg, return 0 */
                qsc_memutils_copy(m, sm + DILITHIUM_SIGNATURE_SIZE, *mlen);
            }
        }
    }

    if (res == false)
    {
        qsc_memutils_clear(m, smlen - DILITHIUM_SIGNATURE_SIZE);
    }

    return res;
}
