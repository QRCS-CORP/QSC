#include "dilithiumbase.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

/* params.h */

#define DILITHIUM_MONT -4186625 /* 2^32 % DILITHIUM_Q */
#define DILITHIUM_QINV 58728449 /* q^(-1) mod 2^32 */

#define DILITHIUM_SEEDBYTES 32
#define DILITHIUM_CRHBYTES 48
#define DILITHIUM_Q 8380417
#define DILITHIUM_D 13
#define DILITHIUM_ROOT_OF_UNITY 1753

#if (QSC_DILITHIUM_MODE == 2)
#   define DILITHIUM_ETA 2
#   define DILITHIUM_TAU 39
#   define DILITHIUM_BETA 78
#   define DILITHIUM_GAMMA1 (1 << 17)
#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1) / 88)
#   define DILITHIUM_OMEGA 80
#elif (QSC_DILITHIUM_MODE == 3)
#   define DILITHIUM_ETA 4
#   define DILITHIUM_TAU 49
#   define DILITHIUM_BETA 196
#   define DILITHIUM_GAMMA1 (1 << 19)
#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1) / 32)
#   define DILITHIUM_OMEGA 55
#elif (QSC_DILITHIUM_MODE == 5)
#   define DILITHIUM_ETA 2
#   define DILITHIUM_TAU 60
#   define DILITHIUM_BETA 120
#   define DILITHIUM_GAMMA1 (1 << 19)
#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q - 1) / 32)
#   define DILITHIUM_OMEGA 75
#endif

#define DILITHIUM_POLYT1_PACKEDBYTES  320
#define DILITHIUM_POLYT0_PACKEDBYTES  416
#define DILITHIUM_POLYVECH_PACKEDBYTES (DILITHIUM_OMEGA + QSC_DILITHIUM_K)

#if (DILITHIUM_GAMMA1 == (1 << 17))
#   define DILITHIUM_POLYZ_PACKEDBYTES   576
#elif (DILITHIUM_GAMMA1 == (1 << 19))
#   define DILITHIUM_POLYZ_PACKEDBYTES   640
#endif

#if (DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 88)
#   define DILITHIUM_POLYW1_PACKEDBYTES  192
#elif (DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 32)
#   define DILITHIUM_POLYW1_PACKEDBYTES  128
#endif

#if (DILITHIUM_ETA == 2)
#   define DILITHIUM_POLYETA_PACKEDBYTES  96
#elif (DILITHIUM_ETA == 4)
#   define DILITHIUM_POLYETA_PACKEDBYTES 128
#endif

#define DILITHIUM_PUBLICKEY_SIZE (DILITHIUM_SEEDBYTES + QSC_DILITHIUM_K * DILITHIUM_POLYT1_PACKEDBYTES)
#define DILITHIUM_PRIVATEKEY_SIZE (2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES \
                               + QSC_DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES \
                               + QSC_DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES \
                               + QSC_DILITHIUM_K * DILITHIUM_POLYT0_PACKEDBYTES)
#define DILITHIUM_SIGNATURE_SIZE (DILITHIUM_SEEDBYTES + QSC_DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES + DILITHIUM_POLYVECH_PACKEDBYTES)

#define DILITHIUM_POLY_UNIFORM_NBLOCKS ((768 + QSC_KECCAK_128_RATE - 1) / QSC_KECCAK_128_RATE)

#if (DILITHIUM_ETA == 2)
#   define DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS ((136 + QSC_KECCAK_128_RATE - 1) / QSC_KECCAK_128_RATE)
#elif (DILITHIUM_ETA == 4)
#   define DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS ((227 + QSC_KECCAK_128_RATE - 1) / QSC_KECCAK_128_RATE)
#endif

#if (DILITHIUM_GAMMA1 == (1 << 17))
#   define DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS ((576 + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
#elif (DILITHIUM_GAMMA1 == (1 << 19))
#   define DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS ((640 + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
#endif

static const int32_t dilithium_zetas[QSC_DILITHIUM_N] =
{
    0x00000000L, 0x000064F7L, 0xFFD83102L, 0xFFF81503L, 0x00039E44L, 0xFFF42118L, 0xFFF2A128L, 0x00071E24L,
    0x001BDE2BL, 0x0023E92BL, 0xFFFA84ADL, 0xFFE0147FL, 0x002F9A75L, 0xFFD3FB09L, 0x002F7A49L, 0x0028E527L,
    0x00299658L, 0x000FA070L, 0xFFEF85A4L, 0x0036B788L, 0xFFF79D90L, 0xFFEEEAA0L, 0x0027F968L, 0xFFDFD37BL,
    0xFFDFADD6L, 0xFFC51AE7L, 0xFFEAA4F7L, 0xFFCDFC98L, 0x001AD035L, 0xFFFFB422L, 0x003D3201L, 0x000445C5L,
    0x00294A67L, 0x00017620L, 0x002EF4CDL, 0x0035DEC5L, 0xFFE6A503L, 0xFFC9302CL, 0xFFD947D4L, 0x003BBEAFL,
    0xFFC51585L, 0xFFD18E7CL, 0x00368A96L, 0xFFD43E41L, 0x00360400L, 0xFFFB6A4DL, 0x0023D69CL, 0xFFF7C55DL,
    0xFFE6123DL, 0xFFE6EAD6L, 0x00357E1EL, 0xFFC5AF59L, 0x0035843FL, 0xFFDF5617L, 0xFFE7945CL, 0x0038738CL,
    0x000C63A8L, 0x00081B9AL, 0x000E8F76L, 0x003B3853L, 0x003B8534L, 0xFFD8FC30L, 0x001F9D54L, 0xFFD54F2DL,
    0xFFC406E5L, 0xFFE8AC81L, 0xFFC7E1CFL, 0xFFD19819L, 0xFFE9D65DL, 0x003509EEL, 0x002135C7L, 0xFFE7CFBBL,
    0xFFECCF75L, 0x001D9772L, 0xFFC1B072L, 0xFFF0BCF6L, 0xFFCF5280L, 0xFFCFD2AEL, 0xFFC890E0L, 0x0001EFCAL,
    0x003410F2L, 0xFFF0FE85L, 0x0020C638L, 0x00296E9FL, 0xFFD2B7A3L, 0xFFC7A44BL, 0xFFF9BA6DL, 0xFFDA3409L,
    0xFFF5C282L, 0xFFED4113L, 0xFFFFA63BL, 0xFFEC09F7L, 0xFFFA2BDDL, 0x001495D4L, 0x001C4563L, 0xFFEA2C62L,
    0xFFCCFBE9L, 0x00040AF0L, 0x0007C417L, 0x002F4588L, 0x0000AD00L, 0xFFEF36BEL, 0x000DCD44L, 0x003C675AL,
    0xFFC72BCAL, 0xFFFFDE7EL, 0x00193948L, 0xFFCE69C0L, 0x0024756CL, 0xFFFCC7DFL, 0x000B98A1L, 0xFFEBE808L,
    0x0002E46CL, 0xFFC9C808L, 0x003036C2L, 0xFFE3BFF6L, 0xFFDB3C93L, 0xFFFD4AE0L, 0x00141305L, 0x00147792L,
    0x00139E25L, 0xFFE7D0E0L, 0xFFF39944L, 0xFFEA0802L, 0xFFD1EEA2L, 0xFFC4C79CL, 0xFFC8A057L, 0x003A97D9L,
    0x001FEA93L, 0x0033FF5AL, 0x002358D4L, 0x003A41F8L, 0xFFCCFF72L, 0x00223DFBL, 0xFFDAAB9FL, 0xFFC9A422L,
    0x000412F5L, 0x00252587L, 0xFFED24F0L, 0x00359B5DL, 0xFFCA48A0L, 0xFFC6A2FCL, 0xFFEDBB56L, 0xFFCF45DEL,
    0x000DBE5EL, 0x001C5E1AL, 0x000DE0E6L, 0x000C7F5AL, 0x00078F83L, 0xFFE7628AL, 0xFFFF5704L, 0xFFF806FCL,
    0xFFF60021L, 0xFFD05AF6L, 0x001F0084L, 0x0030EF86L, 0xFFC9B97DL, 0xFFF7FCD6L, 0xFFF44592L, 0xFFC921C2L,
    0x00053919L, 0x0004610CL, 0xFFDACD41L, 0x003EB01BL, 0x003472E7L, 0xFFCD003BL, 0x001A7CC7L, 0x00031924L,
    0x002B5EE5L, 0x00291199L, 0xFFD87A3AL, 0x00134D71L, 0x003DE11CL, 0x00130984L, 0x0025F051L, 0x00185A46L,
    0xFFC68518L, 0x001314BEL, 0x00283891L, 0xFFC9DB90L, 0xFFD25089L, 0x001C853FL, 0x001D0B4BL, 0xFFEFF6A6L,
    0xFFEBA8BEL, 0x0012E11BL, 0xFFCD5E3EL, 0xFFEA2D2FL, 0xFFF91DE4L, 0x001406C7L, 0x00327283L, 0xFFE20D6EL,
    0xFFEC7953L, 0x001D4099L, 0xFFD92578L, 0xFFEB05ADL, 0x0016E405L, 0x000BDBE7L, 0x00221DE8L, 0x0033F8CFL,
    0xFFF7B934L, 0xFFD4CA0CL, 0xFFE67FF8L, 0xFFE3D157L, 0xFFD8911BL, 0xFFC72C12L, 0x000910D8L, 0xFFC65E1FL,
    0xFFE14658L, 0x00251D8BL, 0x002573B7L, 0xFFFD7C8FL, 0x001DDD98L, 0x00336898L, 0x0002D4BBL, 0xFFED93A7L,
    0xFFCF6CBEL, 0x00027C1CL, 0x0018AA08L, 0x002DFD71L, 0x000C5CA5L, 0x0019379AL, 0xFFC7A167L, 0xFFE48C3DL,
    0xFFD1A13CL, 0x0035C539L, 0x003B0115L, 0x00041DC0L, 0x0021C4F7L, 0xFFF11BF4L, 0x001A35E7L, 0x0007340EL,
    0xFFF97D45L, 0x001A4CD0L, 0xFFE47CAEL, 0x001D2668L, 0xFFE68E98L, 0xFFEF2633L, 0xFFFC05DAL, 0xFFC57FDBL,
    0xFFD32764L, 0xFFDDE1AFL, 0xFFF993DDL, 0xFFDD1D09L, 0x0002CC93L, 0xFFF11805L, 0x00189C2AL, 0xFFC9E5A9L,
    0xFFF78A50L, 0x003BCF2CL, 0xFFFF434EL, 0xFFEB36DFL, 0x003C15CAL, 0x00155E68L, 0xFFF316B6L, 0x001E29CEL
};

/* reduce.c */

static int32_t dilithium_montgomery_reduce(int64_t a)
{
    int32_t t;

    t = (int32_t)a * DILITHIUM_QINV;
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
    a += (a >> 31) & DILITHIUM_Q;

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

    res = 1;

    if (a0 <= DILITHIUM_GAMMA2 || a0 > DILITHIUM_Q - DILITHIUM_GAMMA2 || (a0 == DILITHIUM_Q - DILITHIUM_GAMMA2 && a1 == 0))
    {
        res = 0;
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

/* qsc_dilithium_poly.c */

static void dilithium_shake128_stream_init(qsc_keccak_state *kctx, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce)
{
    uint8_t tn[2];
    tn[0] = (uint8_t)nonce;
    tn[1] = nonce >> 8;

    qsc_keccak_initialize_state(kctx);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_128_RATE, seed, DILITHIUM_SEEDBYTES);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_128_RATE, tn, sizeof(tn));
    qsc_keccak_incremental_finalize(kctx, QSC_KECCAK_128_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
}

static void dilithium_shake256_stream_init(qsc_keccak_state *kctx, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
    uint8_t tn[2];
    tn[0] = (uint8_t)nonce;
    tn[1] = nonce >> 8;

    qsc_keccak_initialize_state(kctx);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_256_RATE, seed, DILITHIUM_CRHBYTES);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_256_RATE, tn, sizeof(tn));
    qsc_keccak_incremental_finalize(kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
}

/* dilithium_ntt.c */

static void dilithium_ntt(int32_t a[QSC_DILITHIUM_N])
{
    size_t j;
    size_t k;
    int32_t zeta;
    int32_t t;

    k = 0;

    for (size_t len = 128; len > 0; len >>= 1)
    {
        for (size_t start = 0; start < QSC_DILITHIUM_N; start = j + len)
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

static void dilithium_invntt_to_mont(int32_t a[QSC_DILITHIUM_N])
{
    size_t j;
    size_t k;
    int32_t t;
    int32_t zeta;
    const int32_t F = 41978; // mont^2/256

    k = 256;

    for (size_t len = 1; len < QSC_DILITHIUM_N; len <<= 1)
    {
        for (size_t start = 0; start < QSC_DILITHIUM_N; start = j + len)
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

    for (j = 0; j < QSC_DILITHIUM_N; ++j)
    {
        a[j] = dilithium_montgomery_reduce((int64_t)F * a[j]);
    }
}

static void dilithium_poly_reduce(qsc_dilithium_poly* a)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        a->coeffs[i] = dilithium_reduce32(a->coeffs[i]);
    }
}

static void dilithium_poly_caddq(qsc_dilithium_poly* a)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        a->coeffs[i] = dilithium_caddq(a->coeffs[i]);
    }
}

static void dilithium_poly_add(qsc_dilithium_poly* c, const qsc_dilithium_poly* a, const qsc_dilithium_poly* b)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

static void dilithium_poly_sub(qsc_dilithium_poly* c, const qsc_dilithium_poly* a, const qsc_dilithium_poly* b)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

static void dilithium_poly_shiftl(qsc_dilithium_poly* a)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        a->coeffs[i] <<= DILITHIUM_D;
    }
}

static void dilithium_poly_ntt(qsc_dilithium_poly* a)
{
    dilithium_ntt(a->coeffs);
}

static void dilithium_poly_invntt_to_mont(qsc_dilithium_poly* a)
{
    dilithium_invntt_to_mont(a->coeffs);
}

static void dilithium_poly_pointwise_montgomery(qsc_dilithium_poly* c, const qsc_dilithium_poly* a, const qsc_dilithium_poly* b)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        c->coeffs[i] = dilithium_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

static void dilithium_poly_power2_round(qsc_dilithium_poly* a1, qsc_dilithium_poly* a0, const qsc_dilithium_poly* a)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        a1->coeffs[i] = dilithium_power2_round(&a0->coeffs[i], a->coeffs[i]);
    }
}

static void dilithium_poly_decompose(qsc_dilithium_poly* a1, qsc_dilithium_poly* a0, const qsc_dilithium_poly* a)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        a1->coeffs[i] = dilithium_decompose(&a0->coeffs[i], a->coeffs[i]);
    }
}

static uint32_t dilithium_poly_make_hint(qsc_dilithium_poly* h, const qsc_dilithium_poly* a0, const qsc_dilithium_poly* a1)
{
    uint32_t s;

    s = 0;

    for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        h->coeffs[i] = dilithium_make_hint(a0->coeffs[i], a1->coeffs[i]);
        s += h->coeffs[i];
    }

    return s;
}

static void dilithium_poly_use_hint(qsc_dilithium_poly* b, const qsc_dilithium_poly* a, const qsc_dilithium_poly* h)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        b->coeffs[i] = dilithium_use_hint(a->coeffs[i], h->coeffs[i]);
    }
}

static int32_t dilithium_poly_chknorm(const qsc_dilithium_poly* a, int32_t B)
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
        for (size_t i = 0; i < QSC_DILITHIUM_N; ++i)
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

static void dilithium_poly_uniform(qsc_dilithium_poly* a, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce)
{
    uint8_t buf[DILITHIUM_POLY_UNIFORM_NBLOCKS * QSC_KECCAK_128_RATE + 2];
    qsc_keccak_state kctx;
    size_t ctr;
    size_t off;
    size_t buflen;

    buflen = DILITHIUM_POLY_UNIFORM_NBLOCKS * QSC_KECCAK_128_RATE;
    dilithium_shake128_stream_init(&kctx, seed, nonce);
    qsc_keccak_squeezeblocks(&kctx, buf, DILITHIUM_POLY_UNIFORM_NBLOCKS, QSC_KECCAK_128_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
    ctr = dilithium_rej_uniform(a->coeffs, QSC_DILITHIUM_N, buf, buflen);

    while (ctr < QSC_DILITHIUM_N)
    {
        off = buflen % 3;

        for (size_t i = 0; i < off; ++i)
        {
            buf[i] = buf[buflen - off + i];
        }

        qsc_keccak_squeezeblocks(&kctx, buf + off, 1, QSC_KECCAK_128_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
        buflen = QSC_KECCAK_128_RATE + off;
        ctr += dilithium_rej_uniform(a->coeffs + ctr, QSC_DILITHIUM_N - ctr, buf, buflen);
    }
}

static size_t dilithium_rej_eta(int32_t* a, size_t len, const uint8_t* buf, size_t buflen)
{
    size_t ctr;
    size_t pos;
    uint32_t t0;
    uint32_t t1;

    ctr = pos = 0;

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

static void dilithium_poly_challenge(qsc_dilithium_poly* c, const uint8_t seed[DILITHIUM_SEEDBYTES])
{
    uint8_t buf[QSC_KECCAK_256_RATE];
    qsc_keccak_state kctx;
    uint64_t signs;
    size_t i;
    size_t b;
    size_t pos;

    qsc_keccak_initialize_state(&kctx);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, seed, DILITHIUM_SEEDBYTES);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_squeezeblocks(&kctx, buf, 1, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
    signs = 0;
    pos = 8;

    for (i = 0; i < 8; ++i)
    {
        signs |= (uint64_t)buf[i] << (8 * i);
    }

    for (i = 0; i < QSC_DILITHIUM_N; ++i)
    {
        c->coeffs[i] = 0;
    }

    for (i = QSC_DILITHIUM_N - DILITHIUM_TAU; i < QSC_DILITHIUM_N; ++i)
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

static void dilithium_polyeta_pack(uint8_t* r, const qsc_dilithium_poly* a)
{
    uint8_t t[8];

#if DILITHIUM_ETA == 2
    for (size_t i = 0; i < QSC_DILITHIUM_N / 8; ++i)
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
    for (size_t i = 0; i < QSC_DILITHIUM_N / 2; ++i)
    {
        t[0] = (uint8_t)(DILITHIUM_ETA - a->coeffs[2 * i]);
        t[1] = (uint8_t)(DILITHIUM_ETA - a->coeffs[(2 * i) + 1]);
        r[i] = (uint8_t)(t[0] | (t[1] << 4));
    }
#endif
}

static void dilithium_polyeta_unpack(qsc_dilithium_poly* r, const uint8_t* a)
{
#if (DILITHIUM_ETA == 2)
    for (size_t i = 0; i < QSC_DILITHIUM_N / 8; ++i)
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
    for (size_t i = 0; i < QSC_DILITHIUM_N / 2; ++i)
    {
        r->coeffs[2 * i] = a[i] & 0x0F;
        r->coeffs[(2 * i) + 1] = a[i] >> 4;
        r->coeffs[2 * i] = DILITHIUM_ETA - r->coeffs[2 * i];
        r->coeffs[(2 * i) + 1] = DILITHIUM_ETA - r->coeffs[(2 * i) + 1];
    }
#endif
}

static void dilithium_polyt1_pack(uint8_t* r, const qsc_dilithium_poly* a)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N / 4; ++i)
    {
        r[5 * i] = (uint8_t)(a->coeffs[4 * i] >> 0);
        r[(5 * i) + 1] = (uint8_t)((a->coeffs[4 * i] >> 8) | (a->coeffs[(4 * i) + 1] << 2));
        r[(5 * i) + 2] = (uint8_t)((a->coeffs[(4 * i) + 1] >> 6) | (a->coeffs[(4 * i) + 2] << 4));
        r[(5 * i) + 3] = (uint8_t)((a->coeffs[(4 * i) + 2] >> 4) | (a->coeffs[(4 * i) + 3] << 6));
        r[(5 * i) + 4] = (uint8_t)(a->coeffs[(4 * i) + 3] >> 2);
    }
}

static void dilithium_polyt1_unpack(qsc_dilithium_poly* r, const uint8_t* a)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N / 4; ++i)
    {
        r->coeffs[4 * i] = ((a[5 * i] >> 0) | ((uint32_t)a[(5 * i) + 1] << 8)) & 0x000003FF;
        r->coeffs[(4 * i) + 1] = ((a[(5 * i) + 1] >> 2) | ((uint32_t)a[(5 * i) + 2] << 6)) & 0x000003FF;
        r->coeffs[(4 * i) + 2] = ((a[(5 * i) + 2] >> 4) | ((uint32_t)a[(5 * i) + 3] << 4)) & 0x000003FF;
        r->coeffs[(4 * i) + 3] = ((a[(5 * i) + 3] >> 6) | ((uint32_t)a[(5 * i) + 4] << 2)) & 0x000003FF;
    }
}

static void dilithium_polyt0_pack(uint8_t* r, const qsc_dilithium_poly* a)
{
    uint32_t t[8];

    for (size_t i = 0; i < QSC_DILITHIUM_N / 8; ++i)
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

static void dilithium_polyt0_unpack(qsc_dilithium_poly* r, const uint8_t* a)
{
    for (size_t i = 0; i < QSC_DILITHIUM_N / 8; ++i)
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

static void dilithium_polyz_pack(uint8_t* r, const qsc_dilithium_poly* a)
{
    uint32_t t[4];

#if (DILITHIUM_GAMMA1 == (1 << 17))
    for (size_t i = 0; i < QSC_DILITHIUM_N / 4; ++i)
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
    for (size_t i = 0; i < QSC_DILITHIUM_N / 2; ++i)
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

static void dilithium_polyz_unpack(qsc_dilithium_poly* r, const uint8_t* a)
{
#if (DILITHIUM_GAMMA1 == (1 << 17))
    for (size_t i = 0; i < QSC_DILITHIUM_N / 4; ++i)
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
    for (size_t i = 0; i < QSC_DILITHIUM_N / 2; ++i)
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

static void dilithium_polyw1_pack(uint8_t* r, const qsc_dilithium_poly* a)
{
#if (DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88)
    for (size_t i = 0; i < QSC_DILITHIUM_N / 4; ++i)
    {
        r[3 * i] = (uint8_t)a->coeffs[4 * i];
        r[3 * i] |= (uint8_t)(a->coeffs[(4 * i) + 1] << 6);
        r[(3 * i) + 1] = (uint8_t)(a->coeffs[(4 * i) + 1] >> 2);
        r[(3 * i) + 1] |= (uint8_t)(a->coeffs[(4 * i) + 2] << 4);
        r[(3 * i) + 2] = (uint8_t)(a->coeffs[(4 * i) + 2] >> 4);
        r[(3 * i) + 2] |= (uint8_t)(a->coeffs[(4 * i) + 3] << 2);
    }
#elif (DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32)
    for (size_t i = 0; i < QSC_DILITHIUM_N / 2; ++i)
    {
        r[i] = (uint8_t)(a->coeffs[2 * i] | (a->coeffs[(2 * i) + 1] << 4));
    }
#endif
}

static void dilithium_poly_uniform_eta(qsc_dilithium_poly* a, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce)
{
    uint8_t buf[DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS * QSC_KECCAK_128_RATE];
    qsc_keccak_state kctx;
    size_t ctr;
    size_t buflen;

    buflen = DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS * QSC_KECCAK_128_RATE;
    dilithium_shake128_stream_init(&kctx, seed, nonce);
    qsc_keccak_squeezeblocks(&kctx, buf, DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, QSC_KECCAK_128_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);

    ctr = dilithium_rej_eta(a->coeffs, QSC_DILITHIUM_N, buf, buflen);

    while (ctr < QSC_DILITHIUM_N)
    {
        qsc_keccak_squeezeblocks(&kctx, buf, 1, QSC_KECCAK_128_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
        ctr += dilithium_rej_eta(a->coeffs + ctr, QSC_DILITHIUM_N - ctr, buf, QSC_KECCAK_128_RATE);
    }
}

static void dilithium_poly_uniform_gamma1(qsc_dilithium_poly* a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
    uint8_t buf[DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS * QSC_KECCAK_256_RATE];
    qsc_keccak_state kctx;

    dilithium_shake256_stream_init(&kctx, seed, nonce);
    qsc_keccak_squeezeblocks(&kctx, buf, DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
    dilithium_polyz_unpack(a, buf);
}

/* polyvec.c */

static void dilithium_polyvec_matrix_expand(qsc_dilithium_polyvecl mat[QSC_DILITHIUM_K], const uint8_t rho[DILITHIUM_SEEDBYTES])
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        for (size_t j = 0; j < QSC_DILITHIUM_L; ++j)
        {
            dilithium_poly_uniform(&mat[i].vec[j], rho, (uint16_t)((i << 8) + j));
        }
    }
}

static void dilithium_polyvecl_pointwise_acc_montgomery(qsc_dilithium_poly* w, const qsc_dilithium_polyvecl* u, const qsc_dilithium_polyvecl* v)
{
    qsc_dilithium_poly t;

    dilithium_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);

    for (size_t i = 1; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        dilithium_poly_add(w, w, &t);
    }
}

static void dilithium_polyvec_matrix_pointwise_montgomery(qsc_dilithium_polyveck* t, const qsc_dilithium_polyvecl mat[QSC_DILITHIUM_K], const qsc_dilithium_polyvecl* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
    }
}

static void dilithium_polyvecl_uniform_eta(qsc_dilithium_polyvecl* v, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce)
{
    for (size_t i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_poly_uniform_eta(&v->vec[i], seed, nonce);
        ++nonce;
    }
}

static void dilithium_polyvecl_uniform_gamma1(qsc_dilithium_polyvecl* v, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce)
{
    for (size_t i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_poly_uniform_gamma1(&v->vec[i], seed, (uint16_t)((QSC_DILITHIUM_L * nonce) + i));
    }
}

static void dilithium_polyvecl_reduce(qsc_dilithium_polyvecl* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_poly_reduce(&v->vec[i]);
    }
}

static void dilithium_polyvecl_add(qsc_dilithium_polyvecl* w, const qsc_dilithium_polyvecl* u, const qsc_dilithium_polyvecl* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void dilithium_polyvecl_ntt(qsc_dilithium_polyvecl* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

static void dilithium_polyvecl_invntt_to_mont(qsc_dilithium_polyvecl* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_poly_invntt_to_mont(&v->vec[i]);
    }
}

static void dilithium_polyvecl_pointwise_poly_montgomery(qsc_dilithium_polyvecl* r, const qsc_dilithium_poly* a, const qsc_dilithium_polyvecl* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

static int32_t dilithium_polyvecl_chknorm(const qsc_dilithium_polyvecl* v, int32_t bound)
{
    int32_t res;

    res = 0;

    for (size_t i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        if (dilithium_poly_chknorm(&v->vec[i], bound) != 0)
        {
            res = 1;
            break;
        }
    }

    return res;
}

static void dilithium_polyveck_uniform_eta(qsc_dilithium_polyveck* v, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_uniform_eta(&v->vec[i], seed, nonce);
        ++nonce;
    }
}

static void dilithium_polyveck_reduce(qsc_dilithium_polyveck* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_reduce(&v->vec[i]);
    }
}

static void dilithium_polyveck_caddq(qsc_dilithium_polyveck* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_caddq(&v->vec[i]);
    }
}

static void dilithium_polyveck_add(qsc_dilithium_polyveck* w, const qsc_dilithium_polyveck* u, const qsc_dilithium_polyveck* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void dilithium_polyveck_sub(qsc_dilithium_polyveck* w, const qsc_dilithium_polyveck* u, const qsc_dilithium_polyveck* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void dilithium_polyveck_shiftl(qsc_dilithium_polyveck* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_shiftl(&v->vec[i]);
    }
}

static void dilithium_polyveck_ntt(qsc_dilithium_polyveck* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

static void dilithium_polyveck_invntt_to_mont(qsc_dilithium_polyveck* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_invntt_to_mont(&v->vec[i]);
    }
}

static void dilithium_polyveck_pointwise_poly_montgomery(qsc_dilithium_polyveck* r, const qsc_dilithium_poly* a, const qsc_dilithium_polyveck* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

static int32_t dilithium_polyveck_chknorm(const qsc_dilithium_polyveck* v, int32_t bound)
{
    int32_t res;

    res = 0;

    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        if (dilithium_poly_chknorm(&v->vec[i], bound) != 0)
        {
            res = 1;
            break;
        }
    }

    return res;
}

static void dilithium_polyveck_power2_round(qsc_dilithium_polyveck* v1, qsc_dilithium_polyveck* v0, const qsc_dilithium_polyveck* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_power2_round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

static void dilithium_polyveck_decompose(qsc_dilithium_polyveck* v1, qsc_dilithium_polyveck* v0, const qsc_dilithium_polyveck* v)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

static uint32_t dilithium_polyveck_make_hint(qsc_dilithium_polyveck* h, const qsc_dilithium_polyveck* v0, const qsc_dilithium_polyveck* v1)
{
    uint32_t s;

    s = 0;

    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        s += dilithium_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    }

    return s;
}

static void dilithium_polyveck_use_hint(qsc_dilithium_polyveck* w, const qsc_dilithium_polyveck* u, const qsc_dilithium_polyveck* h)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
    }
}

static void dilithium_polyveck_pack_w1(uint8_t r[QSC_DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES], const qsc_dilithium_polyveck* w1)
{
    for (size_t i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_polyw1_pack(&r[i * DILITHIUM_POLYW1_PACKEDBYTES], &w1->vec[i]);
    }
}

/* packing.c */

static void dilithium_pack_pk(uint8_t pk[DILITHIUM_PUBLICKEY_SIZE], const uint8_t rho[DILITHIUM_SEEDBYTES], const qsc_dilithium_polyveck* t1)
{
    size_t i;

    for (i = 0; i < DILITHIUM_SEEDBYTES; ++i)
    {
        pk[i] = rho[i];
    }

    pk += DILITHIUM_SEEDBYTES;

    for (i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_polyt1_pack(pk + i * DILITHIUM_POLYT1_PACKEDBYTES, &t1->vec[i]);
    }
}

static void dilithium_unpack_pk(uint8_t rho[DILITHIUM_SEEDBYTES], qsc_dilithium_polyveck* t1, const uint8_t pk[DILITHIUM_PUBLICKEY_SIZE])
{
    size_t i;

    for (i = 0; i < DILITHIUM_SEEDBYTES; ++i)
    {
        rho[i] = pk[i];
    }

    pk += DILITHIUM_SEEDBYTES;

    for (i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_polyt1_unpack(&t1->vec[i], pk + i * DILITHIUM_POLYT1_PACKEDBYTES);
    }
}

static void dilithium_pack_sk(uint8_t sk[DILITHIUM_PRIVATEKEY_SIZE], const uint8_t rho[DILITHIUM_SEEDBYTES], const uint8_t tr[DILITHIUM_CRHBYTES],
    const uint8_t key[DILITHIUM_SEEDBYTES], const qsc_dilithium_polyveck* t0, const qsc_dilithium_polyvecl* s1, const qsc_dilithium_polyveck* s2)
{
    size_t  i;

    qsc_memutils_copy(sk, rho, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    qsc_memutils_copy(sk, key, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    qsc_memutils_copy(sk, tr, DILITHIUM_CRHBYTES);
    sk += DILITHIUM_CRHBYTES;

    for (i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_polyeta_pack(sk + i * DILITHIUM_POLYETA_PACKEDBYTES, &s1->vec[i]);
    }

    sk += QSC_DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_polyeta_pack(sk + i * DILITHIUM_POLYETA_PACKEDBYTES, &s2->vec[i]);
    }

    sk += QSC_DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_polyt0_pack(sk + i * DILITHIUM_POLYT0_PACKEDBYTES, &t0->vec[i]);
    }
}

static void dilithium_unpack_sk(uint8_t rho[DILITHIUM_SEEDBYTES], uint8_t tr[DILITHIUM_CRHBYTES], uint8_t key[DILITHIUM_SEEDBYTES],
    qsc_dilithium_polyveck* t0, qsc_dilithium_polyvecl* s1, qsc_dilithium_polyveck* s2, const uint8_t sk[DILITHIUM_PRIVATEKEY_SIZE])
{
    size_t  i;

    qsc_memutils_copy(rho, sk, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    qsc_memutils_copy(key, sk, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    qsc_memutils_copy(tr, sk, DILITHIUM_CRHBYTES);
    sk += DILITHIUM_CRHBYTES;

    for (i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_polyeta_unpack(&s1->vec[i], sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
    }

    sk += QSC_DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_polyeta_unpack(&s2->vec[i], sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
    }

    sk += QSC_DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        dilithium_polyt0_unpack(&t0->vec[i], sk + i * DILITHIUM_POLYT0_PACKEDBYTES);
    }
}

static void dilithium_pack_sig(uint8_t sig[DILITHIUM_SIGNATURE_SIZE], const uint8_t c[DILITHIUM_SEEDBYTES], const qsc_dilithium_polyvecl* z, const qsc_dilithium_polyveck* h)
{
    size_t i;
    size_t j;
    size_t k;

    for (i = 0; i < DILITHIUM_SEEDBYTES; ++i)
    {
        sig[i] = c[i];
    }

    sig += DILITHIUM_SEEDBYTES;

    for (i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_polyz_pack(sig + i * DILITHIUM_POLYZ_PACKEDBYTES, &z->vec[i]);
    }

    sig += QSC_DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;

    /* Encode h */
    qsc_memutils_clear(sig, DILITHIUM_OMEGA + QSC_DILITHIUM_K);
    k = 0;

    for (i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        for (j = 0; j < QSC_DILITHIUM_N; ++j)
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

static int32_t dilithium_unpack_sig(uint8_t c[DILITHIUM_SEEDBYTES], qsc_dilithium_polyvecl* z, qsc_dilithium_polyveck* h, const uint8_t sig[DILITHIUM_SIGNATURE_SIZE])
{
    size_t i;
    size_t j;
    size_t k;
    int32_t res;

    res = 0;

    qsc_memutils_copy(c, sig, DILITHIUM_SEEDBYTES);
    sig += DILITHIUM_SEEDBYTES;

    for (i = 0; i < QSC_DILITHIUM_L; ++i)
    {
        dilithium_polyz_unpack(&z->vec[i], sig + i * DILITHIUM_POLYZ_PACKEDBYTES);
    }

    sig += QSC_DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;

    /* Decode h */
    k = 0;

    for (i = 0; i < QSC_DILITHIUM_K; ++i)
    {
        for (j = 0; j < QSC_DILITHIUM_N; ++j)
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

void qsc_dilithium_ref_generate_keypair(uint8_t *pk, uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t))
{
    qsc_dilithium_polyvecl mat[QSC_DILITHIUM_K];
    qsc_dilithium_polyvecl s1;
    qsc_dilithium_polyvecl s1hat;
    qsc_dilithium_polyveck s2;
    qsc_dilithium_polyveck t1;
    qsc_dilithium_polyveck t0;
    uint8_t seedbuf[3 * DILITHIUM_SEEDBYTES];
    uint8_t tr[DILITHIUM_CRHBYTES];
    const uint8_t *rho;
    const uint8_t *rhoprime;
    const uint8_t *key;

    /* Get randomness for rho, rhoprime and key */
    rng_generate(seedbuf, DILITHIUM_SEEDBYTES);
    qsc_shake256_compute(seedbuf, 3 * DILITHIUM_SEEDBYTES, seedbuf, DILITHIUM_SEEDBYTES);
    rho = seedbuf;
    rhoprime = seedbuf + DILITHIUM_SEEDBYTES;
    key = seedbuf + 2 * DILITHIUM_SEEDBYTES;

    /* Expand matrix */
    dilithium_polyvec_matrix_expand(mat, rho);

    /* Sample short vectors s1 and s2 */
    dilithium_polyvecl_uniform_eta(&s1, rhoprime, 0);
    dilithium_polyveck_uniform_eta(&s2, rhoprime, QSC_DILITHIUM_L);

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
    qsc_shake256_compute(tr, DILITHIUM_CRHBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);
    dilithium_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
}

void qsc_dilithium_ref_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t))
{
    uint8_t seedbuf[2 * DILITHIUM_SEEDBYTES + 3 * DILITHIUM_CRHBYTES];
    qsc_dilithium_polyvecl mat[QSC_DILITHIUM_K];
    qsc_dilithium_polyvecl s1;
    qsc_dilithium_polyvecl y;
    qsc_dilithium_polyvecl z;
    qsc_dilithium_polyveck h;
    qsc_dilithium_polyveck s2;
    qsc_dilithium_polyveck t0;
    qsc_dilithium_polyveck w1;
    qsc_dilithium_polyveck w0;
    qsc_dilithium_poly cp;
    qsc_keccak_state kctx;
    uint8_t *rho;
    uint8_t *tr;
    uint8_t *key;
    uint8_t *mu;
    uint8_t *rhoprime;
    uint32_t n;
    uint16_t nonce;

    nonce = 0;
    rho = seedbuf;
    tr = rho + DILITHIUM_SEEDBYTES;
    key = tr + DILITHIUM_CRHBYTES;
    mu = key + DILITHIUM_SEEDBYTES;
    rhoprime = mu + DILITHIUM_CRHBYTES;
    dilithium_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute CRH(tr, msg) */
    qsc_keccak_initialize_state(&kctx);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, tr, DILITHIUM_CRHBYTES);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, m, mlen);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);

#ifdef QSC_DILITHIUM_RANDOMIZED_SIGNING
    rng_generate(rhoprime, DILITHIUM_CRHBYTES);
#else
    qsc_shake256_compute(rhoprime, DILITHIUM_CRHBYTES, key, DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES);
#endif

    /* Expand matrix and transform vectors */
    dilithium_polyvec_matrix_expand(mat, rho);
    dilithium_polyvecl_ntt(&s1);
    dilithium_polyveck_ntt(&s2);
    dilithium_polyveck_ntt(&t0);

    while (true)
    {
        /* Sample intermediate vector y */
        dilithium_polyvecl_uniform_gamma1(&y, rhoprime, nonce);
        ++nonce;
        z = y;
        dilithium_polyvecl_ntt(&z);

        /* Matrix-vector multiplication */
        dilithium_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
        dilithium_polyveck_reduce(&w1);
        dilithium_polyveck_invntt_to_mont(&w1);

        /* Decompose w and call the random oracle */
        dilithium_polyveck_caddq(&w1);
        dilithium_polyveck_decompose(&w1, &w0, &w1);
        dilithium_polyveck_pack_w1(sig, &w1);

        qsc_keccak_initialize_state(&kctx);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, sig, QSC_DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
        qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
        qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, sig, DILITHIUM_SEEDBYTES);

        dilithium_poly_challenge(&cp, sig);
        dilithium_poly_ntt(&cp);

        /* Compute z, reject if it reveals secret */
        dilithium_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
        dilithium_polyvecl_invntt_to_mont(&z);
        dilithium_polyvecl_add(&z, &z, &y);
        dilithium_polyvecl_reduce(&z);

        if (dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA) != 0)
        {
            continue;
        }

        /* Check that subtracting cs2 does not change high bits of w and low bits
           do not reveal secret information */
        dilithium_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
        dilithium_polyveck_invntt_to_mont(&h);
        dilithium_polyveck_sub(&w0, &w0, &h);
        dilithium_polyveck_reduce(&w0);

        if (dilithium_polyveck_chknorm(&w0, DILITHIUM_GAMMA2 - DILITHIUM_BETA) != 0)
        {
            continue;
        }

        /* Compute hints for w1 */
        dilithium_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
        dilithium_polyveck_invntt_to_mont(&h);
        dilithium_polyveck_reduce(&h);

        if (dilithium_polyveck_chknorm(&h, DILITHIUM_GAMMA2) != 0)
        {
            continue;
        }

        dilithium_polyveck_add(&w0, &w0, &h);
        dilithium_polyveck_caddq(&w0);
        n = dilithium_polyveck_make_hint(&h, &w0, &w1);

        if (n > DILITHIUM_OMEGA)
        {
            continue;
        }

        break;
    }

    /* Write signature */
    dilithium_pack_sig(sig, sig, &z, &h);
    *siglen = DILITHIUM_SIGNATURE_SIZE;
}

void qsc_dilithium_ref_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t))
{
    for (size_t i = 0; i < mlen; ++i)
    {
        sm[DILITHIUM_SIGNATURE_SIZE + mlen - 1 - i] = m[mlen - 1 - i];
    }

    qsc_dilithium_ref_sign_signature(sm, smlen, sm + DILITHIUM_SIGNATURE_SIZE, mlen, sk, rng_generate);
    *smlen += mlen;
}

bool qsc_dilithium_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    uint8_t buf[QSC_DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES];
    uint8_t rho[DILITHIUM_SEEDBYTES];
    uint8_t mu[DILITHIUM_CRHBYTES];
    uint8_t c[DILITHIUM_SEEDBYTES];
    uint8_t c2[DILITHIUM_SEEDBYTES];
    qsc_dilithium_polyvecl mat[QSC_DILITHIUM_K];
    qsc_dilithium_polyvecl z;
    qsc_dilithium_polyveck h;
    qsc_dilithium_polyveck t1;
    qsc_dilithium_polyveck w1;
    qsc_dilithium_poly cp;
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
                qsc_shake256_compute(mu, DILITHIUM_CRHBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);

                qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
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
                qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, buf, QSC_DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
                qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
                qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, c2, DILITHIUM_SEEDBYTES);

                res = (qsc_intutils_verify(c, c2, DILITHIUM_SEEDBYTES) == 0);
            }
        }
    }

    return res;
}

bool qsc_dilithium_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk)
{
    bool res;

    *mlen = -1;
    res = false;

    if (smlen >= DILITHIUM_SIGNATURE_SIZE)
    {
        *mlen = smlen - DILITHIUM_SIGNATURE_SIZE;
        res = qsc_dilithium_ref_verify(sm, DILITHIUM_SIGNATURE_SIZE, sm + DILITHIUM_SIGNATURE_SIZE, *mlen, pk);

        if (res == true)
        {
            /* All good, copy msg, return 0 */
            qsc_memutils_copy(m, sm + DILITHIUM_SIGNATURE_SIZE, *mlen);
        }
    }

    if (res == false)
    {
        qsc_memutils_clear(m, smlen - DILITHIUM_SIGNATURE_SIZE);
    }

    return res;
}
