#include "ntrubase.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

/* api_bytes */

#define NTRU_SEEDBYTES 32
#define NTRU_PRFKEYBYTES 32
#define NTRU_SHAREDKEYBYTES 32

#if defined(QSC_NTRU_S1HPS2048509)

#define NTRU_HPS
#define NTRU_N 509
#define NTRU_LOGQ 11
#define NTRU_SAMPLE_FG_BYTES (NTRU_SAMPLE_IID_BYTES + NTRU_SAMPLE_FT_BYTES)
#define NTRU_SAMPLE_RM_BYTES (NTRU_SAMPLE_IID_BYTES + NTRU_SAMPLE_FT_BYTES)

#elif defined(QSC_NTRU_HPSS32048677)

#define NTRU_HPS
#define NTRU_N 677
#define NTRU_LOGQ 11
#define NTRU_SAMPLE_FG_BYTES (NTRU_SAMPLE_IID_BYTES + NTRU_SAMPLE_FT_BYTES)
#define NTRU_SAMPLE_RM_BYTES (NTRU_SAMPLE_IID_BYTES + NTRU_SAMPLE_FT_BYTES)

#elif defined(QSC_NTRU_S5HPS4096821)

#define NTRU_HPS
#define NTRU_N 821
#define NTRU_LOGQ 12
#define NTRU_SAMPLE_FG_BYTES   (NTRU_SAMPLE_IID_BYTES + NTRU_SAMPLE_FT_BYTES)
#define NTRU_SAMPLE_RM_BYTES   (NTRU_SAMPLE_IID_BYTES + NTRU_SAMPLE_FT_BYTES)

#elif defined(QSC_NTRU_S5HRSS701)

#define NTRU_HRSS
#define NTRU_N 701
#define NTRU_LOGQ 13
#define NTRU_SAMPLE_FG_BYTES   (2 * NTRU_SAMPLE_IID_BYTES)
#define NTRU_SAMPLE_RM_BYTES   (2 * NTRU_SAMPLE_IID_BYTES)

#else
#	error "The NTRU parameter set is invalid!"
#endif

#define NTRU_Q (1 << NTRU_LOGQ)
#define NTRU_WEIGHT (NTRU_Q / 8 - 2)
#define NTRU_SAMPLE_IID_BYTES (NTRU_N - 1)
#define NTRU_PACK_DEG (NTRU_N - 1)
#define NTRU_PACK_TRINARY_BYTES ((NTRU_PACK_DEG + 4) / 5)
#define NTRU_SAMPLE_FT_BYTES   ((30 * (NTRU_N - 1) + 7) / 8)

#define NTRU_OWCPA_MSGBYTES (2 * NTRU_PACK_TRINARY_BYTES)
#define NTRU_OWCPA_PUBLICKEYBYTES ((NTRU_LOGQ * NTRU_PACK_DEG + 7) / 8)
#define NTRU_OWCPA_SECRETKEYBYTES (2 * NTRU_PACK_TRINARY_BYTES + NTRU_OWCPA_PUBLICKEYBYTES)
#define NTRU_OWCPA_BYTES ((NTRU_LOGQ * NTRU_PACK_DEG + 7) / 8)

#define NTRU_PUBLICKEYBYTES (NTRU_OWCPA_PUBLICKEYBYTES)
#define NTRU_SECRETKEYBYTES (NTRU_OWCPA_SECRETKEYBYTES + NTRU_PRFKEYBYTES)
#define NTRU_CIPHERTEXTBYTES (NTRU_OWCPA_BYTES)

/* poly.h */

typedef struct
{
    uint16_t coeffs[NTRU_N];
} poly;

static uint16_t ntru_modq(uint16_t x)
{
    return x & (NTRU_Q - 1);
}

/* cmov.c */

static void ntru_cmov(uint8_t* r, const uint8_t* x, size_t len, uint8_t b)
{
    /* b = 1 means mov, b = 0 means don't mov*/
    b = (~b + 1);

    for (size_t i = 0; i < len; ++i)
    {
        r[i] ^= b & (x[i] ^ r[i]);
    }
}

/* ntru_crypto_sort_int32.c */

static void ntru_int32_minmax(int32_t* a, int32_t* b)
{
    int32_t ab;
    int32_t c;

    ab = *b ^ *a;
    c = (int32_t)((int64_t)*b - (int64_t)*a);
    c ^= ab & (c ^ *b);
    c >>= 31;
    c &= ab;
    *a ^= c;
    *b ^= c;
}

static void ntru_crypto_sort_int32(int32_t* array, size_t n)
{
    /* assume 2 <= n <= 0x40000000 */

    int32_t* x;
    size_t i;
    size_t j;
    size_t r;
    size_t top;
    int32_t a;
    bool res;

    res = true;
    top = 1;
    x = array;

    while (top < n - top)
    {
        top += top;
    }

    for (size_t p = top; p >= 1; p >>= 1)
    {
        i = 0;

        while (i + (2 * p) <= n)
        {
            for (j = i; j < i + p; ++j)
            {
                ntru_int32_minmax(&x[j], &x[j + p]);
            }

            i += 2 * p;
        }

        for (j = i; j < n - p; ++j)
        {
            ntru_int32_minmax(&x[j], &x[j + p]);
        }

        i = 0;
        j = 0;

        for (size_t q = top; q > p; q >>= 1)
        {
            if (j != i)
            {
                while (true)
                {
                    if (j == n - q)
                    {
                        res = false;
                        break;
                    }

                    a = x[j + p];

                    for (r = q; r > p; r >>= 1)
                    {
                        ntru_int32_minmax(&a, &x[j + r]);
                    }

                    x[j + p] = a;
                    ++j;

                    if (j == i + p)
                    {
                        i += 2 * p;
                        break;
                    }
                }
            }

            if (res == false)
            {
                break;
            }

            while (i + p <= n - q)
            {
                for (j = i; j < i + p; ++j)
                {
                    a = x[j + p];

                    for (r = q; r > p; r >>= 1)
                    {
                        ntru_int32_minmax(&a, &x[j + r]);
                    }

                    x[j + p] = a;
                }

                i += 2 * p;
            }

            /* now i + p > n - q */
            j = i;

            while (j < n - q)
            {
                a = x[j + p];

                for (r = q; r > p; r >>= 1)
                {
                    ntru_int32_minmax(&a, &x[j + r]);
                }

                x[j + p] = a;
                ++j;
            }
        }
    }
}

/* poly_mod.c */

static uint16_t ntru_mod3(uint16_t a)
{
    uint16_t r;
    int16_t t, c;

    r = (a >> 8) + (a & 0xFF); /* r mod 255 == a mod 255 */
    r = (r >> 4) + (r & 0x0F); /* r' mod 15 == r mod 15 */
    r = (r >> 2) + (r & 0x03); /* r' mod 3 == r mod 3 */
    r = (r >> 2) + (r & 0x03); /* r' mod 3 == r mod 3 */

    t = r - 3;
    c = t >> 15;

    return (uint16_t)((c & r) ^ (~c & t));
}

static void ntru_poly_mod_3_Phi_n(poly* r)
{
    for (size_t i = 0; i < NTRU_N; ++i)
    {
        r->coeffs[i] = ntru_mod3(r->coeffs[i] + 2 * r->coeffs[NTRU_N - 1]);
    }
}

static void ntru_poly_mod_q_Phi_n(poly* r)
{
    for (size_t i = 0; i < NTRU_N; ++i)
    {
        r->coeffs[i] = r->coeffs[i] - r->coeffs[NTRU_N - 1];
    }
}

static void ntru_poly_Rq_to_S3(poly* r, const poly* a)
{
    uint16_t flag;

    /* The coefficients of a are stored as non-negative integers. */
    /* We must translate to representatives in [-q/2, q/2) before reduction mod 3. */

    for (size_t i = 0; i < NTRU_N; ++i)
    {
        /* Need an explicit reduction mod q here */
        r->coeffs[i] = ntru_modq(a->coeffs[i]);

        /* flag = 1 if r[i] >= q/2 else 0 */
        flag = r->coeffs[i] >> (NTRU_LOGQ - 1);

        /* Now we will add (-q) mod 3 if r[i] >= q/2 */
        /* Note (-q) mod 3=(-2^k) mod 3=1<<(1-(k&1)) */
        r->coeffs[i] += flag << (1 - (NTRU_LOGQ & 1));
    }

    ntru_poly_mod_3_Phi_n(r);
}

/* poly_rq_mul.c */

static void ntru_poly_Rq_mul(poly* r, const poly* a, const poly* b)
{
    size_t i;

    for (size_t k = 0; k < NTRU_N; ++k)
    {
        r->coeffs[k] = 0;

        for (i = 1; i < NTRU_N - k; ++i)
        {
            r->coeffs[k] += a->coeffs[k + i] * b->coeffs[NTRU_N - i];
        }

        for (i = 0; i < k + 1; ++i)
        {
            r->coeffs[k] += a->coeffs[k - i] * b->coeffs[i];
        }
    }
}

/* poly_r2_inc.c */

static int16_t ntru_both_negative_mask(int16_t x, int16_t y)
{
    /* return -1 if x<0 and y<0; otherwise return 0 */

    return (x & y) >> 15;
}

static void ntru_poly_R2_inv(poly* r, const poly* a)
{
    poly f;
    poly g;
    poly v;
    poly w;
    size_t i;
    int16_t delta;
    int16_t sign;
    int16_t swap;
    int16_t t;

    for (i = 0; i < NTRU_N; ++i)
    {
        v.coeffs[i] = 0;
    }

    for (i = 0; i < NTRU_N; ++i)
    {
        w.coeffs[i] = 0;
    }

    w.coeffs[0] = 1;

    for (i = 0; i < NTRU_N; ++i)
    {
        f.coeffs[i] = 1;
    }

    for (i = 0; i < NTRU_N - 1; ++i)
    {
        g.coeffs[NTRU_N - 2 - i] = (a->coeffs[i] ^ a->coeffs[NTRU_N - 1]) & 1;
    }

    g.coeffs[NTRU_N - 1] = 0;
    delta = 1;

    for (size_t j = 0; j < (2 * (NTRU_N - 1)) - 1; ++j)
    {
        for (i = NTRU_N - 1; i > 0; --i)
        {
            v.coeffs[i] = v.coeffs[i - 1];
        }

        v.coeffs[0] = 0;

        sign = g.coeffs[0] & f.coeffs[0];
        swap = ntru_both_negative_mask(-delta, -(int16_t)g.coeffs[0]);
        delta ^= swap & (delta ^ -delta);
        delta += 1;

        for (i = 0; i < NTRU_N; ++i)
        {
            t = swap & (f.coeffs[i] ^ g.coeffs[i]); f.coeffs[i] ^= t; g.coeffs[i] ^= t;
            t = swap & (v.coeffs[i] ^ w.coeffs[i]); v.coeffs[i] ^= t; w.coeffs[i] ^= t;
        }

        for (i = 0; i < NTRU_N; ++i)
        {
            g.coeffs[i] = g.coeffs[i] ^ (sign & f.coeffs[i]);
        }

        for (i = 0; i < NTRU_N; ++i)
        {
            w.coeffs[i] = w.coeffs[i] ^ (sign & v.coeffs[i]);
        }

        for (i = 0; i < NTRU_N - 1; ++i)
        {
            g.coeffs[i] = g.coeffs[i + 1];
        }

        g.coeffs[NTRU_N - 1] = 0;
    }

    for (i = 0; i < NTRU_N - 1; ++i)
    {
        r->coeffs[i] = v.coeffs[NTRU_N - 2 - i];
    }

    r->coeffs[NTRU_N - 1] = 0;
}

/* poly_s3_inv.c */

static uint8_t ntru_poly_s3_mod3(uint8_t a)
{
    int16_t t;
    int16_t c;

    a = (a >> 2) + (a & 3); /* between 0 and 4 */
    t = a - 3;
    c = t >> 5;

    return (uint8_t)(t ^ (c & (a ^ t)));
}

static int16_t ntru_poly_s3_both_negative_mask(int16_t x, int16_t y)
{
    /* return -1 if x<0 and y<0; otherwise return 0 */

    return (x & y) >> 15;
}

static void ntru_poly_S3_inv(poly* r, const poly* a)
{
    poly f;
    poly g;
    poly v;
    poly w;
    size_t i;
    int16_t delta;
    int16_t sign;
    int16_t swap;
    int16_t t;

    for (i = 0; i < NTRU_N; ++i)
    {
        v.coeffs[i] = 0;
    }

    for (i = 0; i < NTRU_N; ++i)
    {
        w.coeffs[i] = 0;
    }

    w.coeffs[0] = 1;

    for (i = 0; i < NTRU_N; ++i)
    {
        f.coeffs[i] = 1;
    }

    for (i = 0; i < NTRU_N - 1; ++i)
    {
        g.coeffs[NTRU_N - 2 - i] = ntru_poly_s3_mod3((a->coeffs[i] & 3) + 2 * (a->coeffs[NTRU_N - 1] & 3));
    }

    g.coeffs[NTRU_N - 1] = 0;
    delta = 1;

    for (size_t j = 0; j < (2 * (NTRU_N - 1)) - 1; ++j)
    {
        for (i = NTRU_N - 1; i > 0; --i)
        {
            v.coeffs[i] = v.coeffs[i - 1];
        }

        v.coeffs[0] = 0;
        sign = ntru_poly_s3_mod3((uint8_t)(2 * g.coeffs[0] * f.coeffs[0]));
        swap = ntru_poly_s3_both_negative_mask(-delta, -(int16_t)g.coeffs[0]);
        delta ^= swap & (delta ^ -delta);
        delta += 1;

        for (i = 0; i < NTRU_N; ++i)
        {
            t = swap & (f.coeffs[i] ^ g.coeffs[i]); f.coeffs[i] ^= t; g.coeffs[i] ^= t;
            t = swap & (v.coeffs[i] ^ w.coeffs[i]); v.coeffs[i] ^= t; w.coeffs[i] ^= t;
        }

        for (i = 0; i < NTRU_N; ++i)
        {
            g.coeffs[i] = ntru_poly_s3_mod3((uint8_t)(g.coeffs[i] + sign * f.coeffs[i]));
        }

        for (i = 0; i < NTRU_N; ++i)
        {
            w.coeffs[i] = ntru_poly_s3_mod3((uint8_t)(w.coeffs[i] + sign * v.coeffs[i]));
        }

        for (i = 0; i < NTRU_N - 1; ++i)
        {
            g.coeffs[i] = g.coeffs[i + 1];
        }

        g.coeffs[NTRU_N - 1] = 0;
    }

    sign = f.coeffs[0];

    for (i = 0; i < NTRU_N - 1; ++i)
    {
        r->coeffs[i] = ntru_poly_s3_mod3((uint8_t)(sign * v.coeffs[NTRU_N - 2 - i]));
    }

    r->coeffs[NTRU_N - 1] = 0;
}

/* poly.c */

static void ntru_poly_Z3_to_Zq(poly* r)
{
    /* Map {0, 1, 2} -> {0,1,q-1} in place */

    for (size_t i = 0; i < NTRU_N; ++i)
    {
        r->coeffs[i] = r->coeffs[i] | ((-(r->coeffs[i] >> 1)) & (NTRU_Q - 1));
    }
}

static void ntru_poly_trinary_Zq_to_Z3(poly* r)
{
    /* Map {0, 1, q-1} -> {0,1,2} in place */

    for (size_t i = 0; i < NTRU_N; ++i)
    {
        r->coeffs[i] = ntru_modq(r->coeffs[i]);
        r->coeffs[i] = 3 & (r->coeffs[i] ^ (r->coeffs[i] >> (NTRU_LOGQ - 1)));
    }
}

static void ntru_poly_Sq_mul(poly* r, const poly* a, const poly* b)
{
    ntru_poly_Rq_mul(r, a, b);
    ntru_poly_mod_q_Phi_n(r);
}

static void ntru_poly_S3_mul(poly* r, const poly* a, const poly *b)
{
    ntru_poly_Rq_mul(r, a, b);
    ntru_poly_mod_3_Phi_n(r);
}

static void ntru_poly_R2_inv_to_Rq_inv(poly* r, const poly* ai, const poly* a)
{
#if NTRU_Q <= 256 || NTRU_Q >= 65536
#   error "ntru_poly_R2_inv_to_Rq_inv in poly.c assumes 256 < q < 65536"
#endif

    size_t i;
    poly b;
    poly c;
    poly s;

    /* for 0..4 ai = ai * (2 - a*ai)  mod q */

    for (i = 0; i < NTRU_N; ++i)
    {
        b.coeffs[i] = -(a->coeffs[i]);
    }

    for (i = 0; i < NTRU_N; ++i)
    {
        r->coeffs[i] = ai->coeffs[i];
    }

    ntru_poly_Rq_mul(&c, r, &b);
    c.coeffs[0] += 2;       /* c = 2 - a * ai */
    ntru_poly_Rq_mul(&s, &c, r); /* s = ai*c */

    ntru_poly_Rq_mul(&c, &s, &b);
    c.coeffs[0] += 2;       /* c = 2 - a*s */
    ntru_poly_Rq_mul(r, &c, &s); /* r = s*c */

    ntru_poly_Rq_mul(&c, r, &b);
    c.coeffs[0] += 2;       /* c = 2 - a*r */
    ntru_poly_Rq_mul(&s, &c, r); /* s = r*c */

    ntru_poly_Rq_mul(&c, &s, &b);
    c.coeffs[0] += 2;       /* c = 2 - a*s */
    ntru_poly_Rq_mul(r, &c, &s); /* r = s*c */
}

static void ntru_poly_Rq_inv(poly* r, const poly* a)
{
    poly ai2;

    ntru_poly_R2_inv(&ai2, a);
    ntru_poly_R2_inv_to_Rq_inv(r, &ai2, a);
}

/* ntru_poly_lift.c */

#ifdef NTRU_HPS
static void ntru_poly_lift(poly* r, const poly* a)
{
    for (size_t i = 0; i < NTRU_N; ++i)
    {
        r->coeffs[i] = a->coeffs[i];
    }

    ntru_poly_Z3_to_Zq(r);
}
#endif

#ifdef NTRU_HRSS
static void ntru_poly_lift(poly* r, const poly* a)
{
    /* NOTE: Assumes input is in {0,1,2}^N */
    /*       Produces output in [0,Q-1]^N */
    poly b;
    size_t i;
    uint16_t t;
    uint16_t zj;

    /* Define z by <z*x^i, x-1> = delta_{i,0} mod 3:      */
    /*   t      = -1/N mod p = -N mod 3                   */
    /*   z[0]   = 2 - t mod 3                             */
    /*   z[1]   = 0 mod 3                                 */
    /*   z[j]   = z[j-1] + t mod 3                        */
    /* We'll compute b = a/(x-1) mod (3, Phi) using       */
    /*   b[0] = <z, a>, b[1] = <z*x,a>, b[2] = <z*x^2,a>  */
    /*   b[i] = b[i-3] - (a[i] + a[i-1] + a[i-2])         */

    t = 3 - (NTRU_N % 3);
    b.coeffs[0] = a->coeffs[0] * (2 - t) + a->coeffs[1] * 0 + a->coeffs[2] * t;
    b.coeffs[1] = a->coeffs[1] * (2 - t) + a->coeffs[2] * 0;
    b.coeffs[2] = a->coeffs[2] * (2 - t);

    zj = 0; /* z[1] */

    for (i = 3; i < NTRU_N; ++i)
    {
        b.coeffs[0] += a->coeffs[i] * (zj + 2 * t);
        b.coeffs[1] += a->coeffs[i] * (zj + t);
        b.coeffs[2] += a->coeffs[i] * zj;
        zj = (zj + t) % 3;
    }

    b.coeffs[1] += a->coeffs[0] * (zj + t);
    b.coeffs[2] += a->coeffs[0] * zj;
    b.coeffs[2] += a->coeffs[1] * (zj + t);

    b.coeffs[0] = b.coeffs[0];
    b.coeffs[1] = b.coeffs[1];
    b.coeffs[2] = b.coeffs[2];

    for (i = 3; i < NTRU_N; ++i)
    {
        b.coeffs[i] = b.coeffs[i - 3] + 2 * (a->coeffs[i] + a->coeffs[i - 1] + a->coeffs[i - 2]);
    }

    /* Finish reduction mod Phi by subtracting Phi * b[N-1] */
    ntru_poly_mod_3_Phi_n(&b);

    /* Switch from {0,1,2} to {0,1,q-1} coefficient representation */
    ntru_poly_Z3_to_Zq(&b);

    /* Multiply by (x-1) */
    r->coeffs[0] = -(b.coeffs[0]);

    for (i = 0; i < NTRU_N - 1; ++i)
    {
        r->coeffs[i + 1] = b.coeffs[i] - b.coeffs[i + 1];
    }
}
#endif

/* pack3.c */

static void ntru_poly_S3_to_bytes(uint8_t msg[NTRU_OWCPA_MSGBYTES], const poly* a)
{
    int32_t i;
    uint8_t c;

    for (i = 0; i < NTRU_PACK_DEG / 5; ++i)
    {
        c = a->coeffs[(5 * i) + 4] & 0x00FF;
        c = ((3 * c) + a->coeffs[(5 * i) + 3]) & 0x00FF;
        c = ((3 * c) + a->coeffs[(5 * i) + 2]) & 0x00FF;
        c = ((3 * c) + a->coeffs[(5 * i) + 1]) & 0x00FF;
        c = ((3 * c) + a->coeffs[5 * i]) & 0x00FF;
        msg[i] = c;
    }

#if NTRU_PACK_DEG > (NTRU_PACK_DEG / 5) * 5  /* if 5 does not divide NTRU_N-1 */
    i = NTRU_PACK_DEG / 5;
    c = 0;

    for (int32_t j = NTRU_PACK_DEG - (5 * i) - 1; j >= 0; j--)
    {
        c = ((3 * c) + a->coeffs[(5 * i) + j]) & 0x00FF;
    }

    msg[i] = c;
#endif
}

static void ntru_poly_S3_from_bytes(poly* r, const uint8_t msg[NTRU_OWCPA_MSGBYTES])
{
    size_t i;
    uint8_t c;

    for (i = 0; i < NTRU_PACK_DEG / 5; ++i)
    {
        c = msg[i];
        r->coeffs[5 * i] = c;
        r->coeffs[(5 * i) + 1] = (c * 171) >> 9;    /* this is division by 3 */
        r->coeffs[(5 * i) + 2] = (c * 57) >> 9;     /* division by 3 ^ 2 */
        r->coeffs[(5 * i) + 3] = (c * 19) >> 9;     /* division by 3 ^ 3 */
        r->coeffs[(5 * i) + 4] = (c * 203) >> 14;
    }

#if NTRU_PACK_DEG > (NTRU_PACK_DEG / 5) * 5  /* if 5 does not divide NTRU_N-1 */
    i = NTRU_PACK_DEG / 5;
    c = msg[i];

    for (size_t j = 0; ((5 * i) + j) < NTRU_PACK_DEG; ++j)
    {
        r->coeffs[(5 * i) + j] = c;
        c = (c * 171) >> 9;
    }
#endif

    r->coeffs[NTRU_N - 1] = 0;
    ntru_poly_mod_3_Phi_n(r);
}

/* packq.c */

static void ntru_poly_Sq_to_bytes(uint8_t* r, const poly* a)
{
    size_t i;

#if defined(QSC_NTRU_S1HPS2048509) || defined(QSC_NTRU_HPSS32048677)

    uint16_t t[8];
    size_t j;

    for (i = 0; i < NTRU_PACK_DEG / 8; ++i)
    {
        for (j = 0; j < 8; ++j)
        {
            t[j] = ntru_modq(a->coeffs[(8 * i) + j]);
        }

        r[11 * i] = (uint8_t)(t[0] & 0xFF);
        r[(11 * i) + 1] = (uint8_t)((t[0] >> 8) | ((t[1] & 0x1F) << 3));
        r[(11 * i) + 2] = (uint8_t)((t[1] >> 5) | ((t[2] & 0x03) << 6));
        r[(11 * i) + 3] = (uint8_t)((t[2] >> 2) & 0xFF);
        r[(11 * i) + 4] = (uint8_t)((t[2] >> 10) | ((t[3] & 0x7F) << 1));
        r[(11 * i) + 5] = (uint8_t)((t[3] >> 7) | ((t[4] & 0x0F) << 4));
        r[(11 * i) + 6] = (uint8_t)((t[4] >> 4) | ((t[5] & 0x01) << 7));
        r[(11 * i) + 7] = (uint8_t)((t[5] >> 1) & 0xFF);
        r[(11 * i) + 8] = (uint8_t)((t[5] >> 9) | ((t[6] & 0x3F) << 2));
        r[(11 * i) + 9] = (uint8_t)((t[6] >> 6) | ((t[7] & 0x07) << 5));
        r[(11 * i) + 10] = (uint8_t)(t[7] >> 3);
    }

    for (j = 0; j < NTRU_PACK_DEG - 8 * i; ++j)
    {
        t[j] = ntru_modq(a->coeffs[(8 * i) + j]);
    }

    for (; j < 8; ++j)
    {
        t[j] = 0;
    }

    if ((NTRU_PACK_DEG & 0x07) == 4)
    {
        // cases 0 and 6 are impossible since 2 generates (Z/n)* and
        // p mod 8 in {1, 7} implies that 2 is a quadratic residue.
        r[11 * i] = (uint8_t)(t[0] & 0xFF);
        r[(11 * i) + 1] = (uint8_t)((t[0] >> 8) | ((t[1] & 0x1F) << 3));
        r[(11 * i) + 2] = (uint8_t)((t[1] >> 5) | ((t[2] & 0x03) << 6));
        r[(11 * i) + 3] = (uint8_t)((t[2] >> 2) & 0xFF);
        r[(11 * i) + 4] = (uint8_t)((t[2] >> 10) | ((t[3] & 0x7F) << 1));
        r[(11 * i) + 5] = (uint8_t)((t[3] >> 7) | ((t[4] & 0x0F) << 4));
    }
    else if ((NTRU_PACK_DEG & 0x07) == 2)
    {
        r[11 * i] = (uint8_t)(t[0] & 0xFF);
        r[(11 * i) + 1] = (uint8_t)((t[0] >> 8) | ((t[1] & 0x1F) << 3));
        r[(11 * i) + 2] = (uint8_t)((t[1] >> 5) | ((t[2] & 0x03) << 6));
    }

#elif defined(QSC_NTRU_S5HPS4096821)

    for (i = 0; i < NTRU_PACK_DEG / 2; i++)
    {
        r[3 * i] = (uint8_t)(ntru_modq(a->coeffs[2 * i]) & 0xFF);
        r[(3 * i) + 1] = (uint8_t)((ntru_modq(a->coeffs[2 * i]) >> 8) | ((ntru_modq(a->coeffs[(2 * i) + 1]) & 0x0F) << 4));
        r[(3 * i) + 2] = (uint8_t)((ntru_modq(a->coeffs[(2 * i) + 1]) >> 4));
    }

#elif defined(QSC_NTRU_S5HRSS701)

    uint16_t t[8];
    size_t j;

    for (i = 0; i < NTRU_PACK_DEG / 8; ++i)
    {
        for (j = 0; j < 8; ++j)
        {
            t[j] = ntru_modq(a->coeffs[(8 * i) + j]);
        }

        r[13 * i] = (uint8_t)(t[0] & 0xff);
        r[(13 * i) + 1] = (uint8_t)((t[0] >> 8) | ((t[1] & 0x07) << 5));
        r[(13 * i) + 2] = (uint8_t)((t[1] >> 3) & 0xFF);
        r[(13 * i) + 3] = (uint8_t)((t[1] >> 11) | ((t[2] & 0x3F) << 2));
        r[(13 * i) + 4] = (uint8_t)((t[2] >> 6) | ((t[3] & 0x01) << 7));
        r[(13 * i) + 5] = (uint8_t)((t[3] >> 1) & 0xFF);
        r[(13 * i) + 6] = (uint8_t)((t[3] >> 9) | ((t[4] & 0x0F) << 4));
        r[(13 * i) + 7] = (uint8_t)((t[4] >> 4) & 0xFF);
        r[(13 * i) + 8] = (uint8_t)((t[4] >> 12) | ((t[5] & 0x7F) << 1));
        r[(13 * i) + 9] = (uint8_t)((t[5] >> 7) | ((t[6] & 0x03) << 6));
        r[(13 * i) + 10] = (uint8_t)((t[6] >> 2) & 0xFF);
        r[(13 * i) + 11] = (uint8_t)((t[6] >> 10) | ((t[7] & 0x1F) << 3));
        r[(13 * i) + 12] = (uint8_t)((t[7] >> 5));
    }

    for (j = 0; j < NTRU_PACK_DEG - 8 * i; ++j)
    {
        t[j] = ntru_modq(a->coeffs[(8 * i) + j]);
    }

    for (; j < 8; ++j)
    {
        t[j] = 0;
    }

    switch (NTRU_PACK_DEG - 8 * (NTRU_PACK_DEG / 8))
    {
        /* cases 0 and 6 are impossible since 2 generates(Z / n) * and
           p mod 8 in {1, 7} implies that 2 is a quadratic residue. */
    case 4:
        r[13 * i] = (uint8_t)(t[0] & 0xFF);
        r[(13 * i) + 1] = (uint8_t)(t[0] >> 8) | ((t[1] & 0x07) << 5);
        r[(13 * i) + 2] = (uint8_t)(t[1] >> 3) & 0xFF;
        r[(13 * i) + 3] = (uint8_t)(t[1] >> 11) | ((t[2] & 0x3F) << 2);
        r[(13 * i) + 4] = (uint8_t)(t[2] >> 6) | ((t[3] & 0x01) << 7);
        r[(13 * i) + 5] = (uint8_t)(t[3] >> 1) & 0xFF;
        r[(13 * i) + 6] = (uint8_t)(t[3] >> 9) | ((t[4] & 0x0F) << 4);
        break;
    case 2:
        r[13 * i] = (uint8_t)(t[0] & 0xFF);
        r[(13 * i) + 1] = (uint8_t)(t[0] >> 8) | ((t[1] & 0x07) << 5);
        r[(13 * i) + 2] = (uint8_t)(t[1] >> 3) & 0xFF;
        r[(13 * i) + 3] = (uint8_t)(t[1] >> 11) | ((t[2] & 0x3F) << 2);
        break;
    }

#endif
}

static void ntru_poly_Sq_from_bytes(poly* r, const uint8_t* a)
{
    size_t i;

#if defined(QSC_NTRU_S1HPS2048509) || defined(QSC_NTRU_HPSS32048677)

    for (i = 0; i < NTRU_PACK_DEG / 8; ++i)
    {
        r->coeffs[8 * i] = (uint16_t)((a[11 * i] >> 0) | (((uint16_t)a[11 * i + 1] & 0x07) << 8));
        r->coeffs[(8 * i) + 1] = (uint16_t)((a[(11 * i) + 1] >> 3) | (((uint16_t)a[(11 * i) + 2] & 0x3F) << 5));
        r->coeffs[(8 * i) + 2] = (uint16_t)((a[(11 * i) + 2] >> 6) | (((uint16_t)a[(11 * i) + 3] & 0xFF) << 2) | (((uint16_t)a[(11 * i) + 4] & 0x01) << 10));
        r->coeffs[(8 * i) + 3] = (uint16_t)((a[(11 * i) + 4] >> 1) | (((uint16_t)a[(11 * i) + 5] & 0x0F) << 7));
        r->coeffs[(8 * i) + 4] = (uint16_t)((a[(11 * i) + 5] >> 4) | (((uint16_t)a[(11 * i) + 6] & 0x7F) << 4));
        r->coeffs[(8 * i) + 5] = (uint16_t)((a[(11 * i) + 6] >> 7) | (((uint16_t)a[(11 * i) + 7] & 0xFF) << 1) | (((uint16_t)a[(11 * i) + 8] & 0x03) << 9));
        r->coeffs[(8 * i) + 6] = (uint16_t)((a[(11 * i) + 8] >> 2) | (((uint16_t)a[(11 * i) + 9] & 0x1F) << 6));
        r->coeffs[(8 * i) + 7] = (uint16_t)((a[(11 * i) + 9] >> 5) | (((uint16_t)a[(11 * i) + 10] & 0xFF) << 3));
    }

    if ((NTRU_PACK_DEG & 0x07) == 4)
    {
        // cases 0 and 6 are impossible since 2 generates (Z/n)* and
        // p mod 8 in {1, 7} implies that 2 is a quadratic residue.
        r->coeffs[8 * i] = (uint16_t)((a[11 * i] >> 0) | (((uint16_t)a[(11 * i) + 1] & 0x07) << 8));
        r->coeffs[(8 * i) + 1] = (uint16_t)((a[(11 * i) + 1] >> 3) | (((uint16_t)a[(11 * i) + 2] & 0x3F) << 5));
        r->coeffs[(8 * i) + 2] = (uint16_t)((a[(11 * i) + 2] >> 6) | (((uint16_t)a[(11 * i) + 3] & 0xFF) << 2) | (((uint16_t)a[(11 * i) + 4] & 0x01) << 10));
        r->coeffs[(8 * i) + 3] = (uint16_t)((a[(11 * i) + 4] >> 1) | (((uint16_t)a[(11 * i) + 5] & 0x0F) << 7));
    }
    else if ((NTRU_PACK_DEG & 0x07) == 2)
    {
        r->coeffs[8 * i] = (uint16_t)((a[11 * i] >> 0) | (((uint16_t)a[(11 * i) + 1] & 0x07) << 8));
        r->coeffs[(8 * i) + 1] = (uint16_t)((a[(11 * i) + 1] >> 3) | (((uint16_t)a[(11 * i) + 2] & 0x3F) << 5));
    }

    r->coeffs[NTRU_N - 1] = 0;

#elif defined(QSC_NTRU_S5HPS4096821)

    for (i = 0; i < NTRU_PACK_DEG / 2; ++i)
    {
        r->coeffs[2 * i] = (a[3 * i] >> 0) | (((uint16_t)a[(3 * i) + 1] & 0x0F) << 8);
        r->coeffs[(2 * i) + 1] = (a[(3 * i) + 1] >> 4) | (((uint16_t)a[(3 * i) + 2] & 0xFF) << 4);
    }

    r->coeffs[NTRU_N - 1] = 0;

#elif defined(QSC_NTRU_S5HRSS701)

    for (i = 0; i < NTRU_PACK_DEG / 8; ++i)
    {
        r->coeffs[8 * i] = a[13 * i] | (((uint16_t)a[(13 * i) + 1] & 0x1F) << 8);
        r->coeffs[(8 * i) + 1] = (a[(13 * i) + 1] >> 5) | (((uint16_t)a[(13 * i) + 2]) << 3) | (((uint16_t)a[(13 * i) + 3] & 0x03) << 11);
        r->coeffs[(8 * i) + 2] = (a[(13 * i) + 3] >> 2) | (((uint16_t)a[(13 * i) + 4] & 0x7F) << 6);
        r->coeffs[(8 * i) + 3] = (a[(13 * i) + 4] >> 7) | (((uint16_t)a[(13 * i) + 5]) << 1) | (((uint16_t)a[(13 * i) + 6] & 0x0F) << 9);
        r->coeffs[(8 * i) + 4] = (a[(13 * i) + 6] >> 4) | (((uint16_t)a[(13 * i) + 7]) << 4) | (((uint16_t)a[(13 * i) + 8] & 0x01) << 12);
        r->coeffs[(8 * i) + 5] = (a[(13 * i) + 8] >> 1) | (((uint16_t)a[(13 * i) + 9] & 0x3F) << 7);
        r->coeffs[(8 * i) + 6] = (a[(13 * i) + 9] >> 6) | (((uint16_t)a[(13 * i) + 10]) << 2) | (((uint16_t)a[(13 * i) + 11] & 0x07) << 10);
        r->coeffs[(8 * i) + 7] = (a[(13 * i) + 11] >> 3) | (((uint16_t)a[(13 * i) + 12]) << 5);
    }
    switch (NTRU_PACK_DEG & 0x07)
    {
        /* cases 0 and 6 are impossible since 2 generates(Z / n) * and
           p mod 8 in {1, 7} implies that 2 is a quadratic residue. */
    case 4:
        r->coeffs[8 * i] = a[13 * i] | (((uint16_t)a[(13 * i) + 1] & 0x1F) << 8);
        r->coeffs[(8 * i) + 1] = (a[(13 * i) + 1] >> 5) | (((uint16_t)a[(13 * i) + 2]) << 3) | (((uint16_t)a[(13 * i) + 3] & 0x03) << 11);
        r->coeffs[(8 * i) + 2] = (a[(13 * i) + 3] >> 2) | (((uint16_t)a[(13 * i) + 4] & 0x7F) << 6);
        r->coeffs[(8 * i) + 3] = (a[(13 * i) + 4] >> 7) | (((uint16_t)a[(13 * i) + 5]) << 1) | (((uint16_t)a[(13 * i) + 6] & 0x0F) << 9);
        break;
    case 2:
        r->coeffs[8 * i] = a[13 * i] | (((uint16_t)a[(13 * i) + 1] & 0x1F) << 8);
        r->coeffs[(8 * i) + 1] = (a[(13 * i) + 1] >> 5) | (((uint16_t)a[(13 * i) + 2]) << 3) | (((uint16_t)a[(13 * i) + 3] & 0x03) << 11);
        break;
    }

    r->coeffs[NTRU_N - 1] = 0;

#endif
}

static void ntru_poly_Rq_sum_zero_to_bytes(uint8_t* r, const poly* a)
{
    ntru_poly_Sq_to_bytes(r, a);
}

static void ntru_poly_Rq_sum_zero_from_bytes(poly* r, const uint8_t* a)
{
    ntru_poly_Sq_from_bytes(r, a);

    /* Set r[n-1] so that the sum of coefficients is zero mod q */
    r->coeffs[NTRU_N - 1] = 0;

    for (size_t i = 0; i < NTRU_PACK_DEG; ++i)
    {
        r->coeffs[NTRU_N - 1] -= r->coeffs[i];
    }
}

#ifdef NTRU_HPS
static void ntru_sample_fixed_type(poly *r, const uint8_t u[NTRU_SAMPLE_FT_BYTES])
{
    /* Assumes NTRU_SAMPLE_FT_BYTES = ceil(30 * (n - 1) / 8) */

    int32_t s[NTRU_N - 1];
    size_t i;

    /* Use 30 bits of u per word */
    for (i = 0; i < (NTRU_N - 1) / 4; ++i)
    {
        s[4 * i] = (u[15 * i] << 2) + (u[(15 * i) + 1] << 10) + (u[(15 * i) + 2] << 18) + ((uint32_t)u[(15 * i) + 3] << 26);
        s[(4 * i) + 1] = ((u[(15 * i) + 3] & 0xC0) >> 4) + (u[(15 * i) + 4] << 4) + (u[(15 * i) + 5] << 12) + (u[(15 * i) + 6] << 20) + ((uint32_t)u[(15 * i) + 7] << 28);
        s[(4 * i) + 2] = ((u[(15 * i) + 7] & 0xF0) >> 2) + (u[(15 * i) + 8] << 6) + (u[(15 * i) + 9] << 14) + (u[(15 * i) + 10] << 22) + ((uint32_t)u[(15 * i) + 11] << 30);
        s[(4 * i) + 3] = (u[(15 * i) + 11] & 0xFC) + (u[(15 * i) + 12] << 8) + (u[(15 * i) + 13] << 16/*changed to 15*/) + ((uint32_t)u[(15 * i) + 14] << 24);
    }
#if (NTRU_N - 1) > ((NTRU_N - 1) / 4) * 4 // (N-1) = 2 mod 4
    i = (NTRU_N - 1) / 4;
    s[4 * i] = (u[15 * i] << 2) + (u[(15 * i) + 1] << 10) + (u[(15 * i) + 2] << 18) + ((uint32_t)u[(15 * i) + 3] << 26);
    s[(4 * i) + 1] = ((u[(15 * i) + 3] & 0xC0) >> 4) + (u[(15 * i) + 4] << 4) + (u[(15 * i) + 5] << 12) + (u[(15 * i) + 6] << 20) + ((uint32_t)u[(15 * i) + 7] << 28);
#endif

    for (i = 0; i < NTRU_WEIGHT / 2; ++i)
    {
        s[i] |= 1;
    }

    for (i = NTRU_WEIGHT / 2; i < NTRU_WEIGHT; ++i)
    {
        s[i] |= 2;
    }

    ntru_crypto_sort_int32(s, NTRU_N - 1);

    for (i = 0; i < NTRU_N - 1; ++i)
    {
        r->coeffs[i] = ((uint16_t)(s[i] & 3));
    }

    r->coeffs[NTRU_N - 1] = 0;
}
#endif

/* ntru_sample_iid.c */

static uint16_t ntru_sample_iid_mod3(uint16_t a)
{
    uint16_t r;
    int16_t c;
    int16_t t;

    r = (a >> 8) + (a & 0xFF); /* r' mod 255 == a mod 255 */
    r = (r >> 4) + (r & 0x0F); /* r' mod 15 == r mod 15 */
    r = (r >> 2) + (r & 0x03); /* r' mod 3 == r mod 3 */
    r = (r >> 2) + (r & 0x03); /* r' mod 3 == r mod 3 */

    t = r - 3;
    c = t >> 15;

    return (uint16_t)((c & r) ^ (~c & t));
}

static void ntru_sample_iid(poly *r, const uint8_t uniformbytes[NTRU_SAMPLE_IID_BYTES])
{
    /* {0,1,...,255} -> {0,1,2}; Pr[0] = 86/256, Pr[1] = Pr[-1] = 85/256 */

    for (size_t  i = 0; i < NTRU_N - 1; ++i)
    {
        r->coeffs[i] = ntru_sample_iid_mod3(uniformbytes[i]);
    }

    r->coeffs[NTRU_N - 1] = 0;
}

#ifdef NTRU_HRSS
static void ntru_sample_iid_plus(poly *r, const uint8_t uniformbytes[NTRU_SAMPLE_IID_BYTES])
{
    /* Sample r using ntru_sample_iid then conditionally flip
       signs of even index coefficients so that <x*r, r> >= 0. */

    size_t i;
    uint16_t s;

    ntru_sample_iid(r, uniformbytes);

    /* Map {0,1,2} -> {0, 1, 2^16 - 1} */
    for (i = 0; i < NTRU_N - 1; ++i)
    {
        r->coeffs[i] = r->coeffs[i] | (-(r->coeffs[i] >> 1));
    }

    s = 0;

    /* s = <x*r, r>.  (r[n-1] = 0) */
    for (i = 0; i < NTRU_N - 1; ++i)
    {
        s += (uint16_t)((uint32_t)r->coeffs[i + 1] * (uint32_t)r->coeffs[i]);
    }

    /* Extract sign of s (sign(0) = 1) */
    s = 1 | (-(s >> 15));

    for (i = 0; i < NTRU_N; i += 2)
    {
        r->coeffs[i] = (uint16_t)((uint32_t)s * (uint32_t)r->coeffs[i]);
    }

    /* Map {0,1,2^16-1} -> {0, 1, 2} */
    for (i = 0; i < NTRU_N; ++i)
    {
        r->coeffs[i] = 3 & (r->coeffs[i] ^ (r->coeffs[i] >> 15));
    }
}
#endif

/* sample.c */

static void ntru_sample_fg(poly* f, poly* g, const uint8_t uniformbytes[NTRU_SAMPLE_FG_BYTES])
{
#if defined(NTRU_HRSS)
    ntru_sample_iid_plus(f, uniformbytes);
    ntru_sample_iid_plus(g, uniformbytes + NTRU_SAMPLE_IID_BYTES);
#endif

#if defined(NTRU_HPS)
    ntru_sample_iid(f, uniformbytes);
    ntru_sample_fixed_type(g, uniformbytes + NTRU_SAMPLE_IID_BYTES);
#endif
}

static void ntru_sample_rm(poly* r, poly* m, const uint8_t uniformbytes[NTRU_SAMPLE_RM_BYTES])
{
#ifdef NTRU_HRSS
    ntru_sample_iid(r, uniformbytes);
    ntru_sample_iid(m, uniformbytes + NTRU_SAMPLE_IID_BYTES);
#endif

#ifdef NTRU_HPS
    ntru_sample_iid(r, uniformbytes);
    ntru_sample_fixed_type(m, uniformbytes + NTRU_SAMPLE_IID_BYTES);
#endif
}

/* owcpa.c */

static int32_t ntru_owcpa_check_ciphertext(const uint8_t* ciphertext)
{
    /* A ciphertext is log2(q)*(n-1) bits packed into bytes.  */
    /* Check that any unused bits of the final byte are zero. */

    uint16_t t;

    t = ciphertext[NTRU_CIPHERTEXTBYTES - 1];
    t &= 0xFF << (8 - (7 & (NTRU_LOGQ * NTRU_PACK_DEG)));

    /* We have 0 <= t < 256 */
    /* Return 0 on success (t=0), 1 on failure */
    return (1 & ((~t + 1) >> 15));
}

static int32_t ntru_owcpa_check_r(const poly* r)
{
    /* A valid r has coefficients in {0,1,q-1} and has r[N-1] = 0 */
    /* Note: We may assume that 0 <= r[i] <= q-1 for all i        */

    uint32_t t;
    uint16_t c;

    t = 0;

    for (size_t i = 0; i < NTRU_N - 1; ++i)
    {
        c = r->coeffs[i];
        t |= (c + 1) & (NTRU_Q - 4);    /* 0 iff c is in {-1,0,1,2} */
        t |= (c + 2) & 4;               /* 1 if c = 2, 0 if c is in {-1,0,1} */
    }

    t |= r->coeffs[NTRU_N - 1];         /* Coefficient n-1 must be zero */

    /* We have 0 <= t < 2^16. */
    /* Return 0 on success (t=0), 1 on failure */
    return (int32_t)(1 & ((~t + 1) >> 31));
}

#ifdef NTRU_HPS
static int32_t ntru_owcpa_check_m(const poly* m)
{
    /* Check that m is in message space, i.e.
        (1)  |{i : m[i] = 1}| = |{i : m[i] = 2}|, and
        (2)  |{i : m[i] != 0}| = NTRU_WEIGHT.
        Note: We may assume that m has coefficients in {0,1,2}. */

    uint32_t t;
    uint16_t ps;
    uint16_t ms;

    t = 0;
    ms = 0;
    ps = 0;

    for (size_t i = 0; i < NTRU_N; ++i)
    {
        ps += m->coeffs[i] & 1;
        ms += m->coeffs[i] & 2;
    }

    t |= ps ^ (ms >> 1);
    t |= ms ^ NTRU_WEIGHT;

    /* We have 0 <= t < 2^16. */
    /* Return 0 on success (t=0), 1 on failure */
    return (int32_t)(1 & ((~t + 1) >> 31));
}
#endif

static void ntru_owcpa_keypair(uint8_t* pk, uint8_t* sk, const uint8_t seed[NTRU_SAMPLE_FG_BYTES])
{
    poly x1;
    poly x2;
    poly x3;
    poly x4;
    poly x5;
    poly* f;
    poly* g;
    poly* invf_mod3;
    poly* gf;
    poly* invgf;
    poly* tmp;
    poly* invh;
    poly* h;

    f = &x1;
    g = &x2;
    invf_mod3 = &x3;
    gf = &x3;
    invgf = &x4;
    tmp = &x5;
    invh = &x3;
    h = &x3;

    ntru_sample_fg(f, g, seed);

    ntru_poly_S3_inv(invf_mod3, f);
    ntru_poly_S3_to_bytes(sk, f);
    ntru_poly_S3_to_bytes(sk + NTRU_PACK_TRINARY_BYTES, invf_mod3);

    /* Lift coeffs of f and g from Z_p to Z_q */
    ntru_poly_Z3_to_Zq(f);
    ntru_poly_Z3_to_Zq(g);

#ifdef NTRU_HRSS
    /* g = 3*(x-1)*g */
    for (int32_t i = NTRU_N - 1; i > 0; i--)
    {
        g->coeffs[i] = 3 * (g->coeffs[i - 1] - g->coeffs[i]);
    }

    g->coeffs[0] = -(3 * g->coeffs[0]);
#endif

#ifdef NTRU_HPS
    /* g = 3*g */
    for (int32_t i = 0; i < NTRU_N; ++i)
    {
        g->coeffs[i] = 3 * g->coeffs[i];
    }
#endif

    ntru_poly_Rq_mul(gf, g, f);
    ntru_poly_Rq_inv(invgf, gf);

    ntru_poly_Rq_mul(tmp, invgf, f);
    ntru_poly_Sq_mul(invh, tmp, f);
    ntru_poly_Sq_to_bytes(sk + 2 * NTRU_PACK_TRINARY_BYTES, invh);

    ntru_poly_Rq_mul(tmp, invgf, g);
    ntru_poly_Rq_mul(h, tmp, g);
    ntru_poly_Rq_sum_zero_to_bytes(pk, h);
}

static void ntru_owcpa_enc(uint8_t* c, const poly* r, const poly* m, const uint8_t* pk)
{
    poly x1;
    poly x2;
    poly* h;
    poly* liftm;
    poly* ct;

    h = &x1;
    liftm = &x1;
    ct = &x2;

    ntru_poly_Rq_sum_zero_from_bytes(h, pk);
    ntru_poly_Rq_mul(ct, r, h);
    ntru_poly_lift(liftm, m);

    for (int32_t i = 0; i < NTRU_N; ++i)
    {
        ct->coeffs[i] = ct->coeffs[i] + liftm->coeffs[i];
    }

    ntru_poly_Rq_sum_zero_to_bytes(c, ct);
}

static int32_t ntru_owcpa_dec(uint8_t* rm, const uint8_t* ciphertext, const uint8_t* secretkey)
{
    poly x1;
    poly x2;
    poly x3;
    poly x4;
    poly* c;
    poly* f;
    poly* cf;
    poly* mf;
    poly* finv3;
    poly* m;
    poly* liftm;
    poly* invh;
    poly* r;
    poly* b;
    int32_t fail;

    c = &x1;
    f = &x2;
    cf = &x3;
    mf = &x2;
    finv3 = &x3;
    m = &x4;
    liftm = &x2;
    invh = &x3;
    r = &x4;
    b = &x1;

    ntru_poly_Rq_sum_zero_from_bytes(c, ciphertext);
    ntru_poly_S3_from_bytes(f, secretkey);
    ntru_poly_Z3_to_Zq(f);

    ntru_poly_Rq_mul(cf, c, f);
    ntru_poly_Rq_to_S3(mf, cf);

    ntru_poly_S3_from_bytes(finv3, secretkey + NTRU_PACK_TRINARY_BYTES);
    ntru_poly_S3_mul(m, mf, finv3);
    ntru_poly_S3_to_bytes(rm + NTRU_PACK_TRINARY_BYTES, m);

    fail = 0;

    /* Check that the unused bits of the last byte of the ciphertext are zero */
    fail |= ntru_owcpa_check_ciphertext(ciphertext);

    /* For the IND-CCA2 KEM we must ensure that c = Enc(h, (r,m)).
       We can avoid re-computing r*h + Lift(m) as long as we check that
       r (defined as b/h mod (q, Phi_n)) and m are in the message space.
       (m can take any value in S3 in NTRU_HRSS) */

#ifdef NTRU_HPS
    fail |= ntru_owcpa_check_m(m);
#endif

    /* b = c - Lift(m) mod (q, x^n - 1) */
    ntru_poly_lift(liftm, m);

    for (size_t i = 0; i < NTRU_N; ++i)
    {
        b->coeffs[i] = c->coeffs[i] - liftm->coeffs[i];
    }

    /* r = b / h mod (q, Phi_n) */
    ntru_poly_Sq_from_bytes(invh, secretkey + 2 * NTRU_PACK_TRINARY_BYTES);
    ntru_poly_Sq_mul(r, b, invh);

    /* NOTE: Our definition of r as b/h mod (q, Phi_n) follows Figure 4 of
       [Sch18] https://eprint.iacr.org/2018/1174/20181203:032458.
       This differs from Figure 10 of Saito--Xagawa--Yamakawa
       [SXY17] https://eprint.iacr.org/2017/1005/20180516:055500
       where r gets a final reduction modulo p.
       We need this change to use Proposition 1 of [Sch18]. */

    /* Proposition 1 of [Sch18] shows that re-encryption with (r,m) yields c.
       if and only if fail==0 after the following call to ntru_owcpa_check_r
       The procedure given in Fig. 8 of [Sch18] can be skipped because we have
       c(1) = 0 due to the use of poly_Rq_sum_zero_{to,from}bytes. */

    fail |= ntru_owcpa_check_r(r);
    ntru_poly_trinary_Zq_to_Z3(r);
    ntru_poly_S3_to_bytes(rm, r);

    return fail;
}

/* kem.c */

void qsc_ntru_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    uint8_t seed[NTRU_SAMPLE_FG_BYTES];

    rng_generate(seed, NTRU_SAMPLE_FG_BYTES);
    ntru_owcpa_keypair(pk, sk, seed);

    rng_generate(sk + NTRU_OWCPA_SECRETKEYBYTES, NTRU_PRFKEYBYTES);
}

void qsc_ntru_ref_encapsulate(uint8_t* ct, uint8_t* ss, const uint8_t* pk, bool (*rng_generate)(uint8_t*, size_t))
{
    poly r;
    poly m;
    uint8_t rm[NTRU_OWCPA_MSGBYTES];
    uint8_t rm_seed[NTRU_SAMPLE_RM_BYTES];

    rng_generate(rm_seed, NTRU_SAMPLE_RM_BYTES);

    ntru_sample_rm(&r, &m, rm_seed);

    ntru_poly_S3_to_bytes(rm, &r);
    ntru_poly_S3_to_bytes(rm + NTRU_PACK_TRINARY_BYTES, &m);
    qsc_sha3_compute256(ss, rm, NTRU_OWCPA_MSGBYTES);

    ntru_poly_Z3_to_Zq(&r);
    ntru_owcpa_enc(ct, &r, &m, pk);
}

bool qsc_ntru_ref_decapsulate(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
    uint8_t rm[NTRU_OWCPA_MSGBYTES];
    uint8_t buf[NTRU_PRFKEYBYTES + NTRU_CIPHERTEXTBYTES];
    size_t i;
    int32_t fail;

    fail = ntru_owcpa_dec(rm, ct, sk);
    /* If fail = 0 then c = Enc(h, rm). There is no need to re-encapsulate. */
    qsc_sha3_compute256(ss, rm, NTRU_OWCPA_MSGBYTES);

    /* shake(secret PRF key || input ciphertext) */
    for (i = 0; i < NTRU_PRFKEYBYTES; ++i)
    {
        buf[i] = sk[i + NTRU_OWCPA_SECRETKEYBYTES];
    }

    for (i = 0; i < NTRU_CIPHERTEXTBYTES; ++i)
    {
        buf[NTRU_PRFKEYBYTES + i] = ct[i];
    }

    qsc_sha3_compute256(rm, buf, NTRU_PRFKEYBYTES + NTRU_CIPHERTEXTBYTES);
    ntru_cmov(ss, rm, NTRU_SHAREDKEYBYTES, (uint8_t)fail);

    return (fail == 0);
}
