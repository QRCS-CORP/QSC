#include "kyberbase.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

#define KYBER_ZETA_SIZE 128
#define KYBER_MONT 2285 /* 2^16 mod q */
#define KYBER_QINV 62209 /* q^-1 mod 2^16 */
#define KYBER_GEN_MATRIX_NBLOCKS ((12 * QSC_KYBER_N / 8 * (1 << 12) / QSC_KYBER_Q + QSC_KECCAK_128_RATE) / QSC_KECCAK_128_RATE)

static const uint16_t kyber_zetas[KYBER_ZETA_SIZE] =
{
    0xFBEC, 0xFD0A, 0xFE99, 0xFA13, 0x05D5, 0x058E, 0x011F, 0x00CA,
    0xFF55, 0x026E, 0x0629, 0x00B6, 0x03C2, 0xFB4E, 0xFA3E, 0x05BC,
    0x023D, 0xFAD3, 0x0108, 0x017F, 0xFCC3, 0x05B2, 0xF9BE, 0xFF7E,
    0xFD57, 0x03F9, 0x02DC, 0x0260, 0xF9FA, 0x019B, 0xFF33, 0xF9DD,
    0x04C7, 0x028C, 0xFDD8, 0x03F7, 0xFAF3, 0x05D3, 0xFEE6, 0xF9F8,
    0x0204, 0xFFF8, 0xFEC0, 0xFD66, 0xF9AE, 0xFB76, 0x007E, 0x05BD,
    0xFCAB, 0xFFA6, 0xFEF1, 0x033E, 0x006B, 0xFA73, 0xFF09, 0xFC49,
    0xFE72, 0x03C1, 0xFA1C, 0xFD2B, 0x01C0, 0xFBD7, 0x02A5, 0xFB05,
    0xFBB1, 0x01AE, 0x022B, 0x034B, 0xFB1D, 0x0367, 0x060E, 0x0069,
    0x01A6, 0x024B, 0x00B1, 0xFF15, 0xFEDD, 0xFE34, 0x0626, 0x0675,
    0xFF0A, 0x030A, 0x0487, 0xFF6D, 0xFCF7, 0x05CB, 0xFDA6, 0x045F,
    0xF9CA, 0x0284, 0xFC98, 0x015D, 0x01A2, 0x0149, 0xFF64, 0xFFB5,
    0x0331, 0x0449, 0x025B, 0x0262, 0x052A, 0xFAFB, 0xFA47, 0x0180,
    0xFB41, 0xFF78, 0x04C2, 0xFAC9, 0xFC96, 0x00DC, 0xFB5D, 0xF985,
    0xFB5F, 0xFA06, 0xFB02, 0x031A, 0xFA1A, 0xFCAA, 0xFC9A, 0x01DE,
    0xFF94, 0xFECC, 0x03E4, 0x03DF, 0x03BE, 0xFA4C, 0x05F2, 0x065C
};

/* reduce.c */

static int16_t kyber_montgomery_reduce(int32_t a)
{
    int32_t t;
    int16_t u;

    u = (int16_t)(a * (int64_t)KYBER_QINV);
    t = (int32_t)u * QSC_KYBER_Q;
    t = a - t;
    t >>= 16;

    return (int16_t)t;
}

static int16_t kyber_barrett_reduce(int16_t a)
{
    int16_t t;
    const int16_t V = ((1U << 26) + QSC_KYBER_Q / 2) / QSC_KYBER_Q;

    t = ((int32_t)V * a + (1 << 25)) >> 26;
    t *= QSC_KYBER_Q;

    return (a - t);
}

/* poly.h */

/**
* \struct qsc_kyber_poly
* \brief Contains an N sized array of 16bit coefficients. /n
* Elements of R_q = Z_q[X] / (X^n + 1). /n
* Represents polynomial coeffs[0] + X * coeffs[1] + X^2 * xoeffs[2] + ... + X^{n-1} * coeffs[n-1]
*
* \var qsc_kyber_poly::coeffs
* The array of 16bit coefficients
*/
typedef struct
{
    int16_t coeffs[QSC_KYBER_N];
} qsc_kyber_poly;

/**
* \struct qsc_kyber_polyvec
* \brief Contains a K sized vector of qsc_kyber_poly structures
*
* \var qsc_kyber_polyvec::vec
* The polynomial vector array
*/
typedef struct
{
    qsc_kyber_poly vec[QSC_KYBER_K];
} qsc_kyber_polyvec;

/* cbd.c */

static void kyber_cbd2(qsc_kyber_poly* r, const uint8_t buf[2 * QSC_KYBER_N / 4])
{
    uint32_t t;
    uint32_t d;
    int16_t a;
    int16_t b;

    for (size_t i = 0; i < QSC_KYBER_N / 8; ++i)
    {
        t = qsc_intutils_le8to32(buf + (4 * i));
        d = t & 0x55555555UL;
        d += (t >> 1) & 0x55555555UL;

        for (size_t j = 0; j < 8; ++j)
        {
            a = (int16_t)((d >> (4 * j)) & 0x03);
            b = (int16_t)((d >> ((4 * j) + 2)) & 0x03);
            r->coeffs[(8 * i) + j] = a - b;
        }
    }
}

/* kyber_ntt.c */

static int16_t kyber_fqmul(int16_t a, int16_t b)
{
    return kyber_montgomery_reduce((int32_t)a * b);
}

static void kyber_ntt(int16_t r[QSC_KYBER_N])
{
    size_t j;
    size_t k;
    int16_t t;
    int16_t zeta;

    k = 1;

    for (size_t len = 128; len >= 2; len >>= 1)
    {
        for (size_t start = 0; start < QSC_KYBER_N; start = (j + len))
        {
            zeta = (int16_t)kyber_zetas[k];
            ++k;

            for (j = start; j < start + len; ++j)
            {
                t = kyber_fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

static void kyber_invntt(int16_t r[256])
{
    size_t j;
    size_t k;
    int16_t t;
    int16_t zeta;
    const int16_t F = 1441;

    k = 127;

    for (size_t len = 2; len <= 128; len <<= 1)
    {
        for (size_t start = 0; start < 256; start = j + len)
        {
            zeta = (int16_t)kyber_zetas[k];
            --k;

            for (j = start; j < start + len; ++j)
            {
                t = r[j];
                r[j] = kyber_barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = kyber_fqmul(zeta, r[j + len]);
            }
        }
    }

    for (j = 0; j < 256; ++j)
    {
        r[j] = kyber_fqmul(r[j], F);
    }
}

static void kyber_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
    r[0] = kyber_fqmul(a[1], b[1]);
    r[0] = kyber_fqmul(r[0], zeta);
    r[0] += kyber_fqmul(a[0], b[0]);
    r[1] = kyber_fqmul(a[0], b[1]);
    r[1] += kyber_fqmul(a[1], b[0]);
}

/* poly.c */

static void kyber_poly_cbd_eta1(qsc_kyber_poly* r, const uint8_t buf[QSC_KYBER_ETA * QSC_KYBER_N / 4])
{
    kyber_cbd2(r, buf);
}

static void kyber_poly_cbd_eta2(qsc_kyber_poly* r, const uint8_t buf[QSC_KYBER_ETA * QSC_KYBER_N / 4])
{
    kyber_cbd2(r, buf);
}

static void kyber_poly_compress(uint8_t* r, const qsc_kyber_poly* a)
{
    uint8_t t[8];
    int16_t u;

#if (QSC_KYBER_POLYCOMPRESSED_BYTES == 128)
    for (size_t i = 0; i < QSC_KYBER_N / 8; ++i)
    {
        for (size_t j = 0; j < 8; ++j)
        {
            /* map to positive standard representatives */
            u = a->coeffs[(8 * i) + j];
            u += (u >> 15) & QSC_KYBER_Q;
            t[j] = (uint8_t)(((((uint16_t)u << 4) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 0x000F);
        }

        r[0] = (uint8_t)(t[0] | (t[1] << 4));
        r[1] = (uint8_t)(t[2] | (t[3] << 4));
        r[2] = (uint8_t)(t[4] | (t[5] << 4));
        r[3] = (uint8_t)(t[6] | (t[7] << 4));
        r += 4;
    }
#elif (QSC_KYBER_POLYCOMPRESSED_BYTES == 160)
    for (size_t i = 0; i < QSC_KYBER_N / 8; ++i)
    {
        for (size_t j = 0; j < 8; ++j)
        {
            /* map to positive standard representatives */
            u = a->coeffs[(8 * i) + j];
            u += (u >> 15) & QSC_KYBER_Q;
            t[j] = ((((uint32_t)u << 5) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 31;
        }

        r[0] = (uint8_t)(t[0] | (t[1] << 5));
        r[1] = (uint8_t)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
        r[2] = (uint8_t)((t[3] >> 1) | (t[4] << 4));
        r[3] = (uint8_t)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
        r[4] = (uint8_t)((t[6] >> 2) | (t[7] << 3));
        r += 5;
    }
#endif
}

static void kyber_poly_decompress(qsc_kyber_poly* r, const uint8_t* a)
{
#if (QSC_KYBER_POLYCOMPRESSED_BYTES == 128)
    for (size_t i = 0; i < QSC_KYBER_N / 2; ++i)
    {
        r->coeffs[2 * i] = (int16_t)((((uint16_t)(a[0] & 15) * QSC_KYBER_Q) + 8) >> 4);
        r->coeffs[(2 * i) + 1] = (int16_t)((((uint16_t)(a[0] >> 4) * QSC_KYBER_Q) + 8) >> 4);
        a += 1;
    }
#elif (QSC_KYBER_POLYCOMPRESSED_BYTES == 160)
    uint8_t t[8];

    for (size_t i = 0; i < QSC_KYBER_N / 8; ++i)
    {
        t[0] = (uint8_t)(a[0] >> 0);
        t[1] = (uint8_t)((a[0] >> 5) | (a[1] << 3));
        t[2] = (uint8_t)(a[1] >> 2);
        t[3] = (uint8_t)((a[1] >> 7) | (a[2] << 1));
        t[4] = (uint8_t)((a[2] >> 4) | (a[3] << 4));
        t[5] = (uint8_t)(a[3] >> 1);
        t[6] = (uint8_t)((a[3] >> 6) | (a[4] << 2));
        t[7] = (uint8_t)(a[4] >> 3);
        a += 5;

        for (size_t j = 0; j < 8; ++j)
        {
            r->coeffs[(8 * i) + j] = (uint16_t)(((uint32_t)(t[j] & 31) * QSC_KYBER_Q + 16) >> 5);
        }
    }
#endif
}

static void kyber_poly_to_bytes(uint8_t r[QSC_KYBER_POLYBYTES], const qsc_kyber_poly* a)
{
    uint16_t t0;
    uint16_t t1;

    for (size_t i = 0; i < QSC_KYBER_N / 2; ++i)
    {
        /* map to positive standard representatives */
        t0 = a->coeffs[2 * i];
        t0 += ((int16_t)t0 >> 15) & QSC_KYBER_Q;
        t1 = a->coeffs[(2 * i) + 1];
        t1 += ((int16_t)t1 >> 15) & QSC_KYBER_Q;
        r[3 * i] = (uint8_t)(t0 >> 0);
        r[(3 * i) + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[(3 * i) + 2] = (uint8_t)(t1 >> 4);
    }
}

static void kyber_poly_from_bytes(qsc_kyber_poly* r, const uint8_t a[QSC_KYBER_POLYBYTES])
{
    for (size_t i = 0; i < QSC_KYBER_N / 2; ++i)
    {
        r->coeffs[2 * i] = (((a[3 * i] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0x0FFF);
        r->coeffs[(2 * i) + 1] = (((a[(3 * i) + 1] >> 4) | ((uint16_t)a[(3 * i) + 2] << 4)) & 0x0FFF);
    }
}

static void kyber_poly_from_msg(qsc_kyber_poly* r, const uint8_t msg[QSC_KYBER_SYMBYTES])
{
    int16_t mask;

    for (size_t i = 0; i < QSC_KYBER_N / 8; ++i)
    {
        for (size_t j = 0; j < 8; ++j)
        {
            mask = -(int16_t)((msg[i] >> j) & 1);
            r->coeffs[(8 * i) + j] = mask & ((int16_t)(QSC_KYBER_Q + 1) / 2);
        }
    }
}

static void kyber_poly_to_msg(uint8_t msg[QSC_KYBER_SYMBYTES], const qsc_kyber_poly* a)
{
    uint16_t t;

    for (size_t i = 0; i < QSC_KYBER_N / 8; ++i)
    {
        msg[i] = 0;

        for (size_t j = 0; j < 8; ++j)
        {
            t = a->coeffs[(8 * i) + j];
            t += ((int16_t)t >> 15) & QSC_KYBER_Q;
            t = (((t << 1) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 1;
            msg[i] |= (uint8_t)(t << j);
        }
    }
}

static void kyber_poly_get_noise_eta1(qsc_kyber_poly* r, const uint8_t seed[QSC_KYBER_SYMBYTES], uint8_t nonce)
{
    uint8_t buf[QSC_KYBER_ETA * QSC_KYBER_N / 4];
    uint8_t extkey[QSC_KYBER_SYMBYTES + 1];

    qsc_memutils_copy(extkey, seed, QSC_KYBER_SYMBYTES);
    extkey[QSC_KYBER_SYMBYTES] = nonce;
    qsc_shake256_compute(buf, sizeof(buf), extkey, sizeof(extkey));

    kyber_poly_cbd_eta1(r, buf);
}

static void kyber_poly_get_noise_eta2(qsc_kyber_poly* r, const uint8_t seed[QSC_KYBER_SYMBYTES], uint8_t nonce)
{
    uint8_t buf[QSC_KYBER_ETA * QSC_KYBER_N / 4];
    uint8_t extkey[QSC_KYBER_SYMBYTES + 1];

    qsc_memutils_copy(extkey, seed, QSC_KYBER_SYMBYTES);
    extkey[QSC_KYBER_SYMBYTES] = nonce;
    qsc_shake256_compute(buf, sizeof(buf), extkey, sizeof(extkey));

    kyber_poly_cbd_eta2(r, buf);
}

static void kyber_poly_reduce(qsc_kyber_poly* r)
{
    for (size_t i = 0; i < QSC_KYBER_N; ++i)
    {
        r->coeffs[i] = kyber_barrett_reduce(r->coeffs[i]);
    }
}

static void kyber_poly_ntt(qsc_kyber_poly* r)
{
    kyber_ntt(r->coeffs);
    kyber_poly_reduce(r);
}

static void kyber_poly_invntt_to_mont(qsc_kyber_poly* r)
{
    kyber_invntt(r->coeffs);
}

static void kyber_poly_basemul_montgomery(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b)
{
    for (size_t i = 0; i < QSC_KYBER_N / 4; ++i)
    {
        kyber_basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], (int16_t)kyber_zetas[64 + i]);
        kyber_basemul(&r->coeffs[(4 * i) + 2], &a->coeffs[(4 * i) + 2], &b->coeffs[(4 * i) + 2], -(int16_t)kyber_zetas[64 + i]);
    }
}

static void kyber_poly_to_mont(qsc_kyber_poly* r)
{
    const int16_t F = (1ULL << 32) % QSC_KYBER_Q;

    for (size_t i = 0; i < QSC_KYBER_N; ++i)
    {
        r->coeffs[i] = kyber_montgomery_reduce((int32_t)r->coeffs[i] * F);
    }
}

static void kyber_poly_add(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b)
{
    for (size_t i = 0; i < QSC_KYBER_N; ++i)
    {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

static void kyber_poly_sub(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b)
{
    for (size_t i = 0; i < QSC_KYBER_N; ++i)
    {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

/* polyvec.c */

static void kyber_polyvec_compress(uint8_t r[QSC_KYBER_POLYVEC_COMPRESSED_BYTES], const qsc_kyber_polyvec* a)
{
#if (QSC_KYBER_K == 4 || QSC_KYBER_K == 5)
	uint16_t t[8];

    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        for (size_t j = 0; j < QSC_KYBER_N / 8; ++j)
        {
            for (size_t k = 0; k < 8; ++k)
            {
                t[k] = (uint16_t)a->vec[i].coeffs[(8 * j) + k];
                t[k] += (uint16_t)(((int16_t)t[k] >> 15) & QSC_KYBER_Q);
                t[k] = (uint16_t)(((((uint32_t)t[k] << 11) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 0x07FF);
            }

            r[0] = (uint8_t)(t[0] >> 0);
            r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 3));
            r[2] = (uint8_t)((t[1] >> 5) | (t[2] << 6));
            r[3] = (uint8_t)(t[2] >> 2);
            r[4] = (uint8_t)((t[2] >> 10) | (t[3] << 1));
            r[5] = (uint8_t)((t[3] >> 7) | (t[4] << 4));
            r[6] = (uint8_t)((t[4] >> 4) | (t[5] << 7));
            r[7] = (uint8_t)(t[5] >> 1);
            r[8] = (uint8_t)((t[5] >> 9) | (t[6] << 2));
            r[9] = (uint8_t)((t[6] >> 6) | (t[7] << 5));
            r[10] = (uint8_t)(t[7] >> 3);
            r += 11;
        }
    }
#elif (QSC_KYBER_K == 3)
	uint16_t t[4];

    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        for (size_t j = 0; j < QSC_KYBER_N / 4; ++j)
        {
            for (size_t k = 0; k < 4; ++k)
            {
                t[k] = (uint16_t)a->vec[i].coeffs[(4 * j) + k];
                t[k] += (uint16_t)(((int16_t)t[k] >> 15) & QSC_KYBER_Q);
                t[k] = (uint16_t)(((((uint32_t)t[k] << 10) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 0x03FF);
            }

            r[0] = (uint8_t)(t[0] >> 0);
            r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[4] = (uint8_t)(t[3] >> 2);
            r += 5;
        }
    }
#endif
}

static void kyber_polyvec_decompress(qsc_kyber_polyvec* r, const uint8_t a[QSC_KYBER_POLYVEC_COMPRESSED_BYTES])
{
#if (QSC_KYBER_K == 4 || QSC_KYBER_K == 5)

    uint16_t t[8];

    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        for (size_t j = 0; j < QSC_KYBER_N / 8; ++j)
        {
            t[0] = (uint16_t)a[0] | (uint16_t)(a[1] << 8);
            t[1] = (uint16_t)(a[1] >> 3) | (uint16_t)(a[2] << 5);
            t[2] = (uint16_t)(a[2] >> 6) | (uint16_t)(a[3] << 2) | (uint16_t)(a[4] << 10);
            t[3] = (uint16_t)(a[4] >> 1) | (uint16_t)(a[5] << 7);
            t[4] = (uint16_t)(a[5] >> 4) | (uint16_t)(a[6] << 4);
            t[5] = (uint16_t)(a[6] >> 7) | (uint16_t)(a[7] << 1) | (uint16_t)(a[8] << 9);
            t[6] = (uint16_t)(a[8] >> 2) | (uint16_t)(a[9] << 6);
            t[7] = (uint16_t)(a[9] >> 5) | (uint16_t)(a[10] << 3);
            a += 11;

            for (size_t k = 0; k < 8; ++k)
            {
                r->vec[i].coeffs[(8 * j) + k] = (int16_t)(((uint32_t)(t[k] & 0x7FF) * QSC_KYBER_Q + 1024) >> 11);
            }
        }
    }

#elif (QSC_KYBER_K == 3)

	uint16_t t[4];

    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        for (size_t j = 0; j < QSC_KYBER_N / 4; ++j)
        {
            t[0] = (uint16_t)(a[0] | ((uint16_t)a[1] << 8));
            t[1] = (uint16_t)((a[1] >> 2) | ((uint16_t)a[2] << 6));
            t[2] = (uint16_t)((a[2] >> 4) | ((uint16_t)a[3] << 4));
            t[3] = (uint16_t)((a[3] >> 6) | ((uint16_t)a[4] << 2));
            a += 5;

            for (size_t k = 0; k < 4; ++k)
            {
                r->vec[i].coeffs[(4 * j) + k] = (int16_t)(((uint32_t)(t[k] & 0x3FF) * QSC_KYBER_Q + 512) >> 10);
            }
        }
    }

#endif
}

static void kyber_polyvec_to_bytes(uint8_t r[QSC_KYBER_POLYVEC_BYTES], const qsc_kyber_polyvec* a)
{
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_to_bytes(r + (i * QSC_KYBER_POLYBYTES), &a->vec[i]);
    }
}

static void kyber_polyvec_from_bytes(qsc_kyber_polyvec* r, const uint8_t a[QSC_KYBER_POLYVEC_BYTES])
{
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_from_bytes(&r->vec[i], a + (i * QSC_KYBER_POLYBYTES));
    }
}

static void kyber_polyvec_ntt(qsc_kyber_polyvec* r)
{
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_ntt(&r->vec[i]);
    }
}

static void kyber_polyvec_invntt_to_mont(qsc_kyber_polyvec* r)
{
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_invntt_to_mont(&r->vec[i]);
    }
}

static void kyber_polyvec_basemul_acc_montgomery(qsc_kyber_poly* r, const qsc_kyber_polyvec* a, const qsc_kyber_polyvec* b)
{
    qsc_kyber_poly t;

    kyber_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);

    for (size_t i = 1; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        kyber_poly_add(r, r, &t);
    }

    kyber_poly_reduce(r);
}

static void kyber_polyvec_reduce(qsc_kyber_polyvec* r)
{
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_reduce(&r->vec[i]);
    }
}

static void kyber_polyvec_add(qsc_kyber_polyvec* r, const qsc_kyber_polyvec* a, const qsc_kyber_polyvec* b)
{
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/* indcpa.c */

static void kyber_pack_pk(uint8_t r[QSC_KYBER_INDCPA_PUBLICKEY_BYTES], const qsc_kyber_polyvec* pk, const uint8_t seed[QSC_KYBER_SYMBYTES])
{
    kyber_polyvec_to_bytes(r, pk);
    qsc_memutils_copy((r + QSC_KYBER_POLYVEC_BYTES), seed, QSC_KYBER_SYMBYTES);
}

static void kyber_unpack_pk(qsc_kyber_polyvec* pk, uint8_t seed[QSC_KYBER_SYMBYTES], const uint8_t packedpk[QSC_KYBER_INDCPA_PUBLICKEY_BYTES])
{
    kyber_polyvec_from_bytes(pk, packedpk);
    qsc_memutils_copy(seed, (packedpk + QSC_KYBER_POLYVEC_BYTES), QSC_KYBER_SYMBYTES);
}

static void kyber_pack_sk(uint8_t r[QSC_KYBER_INDCPA_SECRETKEY_BYTES], const qsc_kyber_polyvec* sk)
{
    kyber_polyvec_to_bytes(r, sk);
}

static void kyber_unpack_sk(qsc_kyber_polyvec* sk, const uint8_t packedsk[QSC_KYBER_INDCPA_SECRETKEY_BYTES])
{
    kyber_polyvec_from_bytes(sk, packedsk);
}

static void kyber_pack_ciphertext(uint8_t r[QSC_KYBER_INDCPA_BYTES], const qsc_kyber_polyvec* b, const qsc_kyber_poly* v)
{
    kyber_polyvec_compress(r, b);
    kyber_poly_compress(r + QSC_KYBER_POLYVEC_COMPRESSED_BYTES, v);
}

static void kyber_unpack_ciphertext(qsc_kyber_polyvec* b, qsc_kyber_poly* v, const uint8_t c[QSC_KYBER_INDCPA_BYTES])
{
    kyber_polyvec_decompress(b, c);
    kyber_poly_decompress(v, c + QSC_KYBER_POLYVEC_COMPRESSED_BYTES);
}

static uint32_t kyber_rej_uniform(int16_t* r, uint32_t len, const uint8_t* buf, uint32_t buflen)
{
    uint32_t ctr;
    uint32_t pos;
    uint16_t val0;
    uint16_t val1;

    ctr = 0;
    pos = 0;

    while (ctr < len && pos + 3 <= buflen)
    {
        val0 = (uint16_t)(((buf[pos] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0x0FFF);
        val1 = (uint16_t)(((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0x0FFF);
        pos += 3;

        if (val0 < QSC_KYBER_Q)
        {
            r[ctr] = val0;
            ++ctr;
        }

        if (ctr < len && val1 < QSC_KYBER_Q)
        {
            r[ctr] = val1;
            ++ctr;
        }
    }

    return ctr;
}

static void kyber_gen_matrix(qsc_kyber_polyvec* a, const uint8_t seed[QSC_KYBER_SYMBYTES], int32_t transposed)
{
    qsc_keccak_state state;
    uint8_t buf[KYBER_GEN_MATRIX_NBLOCKS * QSC_KECCAK_128_RATE + 2];
    uint8_t extseed[QSC_KYBER_SYMBYTES + 2];
    uint32_t buflen;
    uint32_t ctr;
    uint32_t off;

    qsc_memutils_copy(extseed, seed, QSC_KYBER_SYMBYTES);

    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        for (size_t j = 0; j < QSC_KYBER_K; ++j)
        {
            if (transposed != 0)
            {
                extseed[QSC_KYBER_SYMBYTES] = (uint8_t)i;
                extseed[QSC_KYBER_SYMBYTES + 1] = (uint8_t)j;
            }
            else
            {
                extseed[QSC_KYBER_SYMBYTES] = (uint8_t)j;
                extseed[QSC_KYBER_SYMBYTES + 1] = (uint8_t)i;
            }

            qsc_shake_initialize(&state, QSC_KECCAK_128_RATE, extseed, sizeof(extseed));
            qsc_shake_squeezeblocks(&state, QSC_KECCAK_128_RATE, buf, KYBER_GEN_MATRIX_NBLOCKS);

            buflen = KYBER_GEN_MATRIX_NBLOCKS * QSC_KECCAK_128_RATE;
            ctr = kyber_rej_uniform(a[i].vec[j].coeffs, QSC_KYBER_N, buf, buflen);

            while (ctr < QSC_KYBER_N)
            {
                off = buflen % 3;

                for (size_t k = 0; k < off; ++k)
                {
                    buf[k] = buf[buflen - off + k];
                }

                qsc_shake_squeezeblocks(&state, QSC_KECCAK_128_RATE, buf + off, 1);
                buflen = off + QSC_KECCAK_128_RATE;
                ctr += kyber_rej_uniform(a[i].vec[j].coeffs + ctr, QSC_KYBER_N - ctr, buf, buflen);
            }

            qsc_keccak_dispose(&state);
        }
    }
}

static void kyber_indcpa_keypair(uint8_t pk[QSC_KYBER_INDCPA_PUBLICKEY_BYTES], uint8_t sk[QSC_KYBER_INDCPA_SECRETKEY_BYTES], bool (*rng_generate)(uint8_t*, size_t))
{
    qsc_kyber_polyvec a[QSC_KYBER_K];
    qsc_kyber_polyvec e;
    qsc_kyber_polyvec pkpv;
    qsc_kyber_polyvec skpv;
    uint8_t buf[2 * QSC_KYBER_SYMBYTES];
    const uint8_t* publicseed = buf;
    const uint8_t* noiseseed = buf + QSC_KYBER_SYMBYTES;
    size_t i;
    uint8_t nonce;

    nonce = 0;
    rng_generate(buf, QSC_KYBER_SYMBYTES);
    qsc_sha3_compute512(buf, buf, QSC_KYBER_SYMBYTES);

    kyber_gen_matrix(a, publicseed, 0);

    for (i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_get_noise_eta1(&skpv.vec[i], noiseseed, nonce);
        ++nonce;
    }

    for (i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_get_noise_eta1(&e.vec[i], noiseseed, nonce);
        ++nonce;
    }

    kyber_polyvec_ntt(&skpv);
    kyber_polyvec_ntt(&e);

    for (i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        kyber_poly_to_mont(&pkpv.vec[i]);
    }

    kyber_polyvec_add(&pkpv, &pkpv, &e);
    kyber_polyvec_reduce(&pkpv);

    kyber_pack_sk(sk, &skpv);
    kyber_pack_pk(pk, &pkpv, publicseed);
}

static void kyber_indcpa_enc(uint8_t c[QSC_KYBER_INDCPA_BYTES], const uint8_t m[QSC_KYBER_MSGBYTES],
    const uint8_t pk[QSC_KYBER_INDCPA_PUBLICKEY_BYTES], const uint8_t coins[QSC_KYBER_SYMBYTES])
{
    qsc_kyber_polyvec sp;
    qsc_kyber_polyvec pkpv;
    qsc_kyber_polyvec ep;
    qsc_kyber_polyvec at[QSC_KYBER_K];
    qsc_kyber_polyvec b;
    qsc_kyber_poly v;
    qsc_kyber_poly k;
    qsc_kyber_poly epp;
    uint8_t seed[QSC_KYBER_SYMBYTES];
    size_t i;
    uint8_t nonce;

    nonce = 0;
    kyber_unpack_pk(&pkpv, seed, pk);
    kyber_poly_from_msg(&k, m);
    kyber_gen_matrix(at, seed, 1);

    for (i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_get_noise_eta1(sp.vec + i, coins, nonce);
        ++nonce;
    }

    for (i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_get_noise_eta2(ep.vec + i, coins, nonce);
        ++nonce;
    }

    kyber_poly_get_noise_eta2(&epp, coins, nonce);
    kyber_polyvec_ntt(&sp);

    for (i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
    }

    kyber_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);
    kyber_polyvec_invntt_to_mont(&b);
    kyber_poly_invntt_to_mont(&v);

    kyber_polyvec_add(&b, &b, &ep);
    kyber_poly_add(&v, &v, &epp);
    kyber_poly_add(&v, &v, &k);

    kyber_polyvec_reduce(&b);
    kyber_poly_reduce(&v);

    kyber_pack_ciphertext(c, &b, &v);
}

static void kyber_indcpa_dec(uint8_t m[QSC_KYBER_MSGBYTES], const uint8_t c[QSC_KYBER_INDCPA_BYTES], const uint8_t sk[QSC_KYBER_INDCPA_SECRETKEY_BYTES])
{
    qsc_kyber_polyvec b;
    qsc_kyber_polyvec skpv;
    qsc_kyber_poly v;
    qsc_kyber_poly mp;

    kyber_unpack_ciphertext(&b, &v, c);
    kyber_unpack_sk(&skpv, sk);
    kyber_polyvec_ntt(&b);
    kyber_polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
    kyber_poly_invntt_to_mont(&mp);
    kyber_poly_sub(&mp, &v, &mp);
    kyber_poly_reduce(&mp);
    kyber_poly_to_msg(m, &mp);
}

/* kem.c */

void qsc_kyber_ref_generate_keypair(uint8_t pk[QSC_KYBER_PUBLICKEY_BYTES], uint8_t sk[QSC_KYBER_SECRETKEY_BYTES], bool (*rng_generate)(uint8_t*, size_t))
{
    kyber_indcpa_keypair(pk, sk, rng_generate);
    qsc_memutils_copy((sk + QSC_KYBER_INDCPA_SECRETKEY_BYTES), pk, QSC_KYBER_INDCPA_PUBLICKEY_BYTES);

    qsc_sha3_compute256(sk + QSC_KYBER_SECRETKEY_BYTES - 2 * QSC_KYBER_SYMBYTES, pk, QSC_KYBER_PUBLICKEY_BYTES);
    /* Value z for pseudo-random output on reject */
    rng_generate(sk + QSC_KYBER_SECRETKEY_BYTES - QSC_KYBER_SYMBYTES, QSC_KYBER_SYMBYTES);
}

void qsc_kyber_ref_encapsulate(uint8_t ct[QSC_KYBER_CIPHERTEXT_BYTES], uint8_t ss[QSC_KYBER_MSGBYTES], const uint8_t pk[QSC_KYBER_PUBLICKEY_BYTES], bool (*rng_generate)(uint8_t*, size_t))
{
    uint8_t buf[2 * QSC_KYBER_SYMBYTES];
    uint8_t kr[2 * QSC_KYBER_SYMBYTES];

    rng_generate(buf, QSC_KYBER_SYMBYTES);
    /* Don't release system RNG output */
    qsc_sha3_compute256(buf, buf, QSC_KYBER_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    qsc_sha3_compute256(buf + QSC_KYBER_SYMBYTES, pk, QSC_KYBER_PUBLICKEY_BYTES);
    qsc_sha3_compute512(kr, buf, 2 * QSC_KYBER_SYMBYTES);

    /* coins are in kr+QSC_KYBER_SYMBYTES */
    kyber_indcpa_enc(ct, buf, pk, kr + QSC_KYBER_SYMBYTES);

    /* overwrite coins in kr with H(c) */
    qsc_sha3_compute256(kr + QSC_KYBER_SYMBYTES, ct, QSC_KYBER_CIPHERTEXT_BYTES);
    /* hash concatenation of pre-k and H(c) to k */
    qsc_shake256_compute(ss, QSC_KYBER_MSGBYTES, kr, 2 * QSC_KYBER_SYMBYTES);
}

bool qsc_kyber_ref_decapsulate(uint8_t ss[QSC_KYBER_MSGBYTES], const uint8_t ct[QSC_KYBER_CIPHERTEXT_BYTES], const uint8_t sk[QSC_KYBER_SECRETKEY_BYTES])
{
    uint8_t buf[2 * QSC_KYBER_SYMBYTES];
    uint8_t cmp[QSC_KYBER_CIPHERTEXT_BYTES];
    uint8_t kr[2 * QSC_KYBER_SYMBYTES];
    const uint8_t *pk = sk + QSC_KYBER_INDCPA_SECRETKEY_BYTES;
    int32_t fail;

    kyber_indcpa_dec(buf, ct, sk);

    /* Multitarget countermeasure for coins + contributory KEM */
    qsc_memutils_copy(((uint8_t*)buf + QSC_KYBER_SYMBYTES), (sk + QSC_KYBER_SECRETKEY_BYTES - (2 * QSC_KYBER_SYMBYTES)), QSC_KYBER_SYMBYTES);
    qsc_sha3_compute512(kr, buf, 2 * QSC_KYBER_SYMBYTES);

    /* coins are in kr+QSC_KYBER_SYMBYTES */
    kyber_indcpa_enc(cmp, buf, pk, kr + QSC_KYBER_SYMBYTES);

    fail = qsc_intutils_verify(ct, cmp, QSC_KYBER_CIPHERTEXT_BYTES);

    /* overwrite coins in kr with H(c) */
    qsc_sha3_compute256(kr + QSC_KYBER_SYMBYTES, ct, QSC_KYBER_CIPHERTEXT_BYTES);

    /* Overwrite pre-k with z on re-encryption failure */
    qsc_intutils_cmov(kr, sk + QSC_KYBER_SECRETKEY_BYTES - QSC_KYBER_SYMBYTES, QSC_KYBER_SYMBYTES, (uint8_t)fail);

    /* hash concatenation of pre-k and H(c) to k */
    qsc_shake256_compute(ss, QSC_KYBER_MSGBYTES, kr, 2 * QSC_KYBER_SYMBYTES);

    return (fail == 0);
}
