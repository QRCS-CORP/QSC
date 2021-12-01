#include "kyberbase_avx2.h"

#if defined(QSC_SYSTEM_HAS_AVX2)

#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

#define KYBER_ZETA_SIZE 128
#define KYBER_MONT 2285 /* 2^16 mod q */
#define KYBER_QINV 62209 /* q^-1 mod 2^16 */
#define KYBER_GEN_MATRIX_NBLOCKS ((12 * QSC_KYBER_N / 8 * (1 << 12) / QSC_KYBER_Q + QSC_KECCAK_128_RATE) / QSC_KECCAK_128_RATE)
#define QSC_AVX_REJ_UNIFORM_BUFLEN 504

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
	QSC_ALIGN(32) int16_t coeffs[QSC_KYBER_N];
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

    t = (int16_t)(((int32_t)V * a + (1 << 25)) >> 26);
    t *= QSC_KYBER_Q;

    return (a - t);
}

/* cbd.c */

static void kyber_cbd2_avx2(qsc_kyber_poly *r, const uint8_t buf[4 * QSC_KYBER_N / 8])
{
    __m256i f0;
    __m256i f1;
    __m256i f2;
    __m256i f3;
    const __m256i mask55 = _mm256_set1_epi32(0x55555555);
    const __m256i mask33 = _mm256_set1_epi32(0x33333333);
    const __m256i mask03 = _mm256_set1_epi32(0x03030303);
    const __m256i mask0F = _mm256_set1_epi32(0x0F0F0F0F);

    for (size_t i = 0; i < QSC_KYBER_N / 64; ++i) 
    {
        f0 = _mm256_load_si256((const __m256i*)&buf[32 * i]);

        f1 = _mm256_srli_epi16(f0, 1);
        f0 = _mm256_and_si256(mask55, f0);
        f1 = _mm256_and_si256(mask55, f1);
        f0 = _mm256_add_epi8(f0, f1);

        f1 = _mm256_srli_epi16(f0, 2);
        f0 = _mm256_and_si256(mask33, f0);
        f1 = _mm256_and_si256(mask33, f1);
        f0 = _mm256_add_epi8(f0, mask33);
        f0 = _mm256_sub_epi8(f0, f1);

        f1 = _mm256_srli_epi16(f0, 4);
        f0 = _mm256_and_si256(mask0F, f0);
        f1 = _mm256_and_si256(mask0F, f1);
        f0 = _mm256_sub_epi8(f0, mask03);
        f1 = _mm256_sub_epi8(f1, mask03);

        f2 = _mm256_unpacklo_epi8(f0, f1);
        f3 = _mm256_unpackhi_epi8(f0, f1);

        f0 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f2));
        f1 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f2, 1));
        f2 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f3));
        f3 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f3, 1));

        _mm256_store_si256((__m256i*)(uint8_t*)&r->coeffs[64 * i], f0);
        _mm256_store_si256((__m256i*)(uint8_t*)&r->coeffs[(64 * i) + 16], f2);
        _mm256_store_si256((__m256i*)(uint8_t*)&r->coeffs[(64 * i) + 32], f1);
        _mm256_store_si256((__m256i*)(uint8_t*)&r->coeffs[(64 * i) + 48], f3);
    }
}

/* kyber_ntt.c */

static int16_t kyber_fqmul(int16_t a, int16_t b)
{
    return kyber_montgomery_reduce((int32_t)a * b);
}

static void kyber_ntt_avx(int16_t r[QSC_KYBER_N])
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

static void kyber_invntt_avx(int16_t r[QSC_KYBER_N])
{
    size_t j;
    size_t k;
    int16_t t;
    int16_t zeta;
    const int16_t F = 1441;

    k = 127;

    for (size_t len = 2; len <= 128; len <<= 1)
    {
        for (size_t start = 0; start < 256; start = (j + len))
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
    kyber_cbd2_avx2(r, buf);
}

static void kyber_poly_cbd_eta2(qsc_kyber_poly* r, const uint8_t buf[QSC_KYBER_ETA * QSC_KYBER_N / 4])
{
    kyber_cbd2_avx2(r, buf);
}

#if (QSC_KYBER_POLYCOMPRESSED_BYTES == 128)

static void kyber_poly_compress_avx2(uint8_t r[128], const qsc_kyber_poly* restrict a)
{
    const __m256i v = _mm256_set1_epi16(20159);
    const __m256i shift1 = _mm256_set1_epi16(1 << 9);
    const __m256i mask = _mm256_set1_epi16(15);
    const __m256i shift2 = _mm256_set1_epi16((16 << 8) + 1);
    const __m256i permdidx = _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0);
    __m256i f0;
    __m256i f1;
    __m256i f2;
    __m256i f3;

    for (size_t i = 0; i < QSC_KYBER_N / 64; ++i) 
    {
        f0 = _mm256_load_si256((const __m256i*)&a->coeffs[64 * i]);
        f1 = _mm256_load_si256((const __m256i*)&a->coeffs[(64 * i) + 16]);
        f2 = _mm256_load_si256((const __m256i*)&a->coeffs[(64 * i) + 32]);
        f3 = _mm256_load_si256((const __m256i*)&a->coeffs[(64 * i) + 48]);
        f0 = _mm256_mulhi_epi16(f0, v);
        f1 = _mm256_mulhi_epi16(f1, v);
        f2 = _mm256_mulhi_epi16(f2, v);
        f3 = _mm256_mulhi_epi16(f3, v);
        f0 = _mm256_mulhrs_epi16(f0, shift1);
        f1 = _mm256_mulhrs_epi16(f1, shift1);
        f2 = _mm256_mulhrs_epi16(f2, shift1);
        f3 = _mm256_mulhrs_epi16(f3, shift1);
        f0 = _mm256_and_si256(f0, mask);
        f1 = _mm256_and_si256(f1, mask);
        f2 = _mm256_and_si256(f2, mask);
        f3 = _mm256_and_si256(f3, mask);
        f0 = _mm256_packus_epi16(f0, f1);
        f2 = _mm256_packus_epi16(f2, f3);
        f0 = _mm256_maddubs_epi16(f0, shift2);
        f2 = _mm256_maddubs_epi16(f2, shift2);
        f0 = _mm256_packus_epi16(f0, f2);
        f0 = _mm256_permutevar8x32_epi32(f0, permdidx);
        _mm256_storeu_si256((__m256i*)&r[32 * i], f0);
    }
}

static void kyber_poly_decompress_avx2(qsc_kyber_poly* restrict r, const uint8_t* a)
{
    const __m256i q = _mm256_set1_epi16(3329);
    const __m256i shufbidx = _mm256_set_epi8(7, 7, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4,
        3, 3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0);
    const __m256i mask = _mm256_set1_epi32(0x00F0000F);
    const __m256i shift = _mm256_set1_epi32((128 << 16) + 2048);
    __m256i f;

    for (size_t i = 0; i < QSC_KYBER_N / 16; ++i) 
    {
        f = _mm256_broadcastq_epi64(_mm_loadl_epi64((const __m128i*)&a[8 * i]));
        f = _mm256_shuffle_epi8(f, shufbidx);
        f = _mm256_and_si256(f, mask);
        f = _mm256_mullo_epi16(f, shift);
        f = _mm256_mulhrs_epi16(f, q);
        _mm256_store_si256((__m256i*)&r->coeffs[16 * i], f);
    }
}

#elif (QSC_KYBER_POLYCOMPRESSED_BYTES == 160)

static void kyber_poly_compress_avx2(uint8_t* r, const qsc_kyber_poly* restrict a)
{
    const __m256i v = _mm256_set1_epi16(20159);
    const __m256i shift1 = _mm256_set1_epi16(1 << 10);
    const __m256i mask = _mm256_set1_epi16(31);
    const __m256i shift2 = _mm256_set1_epi16((32 << 8) + 1);
    const __m256i shift3 = _mm256_set1_epi32((1024 << 16) + 1);
    const __m256i sllvdidx = _mm256_set1_epi64x(12);
    const __m256i shufbidx = _mm256_set_epi8(8, -1, -1, -1, -1, -1, 4, 3, 2, 1, 0, -1, 12, 11, 10, 9,
        -1, 12, 11, 10, 9, 8, -1, -1, -1, -1, -1, 4, 3, 2, 1, 0);
    __m256i f0;
    __m256i f1;
    __m128i t0;
    __m128i t1;

    for (size_t i = 0; i < QSC_KYBER_N / 32; ++i) 
    {
        f0 = _mm256_load_si256((const __m256i*)&a->coeffs[32 * i]);
        f1 = _mm256_load_si256((const __m256i*)&a->coeffs[(32 * i) + 16]);
        f0 = _mm256_mulhi_epi16(f0, v);
        f1 = _mm256_mulhi_epi16(f1, v);
        f0 = _mm256_mulhrs_epi16(f0, shift1);
        f1 = _mm256_mulhrs_epi16(f1, shift1);
        f0 = _mm256_and_si256(f0, mask);
        f1 = _mm256_and_si256(f1, mask);
        f0 = _mm256_packus_epi16(f0, f1);
        f0 = _mm256_maddubs_epi16(f0, shift2);
        f0 = _mm256_madd_epi16(f0, shift3);
        f0 = _mm256_sllv_epi32(f0, sllvdidx);
        f0 = _mm256_srlv_epi64(f0, sllvdidx);
        f0 = _mm256_shuffle_epi8(f0, shufbidx);
        t0 = _mm256_castsi256_si128(f0);
        t1 = _mm256_extracti128_si256(f0, 1);
        t0 = _mm_blendv_epi8(t0, t1, _mm256_castsi256_si128(shufbidx));
        _mm_storeu_si128((__m128i*)&r[20 * i], t0);
        _mm_store_ss((float*)&r[(20 * i) + 16], _mm_castsi128_ps(t1));
    }
}

static void kyber_poly_decompress_avx2(qsc_kyber_poly* restrict r, const uint8_t* a)
{
    const __m256i q = _mm256_set1_epi16(3329);
    const __m256i shufbidx = _mm256_set_epi8(9, 9, 9, 8, 8, 8, 8, 7, 7, 6, 6, 6, 6, 5, 5, 5,
        4, 4, 4, 3, 3, 3, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0);
    const __m256i mask = _mm256_set_epi16(248, 1984, 62, 496, 3968, 124, 992, 31,
        248, 1984, 62, 496, 3968, 124, 992, 31);
    const __m256i shift = _mm256_set_epi16(128, 16, 512, 64, 8, 256, 32, 1024,
        128, 16, 512, 64, 8, 256, 32, 1024);
    __m256i f;

    for (size_t i = 0; i < QSC_KYBER_N / 16; ++i) 
    {
        f = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)&a[10 * i]));
        f = _mm256_shuffle_epi8(f, shufbidx);
        f = _mm256_and_si256(f, mask);
        f = _mm256_mullo_epi16(f, shift);
        f = _mm256_mulhrs_epi16(f, q);
        _mm256_store_si256((__m256i*)&r->coeffs[16 * i], f);
    }
}

#endif

static void kyber_poly_to_bytes(uint8_t r[QSC_KYBER_POLYBYTES], const qsc_kyber_poly* a)
{
    uint16_t t0;
    uint16_t t1;

    for (size_t i = 0; i < QSC_KYBER_N / 2; ++i)
    {
        /* map to positive standard representatives */
        t0 = a->coeffs[2 * i];
        t0 += (((int16_t)t0 >> 15) & QSC_KYBER_Q);
        t1 = a->coeffs[(2 * i) + 1];
        t1 += (((int16_t)t1 >> 15) & QSC_KYBER_Q);
        r[3 * i] = (uint8_t)t0;
        r[(3 * i) + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[(3 * i) + 2] = (uint8_t)(t1 >> 4);
    }
}

static void kyber_poly_from_bytes(qsc_kyber_poly* r, const uint8_t a[QSC_KYBER_POLYBYTES])
{
    for (size_t i = 0; i < QSC_KYBER_N / 2; ++i)
    {
        r->coeffs[2 * i] = (((uint16_t)a[3 * i] | ((uint16_t)a[(3 * i) + 1] << 8)) & 0x0FFF);
        r->coeffs[(2 * i) + 1] = ((((uint16_t)a[(3 * i) + 1] >> 4) | ((uint16_t)a[(3 * i) + 2] << 4)) & 0x0FFF);
    }
}

static void kyber_poly_from_msg_avx2(qsc_kyber_poly* restrict r, const uint8_t msg[QSC_KYBER_SYMBYTES])
{
    const __m256i shift = _mm256_broadcastsi128_si256(_mm_set_epi32(0, 1, 2, 3));
    const __m256i idx = _mm256_broadcastsi128_si256(_mm_set_epi8(15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9, 8, 5, 4, 1, 0));
    const __m256i hqs = _mm256_set1_epi16((QSC_KYBER_Q + 1) / 2);
    __m256i f;
    __m256i g0;
    __m256i g1;
    __m256i g2;
    __m256i g3;
    __m256i h0;
    __m256i h1;
    __m256i h2;
    __m256i h3;

    f = _mm256_load_si256((const __m256i*)msg);
    g3 = _mm256_shuffle_epi32(f, 0);
    g3 = _mm256_sllv_epi32(g3, shift);
    g3 = _mm256_shuffle_epi8(g3, idx);
    g0 = _mm256_slli_epi16(g3, 12);
    g1 = _mm256_slli_epi16(g3, 8);
    g2 = _mm256_slli_epi16(g3, 4);
    g0 = _mm256_srai_epi16(g0, 15);
    g1 = _mm256_srai_epi16(g1, 15);
    g2 = _mm256_srai_epi16(g2, 15);
    g3 = _mm256_srai_epi16(g3, 15);
    g0 = _mm256_and_si256(g0, hqs);  /* 19 18 17 16  3  2  1  0 */
    g1 = _mm256_and_si256(g1, hqs);  /* 23 22 21 20  7  6  5  4 */
    g2 = _mm256_and_si256(g2, hqs);  /* 27 26 25 24 11 10  9  8 */
    g3 = _mm256_and_si256(g3, hqs);  /* 31 30 29 28 15 14 13 12 */
    h0 = _mm256_unpacklo_epi64(g0, g1);
    h2 = _mm256_unpackhi_epi64(g0, g1);
    h1 = _mm256_unpacklo_epi64(g2, g3);
    h3 = _mm256_unpackhi_epi64(g2, g3);
    g0 = _mm256_permute2x128_si256(h0, h1, 0x20);
    g2 = _mm256_permute2x128_si256(h0, h1, 0x31);
    g1 = _mm256_permute2x128_si256(h2, h3, 0x20);
    g3 = _mm256_permute2x128_si256(h2, h3, 0x31);
    _mm256_store_si256((__m256i*)&r->coeffs[0], g0);
    _mm256_store_si256((__m256i*)&r->coeffs[16], g1);
    _mm256_store_si256((__m256i*)&r->coeffs[128], g2);
    _mm256_store_si256((__m256i*)&r->coeffs[128 + 16], g3);

    g3 = _mm256_shuffle_epi32(f, 0x55 * 1);
    g3 = _mm256_sllv_epi32(g3, shift);
    g3 = _mm256_shuffle_epi8(g3, idx);
    g0 = _mm256_slli_epi16(g3, 12);
    g1 = _mm256_slli_epi16(g3, 8);
    g2 = _mm256_slli_epi16(g3, 4);
    g0 = _mm256_srai_epi16(g0, 15);
    g1 = _mm256_srai_epi16(g1, 15);
    g2 = _mm256_srai_epi16(g2, 15);
    g3 = _mm256_srai_epi16(g3, 15);
    g0 = _mm256_and_si256(g0, hqs);
    g1 = _mm256_and_si256(g1, hqs);
    g2 = _mm256_and_si256(g2, hqs);
    g3 = _mm256_and_si256(g3, hqs);
    h0 = _mm256_unpacklo_epi64(g0, g1);
    h2 = _mm256_unpackhi_epi64(g0, g1);
    h1 = _mm256_unpacklo_epi64(g2, g3);
    h3 = _mm256_unpackhi_epi64(g2, g3);
    g0 = _mm256_permute2x128_si256(h0, h1, 0x20);
    g2 = _mm256_permute2x128_si256(h0, h1, 0x31);
    g1 = _mm256_permute2x128_si256(h2, h3, 0x20);
    g3 = _mm256_permute2x128_si256(h2, h3, 0x31);
    _mm256_store_si256((__m256i*)&r->coeffs[32], g0);
    _mm256_store_si256((__m256i*)&r->coeffs[32 + 16], g1);
    _mm256_store_si256((__m256i*)&r->coeffs[128 + 32], g2);
    _mm256_store_si256((__m256i*)&r->coeffs[128 + 32 + 16], g3);

    g3 = _mm256_shuffle_epi32(f, 0x55 * 2);
    g3 = _mm256_sllv_epi32(g3, shift);
    g3 = _mm256_shuffle_epi8(g3, idx);
    g0 = _mm256_slli_epi16(g3, 12);
    g1 = _mm256_slli_epi16(g3, 8);
    g2 = _mm256_slli_epi16(g3, 4);
    g0 = _mm256_srai_epi16(g0, 15);
    g1 = _mm256_srai_epi16(g1, 15);
    g2 = _mm256_srai_epi16(g2, 15);
    g3 = _mm256_srai_epi16(g3, 15);
    g0 = _mm256_and_si256(g0, hqs);
    g1 = _mm256_and_si256(g1, hqs);
    g2 = _mm256_and_si256(g2, hqs);
    g3 = _mm256_and_si256(g3, hqs);
    h0 = _mm256_unpacklo_epi64(g0, g1);
    h2 = _mm256_unpackhi_epi64(g0, g1);
    h1 = _mm256_unpacklo_epi64(g2, g3);
    h3 = _mm256_unpackhi_epi64(g2, g3);
    g0 = _mm256_permute2x128_si256(h0, h1, 0x20);
    g2 = _mm256_permute2x128_si256(h0, h1, 0x31);
    g1 = _mm256_permute2x128_si256(h2, h3, 0x20);
    g3 = _mm256_permute2x128_si256(h2, h3, 0x31);
    _mm256_store_si256((__m256i*)&r->coeffs[32 * 2], g0);
    _mm256_store_si256((__m256i*)&r->coeffs[(32 * 2) + 16], g1);
    _mm256_store_si256((__m256i*)&r->coeffs[128 + (32 * 2)], g2);
    _mm256_store_si256((__m256i*)&r->coeffs[128 + (32 * 2) + 16], g3);

    g3 = _mm256_shuffle_epi32(f, 0x55 * 3);
    g3 = _mm256_sllv_epi32(g3, shift);
    g3 = _mm256_shuffle_epi8(g3, idx);
    g0 = _mm256_slli_epi16(g3, 12);
    g1 = _mm256_slli_epi16(g3, 8);
    g2 = _mm256_slli_epi16(g3, 4);
    g0 = _mm256_srai_epi16(g0, 15);
    g1 = _mm256_srai_epi16(g1, 15);
    g2 = _mm256_srai_epi16(g2, 15);
    g3 = _mm256_srai_epi16(g3, 15);
    g0 = _mm256_and_si256(g0, hqs);
    g1 = _mm256_and_si256(g1, hqs);
    g2 = _mm256_and_si256(g2, hqs);
    g3 = _mm256_and_si256(g3, hqs);
    h0 = _mm256_unpacklo_epi64(g0, g1);
    h2 = _mm256_unpackhi_epi64(g0, g1);
    h1 = _mm256_unpacklo_epi64(g2, g3);
    h3 = _mm256_unpackhi_epi64(g2, g3);
    g0 = _mm256_permute2x128_si256(h0, h1, 0x20);
    g2 = _mm256_permute2x128_si256(h0, h1, 0x31);
    g1 = _mm256_permute2x128_si256(h2, h3, 0x20);
    g3 = _mm256_permute2x128_si256(h2, h3, 0x31);

    _mm256_store_si256((__m256i*)&r->coeffs[32 * 3], g0);
    _mm256_store_si256((__m256i*)&r->coeffs[(32 * 3) + 16], g1);
    _mm256_store_si256((__m256i*)&r->coeffs[128 + (32 * 3)], g2);
    _mm256_store_si256((__m256i*)&r->coeffs[128 + (32 * 3) + 16], g3);
}

#if defined(KYBER_HISTORICAL_ENABLE)

static void kyber_poly_compress11_avx2(uint8_t r[352 + 2], const qsc_kyber_poly* restrict a)
{
    // Note: not working
    const __m256i v = _mm256_set1_epi16(20159);
    const __m256i v8 = _mm256_slli_epi16(v, 3);
    const __m256i off = _mm256_set1_epi16(36);
    const __m256i shift1 = _mm256_set1_epi16(1 << 13);
    const __m256i mask = _mm256_set1_epi16(2047);
    const __m256i shift2 = _mm256_set1_epi64x((2048LL << 48) + (1LL << 32) + (2048 << 16) + 1);
    const __m256i sllvdidx = _mm256_set1_epi64x(10);
    const __m256i srlvqidx = _mm256_set_epi64x(30, 10, 30, 10);
    const __m256i shufbidx = _mm256_set_epi8(4, 3, 2, 1, 0, 0, -1, -1, -1, -1, 10, 9, 8, 7, 6, 5,
        -1, -1, -1, -1, -1, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    __m256i f0;
    __m256i f1;
    __m256i f2;
    __m128i t0;
    __m128i t1;

    for (size_t i = 0; i < QSC_KYBER_N / 16; ++i)
    {
        f0 = _mm256_load_si256((const __m256i*)&a->coeffs[16 * i]);
        f1 = _mm256_mullo_epi16(f0, v8);
        f2 = _mm256_add_epi16(f0, off);
        f0 = _mm256_slli_epi16(f0, 3);
        f0 = _mm256_mulhi_epi16(f0, v);
        f2 = _mm256_sub_epi16(f1, f2);
        f1 = _mm256_andnot_si256(f1, f2);
        f1 = _mm256_srli_epi16(f1, 15);
        f0 = _mm256_sub_epi16(f0, f1);
        f0 = _mm256_mulhrs_epi16(f0, shift1);
        f0 = _mm256_and_si256(f0, mask);
        f0 = _mm256_madd_epi16(f0, shift2);
        f0 = _mm256_sllv_epi32(f0, sllvdidx);
        f1 = _mm256_bsrli_epi128(f0, 8);
        f0 = _mm256_srlv_epi64(f0, srlvqidx);
        f1 = _mm256_slli_epi64(f1, 34);
        f0 = _mm256_add_epi64(f0, f1);
        f0 = _mm256_shuffle_epi8(f0, shufbidx);
        t0 = _mm256_castsi256_si128(f0);
        t1 = _mm256_extracti128_si256(f0, 1);
        t0 = _mm_blendv_epi8(t0, t1, _mm256_castsi256_si128(shufbidx));
        _mm_storeu_si128((__m128i*)&r[22 * i], t0);
        _mm_storel_epi64((__m128i*)&r[22 * i + 16], t1);
    }
}

static void kyber_poly_to_msg_avx2(uint8_t msg[QSC_KYBER_SYMBYTES], const qsc_kyber_poly* restrict a) // not workingin VS
{
    /* Note artifact, no longer used */
    __m256i f0;
    __m256i f1;
    __m256i g0;
    __m256i g1;
    const __m256i hqs = _mm256_set1_epi16((QSC_KYBER_Q - 1) / 2);
    const __m256i hhqs = _mm256_set1_epi16((QSC_KYBER_Q - 5) / 4);
    uint32_t small;

    for (size_t i = 0; i < QSC_KYBER_N / 32; ++i)
    {
        f0 = _mm256_load_si256((const __m256i*)&a->coeffs[32 * i]);
        f1 = _mm256_load_si256((const __m256i*)&a->coeffs[(32 * i) + 16]);
        f0 = _mm256_sub_epi16(hqs, f0);
        f1 = _mm256_sub_epi16(hqs, f1);
        g0 = _mm256_srai_epi16(f0, 15);
        g1 = _mm256_srai_epi16(f1, 15);
        f0 = _mm256_xor_si256(f0, g0);
        f1 = _mm256_xor_si256(f1, g1);
        f0 = _mm256_sub_epi16(hhqs, f0);
        f1 = _mm256_sub_epi16(hhqs, f1);
        f0 = _mm256_packs_epi16(f0, f1);
        small = _mm256_movemask_epi8(f0);
        small = ~small;
        msg[4 * i] = (uint8_t)small;
        msg[(4 * i) + 1] = (uint8_t)(small >> 16);
        msg[(4 * i) + 2] = (uint8_t)(small >> 8);
        msg[(4 * i) + 3] = (uint8_t)(small >> 24);
    }
}


static void kyber_poly_from_msg(qsc_kyber_poly* r, const uint8_t msg[QSC_KYBER_SYMBYTES])
{
    /* Note artifact, no longer used */
    int16_t mask;

    for (size_t i = 0; i < QSC_KYBER_N / 8; ++i)
    {
        for (size_t j = 0; j < 8; ++j)
        {
            mask = -(int16_t)((msg[i] >> j) & 1);
            r->coeffs[(8 * i) + j] = mask & (int16_t)((QSC_KYBER_Q + 1) / 2);
        }
    }
}

static void kyber_poly_add(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b)
{
    /* Note artifact, no longer used */
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

static void kyber_polyvec_compress_avx2(uint8_t r[QSC_KYBER_POLYVEC_COMPRESSED_BYTES + 2], const qsc_kyber_polyvec* restrict a)
{
    /* Note artifact, no longer used */
#if (QSC_KYBER_POLYVEC_COMPRESSED_BYTES == (QSC_KYBER_K * 320))
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_compress10_avx2(&r[320 * i], &a->vec[i]);
    }
#elif (QSC_KYBER_POLYVEC_COMPRESSED_BYTES == (QSC_KYBER_K * 352))
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_compress11_avx2(&r[352 * i], &a->vec[i]);
    }
#endif
}

static void kyber_polyvec_decompress(qsc_kyber_polyvec* r, const uint8_t a[QSC_KYBER_POLYVEC_COMPRESSED_BYTES])
{
    /* Note artifact, no longer used */
#if (QSC_KYBER_K == 4 || QSC_KYBER_K == 5)

    uint16_t t[8];

    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        for (size_t j = 0; j < QSC_KYBER_N / 8; ++j)
        {
            t[0] = (uint16_t)(a[0] | (uint16_t)((uint16_t)a[1] << 8));
            t[1] = (uint16_t)((a[1] >> 3) | (uint16_t)(a[2] << 5));
            t[2] = (uint16_t)((a[2] >> 6) | (uint16_t)(a[3] << 2) | (uint16_t)(a[4] << 10));
            t[3] = (uint16_t)((a[4] >> 1) | (uint16_t)(a[5] << 7));
            t[4] = (uint16_t)((a[5] >> 4) | (uint16_t)(a[6] << 4));
            t[5] = (uint16_t)((a[6] >> 7) | (uint16_t)(a[7] << 1) | (uint16_t)(a[8] << 9));
            t[6] = (uint16_t)((a[8] >> 2) | (uint16_t)(a[9] << 6));
            t[7] = (uint16_t)((a[9] >> 5) | (uint16_t)(a[10] << 3));
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
            t[0] = (uint16_t)a[0] | (uint16_t)((uint16_t)a[1] << 8);
            t[1] = (uint16_t)(a[1] >> 2) | (uint16_t)(a[2] << 6);
            t[2] = (uint16_t)(a[2] >> 4) | (uint16_t)(a[3] << 4);
            t[3] = (uint16_t)(a[3] >> 6) | (uint16_t)(a[4] << 2);
            a += 5;

            for (size_t k = 0; k < 4; ++k)
            {
                r->vec[i].coeffs[(4 * j) + k] = (int16_t)(((uint32_t)(t[k] & 0x3FF) * QSC_KYBER_Q + 512) >> 10);
            }
        }
    }

#endif
}

#endif

static void kyber_poly_to_msg(uint8_t msg[QSC_KYBER_SYMBYTES], const qsc_kyber_poly* a)
{
    uint16_t t;

    for (size_t i = 0; i < QSC_KYBER_N / 8; ++i)
    {
        msg[i] = 0;

        for (size_t j = 0; j < 8; ++j)
        {
            t = (uint16_t)a->coeffs[(8 * i) + j];
            t += (uint16_t)(((int16_t)t >> 15) & QSC_KYBER_Q);
            t = (uint16_t)((((t << 1) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 1);
            msg[i] |= (uint8_t)(t << j);
        }
    }
}

static void kyber_poly_get_noise_eta1(qsc_kyber_poly* r, const uint8_t seed[QSC_KYBER_SYMBYTES], uint8_t nonce)
{
    QSC_ALIGN(32) uint8_t buf[QSC_KYBER_ETA * QSC_KYBER_N / 4];
    uint8_t extkey[QSC_KYBER_SYMBYTES + 1];

    qsc_memutils_copy(extkey, seed, QSC_KYBER_SYMBYTES);
    extkey[QSC_KYBER_SYMBYTES] = nonce;
    qsc_shake256_compute(buf, sizeof(buf), extkey, sizeof(extkey));

    kyber_poly_cbd_eta1(r, buf);
}

static void kyber_poly_get_noise_eta2(qsc_kyber_poly* r, const uint8_t seed[QSC_KYBER_SYMBYTES], uint8_t nonce)
{
    QSC_ALIGN(32)uint8_t buf[QSC_KYBER_ETA * QSC_KYBER_N / 4];
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
    kyber_ntt_avx(r->coeffs);
    kyber_poly_reduce(r);
}

static void kyber_poly_invntt_to_mont(qsc_kyber_poly* r)
{
    kyber_invntt_avx(r->coeffs);
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
#if defined(QSC_GCC_ASM_ENABLED)
    kyber_tomont_avx(r->coeffs, kyber_qdata);
#else
    const int16_t F = (1ULL << 32) % QSC_KYBER_Q;

    for (size_t i = 0; i < QSC_KYBER_N; ++i)
    {
        r->coeffs[i] = kyber_montgomery_reduce((int32_t)r->coeffs[i] * F);
    }
#endif
}

static void kyber_poly_add_avx2(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b)
{
    __m256i f0;
    __m256i f1;

    for (size_t i = 0; i < QSC_KYBER_N; i += 16)
    {
        f0 = _mm256_load_si256((const __m256i*)&a->coeffs[i]);
        f1 = _mm256_load_si256((const __m256i*)&b->coeffs[i]);
        f0 = _mm256_add_epi16(f0, f1);

        _mm256_store_si256((__m256i*)&r->coeffs[i], f0);
    }
}

static void kyber_poly_sub_avx2(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b)
{
    __m256i f0;
    __m256i f1;

    for (size_t i = 0; i < QSC_KYBER_N; i += 16)
    {
        f0 = _mm256_load_si256((const __m256i*)&a->coeffs[i]);
        f1 = _mm256_load_si256((const __m256i*)&b->coeffs[i]);
        f0 = _mm256_sub_epi16(f0, f1);
        _mm256_store_si256((__m256i*)&r->coeffs[i], f0);
    }
}

/* polyvec.c */

#if (QSC_KYBER_POLYVEC_COMPRESSED_BYTES == (QSC_KYBER_K * 320))
static void kyber_poly_compress10_avx2(uint8_t r[320], const qsc_kyber_poly* restrict a)
{
    // Note: not working
    const __m256i v = _mm256_set1_epi16(20159);
    const __m256i v8 = _mm256_slli_epi16(v, 3);
    const __m256i off = _mm256_set1_epi16(15);
    const __m256i shift1 = _mm256_set1_epi16(1 << 12);
    const __m256i mask = _mm256_set1_epi16(1023);
    const __m256i shift2 = _mm256_set1_epi64x((1024LL << 48) + (1LL << 32) + (1024 << 16) + 1);
    const __m256i sllvdidx = _mm256_set1_epi64x(12);
    const __m256i shufbidx = _mm256_set_epi8(8, 4, 3, 2, 1, 0, -1, -1, -1, -1, -1, -1, 12, 11, 10, 9,
        -1, -1, -1, -1, -1, -1, 12, 11, 10, 9, 8, 4, 3, 2, 1, 0);
    __m256i f0;
    __m256i f1;
    __m256i f2;
    __m128i t0;
    __m128i t1;

    for (size_t i = 0; i < QSC_KYBER_N / 16; ++i)
    {
        f0 = _mm256_load_si256((const __m256i*)&a->coeffs[i * 16]);
        f1 = _mm256_mullo_epi16(f0, v8);
        f2 = _mm256_add_epi16(f0, off);
        f0 = _mm256_slli_epi16(f0, 3);
        f0 = _mm256_mulhi_epi16(f0, v);
        f2 = _mm256_sub_epi16(f1, f2);
        f1 = _mm256_andnot_si256(f1, f2);
        f1 = _mm256_srli_epi16(f1, 15);
        f0 = _mm256_sub_epi16(f0, f1);
        f0 = _mm256_mulhrs_epi16(f0, shift1);
        f0 = _mm256_and_si256(f0, mask);
        f0 = _mm256_madd_epi16(f0, shift2);
        f0 = _mm256_sllv_epi32(f0, sllvdidx);
        f0 = _mm256_srli_epi64(f0, 12);
        f0 = _mm256_shuffle_epi8(f0, shufbidx);
        t0 = _mm256_castsi256_si128(f0);
        t1 = _mm256_extracti128_si256(f0, 1);
        t0 = _mm_blend_epi16(t0, t1, 0xE0);
        _mm_storeu_si128((__m128i*)&r[20 * i], t0);
        qsc_memutils_copy(&r[20 * i + 16], &t1, 4);
    }
}

static void kyber_poly_decompress10_avx2(qsc_kyber_poly* restrict r, const uint8_t a[320 + 12])
{
    const __m256i q = _mm256_set1_epi32((QSC_KYBER_Q << 16) + 4 * QSC_KYBER_Q);
    const __m256i shufbidx = _mm256_set_epi8(11, 10, 10, 9, 9, 8, 8, 7,
        6, 5, 5, 4, 4, 3, 3, 2, 9, 8, 8, 7, 7, 6, 6, 5, 4, 3, 3, 2, 2, 1, 1, 0);
    const __m256i sllvdidx = _mm256_set1_epi64x(4);
    const __m256i mask = _mm256_set1_epi32((32736 << 16) + 8184);
    __m256i f;

    for (size_t i = 0; i < QSC_KYBER_N / 16; ++i)
    {
        f = _mm256_loadu_si256((const __m256i*)&a[20 * i]);
        f = _mm256_permute4x64_epi64(f, 0x94);
        f = _mm256_shuffle_epi8(f, shufbidx);
        f = _mm256_sllv_epi32(f, sllvdidx);
        f = _mm256_srli_epi16(f, 1);
        f = _mm256_and_si256(f, mask);
        f = _mm256_mulhrs_epi16(f, q);
        _mm256_store_si256((__m256i*)&r->coeffs[16 * i], f);
    }
}

#elif (QSC_KYBER_POLYVEC_COMPRESSED_BYTES == (QSC_KYBER_K * 352))

static void kyber_poly_decompress11_avx2(qsc_kyber_poly* restrict r, const uint8_t a[352 + 10])
{
    const __m256i q = _mm256_set1_epi16(3329);
    const __m256i shufbidx = _mm256_set_epi8(13, 12, 12, 11, 10, 9, 9, 8,
        8, 7, 6, 5, 5, 4, 4, 3, 10, 9, 9, 8, 7, 6, 6, 5, 5, 4, 3, 2, 2, 1, 1, 0);
    const __m256i srlvdidx = _mm256_set_epi32(0, 0, 1, 0, 0, 0, 1, 0);
    const __m256i srlvqidx = _mm256_set_epi64x(2, 0, 2, 0);
    const __m256i shift = _mm256_set_epi16(4, 32, 1, 8, 32, 1, 4, 32, 4, 32, 1, 8, 32, 1, 4, 32);
    const __m256i mask = _mm256_set1_epi16(32752);
    __m256i f;

    for (size_t i = 0; i < QSC_KYBER_N / 16; ++i)
    {
        f = _mm256_loadu_si256((__m256i*)&a[22 * i]);
        f = _mm256_permute4x64_epi64(f, 0x94);
        f = _mm256_shuffle_epi8(f, shufbidx);
        f = _mm256_srlv_epi32(f, srlvdidx);
        f = _mm256_srlv_epi64(f, srlvqidx);
        f = _mm256_mullo_epi16(f, shift);
        f = _mm256_srli_epi16(f, 1);
        f = _mm256_and_si256(f, mask);
        f = _mm256_mulhrs_epi16(f, q);
        _mm256_store_si256((__m256i*)&r->coeffs[16 * i], f);
    }
}

#endif

static void kyber_polyvec_decompress_avx2(qsc_kyber_polyvec* restrict r, const uint8_t a[QSC_KYBER_POLYVEC_COMPRESSED_BYTES + 12])
{
#if (QSC_KYBER_POLYVEC_COMPRESSED_BYTES == (QSC_KYBER_K * 320))
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_decompress10_avx2(&r->vec[i], &a[320 * i]);
    }
#elif (QSC_KYBER_POLYVEC_COMPRESSED_BYTES == (QSC_KYBER_K * 352))
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_decompress11_avx2(&r->vec[i], &a[352 * i]);
    }
#endif
}

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

            r[0] = (uint8_t)t[0];
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
                t[k] = a->vec[i].coeffs[(4 * j) + k];
                t[k] += ((int16_t)t[k] >> 15) & QSC_KYBER_Q;
                t[k] = ((((uint32_t)t[k] << 10) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 0x3FF;
            }

            r[0] = (uint8_t)t[0];
            r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[4] = (uint8_t)(t[3] >> 2);
            r += 5;
        }
    }
#endif
}

static void kyber_polyvec_to_bytes(uint8_t r[QSC_KYBER_POLYVEC_BYTES], const qsc_kyber_polyvec* a)
{
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_to_bytes((r + (i * QSC_KYBER_POLYBYTES)), &a->vec[i]);
    }
}

static void kyber_polyvec_from_bytes(qsc_kyber_polyvec* r, const uint8_t a[QSC_KYBER_POLYVEC_BYTES])
{
    for (size_t i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_from_bytes(&r->vec[i], (a + (i * QSC_KYBER_POLYBYTES)));
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
        kyber_poly_add_avx2(r, r, &t);
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
        kyber_poly_add_avx2(&r->vec[i], &a->vec[i], &b->vec[i]);
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
    kyber_poly_compress_avx2((r + QSC_KYBER_POLYVEC_COMPRESSED_BYTES), v);
}

static void kyber_unpack_ciphertext(qsc_kyber_polyvec* b, qsc_kyber_poly* v, const uint8_t c[QSC_KYBER_INDCPA_BYTES])
{
    kyber_polyvec_decompress_avx2(b, c);
    kyber_poly_decompress_avx2(v, (c + QSC_KYBER_POLYVEC_COMPRESSED_BYTES));
}

static const int8_t kyber_rej_idx[256][8] =
{
    { -1, -1, -1, -1, -1, -1, -1, -1 }, { 0, -1, -1, -1, -1, -1, -1, -1 },
    { 2, -1, -1, -1, -1, -1, -1, -1 }, { 0,  2, -1, -1, -1, -1, -1, -1 },
    { 4, -1, -1, -1, -1, -1, -1, -1 }, { 0,  4, -1, -1, -1, -1, -1, -1 },
    { 2,  4, -1, -1, -1, -1, -1, -1 }, { 0,  2,  4, -1, -1, -1, -1, -1 },
    { 6, -1, -1, -1, -1, -1, -1, -1 }, { 0,  6, -1, -1, -1, -1, -1, -1 },
    { 2,  6, -1, -1, -1, -1, -1, -1 }, { 0,  2,  6, -1, -1, -1, -1, -1 },
    { 4,  6, -1, -1, -1, -1, -1, -1 }, { 0,  4,  6, -1, -1, -1, -1, -1 },
    { 2,  4,  6, -1, -1, -1, -1, -1 }, { 0,  2,  4,  6, -1, -1, -1, -1 },
    { 8, -1, -1, -1, -1, -1, -1, -1 }, { 0,  8, -1, -1, -1, -1, -1, -1 },
    { 2,  8, -1, -1, -1, -1, -1, -1 }, { 0,  2,  8, -1, -1, -1, -1, -1 },
    { 4,  8, -1, -1, -1, -1, -1, -1 }, { 0,  4,  8, -1, -1, -1, -1, -1 },
    { 2,  4,  8, -1, -1, -1, -1, -1 }, { 0,  2,  4,  8, -1, -1, -1, -1 },
    { 6,  8, -1, -1, -1, -1, -1, -1 }, { 0,  6,  8, -1, -1, -1, -1, -1 },
    { 2,  6,  8, -1, -1, -1, -1, -1 }, { 0,  2,  6,  8, -1, -1, -1, -1 },
    { 4,  6,  8, -1, -1, -1, -1, -1 }, { 0,  4,  6,  8, -1, -1, -1, -1 },
    { 2,  4,  6,  8, -1, -1, -1, -1 }, { 0,  2,  4,  6,  8, -1, -1, -1 },
    { 10, -1, -1, -1, -1, -1, -1, -1 },{ 0, 10, -1, -1, -1, -1, -1, -1 },
    { 2, 10, -1, -1, -1, -1, -1, -1 }, { 0,  2, 10, -1, -1, -1, -1, -1 },
    { 4, 10, -1, -1, -1, -1, -1, -1 }, { 0,  4, 10, -1, -1, -1, -1, -1 },
    { 2,  4, 10, -1, -1, -1, -1, -1 }, { 0,  2,  4, 10, -1, -1, -1, -1 },
    { 6, 10, -1, -1, -1, -1, -1, -1 }, { 0,  6, 10, -1, -1, -1, -1, -1 },
    { 2,  6, 10, -1, -1, -1, -1, -1 }, { 0,  2,  6, 10, -1, -1, -1, -1 },
    { 4,  6, 10, -1, -1, -1, -1, -1 }, { 0,  4,  6, 10, -1, -1, -1, -1 },
    { 2,  4,  6, 10, -1, -1, -1, -1 }, { 0,  2,  4,  6, 10, -1, -1, -1 },
    { 8, 10, -1, -1, -1, -1, -1, -1 }, { 0,  8, 10, -1, -1, -1, -1, -1 },
    { 2,  8, 10, -1, -1, -1, -1, -1 }, { 0,  2,  8, 10, -1, -1, -1, -1 },
    { 4,  8, 10, -1, -1, -1, -1, -1 }, { 0,  4,  8, 10, -1, -1, -1, -1 },
    { 2,  4,  8, 10, -1, -1, -1, -1 }, { 0,  2,  4,  8, 10, -1, -1, -1 },
    { 6,  8, 10, -1, -1, -1, -1, -1 }, { 0,  6,  8, 10, -1, -1, -1, -1 },
    { 2,  6,  8, 10, -1, -1, -1, -1 }, { 0,  2,  6,  8, 10, -1, -1, -1 },
    { 4,  6,  8, 10, -1, -1, -1, -1 }, { 0,  4,  6,  8, 10, -1, -1, -1 },
    { 2,  4,  6,  8, 10, -1, -1, -1 }, { 0,  2,  4,  6,  8, 10, -1, -1 },
    { 12, -1, -1, -1, -1, -1, -1, -1 }, { 0, 12, -1, -1, -1, -1, -1, -1 },
    { 2, 12, -1, -1, -1, -1, -1, -1 }, { 0,  2, 12, -1, -1, -1, -1, -1 },
    { 4, 12, -1, -1, -1, -1, -1, -1 }, { 0,  4, 12, -1, -1, -1, -1, -1 },
    { 2,  4, 12, -1, -1, -1, -1, -1 }, { 0,  2,  4, 12, -1, -1, -1, -1 },
    { 6, 12, -1, -1, -1, -1, -1, -1 }, { 0,  6, 12, -1, -1, -1, -1, -1 },
    { 2,  6, 12, -1, -1, -1, -1, -1 }, { 0,  2,  6, 12, -1, -1, -1, -1 },
    { 4,  6, 12, -1, -1, -1, -1, -1 }, { 0,  4,  6, 12, -1, -1, -1, -1 },
    { 2,  4,  6, 12, -1, -1, -1, -1 }, { 0,  2,  4,  6, 12, -1, -1, -1 },
    { 8, 12, -1, -1, -1, -1, -1, -1 }, { 0,  8, 12, -1, -1, -1, -1, -1 },
    { 2,  8, 12, -1, -1, -1, -1, -1 }, { 0,  2,  8, 12, -1, -1, -1, -1 },
    { 4,  8, 12, -1, -1, -1, -1, -1 }, { 0,  4,  8, 12, -1, -1, -1, -1 },
    { 2,  4,  8, 12, -1, -1, -1, -1 }, { 0,  2,  4,  8, 12, -1, -1, -1 },
    { 6,  8, 12, -1, -1, -1, -1, -1 }, { 0,  6,  8, 12, -1, -1, -1, -1 },
    { 2,  6,  8, 12, -1, -1, -1, -1 }, { 0,  2,  6,  8, 12, -1, -1, -1 },
    { 4,  6,  8, 12, -1, -1, -1, -1 }, { 0,  4,  6,  8, 12, -1, -1, -1 },
    { 2,  4,  6,  8, 12, -1, -1, -1 }, { 0,  2,  4,  6,  8, 12, -1, -1 },
    { 10, 12, -1, -1, -1, -1, -1, -1 }, { 0, 10, 12, -1, -1, -1, -1, -1 },
    { 2, 10, 12, -1, -1, -1, -1, -1 }, { 0,  2, 10, 12, -1, -1, -1, -1 },
    { 4, 10, 12, -1, -1, -1, -1, -1 }, { 0,  4, 10, 12, -1, -1, -1, -1 },
    { 2,  4, 10, 12, -1, -1, -1, -1 }, { 0,  2,  4, 10, 12, -1, -1, -1 },
    { 6, 10, 12, -1, -1, -1, -1, -1 }, { 0,  6, 10, 12, -1, -1, -1, -1 },
    { 2,  6, 10, 12, -1, -1, -1, -1 }, { 0,  2,  6, 10, 12, -1, -1, -1 },
    { 4,  6, 10, 12, -1, -1, -1, -1 }, { 0,  4,  6, 10, 12, -1, -1, -1 },
    { 2,  4,  6, 10, 12, -1, -1, -1 }, { 0,  2,  4,  6, 10, 12, -1, -1 },
    { 8, 10, 12, -1, -1, -1, -1, -1 }, { 0,  8, 10, 12, -1, -1, -1, -1 },
    { 2,  8, 10, 12, -1, -1, -1, -1 }, { 0,  2,  8, 10, 12, -1, -1, -1 },
    { 4,  8, 10, 12, -1, -1, -1, -1 }, { 0,  4,  8, 10, 12, -1, -1, -1 },
    { 2,  4,  8, 10, 12, -1, -1, -1 }, { 0,  2,  4,  8, 10, 12, -1, -1 },
    { 6,  8, 10, 12, -1, -1, -1, -1 }, { 0,  6,  8, 10, 12, -1, -1, -1 },
    { 2,  6,  8, 10, 12, -1, -1, -1 }, { 0,  2,  6,  8, 10, 12, -1, -1 },
    { 4,  6,  8, 10, 12, -1, -1, -1 }, { 0,  4,  6,  8, 10, 12, -1, -1 },
    { 2,  4,  6,  8, 10, 12, -1, -1 }, { 0,  2,  4,  6,  8, 10, 12, -1 },
    { 14, -1, -1, -1, -1, -1, -1, -1 }, { 0, 14, -1, -1, -1, -1, -1, -1 },
    { 2, 14, -1, -1, -1, -1, -1, -1 }, { 0,  2, 14, -1, -1, -1, -1, -1 },
    { 4, 14, -1, -1, -1, -1, -1, -1 }, { 0,  4, 14, -1, -1, -1, -1, -1 },
    { 2,  4, 14, -1, -1, -1, -1, -1 }, { 0,  2,  4, 14, -1, -1, -1, -1 },
    { 6, 14, -1, -1, -1, -1, -1, -1 }, { 0,  6, 14, -1, -1, -1, -1, -1 },
    { 2,  6, 14, -1, -1, -1, -1, -1 }, { 0,  2,  6, 14, -1, -1, -1, -1 },
    { 4,  6, 14, -1, -1, -1, -1, -1 }, { 0,  4,  6, 14, -1, -1, -1, -1 },
    { 2,  4,  6, 14, -1, -1, -1, -1 }, { 0,  2,  4,  6, 14, -1, -1, -1 },
    { 8, 14, -1, -1, -1, -1, -1, -1 }, { 0,  8, 14, -1, -1, -1, -1, -1 },
    { 2,  8, 14, -1, -1, -1, -1, -1 }, { 0,  2,  8, 14, -1, -1, -1, -1 },
    { 4,  8, 14, -1, -1, -1, -1, -1 }, { 0,  4,  8, 14, -1, -1, -1, -1 },
    { 2,  4,  8, 14, -1, -1, -1, -1 }, { 0,  2,  4,  8, 14, -1, -1, -1 },
    { 6,  8, 14, -1, -1, -1, -1, -1 }, { 0,  6,  8, 14, -1, -1, -1, -1 },
    { 2,  6,  8, 14, -1, -1, -1, -1 }, { 0,  2,  6,  8, 14, -1, -1, -1 },
    { 4,  6,  8, 14, -1, -1, -1, -1 }, { 0,  4,  6,  8, 14, -1, -1, -1 },
    { 2,  4,  6,  8, 14, -1, -1, -1 }, { 0,  2,  4,  6,  8, 14, -1, -1 },
    { 10, 14, -1, -1, -1, -1, -1, -1 }, { 0, 10, 14, -1, -1, -1, -1, -1 },
    { 2, 10, 14, -1, -1, -1, -1, -1 }, { 0,  2, 10, 14, -1, -1, -1, -1 },
    { 4, 10, 14, -1, -1, -1, -1, -1 }, { 0,  4, 10, 14, -1, -1, -1, -1 },
    { 2,  4, 10, 14, -1, -1, -1, -1 }, { 0,  2,  4, 10, 14, -1, -1, -1 },
    { 6, 10, 14, -1, -1, -1, -1, -1 }, { 0,  6, 10, 14, -1, -1, -1, -1 },
    { 2,  6, 10, 14, -1, -1, -1, -1 }, { 0,  2,  6, 10, 14, -1, -1, -1 },
    { 4,  6, 10, 14, -1, -1, -1, -1 }, { 0,  4,  6, 10, 14, -1, -1, -1 },
    { 2,  4,  6, 10, 14, -1, -1, -1 }, { 0,  2,  4,  6, 10, 14, -1, -1 },
    { 8, 10, 14, -1, -1, -1, -1, -1 }, { 0,  8, 10, 14, -1, -1, -1, -1 },
    { 2,  8, 10, 14, -1, -1, -1, -1 }, { 0,  2,  8, 10, 14, -1, -1, -1 },
    { 4,  8, 10, 14, -1, -1, -1, -1 }, { 0,  4,  8, 10, 14, -1, -1, -1 },
    { 2,  4,  8, 10, 14, -1, -1, -1 }, { 0,  2,  4,  8, 10, 14, -1, -1 },
    { 6,  8, 10, 14, -1, -1, -1, -1 }, { 0,  6,  8, 10, 14, -1, -1, -1 },
    { 2,  6,  8, 10, 14, -1, -1, -1 }, { 0,  2,  6,  8, 10, 14, -1, -1 },
    { 4,  6,  8, 10, 14, -1, -1, -1 }, { 0,  4,  6,  8, 10, 14, -1, -1 },
    { 2,  4,  6,  8, 10, 14, -1, -1 }, { 0,  2,  4,  6,  8, 10, 14, -1 },
    { 12, 14, -1, -1, -1, -1, -1, -1 }, { 0, 12, 14, -1, -1, -1, -1, -1 },
    { 2, 12, 14, -1, -1, -1, -1, -1 }, { 0,  2, 12, 14, -1, -1, -1, -1 },
    { 4, 12, 14, -1, -1, -1, -1, -1 }, { 0,  4, 12, 14, -1, -1, -1, -1 },
    { 2,  4, 12, 14, -1, -1, -1, -1 }, { 0,  2,  4, 12, 14, -1, -1, -1 },
    { 6, 12, 14, -1, -1, -1, -1, -1 }, { 0,  6, 12, 14, -1, -1, -1, -1 },
    { 2,  6, 12, 14, -1, -1, -1, -1 }, { 0,  2,  6, 12, 14, -1, -1, -1 },
    { 4,  6, 12, 14, -1, -1, -1, -1 }, { 0,  4,  6, 12, 14, -1, -1, -1 },
    { 2,  4,  6, 12, 14, -1, -1, -1 }, { 0,  2,  4,  6, 12, 14, -1, -1 },
    { 8, 12, 14, -1, -1, -1, -1, -1 }, { 0,  8, 12, 14, -1, -1, -1, -1 },
    { 2,  8, 12, 14, -1, -1, -1, -1 }, { 0,  2,  8, 12, 14, -1, -1, -1 },
    { 4,  8, 12, 14, -1, -1, -1, -1 }, { 0,  4,  8, 12, 14, -1, -1, -1 },
    { 2,  4,  8, 12, 14, -1, -1, -1 }, { 0,  2,  4,  8, 12, 14, -1, -1 },
    { 6,  8, 12, 14, -1, -1, -1, -1 }, { 0,  6,  8, 12, 14, -1, -1, -1 },
    { 2,  6,  8, 12, 14, -1, -1, -1 }, { 0,  2,  6,  8, 12, 14, -1, -1 },
    { 4,  6,  8, 12, 14, -1, -1, -1 }, { 0,  4,  6,  8, 12, 14, -1, -1 },
    { 2,  4,  6,  8, 12, 14, -1, -1 }, { 0,  2,  4,  6,  8, 12, 14, -1 },
    { 10, 12, 14, -1, -1, -1, -1, -1 }, { 0, 10, 12, 14, -1, -1, -1, -1 },
    { 2, 10, 12, 14, -1, -1, -1, -1 }, { 0,  2, 10, 12, 14, -1, -1, -1 },
    { 4, 10, 12, 14, -1, -1, -1, -1 }, { 0,  4, 10, 12, 14, -1, -1, -1 },
    { 2,  4, 10, 12, 14, -1, -1, -1 }, { 0,  2,  4, 10, 12, 14, -1, -1 },
    { 6, 10, 12, 14, -1, -1, -1, -1 }, { 0,  6, 10, 12, 14, -1, -1, -1 },
    { 2,  6, 10, 12, 14, -1, -1, -1 }, { 0,  2,  6, 10, 12, 14, -1, -1 },
    { 4,  6, 10, 12, 14, -1, -1, -1 }, { 0,  4,  6, 10, 12, 14, -1, -1 },
    { 2,  4,  6, 10, 12, 14, -1, -1 }, { 0,  2,  4,  6, 10, 12, 14, -1 },
    { 8, 10, 12, 14, -1, -1, -1, -1 }, { 0,  8, 10, 12, 14, -1, -1, -1 },
    { 2,  8, 10, 12, 14, -1, -1, -1 }, { 0,  2,  8, 10, 12, 14, -1, -1 },
    { 4,  8, 10, 12, 14, -1, -1, -1 }, { 0,  4,  8, 10, 12, 14, -1, -1 },
    { 2,  4,  8, 10, 12, 14, -1, -1 }, { 0,  2,  4,  8, 10, 12, 14, -1 },
    { 6,  8, 10, 12, 14, -1, -1, -1 }, { 0,  6,  8, 10, 12, 14, -1, -1 },
    { 2,  6,  8, 10, 12, 14, -1, -1 }, { 0,  2,  6,  8, 10, 12, 14, -1 },
    { 4,  6,  8, 10, 12, 14, -1, -1 }, { 0,  4,  6,  8, 10, 12, 14, -1 },
    { 2,  4,  6,  8, 10, 12, 14, -1 }, { 0,  2,  4,  6,  8, 10, 12, 14 }
};

uint32_t kyber_rej_uniform_avx2(int16_t* restrict r, const uint8_t* restrict buf)
{
    const __m256i bound = _mm256_set1_epi16(QSC_KYBER_Q);
    const __m256i ones = _mm256_set1_epi8(1);
    const __m256i mask = _mm256_set1_epi16(0xFFF);
    const __m256i idx8 = _mm256_set_epi8(15, 14, 14, 13, 12, 11, 11, 10,
        9, 8, 8, 7, 6, 5, 5, 4, 11, 10, 10, 9, 8, 7, 7, 6, 5, 4, 4, 3, 2, 1, 1, 0);
    __m256i f0;
    __m256i f1;
    __m256i g0;
    __m256i g1;
    __m256i g2;
    __m256i g3;
    __m128i f;
    __m128i t;
    __m128i pilo;
    __m128i pihi;
    uint32_t ctr;
    uint32_t pos;
    uint16_t val0;
    uint16_t val1;
    uint32_t good;

    ctr = 0;
    pos = 0;

    while (ctr <= QSC_KYBER_N - 32 && pos <= QSC_AVX_REJ_UNIFORM_BUFLEN - 48)
    {
        f0 = _mm256_loadu_si256((const __m256i*)&buf[pos]);
        f1 = _mm256_loadu_si256((const __m256i*)&buf[pos + 24]);
        f0 = _mm256_permute4x64_epi64(f0, 0x94);
        f1 = _mm256_permute4x64_epi64(f1, 0x94);
        f0 = _mm256_shuffle_epi8(f0, idx8);
        f1 = _mm256_shuffle_epi8(f1, idx8);
        g0 = _mm256_srli_epi16(f0, 4);
        g1 = _mm256_srli_epi16(f1, 4);
        f0 = _mm256_blend_epi16(f0, g0, 0xAA);
        f1 = _mm256_blend_epi16(f1, g1, 0xAA);
        f0 = _mm256_and_si256(f0, mask);
        f1 = _mm256_and_si256(f1, mask);
        pos += 48;

        g0 = _mm256_cmpgt_epi16(bound, f0);
        g1 = _mm256_cmpgt_epi16(bound, f1);
        g0 = _mm256_packs_epi16(g0, g1);
        good = _mm256_movemask_epi8(g0);
        g0 = _mm256_castsi128_si256(_mm_loadl_epi64((const __m128i*)&kyber_rej_idx[good & 0xFF]));
        g1 = _mm256_castsi128_si256(_mm_loadl_epi64((const __m128i*)&kyber_rej_idx[(good >> 8) & 0xFF]));
        g0 = _mm256_inserti128_si256(g0, _mm_loadl_epi64((const __m128i*)&kyber_rej_idx[(good >> 16) & 0xFF]), 1);
        g1 = _mm256_inserti128_si256(g1, _mm_loadl_epi64((const __m128i*)&kyber_rej_idx[(good >> 24) & 0xFF]), 1);
        g2 = _mm256_add_epi8(g0, ones);
        g3 = _mm256_add_epi8(g1, ones);
        g0 = _mm256_unpacklo_epi8(g0, g2);
        g1 = _mm256_unpacklo_epi8(g1, g3);
        f0 = _mm256_shuffle_epi8(f0, g0);
        f1 = _mm256_shuffle_epi8(f1, g1);

        _mm_storeu_si128((__m128i*)&r[ctr], _mm256_castsi256_si128(f0));
        ctr += _mm_popcnt_u32(good & 0xFF);
        _mm_storeu_si128((__m128i*)&r[ctr], _mm256_extracti128_si256(f0, 1));
        ctr += _mm_popcnt_u32((good >> 16) & 0xFF);
        _mm_storeu_si128((__m128i*)&r[ctr], _mm256_castsi256_si128(f1));
        ctr += _mm_popcnt_u32((good >> 8) & 0xFF);
        _mm_storeu_si128((__m128i*)&r[ctr], _mm256_extracti128_si256(f1, 1));
        ctr += _mm_popcnt_u32((good >> 24) & 0xFF);
    }

    while (ctr <= QSC_KYBER_N - 8 && pos <= QSC_AVX_REJ_UNIFORM_BUFLEN - 12)
    {
        f = _mm_loadu_si128((const __m128i*)&buf[pos]);
        f = _mm_shuffle_epi8(f, _mm256_castsi256_si128(idx8));
        t = _mm_srli_epi16(f, 4);
        f = _mm_blend_epi16(f, t, 0xAA);
        f = _mm_and_si128(f, _mm256_castsi256_si128(mask));
        pos += 12;
        t = _mm_cmpgt_epi16(_mm256_castsi256_si128(bound), f);
        good = _mm_movemask_epi8(t);
        good = _pext_u32(good, 0x5555);
        pilo = _mm_loadl_epi64((const __m128i*)&kyber_rej_idx[good]);
        pihi = _mm_add_epi8(pilo, _mm256_castsi256_si128(ones));
        pilo = _mm_unpacklo_epi8(pilo, pihi);
        f = _mm_shuffle_epi8(f, pilo);
        _mm_storeu_si128((__m128i*)&r[ctr], f);
        ctr += _mm_popcnt_u32(good);
    }

    while (ctr < QSC_KYBER_N && pos <= QSC_AVX_REJ_UNIFORM_BUFLEN - 3)
    {
        val0 = (uint16_t)(((uint16_t)buf[pos + 0] | ((uint16_t)buf[pos + 1] << 8)) & 0x0FFF);
        val1 = (uint16_t)(((uint16_t)buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4));
        pos += 3;

        if (val0 < QSC_KYBER_Q)
        {
            r[ctr] = val0;
            ++ctr;
        }

        if (val1 < QSC_KYBER_Q && ctr < QSC_KYBER_N)
        {
            r[ctr] = val1;
            ++ctr;
        }
    }

    return ctr;
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
        val0 = (uint16_t)(((uint16_t)buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x0FFF);
        val1 = (uint16_t)((((uint16_t)buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0x0FFF);
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

static void kyber_gen_matrix_avx2(qsc_kyber_polyvec* a, const uint8_t seed[QSC_KYBER_SYMBYTES], int32_t transposed)
{
    __m256i ksa[QSC_KECCAK_STATE_SIZE] = { 0 };
#if (QSC_KYBER_K == 5)
    QSC_ALIGN(32) uint8_t buf[5][KYBER_GEN_MATRIX_NBLOCKS * QSC_KECCAK_128_RATE + 2] = { 0 };
    QSC_ALIGN(32) uint8_t extseed[5][QSC_KYBER_SYMBYTES + 2] = { 0 };
    qsc_keccak_state kctx;
#else
    QSC_ALIGN(32) uint8_t buf[4][KYBER_GEN_MATRIX_NBLOCKS * QSC_KECCAK_128_RATE + 2] = { 0 };
    QSC_ALIGN(32) uint8_t extseed[4][QSC_KYBER_SYMBYTES + 2] = { 0 };
#endif

    uint32_t ctr[QSC_KYBER_K] = { 0 };
    size_t i;
    size_t j;
    bool bchk;

    for (i = 0; i < QSC_KYBER_K; ++i)
    {
        qsc_memutils_copy(extseed[i], seed, QSC_KYBER_SYMBYTES);
    }

    for (i = 0; i < QSC_KYBER_K; ++i)
    {
        for (j = 0; j < QSC_KYBER_K; ++j)
        {
            if (transposed != 0)
            {
                extseed[j][QSC_KYBER_SYMBYTES] = (uint8_t)i;
                extseed[j][QSC_KYBER_SYMBYTES + 1] = (uint8_t)j;
            }
            else
            {
                extseed[j][QSC_KYBER_SYMBYTES] = (uint8_t)j;
                extseed[j][QSC_KYBER_SYMBYTES + 1] = (uint8_t)i;
            }
        }

        qsc_keccakx4_absorb(ksa, QSC_KECCAK_128_RATE, extseed[0], extseed[1], extseed[2], extseed[3], sizeof(extseed[0]), QSC_KECCAK_SHAKE_DOMAIN_ID);
        qsc_keccakx4_squeezeblocks(ksa, QSC_KECCAK_128_RATE, buf[0], buf[1], buf[2], buf[3], KYBER_GEN_MATRIX_NBLOCKS);

#if (QSC_KYBER_K == 5)
        qsc_shake_initialize(&kctx, QSC_KECCAK_128_RATE, extseed[4], sizeof(extseed[4]));
        qsc_shake_squeezeblocks(&kctx, QSC_KECCAK_128_RATE, buf[4], KYBER_GEN_MATRIX_NBLOCKS);
#endif
        bchk = false;

        for (j = 0; j < QSC_KYBER_K; ++j)
        {
            ctr[j] = kyber_rej_uniform_avx2(a[i].vec[j].coeffs, buf[j]);

            if (ctr[j] < QSC_KYBER_N)
            {
                bchk = true;
            }
        }

        while (bchk == true)
        {
            qsc_keccakx4_squeezeblocks(ksa, QSC_KECCAK_128_RATE, buf[0], buf[1], buf[2], buf[3], 1);
#if (QSC_KYBER_K == 5)
            qsc_shake_squeezeblocks(&kctx, QSC_KECCAK_128_RATE, buf[4], 1);
#endif
            bchk = false;

            for (j = 0; j < QSC_KYBER_K; ++j)
            {
                if (ctr[j] < QSC_KYBER_N)
                {
                    ctr[j] += kyber_rej_uniform((a[i].vec[j].coeffs + ctr[j]), QSC_KYBER_N - ctr[j], buf[j], QSC_KECCAK_128_RATE);

                    if (ctr[j] < QSC_KYBER_N)
                    {
                        bchk = true;
                    }
                }
            }
        } 

        qsc_memutils_clear(ksa, sizeof(ksa));
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

    kyber_gen_matrix_avx2(a, publicseed, 0);

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
    kyber_poly_from_msg_avx2(&k, m);
    kyber_gen_matrix_avx2(at, seed, 1);

    for (i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_get_noise_eta1((sp.vec + i), coins, nonce);
        ++nonce;
    }

    for (i = 0; i < QSC_KYBER_K; ++i)
    {
        kyber_poly_get_noise_eta2((ep.vec + i), coins, nonce);
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
    kyber_poly_add_avx2(&v, &v, &epp);
    kyber_poly_add_avx2(&v, &v, &k);

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
    kyber_poly_sub_avx2(&mp, &v, &mp);
    kyber_poly_reduce(&mp);
    kyber_poly_to_msg(m, &mp);
}

/* verify.c */

void kyber_cmov_avx2(uint8_t* restrict r, const uint8_t* restrict x, size_t len, uint8_t b)
{
    __m256i xvec;
    __m256i rvec;
    __m256i bvec;
    size_t pos;

    b = -b;
    bvec = _mm256_set1_epi8(b);

    for (pos = 0; pos + 32 <= len; pos += 32)
    {
        rvec = _mm256_loadu_si256((const __m256i*)&r[pos]);
        xvec = _mm256_loadu_si256((const __m256i*)&x[pos]);
        xvec = _mm256_xor_si256(xvec, rvec);
        xvec = _mm256_and_si256(xvec, bvec);
        rvec = _mm256_xor_si256(rvec, xvec);
        _mm256_storeu_si256((__m256i*)&r[pos], rvec);
    }

    while (pos < len)
    {
        r[pos] ^= b & (x[pos] ^ r[pos]);
        pos += 1;
    }
}

int32_t kyber_verify_avx2(const uint8_t* a, const uint8_t* b, size_t len)
{
    __m256i avec;
    __m256i bvec;
    __m256i cvec;
    uint64_t r;
    size_t pos;

    cvec = _mm256_setzero_si256();

    for (pos = 0; pos + 32 <= len; pos += 32)
    {
        avec = _mm256_loadu_si256((const __m256i*)&a[pos]);
        bvec = _mm256_loadu_si256((const __m256i*)&b[pos]);
        avec = _mm256_xor_si256(avec, bvec);
        cvec = _mm256_or_si256(cvec, avec);
    }

    r = 1ULL - _mm256_testz_si256(cvec, cvec);

    if (pos < len)
    {
        avec = _mm256_loadu_si256((const __m256i*)&a[pos]);
        bvec = _mm256_loadu_si256((const __m256i*)&b[pos]);
        cvec = _mm256_cmpeq_epi8(avec, bvec);
        r |= _mm256_movemask_epi8(cvec) & ((uint32_t)-1L >> (32 + pos - len));
    }

    r = (uint64_t)(-(int64_t)r) >> 63;

    return (uint32_t)r;
}

/* kem.c */

void qsc_kyber_avx2_generate_keypair(uint8_t pk[QSC_KYBER_PUBLICKEY_BYTES], uint8_t sk[QSC_KYBER_SECRETKEY_BYTES], bool (*rng_generate)(uint8_t*, size_t))
{
    kyber_indcpa_keypair(pk, sk, rng_generate);
    qsc_memutils_copy((sk + QSC_KYBER_INDCPA_SECRETKEY_BYTES), pk, QSC_KYBER_INDCPA_PUBLICKEY_BYTES);

    qsc_sha3_compute256((sk + QSC_KYBER_SECRETKEY_BYTES - 2 * QSC_KYBER_SYMBYTES), pk, QSC_KYBER_PUBLICKEY_BYTES);
    /* Value z for pseudo-random output on reject */
    rng_generate((sk + QSC_KYBER_SECRETKEY_BYTES - QSC_KYBER_SYMBYTES), QSC_KYBER_SYMBYTES);
}

void qsc_kyber_avx2_encapsulate(uint8_t ct[QSC_KYBER_CIPHERTEXT_BYTES], uint8_t ss[QSC_KYBER_MSGBYTES], const uint8_t pk[QSC_KYBER_PUBLICKEY_BYTES], bool (*rng_generate)(uint8_t*, size_t))
{
    QSC_ALIGN(32)uint8_t buf[2 * QSC_KYBER_SYMBYTES];
    QSC_ALIGN(32)uint8_t kr[2 * QSC_KYBER_SYMBYTES];

    rng_generate(buf, QSC_KYBER_SYMBYTES);
    /* Don't release system RNG output */
    qsc_sha3_compute256(buf, buf, QSC_KYBER_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    qsc_sha3_compute256((buf + QSC_KYBER_SYMBYTES), pk, QSC_KYBER_PUBLICKEY_BYTES);
    qsc_sha3_compute512(kr, buf, 2 * QSC_KYBER_SYMBYTES);

    /* coins are in kr+QSC_KYBER_SYMBYTES */
    kyber_indcpa_enc(ct, buf, pk, (kr + QSC_KYBER_SYMBYTES));

    /* overwrite coins in kr with H(c) */
    qsc_sha3_compute256((kr + QSC_KYBER_SYMBYTES), ct, QSC_KYBER_CIPHERTEXT_BYTES);
    /* hash concatenation of pre-k and H(c) to k */
    qsc_shake256_compute(ss, QSC_KYBER_MSGBYTES, kr, 2 * QSC_KYBER_SYMBYTES);
}

bool qsc_kyber_avx2_decapsulate(uint8_t ss[QSC_KYBER_MSGBYTES], const uint8_t ct[QSC_KYBER_CIPHERTEXT_BYTES], const uint8_t sk[QSC_KYBER_SECRETKEY_BYTES])
{
    QSC_ALIGN(32)uint8_t buf[2 * QSC_KYBER_SYMBYTES];
    QSC_ALIGN(32)uint8_t cmp[QSC_KYBER_CIPHERTEXT_BYTES];
    QSC_ALIGN(32)uint8_t kr[2 * QSC_KYBER_SYMBYTES];
    const uint8_t *pk = sk + QSC_KYBER_INDCPA_SECRETKEY_BYTES;
    int32_t fail;

    kyber_indcpa_dec(buf, ct, sk);

    /* Multitarget countermeasure for coins + contributory KEM */
    qsc_memutils_copy((buf + QSC_KYBER_SYMBYTES), (sk + QSC_KYBER_SECRETKEY_BYTES - (2 * QSC_KYBER_SYMBYTES)), QSC_KYBER_SYMBYTES);
    qsc_sha3_compute512(kr, buf, 2 * QSC_KYBER_SYMBYTES);

    /* coins are in kr+QSC_KYBER_SYMBYTES */
    kyber_indcpa_enc(cmp, buf, pk, (kr + QSC_KYBER_SYMBYTES));

    fail = kyber_verify_avx2(ct, cmp, QSC_KYBER_CIPHERTEXT_BYTES);

    /* overwrite coins in kr with H(c) */
    qsc_sha3_compute256((kr + QSC_KYBER_SYMBYTES), ct, QSC_KYBER_CIPHERTEXT_BYTES);

    /* Overwrite pre-k with z on re-encryption failure */
    kyber_cmov_avx2(kr, (sk + QSC_KYBER_SECRETKEY_BYTES - QSC_KYBER_SYMBYTES), QSC_KYBER_SYMBYTES, (uint8_t)fail);

    /* hash concatenation of pre-k and H(c) to k */
    qsc_shake256_compute(ss, QSC_KYBER_MSGBYTES, kr, 2 * QSC_KYBER_SYMBYTES);

    return (fail == 0);
}

#endif
