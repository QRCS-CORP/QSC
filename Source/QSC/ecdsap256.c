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

/* THIRD-PARTY ATTRIBUTION: The prime-field reduction (P-256) 
 * and signed fixed-base windowing structure based in part on 
 * algorithms published by Botan, and author Jack Lloyd. */

#include "ecdsap256.h"
#include "csp.h"
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

/*! \brief Montgomery representation of field element one, 2^256 mod p. */
static const uint32_t P256_MONT_ONE[8U] =
{
	0x00000001U, 0x00000000U, 0x00000000U, 0xFFFFFFFFU,
	0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU, 0x00000000U
};

/*! \brief Independently derived canonical generator multiples in Montgomery representation.
 * \details Every coordinate is generated from the published NIST domain parameters,
 * not copied from another software implementation; entry 0 represents infinity.
 * \note The read-only data are public, shared without synchronization, and never
 * indexed using a secret scalar. The table is scanned in constant time.
 */
static const uint32_t P256_GENERATOR_MONT[16U][2U][8U] =
{
	{ { 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U },
	  { 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U } } /* 0G */,
	{ { 0x18A9143CU, 0x79E730D4U, 0x5FEDB601U, 0x75BA95FCU, 0x77622510U, 0x79FB732BU, 0xA53755C6U, 0x18905F76U },
	  { 0xCE95560AU, 0xDDF25357U, 0xBA19E45CU, 0x8B4AB8E4U, 0xDD21F325U, 0xD2E88688U, 0x25885D85U, 0x8571FF18U } } /* 1G */,
	{ { 0x10DDD64DU, 0x850046D4U, 0xA433827DU, 0xAA6AE3C1U, 0x8D1490D9U, 0x73220503U, 0x3DCF3A3BU, 0xF6BB32E4U },
	  { 0x61BEE1A5U, 0x2F3648D3U, 0xEB236FF8U, 0x152CD7CBU, 0x92042DBEU, 0x19A8FB0EU, 0x0A5B8A3BU, 0x78C57751U } } /* 2G */,
	{ { 0x4EEBC127U, 0xFFAC3F90U, 0x087D81FBU, 0xB027F84AU, 0x87CBBC98U, 0x66AD77DDU, 0xB6FF747EU, 0x26936A3FU },
	  { 0xC983A7EBU, 0xB04C5C1FU, 0x0861FE1AU, 0x583E47ADU, 0x1A2EE98EU, 0x78820831U, 0xE587CC07U, 0xD5F06A29U } } /* 3G */,
	{ { 0x46918DCCU, 0x74B0B50DU, 0xC623C173U, 0x4650A6EDU, 0xE8100AF2U, 0x0CDAACACU, 0x41B0176BU, 0x577362F5U },
	  { 0xE4CBABA6U, 0x2D96F24CU, 0xFAD6F447U, 0x17628471U, 0xE5DDD22EU, 0x6B6C36DEU, 0x4C5AB863U, 0x84B14C39U } } /* 4G */,
	{ { 0xC45C61F5U, 0xBE1B8AAEU, 0x94B9537DU, 0x90EC649AU, 0xD076C20CU, 0x941CB5AAU, 0x890523C8U, 0xC9079605U },
	  { 0xE7BA4F10U, 0xEB309B4AU, 0xE5EB882BU, 0x73C568EFU, 0x7E7A1F68U, 0x3540A987U, 0x2DD1E916U, 0x73A076BBU } } /* 5G */,
	{ { 0x3E77664AU, 0x40394737U, 0x346CEE3EU, 0x55AE744FU, 0x5B17A3ADU, 0xD50A961AU, 0x54213673U, 0x13074B59U },
	  { 0xD377E44BU, 0x93D36220U, 0xADFF14B5U, 0x299C2B53U, 0xEF639F11U, 0xF424D44CU, 0x4A07F75FU, 0xA4C9916DU } } /* 6G */,
	{ { 0xA0173B4FU, 0x0746354EU, 0xD23C00F7U, 0x2BD20213U, 0x0C23BB08U, 0xF43EAAB5U, 0xC3123E03U, 0x13BA5119U },
	  { 0x3F5B9D4DU, 0x2847D030U, 0x5DA67BDDU, 0x6742F2F2U, 0x77C94195U, 0xEF933BDCU, 0x6E240867U, 0xEAEDD915U } } /* 7G */,
	{ { 0x9499A78FU, 0x27F14CD1U, 0x6F9B3455U, 0x462AB5C5U, 0xF02CFC6BU, 0x8F90F02AU, 0xB265230DU, 0xB763891EU },
	  { 0x532D4977U, 0xF59DA3A9U, 0xCF9EBA15U, 0x21E3327DU, 0xBE60BBF0U, 0x123C7B84U, 0x7706DF76U, 0x56EC12F2U } } /* 8G */,
	{ { 0x264E20E8U, 0x75C96E8FU, 0x59A7A841U, 0xABE6BFEDU, 0x44C8EB00U, 0x2CC09C04U, 0xF0C4E16BU, 0xE05B3080U },
	  { 0xA45F3314U, 0x1EB7777AU, 0xCE5D45E3U, 0x56AF7BEDU, 0x88B12F1AU, 0x2B6E019AU, 0xFD835F9BU, 0x086659CDU } } /* 9G */,
	{ { 0x9DC21EC8U, 0x2C18DBD1U, 0x0FCF8139U, 0x98F9868AU, 0x48250B49U, 0x737D2CD6U, 0x24B3428FU, 0xCC61C947U },
	  { 0x80DD9E76U, 0x0C2B4078U, 0x383FBE08U, 0xC43A8991U, 0x779BE5D2U, 0x5F7D2D65U, 0xEB3B4AB5U, 0x78719A54U } } /* 10G */,
	{ { 0x6245E404U, 0xEA7D260AU, 0x6E7FDFE0U, 0x9DE40795U, 0x8DAC1AB5U, 0x1FF3A415U, 0x649C9073U, 0x3E7090F1U },
	  { 0x2B944E88U, 0x1A768561U, 0xE57F61C8U, 0x250F939EU, 0x1EAD643DU, 0x0C0DAA89U, 0xE125B88EU, 0x68930023U } } /* 11G */,
	{ { 0xD2697768U, 0x04B71AA7U, 0xCA345A33U, 0xABDEDEF5U, 0xEE37385EU, 0x2409D29DU, 0xCB83E156U, 0x4EE1DF77U },
	  { 0x1CBB5B43U, 0x0CAC12D9U, 0xCA895637U, 0x170ED2F6U, 0x8ADE6D66U, 0x28228CFAU, 0x53238ACAU, 0x7FF57C95U } } /* 12G */,
	{ { 0x4B2ED709U, 0xCCC42563U, 0x856FD30DU, 0x0E356769U, 0x559E9811U, 0xBCBCD43FU, 0x5395B759U, 0x738477ACU },
	  { 0xC00EE17FU, 0x35752B90U, 0x742ED2E3U, 0x68748390U, 0xBD1F5BC1U, 0x7CD06422U, 0xC9E7B797U, 0xFBC08769U } } /* 13G */,
	{ { 0xB0CF664AU, 0xA242A35BU, 0x7F9707E3U, 0x126E48F7U, 0xC6832660U, 0x1717BF54U, 0xFD12C72EU, 0xFAAE7332U },
	  { 0x995D586BU, 0x27B52DB7U, 0x832237C2U, 0xBE29569EU, 0x2A65E7DBU, 0xE8E4193EU, 0x2EAA1BBBU, 0x152706DCU } } /* 14G */,
	{ { 0xBC60055BU, 0x72BCD8B7U, 0x56E27E4BU, 0x03CC23EEU, 0xE4819370U, 0xEE337424U, 0x0AD3DA09U, 0xE2AA0E43U },
	  { 0x6383C45DU, 0x40B8524FU, 0x42A41B25U, 0xD7663554U, 0x778A4797U, 0x64EFA6DEU, 0x7079ADF4U, 0x2042170AU } } /* 15G */
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
    /* set a field element to the Montgomery-domain multiplicative identity */
	fe256_copy(r, P256_MONT_ONE);
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

    /* accept tmp only if there was no borrow (r >= mod) */
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

/*! \brief Montgomery R-squared constant for the P256_P modulus. */
static const uint32_t P256_P_R2[8U] =
{
	0x00000003U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFBU,
	0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFDU, 0x00000004U
};

/*! \brief Montgomery R-squared constant for the P256_N modulus. */
static const uint32_t P256_N_R2[8U] =
{
	0xBE79EEA2U, 0x83244C95U, 0x49BD6FA6U, 0x4699799CU,
	0x2B6BEC59U, 0x2845B239U, 0xF3D95620U, 0x66E12D94U
};

/* multiply two 256-bit values to form a double-width integer */
static void fe256_mul_raw(uint32_t c[16U], const fe256 a, const fe256 b);

static void mod_montgomery512(uint32_t out[8U], const uint32_t in[16U], const uint32_t mod[8U], uint32_t inverse)
{
    /* constant-iteration Montgomery reduction of a double-width integer */
	uint32_t t[18U] = { 0U };
	uint32_t candidate[9U] = { 0U };
	uint32_t reduced[9U] = { 0U };
	uint32_t modulus[9U] = { 0U };
	uint32_t selected;
	uint32_t word;
	uint64_t carry;
	uint64_t value;
	size_t i;
	size_t j;

	for (i = 0U; i < 16U; ++i)
	{
		t[i] = in[i];
	}

	for (i = 0U; i < 8U; ++i)
	{
		word = (uint32_t)((uint64_t)t[i] * (uint64_t)inverse);
		carry = 0U;

		for (j = 0U; j < 8U; ++j)
		{
			value = ((uint64_t)word * (uint64_t)mod[j]) + (uint64_t)t[i + j] + carry;
			t[i + j] = (uint32_t)value;
			carry = value >> 32U;
		}

		for (j = i + 8U; j < 18U; ++j)
		{
			value = (uint64_t)t[j] + carry;
			t[j] = (uint32_t)value;
			carry = value >> 32U;
		}
	}

	for (i = 0U; i < 8U; ++i)
	{
		modulus[i] = mod[i];
	}

	for (i = 0U; i < 9U; ++i)
	{
		candidate[i] = t[i + 8U];
	}

	ct_sub_9x32(reduced, candidate, modulus);
	selected = (uint32_t)(0U - ct_ge_9x32(candidate, modulus));

	for (i = 0U; i < 8U; ++i)
	{
		out[i] = (candidate[i] & ~selected) | (reduced[i] & selected);
	}

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(candidate, sizeof(candidate));
	qsc_memutils_secure_erase(reduced, sizeof(reduced));
}

static void mod_reduce512_montgomery(uint32_t out[8U], const uint32_t in[16U], const uint32_t mod[8U], uint32_t inverse, const uint32_t squared_radix[8U])
{
    /* reduce a 512-bit product in standard representation using two Montgomery steps */
	uint32_t intermediate[8U] = { 0U };
	uint32_t product[16U] = { 0U };

	mod_montgomery512(intermediate, in, mod, inverse);
	fe256_mul_raw(product, intermediate, squared_radix);
	mod_montgomery512(out, product, mod, inverse);

	qsc_memutils_secure_erase(intermediate, sizeof(intermediate));
	qsc_memutils_secure_erase(product, sizeof(product));
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

static void fe_copy(uint32_t dst[8U], const uint32_t src[8U])
{
    size_t i;

    for (i = 0U; i < 8U; ++i)
    {
        dst[i] = src[i];
    }
}

static void fe256_mont_encode(fe256 r, const fe256 a)
{
    /* encode a standard field element into Montgomery coordinates */
	uint32_t product[16U] = { 0U };

	fe256_mul_raw(product, a, P256_P_R2);
	mod_montgomery512(r, product, P256_P, 1U);
	qsc_memutils_secure_erase(product, sizeof(product));
}

static void fe256_mont_decode(fe256 r, const fe256 a)
{
    /* decode a Montgomery element to the canonical external field representation */
	uint32_t product[16U] = { 0U };
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		product[i] = a[i];
	}

	mod_montgomery512(r, product, P256_P, 1U);
	qsc_memutils_secure_erase(product, sizeof(product));
}

/* native-width field modulus for Montgomery multiplication. */
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
static const uint64_t P256_P64[4U] = { UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x00000000FFFFFFFF), UINT64_C(0x0000000000000000), UINT64_C(0xFFFFFFFF00000001) };
/* native-width subgroup order for Montgomery multiplication. */
#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static const uint64_t P256_N64[4U] = { UINT64_C(0xF3B9CAC2FC632551), UINT64_C(0xBCE6FAADA7179E84), UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFF00000000) };
#endif
#endif

#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static void mod_mont_mul64(fe256 r, const fe256 a, const fe256 b, const uint64_t modulus[4U], uint64_t inverse)
{
    /* multiply Montgomery P-256 field residues using native double-width integer operations */
	uint64_t left[4U] = { 0U };
	uint64_t right[4U] = { 0U };
	uint64_t temporary[10U] = { 0U };
	uint64_t reduced[4U] = { 0U };
	__uint128_t value;
	uint64_t carry;
	uint64_t borrow;
	uint64_t word;
	uint64_t select;
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
			value = ((__uint128_t)left[i] * right[j]) + temporary[i + j] + carry;
			temporary[i + j] = (uint64_t)value;
			carry = (uint64_t)(value >> 64U);
		}

		for (j = i + 4U; j < 10U; ++j)
		{
			value = (__uint128_t)temporary[j] + carry;
			temporary[j] = (uint64_t)value;
			carry = (uint64_t)(value >> 64U);
		}
	}

	for (i = 0U; i < 4U; ++i)
	{
		word = temporary[i] * inverse;
		carry = 0U;

		for (j = 0U; j < 4U; ++j)
		{
			value = ((__uint128_t)word * modulus[j]) + temporary[i + j] + carry;
			temporary[i + j] = (uint64_t)value;
			carry = (uint64_t)(value >> 64U);
		}

		for (j = i + 4U; j < 10U; ++j)
		{
			value = (__uint128_t)temporary[j] + carry;
			temporary[j] = (uint64_t)value;
			carry = (uint64_t)(value >> 64U);
		}
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)temporary[i + 4U] - modulus[i] - borrow;
		reduced[i] = (uint64_t)value;
		borrow = (uint64_t)(value >> 127U);
	}

	word = temporary[8U];
	select = (uint64_t)(0U - ((uint64_t)((word | (0U - word)) >> 63U) | (borrow ^ 1U)));

	for (i = 0U; i < 4U; ++i)
	{
		word = (temporary[i + 4U] & ~select) | (reduced[i] & select);
		r[2U * i] = (uint32_t)word;
		r[2U * i + 1U] = (uint32_t)(word >> 32U);
	}

	qsc_memutils_secure_erase(left, sizeof(left));
	qsc_memutils_secure_erase(right, sizeof(right));
	qsc_memutils_secure_erase(temporary, sizeof(temporary));
	qsc_memutils_secure_erase(reduced, sizeof(reduced));
}
#endif

#endif

#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
static void fe256_botan_mont_mul(fe256 r, const fe256 a, const fe256 b)
{
    /* multiply Montgomery field elements using P-256-specific reduction */
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
        value = (__uint128_t)product[i + 4U] - P256_P64[i] - borrow;
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
#endif

static void fe_mul(fe256 r, const fe256 a, const fe256 b)
{
    /* multiply two Montgomery field residues without decoding intermediate values */
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
	fe256_botan_mont_mul(r, a, b);
#else
	uint32_t product[16U] = { 0U };

	fe256_mul_raw(product, a, b);
	mod_montgomery512(r, product, P256_P, 1U);
	qsc_memutils_secure_erase(product, sizeof(product));
#endif
}

static void fe_sqr(fe256 r, const fe256 a)
{
    /* r = a^2 mod p */
    fe_mul(r, a, a);
}

static void fe_mul_small(fe256 r, const fe256 a, uint32_t k)
{
    /* multiply a field element by a small public scalar */
	fe256 doubled = { 0U };
	fe256 quadrupled = { 0U };

	if (k == 2U || k == 3U || k == 4U || k == 8U)
	{
		fe_add(doubled, a, a);

		if (k == 2U)
		{
			fe256_copy(r, doubled);
		}
		else if (k == 3U)
		{
			fe_add(r, doubled, a);
		}
		else
		{
			fe_add(quadrupled, doubled, doubled);

			if (k == 4U)
			{
				fe256_copy(r, quadrupled);
			}
			else
			{
				fe_add(r, quadrupled, quadrupled);
			}
		}
	}
	else
	{
		fe256 accumulator = { 0U };
		fe256 current = { 0U };
		fe256 summed = { 0U };
		uint32_t digit;
		size_t bit;

		fe256_copy(current, a);

		for (bit = 0U; bit < 32U; ++bit)
		{
			fe_add(summed, accumulator, current);
			digit = (k >> bit) & 1U;
			fe256_ct_select(accumulator, digit, summed, accumulator);
			fe_add(current, current, current);
		}

		fe256_copy(r, accumulator);
		qsc_memutils_secure_erase(accumulator, sizeof(accumulator));
		qsc_memutils_secure_erase(current, sizeof(current));
		qsc_memutils_secure_erase(summed, sizeof(summed));
	}

	qsc_memutils_secure_erase(doubled, sizeof(doubled));
	qsc_memutils_secure_erase(quadrupled, sizeof(quadrupled));
}

static void fe_inv(uint32_t r[8U], const uint32_t a[8U])
{
    static const uint32_t p_minus_2[8U] =
    {
        0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
        0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU
    };
	uint32_t powers[16U][8U] = { { 0U } };
	uint32_t accumulator[8U] = { 0U };
	uint32_t digit;
	size_t i;
	size_t j;

	fe256_copy(powers[0U], P256_MONT_ONE);
	fe_copy(powers[1U], a);

	for (i = 2U; i < 16U; ++i)
	{
		fe_mul(powers[i], powers[i - 1U], a);
	}

	fe256_copy(accumulator, P256_MONT_ONE);

	for (i = 64U; i > 0U; --i)
	{
		for (j = 0U; j < 4U; ++j)
		{
			fe_sqr(accumulator, accumulator);
		}

		digit = (p_minus_2[(i - 1U) / 8U] >> (((uint32_t)((i - 1U) % 8U)) * 4U)) & 15U;
		fe_mul(accumulator, accumulator, powers[digit]);
	}

	fe_copy(r, accumulator);
	qsc_memutils_secure_erase(powers, sizeof(powers));
	qsc_memutils_secure_erase(accumulator, sizeof(accumulator));
}

static void sc256_mul_raw(uint32_t c[16U], const uint32_t a[8U], const uint32_t b[8U])
{
    /* 256x256 -> 512-bit schoolbook multiplication (same as fe256_mul_raw,
     * reused for scalar field - separate alias for clarity). */
    fe256_mul_raw(c, a, b);
}

static void sc256_reduce512(uint32_t r[8U], const uint32_t c[16U])
{
    /* conservative correctness-first reduction of a 512-bit value modulo n.
     * replaces the previous Barrett reduction implementation. */
    mod_reduce512_montgomery(r, c, P256_N, 0xEE00BC4FU, P256_N_R2);
}

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static void sc_copy(uint32_t dst[8U], const uint32_t src[8U])
{
    size_t i;

    for (i = 0U; i < 8U; ++i)
    {
        dst[i] = src[i];
    }
}
#endif /* Native public scalar inversion selection */


#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER)
static void sc_add(uint32_t* r, const uint32_t* a, const uint32_t* b)
{
    uint32_t t[8U] = { 0U };
    uint32_t u[8U] = { 0U };
    uint64_t borrow;
    uint64_t carry;
    uint64_t x;
    uint32_t mask;
    uint32_t reduce;

    /* t = a + b mod 2^256, keep the carry */
    carry = 0U;

    for (size_t i = 0U; i < 8U; ++i)
    {
        x = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        t[i] = (uint32_t)x;
        carry = x >> 32U;
    }

    /* u = t - n */
    borrow = 0U;

    for (size_t i = 0U; i < 8U; ++i)
    {
        x = (uint64_t)t[i] - (uint64_t)P256_N[i] - borrow;
        u[i] = (uint32_t)x;
        borrow = (x >> 63U) & 1U;
    }

    /* reduce if carry occurred, or if t >= n (i.e. subtraction did not borrow) */
    reduce = (uint32_t)carry | (uint32_t)(1U ^ (uint32_t)borrow);
    mask = (uint32_t)(0U - reduce);

    for (size_t i = 0U; i < 8U; ++i)
    {
        r[i] = (u[i] & mask) | (t[i] & ~mask);
    }

    qsc_memutils_secure_erase(t, sizeof(t));
    qsc_memutils_secure_erase(u, sizeof(u));
}
#endif


static void sc_mul(uint32_t r[8U], const uint32_t a[8U], const uint32_t b[8U])
{
    /* r = a * b mod n */
    uint32_t c[16U] = { 0U };

    sc256_mul_raw(c, a, b);
    sc256_reduce512(r, c);
}

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static void sc_mont_mul(uint32_t r[8U], const uint32_t a[8U], const uint32_t b[8U])
{
    /* compute one Montgomery product modulo the ECDSA subgroup order */
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
	mod_mont_mul64(r, a, b, P256_N64, UINT64_C(0xCCD1C8AAEE00BC4F));
#else
	uint32_t product[16U] = { 0U };

	fe256_mul_raw(product, a, b);
	mod_montgomery512(r, product, P256_N, 0xEE00BC4FU);
	qsc_memutils_secure_erase(product, sizeof(product));
#endif
}
#endif

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static void sc_mont_encode(uint32_t r[8U], const uint32_t a[8U])
{
    /* encode a canonical subgroup scalar into Montgomery representation */
	sc_mont_mul(r, a, P256_N_R2);
}
#endif

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static void sc_mont_decode(uint32_t r[8U], const uint32_t a[8U])
{
    /* decode an ECDSA subgroup scalar from Montgomery representation */
	static const uint32_t one[8U] = { 1U };

	sc_mont_mul(r, a, one);
}
#endif

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static void sc_mont_square_n(uint32_t value[8U], size_t count)
{
    /* envert a nonzero subgroup-order residue using a fixed public exponent */
	size_t i;

	for (i = 0U; i < count; ++i)
	{
		sc_mont_mul(value, value, value);
	}
}
#endif

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static void sc_inv_mont(uint32_t r[8U], const uint32_t a[8U])
{
    /* invert a nonzero Montgomery scalar using P-256 addition chain */
	uint32_t t[15U][8U] = { { 0U } };
	uint32_t z[8U] = { 0U };

	sc_mont_mul(t[1U], a, a);
	sc_mont_mul(t[5U], t[1U], t[1U]);
	sc_mont_mul(t[2U], t[5U], a);
	sc_mont_mul(t[10U], t[2U], a);
	sc_mont_mul(t[3U], t[2U], t[5U]);
	sc_mont_mul(z, t[10U], t[3U]);
	sc_mont_mul(t[9U], t[3U], t[3U]);
	sc_mont_mul(t[4U], t[10U], z);
	sc_mont_mul(t[0U], t[10U], t[9U]);
	sc_mont_mul(t[13U], t[0U], t[1U]);
	sc_mont_mul(t[8U], t[13U], t[4U]);
	sc_mont_mul(t[4U], t[3U], t[8U]);
	sc_mont_mul(t[7U], t[2U], t[4U]);
	sc_mont_mul(t[2U], t[1U], t[7U]);
	sc_mont_mul(t[6U], t[7U], t[9U]);
	sc_mont_mul(t[3U], t[6U], t[9U]);
	sc_mont_mul(t[1U], t[1U], t[3U]);
	sc_mont_mul(t[12U], t[3U], t[9U]);
	sc_mont_mul(t[5U], t[5U], t[12U]);
	sc_mont_mul(t[11U], t[10U], t[5U]);
	sc_mont_mul(t[0U], t[0U], t[11U]);
	sc_mont_mul(t[9U], t[9U], t[0U]);
	sc_mont_mul(t[10U], t[10U], t[9U]);
	sc_mont_mul(t[4U], t[4U], t[10U]);
	sc_mont_mul(t[13U], t[13U], t[4U]);
	sc_copy(t[14U], t[13U]);
	sc_mont_square_n(t[14U], 8U);
	sc_mont_mul(t[13U], t[13U], t[14U]);
	sc_copy(t[14U], t[13U]);
	sc_mont_square_n(t[14U], 16U);
	sc_mont_mul(t[14U], t[14U], t[13U]);
	sc_mont_square_n(t[14U], 48U);
	sc_mont_mul(t[14U], t[14U], t[13U]);
	sc_mont_square_n(t[14U], 16U);
	sc_mont_mul(t[14U], t[14U], t[13U]);
	sc_mont_square_n(t[14U], 16U);
	sc_mont_mul(t[14U], t[14U], t[13U]);
	sc_mont_square_n(t[14U], 16U);
	sc_mont_mul(t[13U], t[13U], t[14U]);
	sc_mont_square_n(t[13U], 6U);
	sc_mont_mul(t[13U], t[13U], t[8U]);
	sc_mont_square_n(t[13U], 9U);
	sc_mont_mul(t[12U], t[12U], t[13U]);
	sc_mont_square_n(t[12U], 8U);
	sc_mont_mul(t[11U], t[11U], t[12U]);
	sc_mont_square_n(t[11U], 9U);
	sc_mont_mul(t[10U], t[10U], t[11U]);
	sc_mont_square_n(t[10U], 8U);
	sc_mont_mul(t[9U], t[9U], t[10U]);
	sc_mont_square_n(t[9U], 9U);
	sc_mont_mul(t[8U], t[8U], t[9U]);
	sc_mont_square_n(t[8U], 8U);
	sc_mont_mul(t[7U], t[7U], t[8U]);
	sc_mont_square_n(t[7U], 11U);
	sc_mont_mul(t[6U], t[6U], t[7U]);
	sc_mont_square_n(t[6U], 9U);
	sc_mont_mul(t[5U], t[5U], t[6U]);
	sc_mont_square_n(t[5U], 10U);
	sc_mont_mul(t[4U], t[4U], t[5U]);
	sc_mont_square_n(t[4U], 8U);
	sc_mont_mul(t[3U], t[3U], t[4U]);
	sc_mont_square_n(t[3U], 7U);
	sc_mont_mul(t[2U], t[2U], t[3U]);
	sc_mont_square_n(t[2U], 10U);
	sc_mont_mul(t[1U], t[1U], t[2U]);
	sc_mont_square_n(t[1U], 10U);
	sc_mont_mul(t[0U], t[0U], t[1U]);
	sc_mont_square_n(t[0U], 6U);
	sc_mont_mul(z, z, t[0U]);

	sc_copy(r, z);
	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(z, sizeof(z));
}
#endif

#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static void sc_inv(uint32_t r[8U], const uint32_t a[8U])
{
    /* invert a canonical P-256 order scalar for constant-time verification */
	uint32_t mont[8U] = { 0U };

	sc_mont_encode(mont, a);
	sc_inv_mont(mont, mont);
	sc_mont_decode(r, mont);
	qsc_memutils_secure_erase(mont, sizeof(mont));
}
#endif

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
    /* branch-free Jacobian doubling.
     * for the Jacobian point-at-infinity representation used here, a result
     * with Z == 0 is treated as infinity by the rest of the code. */
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
    /* Constant-time Jacobian addition with masked exceptional-case handling.
     *
     * Cases handled without branches:
     *   1. P = inf  -> R = Q
     *   2. Q = inf  -> R = P
     *   3. P = Q    -> R = 2P
     *   4. P = -Q   -> R = inf
     *   5. general  -> standard add-2007-bl result */

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

#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static void p256_add_mixed(p256_jac_t* R, const p256_jac_t* P, const p256_jac_t* Q)
{
    /* constant-time Jacobian plus affine-point addition with masked exceptional cases */
	fe256 z1z1;
	fe256 u2;
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
	p256_jac_t sum;
	p256_jac_t doubled;
	p256_jac_t infinity;
	p256_jac_t selected;
	uint32_t pinf;
	uint32_t qinf;
	uint32_t hzero;
	uint32_t rzero;
	uint32_t equal;
	uint32_t opposite;
	uint32_t regular;

	fe_sqr(z1z1, P->Z);
	fe_mul(u2, Q->X, z1z1);
	fe_mul(s2, Q->Y, P->Z);
	fe_mul(s2, s2, z1z1);
	fe_sub(h, u2, P->X);
	fe_sub(r2, s2, P->Y);
	fe_mul_small(r2, r2, 2U);
	fe_mul_small(i, h, 2U);
	fe_sqr(i, i);
	fe_mul(j, h, i);
	fe_mul(v, P->X, i);
	fe_sqr(x3, r2);
	fe_sub(x3, x3, j);
	fe_sub(x3, x3, v);
	fe_sub(x3, x3, v);
	fe_sub(tmp, v, x3);
	fe_mul(y3, r2, tmp);
	fe_mul(tmp, P->Y, j);
	fe_mul_small(tmp, tmp, 2U);
	fe_sub(y3, y3, tmp);
	fe_mul(z3, P->Z, h);
	fe_mul_small(z3, z3, 2U);
	fe256_copy(sum.X, x3);
	fe256_copy(sum.Y, y3);
	fe256_copy(sum.Z, z3);

	p256_dbl(&doubled, P);
	p256_set_infinity(&infinity);
	pinf = p256_is_infinity(P);
	qinf = p256_is_infinity(Q);
	hzero = fe256_is_zero(h);
	rzero = fe256_is_zero(r2);
	equal = hzero & rzero;
	opposite = hzero & (rzero ^ 1U);
	regular = (pinf | qinf | equal | opposite) ^ 1U;
	p256_set_infinity(&selected);
	p256_jac_ct_select(&selected, regular, &sum, &selected);
	p256_jac_ct_select(&selected, equal, &doubled, &selected);
	p256_jac_ct_select(&selected, opposite, &infinity, &selected);
	p256_jac_ct_select(&selected, qinf, P, &selected);
	p256_jac_ct_select(&selected, pinf, Q, &selected);
	*R = selected;

	qsc_memutils_secure_erase(&sum, sizeof(sum));
	qsc_memutils_secure_erase(&doubled, sizeof(doubled));
	qsc_memutils_secure_erase(&infinity, sizeof(infinity));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
}
#endif

/*! \brief Multiply the fixed P-256 generator using signed windows.
 * \param R: [p256_jac_t*] Writable projective result, QSC Montgomery domain.
 * \param k: [const uint32_t*] Valid scalar less than the curve subgroup order.
 * \note Uses 65 fixed iterations, masked scanning of eight read-only
 * points per window, and no secret-derived branches or array indexes.
 * No assembly or mutable global state is used.
 */
static const uint32_t P256_BOTAN_BOOTH_MONT[65U][8U][2U][8U] =
{
    { { { 0x18A9143CU, 0x79E730D4U, 0x5FEDB601U, 0x75BA95FCU, 0x77622510U, 0x79FB732BU, 0xA53755C6U, 0x18905F76U }, { 0xCE95560AU, 0xDDF25357U, 0xBA19E45CU, 0x8B4AB8E4U, 0xDD21F325U, 0xD2E88688U, 0x25885D85U, 0x8571FF18U } },
      { { 0x10DDD64DU, 0x850046D4U, 0xA433827DU, 0xAA6AE3C1U, 0x8D1490D9U, 0x73220503U, 0x3DCF3A3BU, 0xF6BB32E4U }, { 0x61BEE1A5U, 0x2F3648D3U, 0xEB236FF8U, 0x152CD7CBU, 0x92042DBEU, 0x19A8FB0EU, 0x0A5B8A3BU, 0x78C57751U } },
      { { 0x4EEBC127U, 0xFFAC3F90U, 0x087D81FBU, 0xB027F84AU, 0x87CBBC98U, 0x66AD77DDU, 0xB6FF747EU, 0x26936A3FU }, { 0xC983A7EBU, 0xB04C5C1FU, 0x0861FE1AU, 0x583E47ADU, 0x1A2EE98EU, 0x78820831U, 0xE587CC07U, 0xD5F06A29U } },
      { { 0x46918DCCU, 0x74B0B50DU, 0xC623C173U, 0x4650A6EDU, 0xE8100AF2U, 0x0CDAACACU, 0x41B0176BU, 0x577362F5U }, { 0xE4CBABA6U, 0x2D96F24CU, 0xFAD6F447U, 0x17628471U, 0xE5DDD22EU, 0x6B6C36DEU, 0x4C5AB863U, 0x84B14C39U } },
      { { 0xC45C61F5U, 0xBE1B8AAEU, 0x94B9537DU, 0x90EC649AU, 0xD076C20CU, 0x941CB5AAU, 0x890523C8U, 0xC9079605U }, { 0xE7BA4F10U, 0xEB309B4AU, 0xE5EB882BU, 0x73C568EFU, 0x7E7A1F68U, 0x3540A987U, 0x2DD1E916U, 0x73A076BBU } },
      { { 0x3E77664AU, 0x40394737U, 0x346CEE3EU, 0x55AE744FU, 0x5B17A3ADU, 0xD50A961AU, 0x54213673U, 0x13074B59U }, { 0xD377E44BU, 0x93D36220U, 0xADFF14B5U, 0x299C2B53U, 0xEF639F11U, 0xF424D44CU, 0x4A07F75FU, 0xA4C9916DU } },
      { { 0xA0173B4FU, 0x0746354EU, 0xD23C00F7U, 0x2BD20213U, 0x0C23BB08U, 0xF43EAAB5U, 0xC3123E03U, 0x13BA5119U }, { 0x3F5B9D4DU, 0x2847D030U, 0x5DA67BDDU, 0x6742F2F2U, 0x77C94195U, 0xEF933BDCU, 0x6E240867U, 0xEAEDD915U } },
      { { 0x9499A78FU, 0x27F14CD1U, 0x6F9B3455U, 0x462AB5C5U, 0xF02CFC6BU, 0x8F90F02AU, 0xB265230DU, 0xB763891EU }, { 0x532D4977U, 0xF59DA3A9U, 0xCF9EBA15U, 0x21E3327DU, 0xBE60BBF0U, 0x123C7B84U, 0x7706DF76U, 0x56EC12F2U } } } /* window 0 */,
    { { { 0x0BC6FB80U, 0x808B0B65U, 0x3FFE2E6BU, 0x5882E075U, 0x2C83F549U, 0xD5EF2F7CU, 0x9103B723U, 0x54D63C80U }, { 0x52A23F9BU, 0xF2F11BD6U, 0x4B0B6587U, 0x3670C319U, 0xB1580E9EU, 0x55C4623BU, 0x01EFE220U, 0x64EDF7B2U } },
      { { 0xC5E3A3D8U, 0xD8C5FCCFU, 0x4079DFBFU, 0xBEFD904CU, 0xFEAD0197U, 0xBC6D6A58U, 0x695532A4U, 0x39227077U }, { 0xDBEF42F5U, 0x09E23E6DU, 0x480A9908U, 0x7E449B64U, 0xAD9A2E40U, 0x7B969C1AU, 0x9591C2A4U, 0x6231D792U } },
      { { 0x77ADC612U, 0x6B344130U, 0xBBD803A0U, 0xA7496529U, 0x6D8805BDU, 0x1A1BAAA7U, 0x470343ADU, 0xC8403902U }, { 0x175ADFF1U, 0x39F59F66U, 0xB7D8C5B7U, 0x0B26D7FBU, 0x529D75E3U, 0xA875F5CEU, 0x41325CC2U, 0x85EFC7E9U } },
      { { 0x05968B80U, 0xDB6D96F3U, 0x089F73B9U, 0x380A0913U, 0xC2C61E01U, 0x7DA70B83U, 0x569B38C7U, 0x95FB8394U }, { 0x80EDFE2FU, 0x9A3C6512U, 0x8FAEAF82U, 0x8F726BB9U, 0x78424BF8U, 0x8010A4A0U, 0x0E844970U, 0x29672044U } },
      { { 0x52B3E584U, 0x492BDC07U, 0xB5F86A2CU, 0x35FF9AA8U, 0xB27DE573U, 0x2074213DU, 0x5263832AU, 0xC0BFFFC4U }, { 0x1D49C605U, 0x2429C22AU, 0xB320EBFBU, 0x1B037D75U, 0x9220F428U, 0x52B6A173U, 0xA4CD2660U, 0x2995919CU } },
      { { 0x33E12B70U, 0x802B8D23U, 0x19DD329BU, 0x6D490A4BU, 0x6ABC354DU, 0x14F356CCU, 0xD0A0DA0DU, 0x11EDDF7FU }, { 0xD87FD1D8U, 0x1E208328U, 0xFD025813U, 0xFD2F4F8CU, 0x7C29BCA2U, 0x03B48CC4U, 0x241A2B71U, 0x3F2A78B3U } },
      { { 0x0A99CBCAU, 0x6A950576U, 0x04A428F2U, 0x94E258F6U, 0x7832BA0CU, 0x45AB5A4DU, 0x8938C167U, 0x71704D00U }, { 0xF88B8B70U, 0xDB97AB0EU, 0xC00EB207U, 0x56FEB92EU, 0x7D367D80U, 0xE7035268U, 0xC7973A41U, 0x65000C24U } },
      { { 0x7A2AD62AU, 0x63C5CB81U, 0xAC62FF54U, 0x7EF2B6B9U, 0xB3AD9DB5U, 0x3749BBA4U, 0x46D5A617U, 0xAD311F2CU }, { 0xC2FF3B6DU, 0xB77A8087U, 0x367834FFU, 0xB46FEAF3U, 0x75D6B138U, 0xF8AA266DU, 0xEC008188U, 0xFA38D320U } } } /* window 1 */,
    { { { 0x696946FCU, 0x486D8FFAU, 0xB9CBA56DU, 0x50FBC6D8U, 0x90F35A15U, 0x7E3D423EU, 0xC0DD962CU, 0x7C3DA195U }, { 0x3CFD5D8BU, 0xE673FDB0U, 0x889DFCA5U, 0x0704B7C2U, 0xF52305AAU, 0xF6CE581FU, 0x914D5E53U, 0x399D49EBU } },
      { { 0x39949296U, 0x44E38110U, 0x361DB1B5U, 0x5B63827BU, 0x206EAFF5U, 0x3E5323EDU, 0xC21F4290U, 0x942370D2U }, { 0xE0D985A1U, 0xF2CAAF2EU, 0x7239846DU, 0x192CC64BU, 0xAE6312F8U, 0x7C0B8F47U, 0x96620108U, 0x7DC61F91U } },
      { { 0xED4C3717U, 0x35D6A53EU, 0x3D0ED2A3U, 0x9F8240CFU, 0xE5543AA5U, 0x8C0D4D05U, 0xDD33B4B4U, 0x45D5BBFBU }, { 0x137FD28EU, 0xFA04CC73U, 0xC73B3FFDU, 0x862AC6EFU, 0x31F51EF2U, 0x403FF9F5U, 0xBC73F5A2U, 0x34D5E0FCU } },
      { { 0x44CC3ADDU, 0x4F7081E1U, 0x87BE82CFU, 0xD5FFA1D6U, 0x0EDD6472U, 0x89890B6CU, 0x3ED17863U, 0xADA26E1AU }, { 0x63483CAAU, 0x276F2715U, 0x2F6077FDU, 0xE6924CD9U, 0x0A466E3CU, 0x05A7FE98U, 0xB1902D1FU, 0xF1C794B0U } },
      { { 0x08369A90U, 0x33B2385CU, 0x190EB4F8U, 0x2990C59BU, 0xC68EAC80U, 0x819A6145U, 0x2EC4A014U, 0x7A786D62U }, { 0x20AC3A8DU, 0x33FAADBEU, 0x5ABA2D30U, 0x31A21781U, 0xDBA4F565U, 0x209D2742U, 0x55AA0FBBU, 0xDB2CE9E3U } },
      { { 0x8BD7AFF1U, 0xB3156BF3U, 0x1D81B146U, 0x1B5EE4CBU, 0xD628A915U, 0x7BA1AC41U, 0xFD89699EU, 0x8F3A8F9CU }, { 0xA0748BE7U, 0x7329B9C9U, 0xA92E621FU, 0x1D391C95U, 0x4D10A837U, 0xE51E6B21U, 0x4947B435U, 0xD255F53AU } },
      { { 0x74A86108U, 0x0C4A58D4U, 0xEE4C5D90U, 0xF8048A8FU, 0xE86D4C80U, 0xE3C7C924U, 0x056A1E60U, 0x28C889DEU }, { 0xB214A040U, 0x57E2662EU, 0x37E10347U, 0xE8C48E98U, 0x80AC748AU, 0x87742862U, 0x186B06F2U, 0xF1C24022U } },
      { { 0xEB7926B8U, 0x3D2B24B9U, 0xCDBE5509U, 0xBFF88CB3U, 0xE4DD640BU, 0xD0F399AFU, 0x2F76ED45U, 0x3C5FE130U }, { 0x3764FB3DU, 0x6F3562F4U, 0x3151B62DU, 0x7B5AF318U, 0xD79CE5F3U, 0xD5BD0BC7U, 0xEC66890FU, 0xFDAF6B20U } } } /* window 2 */,
    { { { 0xAB4B35A2U, 0x6772B0E5U, 0xF5EEAACFU, 0x1D8B6001U, 0x795B9580U, 0x728F7CE4U, 0x41FB81DAU, 0x4A20ED2AU }, { 0x4FEC01E6U, 0x9F685CD4U, 0xA7FF50ADU, 0x3ED7DDCCU, 0x0C2D97FDU, 0x460FD264U, 0xEB82F4F9U, 0x3A241426U } },
      { { 0xD5D721D5U, 0x80009862U, 0x5BD3A182U, 0x0C3357A3U, 0x7AA2CDA4U, 0x27F3A83BU, 0xF6F83085U, 0xB58AE74EU }, { 0x2E6DAD6BU, 0x2A911A81U, 0xF43D6C5BU, 0xDE286051U, 0xF996C4D8U, 0x4BDCCC41U, 0x0AE1E24EU, 0xE7312EC0U } },
      { { 0xAAE6EE70U, 0x6FAF68FEU, 0x5602B0C9U, 0x78F4CC15U, 0x6E94052AU, 0x7E3321A8U, 0x734D5D80U, 0x2FB3A0D6U }, { 0xB25A43BAU, 0xF3B98F3BU, 0x19EE2951U, 0x30BF8031U, 0x21B0612AU, 0x7FFEE433U, 0x2EB821D0U, 0x12F775E4U } },
      { { 0x6E6485B3U, 0xF8D112E7U, 0x771C52F8U, 0x4D3E24DBU, 0x684A2F6DU, 0x48E3EE41U, 0x21D95551U, 0x7161957DU }, { 0xCDB12A6CU, 0x19631283U, 0x2E50E164U, 0xBF3FA882U, 0x3166CC73U, 0xF6254B63U, 0xAEE8CC38U, 0x3AEFA7AEU } },
      { { 0x37A929A9U, 0x46F70080U, 0x19FEC6BDU, 0x65601A8EU, 0x12AB8B62U, 0x537F5EDCU, 0x5E5990CFU, 0xE497CD95U }, { 0x9AA5B2F9U, 0x2FCD387FU, 0x67B78FE8U, 0xE5FAA3FFU, 0x295D5E30U, 0x1BCF538DU, 0xA813A7ECU, 0x3A573239U } },
      { { 0xD17C2409U, 0xE9F5286BU, 0x63264D9BU, 0x2C4E4793U, 0x17F6880FU, 0x177042B1U, 0x4CE1EE43U, 0x39B7E2C8U }, { 0xD096F4A9U, 0xCEC8E722U, 0xBED5E697U, 0x6861AECBU, 0x6C231911U, 0xC2D153F0U, 0x2890537AU, 0xCC2F42B8U } },
      { { 0xD0A917B4U, 0x33E2CB51U, 0x4899F931U, 0xC2CFA3F3U, 0xE9A2F6B6U, 0xB2C94F4BU, 0x7CA162B7U, 0x9707B181U }, { 0xD5F8B10DU, 0xB602A172U, 0x4FD4542AU, 0xFD307835U, 0xDD996992U, 0xEEF226DDU, 0xEB0A15E1U, 0x221FA989U } },
      { { 0x3B36F9FDU, 0x79B0FE62U, 0xFDE19FC0U, 0x26543B23U, 0x958482EFU, 0x136E64A0U, 0x9B095825U, 0x23F63771U }, { 0xB6A1142EU, 0x14CFD596U, 0x335AAC0BU, 0x5EA6AAC6U, 0xF3081DD5U, 0x86A0E8BDU, 0x003DC12AU, 0x5FB89D79U } } } /* window 3 */,
    { { { 0xE3779EE3U, 0x0F0165FCU, 0xBD495D9EU, 0xE00E7F9DU, 0x20284E7AU, 0x1FA4EFA2U, 0x47AC6219U, 0x4564BADEU }, { 0xC4708E8EU, 0x90E6312AU, 0xA71E9ADFU, 0x4F5725FBU, 0x3D684B9FU, 0xE95F55AEU, 0x1E94B415U, 0x47F7CCB1U } },
      { { 0x61A341C1U, 0x36178903U, 0x0CFD6142U, 0x3604DC60U, 0x8533316CU, 0x022295EBU, 0x44AF2922U, 0x3DBDE4ACU }, { 0x1C7EEF69U, 0x898AFC5DU, 0xD14F4FA1U, 0x58896805U, 0x203C21CAU, 0x05002160U, 0x40EF730BU, 0x6F0D1F30U } },
      { { 0xBE7A2AF3U, 0xBD9B8B1DU, 0x4FB74A72U, 0xEC51CAA9U, 0x63879697U, 0xB9937A4BU, 0xEC2687D5U, 0x7C9A9D20U }, { 0x6EF5F014U, 0x1773E44FU, 0xE90C6900U, 0x8ABCF412U, 0x8142161EU, 0x387BD022U, 0xFCB6FF2AU, 0x50393755U } },
      { { 0x77F7195AU, 0xFABF7709U, 0xADEB838FU, 0x8EC86167U, 0xBB4F012DU, 0xEA1285A8U, 0x9A3EAB3FU, 0xD6883503U }, { 0x309004C2U, 0xEE5D24F8U, 0x13FFE95EU, 0xA96E4B76U, 0xBD223EA4U, 0x0CDFFE12U, 0xB6739A53U, 0x8F5C2EE5U } },
      { { 0x59145A65U, 0x3D613339U, 0xFA406337U, 0xCD9BC368U, 0x2D8A52A0U, 0x82D11BE3U, 0x97A1C590U, 0xF6877B27U }, { 0xF5CBDB25U, 0x837A819BU, 0xDE090249U, 0x2A4FD1D8U, 0x74990E5FU, 0x622A7DE7U, 0x7945511BU, 0x840FA5A0U } },
      { { 0x6B0CF82EU, 0xE58E90B3U, 0x2615B5E7U, 0x6438D246U, 0x669C145AU, 0x07B1F8FCU, 0x36F1E1CBU, 0xB0D8B2DAU }, { 0xD9184C4DU, 0x54D5DADBU, 0xF93D9976U, 0x3DBB18D5U, 0xD1147D47U, 0x0A3E0F56U, 0xA0A48609U, 0x2AFA8C8DU } },
      { { 0xE3533D77U, 0x26E08C07U, 0x2E341C99U, 0xD7222E6AU, 0x8D2DC4EDU, 0x9D60EC3DU, 0x7C476CF8U, 0xBDFE0D8FU }, { 0x1D056605U, 0x1FE59AB6U, 0x86A8551FU, 0xA9EA9DF6U, 0x47FB8D8CU, 0x8489941EU, 0x4A7F1B10U, 0xFEB874EBU } },
      { { 0xBD763802U, 0xED406AA9U, 0x65303DA1U, 0xC21486A0U, 0xC7E62EC4U, 0x61AE291EU, 0xDF99333EU, 0x622A0492U }, { 0xBB7A8EE0U, 0x7FD80C9DU, 0x6C01AEDBU, 0xDC2ED3BCU, 0x08BE74ECU, 0x35C35A12U, 0x469F671FU, 0xD540CB1AU } } } /* window 4 */,
    { { { 0x584C5E20U, 0xA7A8746AU, 0xB9DC7035U, 0x267E4EA1U, 0xB9548C9BU, 0x593A15CFU, 0x4BD012F3U, 0x5E6E2135U }, { 0x8C8F936EU, 0xDF31CC6AU, 0xB5C241DCU, 0x8AF84D04U, 0x345EFB86U, 0x63990A6FU, 0xB9B962CBU, 0x6FEF4E61U } },
      { { 0x25722608U, 0xF6368F09U, 0x131CF5C6U, 0x131260DBU, 0xFAB4F7ACU, 0x40EB353BU, 0x37EEE829U, 0x85C78880U }, { 0xC3BDF24EU, 0x4C1581FFU, 0xF5C3C5A8U, 0x5BFF75CBU, 0xA14E6F40U, 0x35E8C83FU, 0x0295E0CAU, 0xB81D1C0FU } },
      { { 0x442A8AD1U, 0xF2EFE23DU, 0x06B9C164U, 0xC3816A7DU, 0xDC0AA5E5U, 0xA9DF2D8BU, 0x120A8E65U, 0x191AE46FU }, { 0x00611C5BU, 0x83667F87U, 0xFF109948U, 0x83171ED7U, 0xCA695952U, 0x33A2ECF8U, 0xF48D1A13U, 0xFA4A73EEU } },
      { { 0xF43A730FU, 0xFCDE7CC8U, 0x33AB590EU, 0xE89B6F3CU, 0xAD03240BU, 0xC823F529U, 0x98BEA5DBU, 0x82B79AFEU }, { 0x962FE5DEU, 0x568F2856U, 0x60C591F3U, 0x0C590ADBU, 0x4A28A858U, 0x1FC74A14U, 0xB3203F4CU, 0x3B662498U } },
      { { 0x82DD1B6AU, 0x48FC4ED0U, 0x67B703AFU, 0x5783A138U, 0x005D6AAAU, 0x2463CB9AU, 0x706ECD43U, 0xD31EC55CU }, { 0x8E9A7641U, 0x9F8ED33FU, 0x098D9E7AU, 0x625453EDU, 0xEC887493U, 0xA3BEADE4U, 0x5A795566U, 0x442B8050U } },
      { { 0x6C39765AU, 0x91E3CF0DU, 0xAC3CCA0BU, 0xA2DB3ACDU, 0xCB953B50U, 0x288F2F08U, 0xCF43CF1AU, 0x2414582CU }, { 0x60EEE9A8U, 0x8DEC8BBCU, 0x729AA042U, 0x54C79F02U, 0x6532F5D5U, 0xD81CD5ECU, 0xCF82E15FU, 0xA672303AU } },
      { { 0x3BFAB839U, 0x46DF582DU, 0x2F8ADADEU, 0x92474E04U, 0x147A1BC3U, 0x36A7766AU, 0x0DC0F979U, 0xB6940F54U }, { 0xF2759F25U, 0x44738EF2U, 0xA719F4C6U, 0x9DD95789U, 0x0750C345U, 0x2859B7F4U, 0xB22180D5U, 0x5E788BF2U } },
      { { 0x719C0563U, 0x376AAFA8U, 0xBC5FC79FU, 0xCD8AD2DCU, 0xCB750CD3U, 0x303FDB9FU, 0x4418B08EU, 0x14FF052FU }, { 0x3E2D6520U, 0xF75084CFU, 0x144ED509U, 0x7EBDF0F8U, 0xD3F25B98U, 0xF43BF0F2U, 0xA354D837U, 0x86AD71CFU } } } /* window 5 */,
    { { { 0x868AF75DU, 0xD9D0C8C4U, 0x45C8C7EAU, 0xD7325CFFU, 0xCC81ECB0U, 0xAB471996U, 0x611824EDU, 0xFF5D55F3U }, { 0x1977A0EEU, 0xBE314541U, 0x722038C6U, 0x5085C4C5U, 0xF94BB495U, 0x2D5335BFU, 0xC8E2A082U, 0x894AD8A6U } },
      { { 0x2C11BB37U, 0x540234B2U, 0xED4C74A3U, 0x2D0366DDU, 0xEEC5F25DU, 0xF9A968DAU, 0x67B63142U, 0x36601068U }, { 0x68D7B6D4U, 0x07CD6D2CU, 0x0C842942U, 0xA8F74F09U, 0x7768B1EEU, 0xE2751404U, 0xFE62AEE4U, 0x4B5F7E89U } },
      { { 0x1994EF20U, 0xD1E059B2U, 0x638AE318U, 0x2A653B69U, 0x2F699010U, 0x70D5EB58U, 0x09F5F84AU, 0x279739F7U }, { 0x8B799336U, 0x5DA4663CU, 0x203C37EBU, 0xFDFDF14DU, 0xA1DBFB2DU, 0x32D8A9DCU, 0x77D48F9BU, 0xAB40CFF0U } },
      { { 0x879FBBEDU, 0xF2369F0BU, 0xDA9D1869U, 0x0FF0AE86U, 0x56766F45U, 0x5251D759U, 0x2BE8D0FCU, 0x4984D8C0U }, { 0xD21008F0U, 0x7ECC95A6U, 0x3A1A1C49U, 0x29BD54A0U, 0xD26C50F3U, 0xAB9828C5U, 0x51D0D251U, 0x32C0087CU } },
      { { 0xFBAF50A5U, 0xF61790ABU, 0x684E0750U, 0xDF55E76BU, 0xF176B005U, 0xEC516DA7U, 0x7A2DDDC7U, 0x575553BBU }, { 0x553AFA73U, 0x37C87CA3U, 0x4D55C251U, 0x315F3FFCU, 0xAF3E5D35U, 0xE846442AU, 0x6495FF28U, 0x61B91149U } },
      { { 0x62B5F3AFU, 0x47FEEB66U, 0x0ABB3734U, 0xCEFAB561U, 0x19F35CB1U, 0x449DE60EU, 0x157F0EB9U, 0x39F8DB14U }, { 0x3C61BFD6U, 0xFFAECC5BU, 0x41216703U, 0xA5A4D41DU, 0x224E1CC2U, 0x7F8FABEDU, 0x871AD953U, 0x0D5A8186U } },
      { { 0x56F90823U, 0x4BDF3A49U, 0x741D777BU, 0xBA0F5080U, 0xF38BF760U, 0x091D71C3U, 0x9B625B02U, 0x9633D50FU }, { 0xB8C9DE61U, 0x03ECB743U, 0x5DE74720U, 0xB4751254U, 0x74CE1CB2U, 0x9F9DEFC9U, 0x00BD32EFU, 0x774A4F6AU } },
      { { 0x01799A52U, 0x190D8EA6U, 0xB86D2952U, 0xA20CEC41U, 0x7FFF2A7CU, 0x3062FFB2U, 0x79F19D37U, 0x741B32E5U }, { 0x4EB57D47U, 0xF80D8181U, 0x16AEF06BU, 0x7A2D0ED4U, 0x1CECB588U, 0x09735FB0U, 0xC6061F5BU, 0x1641CAAAU } } } /* window 6 */,
    { { { 0x20151427U, 0x7F99824FU, 0x92430206U, 0x206828B6U, 0xE1112357U, 0xAA9097D7U, 0x09E414ECU, 0xACF9A2F2U }, { 0x27915356U, 0xDBDAC9DAU, 0x001EFEE3U, 0x7E0734B7U, 0xD2B288E2U, 0x54FAB5BBU, 0xF62DD09CU, 0x4C630FC4U } },
      { { 0x1AC2703BU, 0x8537107AU, 0x6BC857B5U, 0xB49258D8U, 0xBCDACCD1U, 0x57DF14DEU, 0xC4AE8529U, 0x24AB68D7U }, { 0x734E59D0U, 0x7ED8B5D4U, 0xC495CC80U, 0x5F8740C8U, 0x291DB9B3U, 0x84AEDD5AU, 0x4FB995BEU, 0x80B360F8U } },
      { { 0x5FA067D1U, 0xAE915F5DU, 0x9668960CU, 0x4134B57FU, 0xA48EDAACU, 0xBD3656D6U, 0xFC1D7436U, 0xDAC1E3E4U }, { 0xD81FBB26U, 0x674FF869U, 0xB26C33D4U, 0x449ED3ECU, 0xD94203E8U, 0x85138705U, 0xBEEB6F4AU, 0xCCDE538BU } },
      { { 0xA61A76FAU, 0x55D5C68DU, 0xCA1554DCU, 0x598B441DU, 0x773B279CU, 0xD39923B9U, 0x36BF9EFCU, 0x33331D3CU }, { 0x298DE399U, 0x2D4C848EU, 0xA1A27F56U, 0xCFDB8E77U, 0x57B8AB70U, 0x94C855EAU, 0x6F7879BAU, 0xDCDB9DAEU } },
      { { 0x019F2A59U, 0x7BDFF8C2U, 0xCB4FBC74U, 0xB3CE5BB3U, 0x8A9173DDU, 0xEA907F68U, 0x95A75439U, 0x6CD3D0D3U }, { 0xEFED021CU, 0x92ECC4D6U, 0x6A77339AU, 0x09A9F9B0U, 0x7188C64AU, 0x87CA6B15U, 0x44899158U, 0x10C29968U } },
      { { 0xED6E82EFU, 0x5859A229U, 0x65EBAF4EU, 0x16F338E3U, 0x5EAD67AEU, 0x0CD31387U, 0x54EF0BB4U, 0x1C73D228U }, { 0x74A5C8C7U, 0x4CB55131U, 0x7F69AD6AU, 0x01CD2970U, 0xE966F87EU, 0xA04D00DDU, 0x0B7B0321U, 0xD96FE447U } },
      { { 0x88FBD381U, 0x342AC06EU, 0x5C35A493U, 0x02CD4A84U, 0x54F1BBCDU, 0xE8FA89DEU, 0x2575ED4CU, 0x341D6367U }, { 0xD238202BU, 0xEBE357FBU, 0xA984EAD9U, 0x600B4D1AU, 0x52436EA0U, 0xC35C9F44U, 0xA370751BU, 0x96FE0A39U } },
      { { 0x7F636A38U, 0x4C4F0736U, 0x0E76D5CBU, 0x9F943FB7U, 0xA8B68B8BU, 0xB03510BAU, 0x9ED07A1FU, 0xC246780AU }, { 0x6D549FC2U, 0x3C051415U, 0x607781CAU, 0xC2953F31U, 0xD8D95413U, 0x955E2C69U, 0x7BD282E3U, 0xB300FADCU } } } /* window 7 */,
    { { { 0x4147519AU, 0x20288602U, 0x26B372F0U, 0xD0981EACU, 0xA785EBC8U, 0xA9D4A7CAU, 0xDBDF58E9U, 0xD953C50DU }, { 0xFD590F8FU, 0x9D6361CCU, 0x44E6C917U, 0x72E9626BU, 0x22EB64CFU, 0x7FD96110U, 0x9EB288F3U, 0x863EBB7EU } },
      { { 0x678A31B0U, 0x877B7CF5U, 0x3998B620U, 0xD50301AEU, 0xC00FB396U, 0x734257C5U, 0x04E672A6U, 0xF9FB18A0U }, { 0xE8758851U, 0xFF8BD8EBU, 0x5D99BA44U, 0x1E64E4C6U, 0x7DFD93B7U, 0x4B8EAEDFU, 0x04E76B8CU, 0xBA2F2A98U } },
      { { 0xE90FB21EU, 0xA18F07E0U, 0xBBA7FCA1U, 0x00FD2B80U, 0x95CD67B5U, 0x20387F27U, 0xD39707F7U, 0x5B89A4E7U }, { 0x894407CEU, 0x8F83AD3FU, 0x6C226132U, 0xA0025B94U, 0xF906C13BU, 0xC79563C7U, 0x4E7BB025U, 0x5F548F31U } },
      { { 0xC35D8794U, 0x0EE6D3A7U, 0x0356BAE5U, 0x042E6558U, 0x643322FDU, 0x9F59698DU, 0x50A61967U, 0x9379AE15U }, { 0xFCC9981EU, 0x64B9AE62U, 0x6D2934C6U, 0xAED3D631U, 0x5E4E65EBU, 0x2454B302U, 0xF9950428U, 0xAB09F647U } },
      { { 0x31B85F09U, 0xC1B3D3D3U, 0xA88AE64AU, 0x0F45354AU, 0x2FEC50FDU, 0xA8B626D3U, 0xE828834FU, 0x1BDCFBD4U }, { 0xCD522539U, 0xE45A2866U, 0x810F7AB3U, 0xFA9D4732U, 0xC905F293U, 0xD8C1D6B4U, 0x3461B597U, 0x10AC8047U } },
      { { 0x6D91CD2CU, 0xE2C81536U, 0xDAA3F0E4U, 0x40A2BEEAU, 0x2441E083U, 0xFB167A59U, 0xE9240347U, 0x004675E9U }, { 0x840E446EU, 0x7848AAFFU, 0xEA308F72U, 0x9F9F258FU, 0x639BFAD9U, 0x50F12899U, 0x205C0AF6U, 0x0939AE63U } },
      { { 0x6FC627E2U, 0xBBB17514U, 0x91573A51U, 0xA0569BC5U, 0x358243D5U, 0xA7016D9EU, 0xAC1D6692U, 0x0DAC0C56U }, { 0xDA590D5FU, 0x993833B5U, 0xDE817491U, 0xA8067803U, 0x4DBF75D0U, 0x65B4F212U, 0xCCF80CFBU, 0xCC960232U } },
      { { 0x22248ACCU, 0xB2083A12U, 0x3264E366U, 0x1F6EC0EFU, 0x5AFDEE28U, 0x5659B704U, 0xE6430BB5U, 0x7A823A40U }, { 0xE1900A79U, 0x24592A04U, 0xC9EE6576U, 0xCDE09D4AU, 0x4B5EA54AU, 0x52B6463FU, 0xD3CA65A7U, 0x1EFE9ED3U } } } /* window 8 */,
    { { { 0x305406DDU, 0xE27A6DBEU, 0xDD5D1957U, 0x8EB7DC7FU, 0x387D4D8FU, 0xF54A6876U, 0xC7762DE4U, 0x9C479409U }, { 0x99B30778U, 0xBE4D5B5DU, 0x6E793682U, 0x25380C56U, 0xDAC740E3U, 0x602D37F3U, 0x1566E4AEU, 0x140DEABEU } },
      { { 0xC49A861EU, 0xEAEE6126U, 0xE14F0D06U, 0x024F3B65U, 0xC69BFC17U, 0x51A3F1E8U, 0xA7686381U, 0xC3C3A8E9U }, { 0xB103D4C8U, 0x3400752CU, 0x9218B36BU, 0x02BC4613U, 0x7651504AU, 0xC67F75EBU, 0xD02AEBFAU, 0xD6848B56U } },
      { { 0x1782269BU, 0x958381DBU, 0x2597E550U, 0xAE34BF79U, 0x5F385153U, 0xBB5C6064U, 0xE3088048U, 0x6F0E96AFU }, { 0x77884456U, 0xBF6A0215U, 0x69310EA7U, 0xB3B5688CU, 0x04FAD2DEU, 0x17C94295U, 0x17896D4DU, 0xE020F0E5U } },
      { { 0xBBE5A1A9U, 0xCCA4428DU, 0x3126BD67U, 0x8187FD5FU, 0x48105826U, 0x0036973AU, 0xB8BD61A0U, 0xA39B6663U }, { 0x2D65A808U, 0x6D42DEEFU, 0x94636B19U, 0x4969044FU, 0xDD5D564CU, 0xF611EE47U, 0xD2873077U, 0x7B2F3A49U } },
      { { 0x0F82B214U, 0x03B0D8DDU, 0xF103CBC6U, 0x460C34F9U, 0x18D79E19U, 0xF32E5C03U, 0xA84117F8U, 0x8B8888BAU }, { 0xC0722677U, 0x8F3C37DCU, 0x1C1C0F27U, 0x10D21BE9U, 0xE0F7A0C6U, 0xD47C8468U, 0xADECC0E0U, 0x9BF02213U } },
      { { 0xB7FE7B6EU, 0x97554160U, 0x400A3FB2U, 0x7D16189AU, 0xE328CA1EU, 0xD73E9BEAU, 0xE793D8CCU, 0x0DD04B97U }, { 0x506DB8CCU, 0xA9C83C9BU, 0xCF38814CU, 0x5CD47AAEU, 0xB64B45E6U, 0x26FC430DU, 0xD818EA84U, 0x079B5499U } },
      { { 0xE0AC2941U, 0x03B5D21AU, 0xC2D31937U, 0x279B0254U, 0xCAC992D0U, 0x3307C052U, 0xEFA8B1F3U, 0x6AA7CB92U }, { 0x0D37C7A5U, 0x5A182580U, 0x342D5422U, 0x13380C37U, 0xD5D2EF92U, 0x92AC2D66U, 0x030C63C6U, 0x035A70C9U } },
      { { 0x71BA1861U, 0x5109B785U, 0xD0C8F93DU, 0x48B22D5CU, 0x8633BB93U, 0xE8FA84A7U, 0x5AEBBD08U, 0x53FBA6BAU }, { 0xE5EEA7D8U, 0x7FF27DF3U, 0x68CA7158U, 0x521C8796U, 0xCE6F1A05U, 0xB9D5133BU, 0xFD0EBEE4U, 0x2D50CD53U } } } /* window 9 */,
    { { { 0x533EF217U, 0x889F6D65U, 0xC3CA2E87U, 0x7158C7E4U, 0xDC2B4167U, 0xFB670DFBU, 0x844C257FU, 0x75910A01U }, { 0xCF88577DU, 0xF336BF07U, 0xE45E2ACEU, 0x22245250U, 0x7CA23D85U, 0x2ED92E8DU, 0x2B812F58U, 0x29F8BE4CU } },
      { { 0x2133FFD9U, 0xFBB9B245U, 0x830F1A20U, 0x39A8B2F1U, 0xD5A1F52AU, 0x484BC97DU, 0xA40EDDF8U, 0xD6AEBF56U }, { 0x76CCDAC6U, 0x32257ACBU, 0x1586FF27U, 0xAF4D36ECU, 0xF8DE7DD1U, 0x8EAA8863U, 0x88647C16U, 0x0045D5CFU } },
      { { 0x51FACC61U, 0xC51E4143U, 0xE68A25BCU, 0xBAF2647DU, 0x0FF872EDU, 0x8F5271A0U, 0x3D2D9659U, 0x8F32EF99U }, { 0x7593CBD4U, 0xCA12488CU, 0x02B82FABU, 0xED266C5DU, 0x14EB3F16U, 0x0A2F78ADU, 0x4D47AFE3U, 0xC3404948U } },
      { { 0xC005979DU, 0xA6F3D574U, 0x6A40E350U, 0xC2072B42U, 0x8DE2ECF9U, 0xFCA5C156U, 0xA515344EU, 0xA8C8BF5BU }, { 0x114DF14AU, 0x97AEE555U, 0xFDC5EC6BU, 0xD4374A4DU, 0x2CA85418U, 0x754CC28FU, 0xD3C41F78U, 0x71CB9E27U } },
      { { 0x09470496U, 0x09C16702U, 0xEBD23815U, 0xA489A5EDU, 0x8EDD4398U, 0xC4DDE464U, 0x80111696U, 0x3CA7B94AU }, { 0x2AD636A4U, 0x3C385D68U, 0x08DC5F1EU, 0x67027025U, 0xAFA21943U, 0x0C1965DEU, 0x610BE69EU, 0x18666E16U } },
      { { 0x0369C8E1U, 0x6792FD35U, 0xB9DC843BU, 0x9271AA62U, 0x4D02E2ABU, 0x8711A4B1U, 0x7EE1A383U, 0x02B2A3E2U }, { 0x0E2B379BU, 0xB226E35FU, 0xD652AB25U, 0x3D3DE39CU, 0x3B560106U, 0xACA6D4C9U, 0xC95BD877U, 0xECED0CF4U } },
      { { 0x2A604B3BU, 0x45BEB4CAU, 0x3A616762U, 0x56F65184U, 0x978B806EU, 0xF52F5A70U, 0x11DC4480U, 0x7AA39787U }, { 0x0E01FABCU, 0xE13FAC2AU, 0x237D99F9U, 0x7C6EE8A5U, 0x05211FFEU, 0x251384EEU, 0x1BC9D3EBU, 0x4FF6976DU } },
      { { 0x03605C39U, 0x89105079U, 0xA142C96CU, 0xF0843D9EU, 0x16923684U, 0xF3744934U, 0xFA0A2893U, 0x732CAA2FU }, { 0x61160170U, 0xB2E8C270U, 0x437FBAA3U, 0xC32788CCU, 0xA6EDA3ACU, 0x39CD818EU, 0x9E2B2E07U, 0xE2E94239U } } } /* window 10 */,
    { { { 0x5922AC1CU, 0x8DF27545U, 0xA52B3F63U, 0xA7B3EF5CU, 0x71DE57C4U, 0x8E77B214U, 0x834C008BU, 0x31682C10U }, { 0x4BD55D31U, 0xC76824F0U, 0x17B61C71U, 0xB6D1C086U, 0xC2A5089DU, 0x31DB0903U, 0x184E5D3FU, 0x9C092172U } },
      { { 0xEA6C3997U, 0x5ACE5035U, 0xC2610BEFU, 0x54259AAAU, 0x3C80DD39U, 0xEF18BB3FU, 0x5FC3FA39U, 0x6910B95BU }, { 0x43E09AEEU, 0xFCE2F510U, 0xA7675665U, 0xCED56C9FU, 0xD872DB61U, 0x10E265ACU, 0xAE9FCE69U, 0x6982812EU } },
      { { 0x768FCCFCU, 0xCA2EB690U, 0xB835B362U, 0xF402D37DU, 0xE2FDFCCEU, 0x0EFAC0D0U, 0xB638D990U, 0xEFC9CDEFU }, { 0xD1669A8BU, 0x2AF12B72U, 0x5774CCBDU, 0x33C536BCU, 0xFB34870EU, 0x30B21909U, 0x7DF25ACAU, 0xC38FA2F7U } },
      { { 0x1341ED7AU, 0xB8FA3D93U, 0xA7B59D49U, 0x4223272CU, 0x83B8C4A4U, 0x3DCB1947U, 0xED1302E4U, 0x4E413C01U }, { 0xE17E44CEU, 0x6D999127U, 0x33B3ADFBU, 0xEE86BF75U, 0x25AA96CAU, 0xF6902FE6U, 0xE5AAE47DU, 0xB73540E4U } },
      { { 0xB2C69DBCU, 0x7BFC5E75U, 0x03C3DA6CU, 0x3AA77A29U, 0xCA910271U, 0xDE0DF03CU, 0x7806DC55U, 0xCBD5CA4AU }, { 0x6DB476CBU, 0xE1CA5807U, 0x5F37A31EU, 0xFDE15D62U, 0xF41AF416U, 0xF49AF520U, 0x7D342DB5U, 0x96C5C5B1U } },
      { { 0x872B4A60U, 0xCC50EF6CU, 0x4613521BU, 0xAB2A34A4U, 0x983E15D1U, 0x39C5C190U, 0x59905512U, 0x61DDE5DFU }, { 0x9F2275F3U, 0xE417F621U, 0x451D894BU, 0x0750C8B6U, 0x78B0BDAAU, 0x75B04AB9U, 0x458589BDU, 0x3BFD9FD4U } },
      { { 0xDB22B94BU, 0xC792E02AU, 0xA1EAA45BU, 0x993D8AE9U, 0xCD1E1C63U, 0x8AAD6CD3U, 0xC5CE688AU, 0x89529CA7U }, { 0xE572A253U, 0x2CCEE3AAU, 0x02A21EFBU, 0xE02B6438U, 0xC9430358U, 0xA7091B6EU, 0x9D7DB504U, 0x06D1B1FAU } },
      { { 0xAF95894CU, 0xAAFCBFABU, 0x276B2241U, 0x7B9BDC07U, 0x5BDDA48BU, 0xEAF98362U, 0xA3FCB4DFU, 0x5977FAF2U }, { 0x052C4B5BU, 0xBED042EFU, 0x067591F0U, 0x9FE87F71U, 0x22F24EC7U, 0xC89C73CAU, 0xE64A9F1BU, 0x7D37FA9EU } } } /* window 11 */,
    { { { 0x0A750C0FU, 0xCC7A6488U, 0x4E548E83U, 0x39BACFE3U, 0x0C110F05U, 0x3D418C76U, 0xB1F11588U, 0x3E4DAA4CU }, { 0x5FFC69FFU, 0x2733E7B5U, 0x92053127U, 0x46F147BCU, 0xD722DF94U, 0x885B2434U, 0xE6FC6B7CU, 0x6A444F65U } },
      { { 0xC3F16EA8U, 0x7A1A465AU, 0xB2F1D11CU, 0x115A461DU, 0x6C68A172U, 0x4767DD95U, 0xD13A4698U, 0x3392F2EBU }, { 0xE526CDC7U, 0xC7A99CCDU, 0x22292B81U, 0x8E537FDCU, 0xA6D39198U, 0x76D8CF69U, 0x2446852DU, 0xFFC5FF43U } },
      { { 0xBDAEDFBDU, 0x6D0B16F4U, 0x86746CEDU, 0x23FD3260U, 0xFF4B3E17U, 0x8BFB1D2FU, 0x019C14C8U, 0xC7F2EC2DU }, { 0x45104B0DU, 0x3E0832F2U, 0xADEA2B7EU, 0x5F00DAFBU, 0x99FBFB0FU, 0x29E5CF66U, 0x61827CDAU, 0x264F9723U } },
      { { 0xA90567E6U, 0x97B14F7EU, 0xB6AE5CB7U, 0x513257B7U, 0x9F10903DU, 0x85454A3CU, 0x69BC3724U, 0xD8D2C9ADU }, { 0x6B29CB44U, 0x38DA9324U, 0x77C8CBACU, 0xB540A21DU, 0x01918E42U, 0x9BBFE435U, 0x56C3614EU, 0xFFFA707AU } },
      { { 0xE30BC27FU, 0x6EB1A2F3U, 0xB0836511U, 0xE5F0C05AU, 0x4965AB0EU, 0x4D741BBFU, 0x83464BBDU, 0xFEEC41CAU }, { 0x99D0B09FU, 0x1ACA705FU, 0xF42DA5FAU, 0xC5D6CC56U, 0xCC52B931U, 0x49964EDDU, 0xC884D8D8U, 0x8AE59615U } },
      { { 0xD4E353B7U, 0x0CE4E3F1U, 0xEF46B0A0U, 0x062D8A14U, 0x574B73FDU, 0x6408D5ABU, 0xD3273FFDU, 0xBC41D1C9U }, { 0x6BE77800U, 0x3538E1E7U, 0xC5655031U, 0x71FE8B37U, 0x6B9B331AU, 0x1CD91621U, 0xBB388F73U, 0xAD825D0BU } },
      { { 0x39F8868AU, 0xF634B57BU, 0x75CC69AFU, 0xE27F4FD4U, 0xD0D5496EU, 0xA47E58CBU, 0xD323E07FU, 0x8A26793FU }, { 0xFA30F349U, 0xC61A9B72U, 0xB696D134U, 0x94C9D9C9U, 0x5880A6D1U, 0x792BECA8U, 0xAF039995U, 0xBDCC4645U } },
      { { 0x1CB76219U, 0x56C2E05BU, 0x71567E7EU, 0x0EC0BF91U, 0x61C4C910U, 0xE7076F86U, 0xBABC04D9U, 0xD67B085BU }, { 0x5E93A96AU, 0x9FB90459U, 0xFBDC249AU, 0x7526C1EAU, 0xECDD0BB7U, 0x0D44D367U, 0x9DC0D695U, 0x95399917U } } } /* window 12 */,
    { { { 0xCECA9754U, 0x83F49167U, 0x4B7939A0U, 0x426D2CF6U, 0x723FD0BFU, 0x2555E355U, 0xC4F144E2U, 0xA96E6D06U }, { 0x87880E61U, 0x4768A8DDU, 0xE508E4D5U, 0x15543815U, 0xB1B65E15U, 0x09D7E772U, 0xAC302FA0U, 0x63439DD6U } },
      { { 0x983C38B5U, 0x859D3145U, 0x637ABC8BU, 0xB14F176CU, 0xCAFF7BE6U, 0x2793FB9DU, 0x35A66A5AU, 0xEBE5A55FU }, { 0x9F87DC59U, 0x7CEC1DCDU, 0xFBDBF560U, 0x7C595CD3U, 0x26EB3257U, 0x5B543B22U, 0xC4C935FDU, 0x69080646U } },
      { { 0xADD70482U, 0x6AAC688EU, 0x7B4A4E8AU, 0x708DE92AU, 0x758A6EEFU, 0x75B6DD73U, 0x725B3C43U, 0xEA4BF352U }, { 0x87912868U, 0x10041F2CU, 0xEF09297AU, 0xB1B1BE95U, 0xA9F3860AU, 0x19AE23C5U, 0x515DCF4BU, 0xC4F0F839U } },
      { { 0x1D531696U, 0xB9345238U, 0x88CDDE69U, 0x57201C00U, 0x9A86AFC7U, 0xDDE92251U, 0xBD35CEA8U, 0xE3043895U }, { 0x8555970DU, 0x7608C1E1U, 0x2535935EU, 0x8267DFA9U, 0x322EA38BU, 0xD4C60A57U, 0x804EF8B5U, 0xE0BF7977U } },
      { { 0x16A66E91U, 0xD730049FU, 0xFA1B0E0DU, 0xE97F2820U, 0x304C28EAU, 0x4131E003U, 0x526BAC62U, 0x820AB732U }, { 0x28714423U, 0xB2AC9EF9U, 0xADB10CB2U, 0x54ECFFFAU, 0xF886A4CCU, 0x8781476EU, 0xDB2F8D49U, 0x4B2C87B5U } },
      { { 0x86D2E0F8U, 0x6ADA1D42U, 0x0E8A9FD5U, 0xE5920122U, 0x708C1B49U, 0x02C936AFU, 0x2B4BFAFFU, 0x60F30FEEU }, { 0x858E6A61U, 0x6637AD06U, 0x3FD374D0U, 0xCE4C7767U, 0x7188DEFBU, 0x39D54B2DU, 0xF56A6B66U, 0xA8C9D250U } },
      { { 0x5F520698U, 0x0E6EC096U, 0x44F7B8D9U, 0x640631FEU, 0xA35A68B9U, 0x92FD34FCU, 0x4D40CF4EU, 0x9C5A4B66U }, { 0x80B6783DU, 0x949454BFU, 0x3A320A10U, 0x80E701FEU, 0x1A0A39B2U, 0x8D1A564AU, 0x320587DBU, 0x1436D53DU } },
      { { 0xC094DBB5U, 0x6233EA68U, 0xD968D410U, 0xB77D062EU, 0x58B3002DU, 0x3E719BBCU, 0x3DC49D58U, 0x68E7DD3DU }, { 0x013A5E58U, 0x8D825740U, 0x3C9E3C1BU, 0x21311747U, 0x7C99B6ABU, 0x0CB0A2A7U, 0xC2F888F2U, 0x5C48A3B3U } } } /* window 13 */,
    { { { 0x991724F3U, 0xC7913E91U, 0x39CBD686U, 0x5EDA799CU, 0x63D4FC1EU, 0xDDB595C7U, 0xAC4FED54U, 0x6B63B80BU }, { 0x7E5FB516U, 0x6EA0FC69U, 0xD0F1C964U, 0x737708BAU, 0x11A92CA5U, 0x9628745FU, 0x9A86967AU, 0x61F37958U } },
      { { 0xAA665072U, 0x9AF39B2CU, 0xEFD324EFU, 0x78322FA4U, 0xC327BD31U, 0x3D153394U, 0x3129DAB0U, 0x81D5F271U }, { 0xF48027F5U, 0xC72E0C42U, 0x8536E717U, 0xAA40CDBCU, 0x2D369D0FU, 0xF45A657AU, 0xEA7F74E6U, 0xB03BBFC4U } },
      { { 0x0D738DEDU, 0x46A8C418U, 0xE0DE5729U, 0x6F1A5BB0U, 0x8BA81675U, 0xF10230B9U, 0x112B33D4U, 0x32C6F30CU }, { 0xD8FFFB62U, 0x7559129DU, 0xB459BF05U, 0x6A281B47U, 0xFA3B6776U, 0x77C1BD3AU, 0x7829973AU, 0x0709B380U } },
      { { 0xA3326505U, 0x8C26B232U, 0xEE1D41BFU, 0x38D69272U, 0xFFE32AFAU, 0x0459453EU, 0x7CB3EA87U, 0xCE8143ADU }, { 0x7E6AB666U, 0x932EC1FAU, 0x22286264U, 0x6CD2D230U, 0x6736F8EDU, 0x459A46FEU, 0x9ECA85BBU, 0x50BF0D00U } },
      { { 0x877A21ECU, 0x0B825852U, 0x0F537A94U, 0x300414A7U, 0x21A9A6A2U, 0x3F1CBA40U, 0x76943C00U, 0x50824EEEU }, { 0xF83CBA5DU, 0xA0DBFCECU, 0x93B4F3C0U, 0xF9538148U, 0x48F24DD7U, 0x61744162U, 0xE4FB09DDU, 0x5322D64DU } },
      { { 0x3D9325F3U, 0x57447384U, 0xF371CB84U, 0xA9BEF2D0U, 0xA61E36C5U, 0x77D2188BU, 0xC602DF72U, 0xBBD6A7D7U }, { 0x8F61BC0BU, 0xBA3AA902U, 0x6ED0B6A1U, 0xF49085EDU, 0xAE6E8298U, 0x8BC625D6U, 0xA2E9C01DU, 0x832B0B1DU } },
      { { 0xF1F0CED1U, 0xA337C447U, 0x9492DD2BU, 0x800CC793U, 0xBEA08EFAU, 0x4B93151DU, 0xDE0A741EU, 0x820CF3F8U }, { 0x1C0F7D13U, 0xFF1982DCU, 0x84DDE6CAU, 0xEF921960U, 0x45F96EE3U, 0x1AD7D972U, 0x29DEA0C7U, 0x319C8DBEU } },
      { { 0x7B82B99BU, 0xD3EA3871U, 0x470EB624U, 0x75922D4DU, 0x3B95D466U, 0x8F66EC54U, 0xBEE1E346U, 0x66E673CCU }, { 0xB5F2B89AU, 0x6AFE67C4U, 0x290E5CD3U, 0x3DE9C1E6U, 0x310A2ADAU, 0x8C278BB6U, 0x0BDB323BU, 0x420FA384U } } } /* window 14 */,
    { { { 0x6424C49BU, 0x646F9679U, 0x67C241C9U, 0xF888DFE8U, 0x24F68B49U, 0xE12D4B93U, 0xA571DF20U, 0x9A6B62D8U }, { 0x179483CBU, 0x81B4B26DU, 0x9511FAE2U, 0x666F9632U, 0xD53AA51FU, 0xD281B3E4U, 0x7F3DBD16U, 0x7F96A765U } },
      { { 0x051AF62BU, 0x8553D37CU, 0x0BF94496U, 0xE9A998EBU, 0xB0D59AA1U, 0xE0844F9FU, 0xE6AFB813U, 0x983FD558U }, { 0x65D69804U, 0x9670C0CAU, 0x6EA5FF2DU, 0x732B22DEU, 0x5FD8623BU, 0xD7640BA9U, 0xA6351782U, 0x9F619163U } },
      { { 0xBDEFDD4FU, 0xF167B4E0U, 0xF366E401U, 0x69958465U, 0xA73BBEC0U, 0x5AA368ABU, 0x7B240C21U, 0x12148709U }, { 0x18969006U, 0x378C3233U, 0xE1FE53D1U, 0xCB4D73CEU, 0x130C4361U, 0x5F50A80EU, 0x7EF5212BU, 0xD67F5951U } },
      { { 0x8CAD38C0U, 0x332F8108U, 0x6BD68AE2U, 0x471B7E90U, 0x0D8E27A3U, 0x56AC3FB2U, 0x136B4B0DU, 0xB54660DBU }, { 0xA6FD8DE4U, 0x123A1E11U, 0xA37799EFU, 0x44DBFFEAU, 0xCE6AC17CU, 0x4540B977U, 0xAF60ACEFU, 0x495173A8U } },
      { { 0x4573EAB0U, 0xEB443743U, 0xD1AC6031U, 0x11570DFBU, 0x44DD9AFDU, 0xF7D9B45BU, 0x22067231U, 0xB8066ADDU }, { 0xF8A3F0B4U, 0x15F92AD8U, 0xE0ACE2A2U, 0x9E0E4899U, 0xFAB38B80U, 0xBDCD0AADU, 0x17020052U, 0x46506AE9U } },
      { { 0x8FCA399DU, 0x429A69F7U, 0x0207BB63U, 0xFE9E27D2U, 0x8788F582U, 0xEC655ED6U, 0xADB75F6EU, 0xA426D748U }, { 0xCA81C66DU, 0x18695C02U, 0xA531D425U, 0x84FB8D27U, 0xDEFF48BAU, 0x3A3A8956U, 0x766D2247U, 0xAF1D0D56U } },
      { { 0x352C4B5CU, 0x5A059565U, 0x590BC3E2U, 0x49261531U, 0xF66F9F5FU, 0x809F7521U, 0xC70A4A9BU, 0x2BAEF6BFU }, { 0x09ED3561U, 0xE7E6FA65U, 0x984B230CU, 0x11370233U, 0xD04CDC69U, 0x2151659BU, 0xF007D416U, 0xBDB83C63U } },
      { { 0x391C2A82U, 0x9EBB284DU, 0x158308E8U, 0xBCDD4863U, 0x83F1EDCAU, 0x006F16ECU, 0x695DC6C8U, 0xA13E2C37U }, { 0x4A057A87U, 0x2AB756F0U, 0xA6B48F98U, 0xA8765500U, 0x68651C44U, 0x4252FACEU, 0xE1765E02U, 0xA52B540BU } } } /* window 15 */,
    { { { 0x16A0D2BBU, 0x4F922FC5U, 0x1A623499U, 0x0D5CC16CU, 0x57C62C8BU, 0x9241CF3AU, 0xFD1B667FU, 0x2F5E6961U }, { 0xF5A01797U, 0x5C15C70BU, 0x60956192U, 0x3D20B44DU, 0x071FDB52U, 0x04911B37U, 0x8D6F0F7BU, 0xF648F916U } },
      { { 0xFAC61D9AU, 0x027CC8B8U, 0xE3C6FE8AU, 0x7D25E062U, 0xE5BFF503U, 0xE08805BFU, 0x6FF632F7U, 0x13271E6CU }, { 0x232F76A5U, 0x55DCA6C0U, 0x701EF426U, 0x8957C32DU, 0xA10A5178U, 0xEE728BCBU, 0xB62C5173U, 0x5EA60411U } },
      { { 0xB5DEF996U, 0x4090914BU, 0x233DD1E7U, 0x1CB69C83U, 0x9B3D5E76U, 0xC1E9C1D3U, 0xFCCF6012U, 0x1F3338EDU }, { 0x2F5378A8U, 0xB1E95D0DU, 0x2F00CD21U, 0xACF4C2C7U, 0xEB5FE290U, 0x6E984240U, 0x248088AEU, 0xD66C038DU } },
      { { 0xB4D8BC50U, 0x9AD5462BU, 0xA9195770U, 0x181C0B16U, 0x78412A68U, 0xEBD4FE1CU, 0xC0DFF48CU, 0xAE0341BCU }, { 0x7003E866U, 0xB6BC45CFU, 0x8A24A41BU, 0xF11A6DEAU, 0xD04C24C2U, 0x5407151AU, 0xDA5B7B68U, 0x62C9D27DU } },
      { { 0x614C0900U, 0xD4992B30U, 0xBD00C24BU, 0xDA98D121U, 0x7EC4BFA1U, 0x7F534DC8U, 0x37DC34BCU, 0x4A5FF674U }, { 0x1D7EA1D7U, 0x68C196B8U, 0x80A6D208U, 0x38CF2893U, 0xE3CBBD6EU, 0xFD56CD09U, 0x4205A5B6U, 0xEC72E27EU } },
      { { 0xA8AFD30BU, 0x32865719U, 0x8A826DCEU, 0x86798328U, 0xC4A8FBE0U, 0xDF04E891U, 0xEBF56AD3U, 0xBB6B6E1BU }, { 0x471F1FF0U, 0x0A695B11U, 0xBE15BAF0U, 0xD76C3389U, 0xBE96C43EU, 0x018EDB95U, 0x90794158U, 0xF2BEAAF4U } },
      { { 0xB88756DDU, 0xE8B97932U, 0xF17E3E61U, 0xED4E8652U, 0x3EE1C4A4U, 0xC2DD1499U, 0x597F8C0EU, 0xC0AAEE17U }, { 0x6C168AF3U, 0x15C4EDB9U, 0xB39AE875U, 0x6563C7BFU, 0x20ADB436U, 0xADFADB6FU, 0x9A042AC0U, 0xAD55E8C9U } },
      { { 0x523B8BF6U, 0x0A50B12EU, 0x8F910C1BU, 0x8009EB5BU, 0x4A167588U, 0xF535AF82U, 0xFB2A2ABDU, 0x0F835F9CU }, { 0x2AFCEB62U, 0xF59B2931U, 0x169D383FU, 0xC797DF2AU, 0x66AC02B0U, 0xEB3F5FB0U, 0xDAA2D0CAU, 0x029D4C6FU } } } /* window 16 */,
    { { { 0xF5B343BCU, 0x58AF2010U, 0xF2F142FEU, 0x0F2E400AU, 0xA85F4BDFU, 0x3483BFDEU, 0x03BFEAA9U, 0xF0B1D093U }, { 0xC7081603U, 0x2EA01B95U, 0x3DBA1097U, 0xE943E4C9U, 0xB438F3A6U, 0x47BE92ADU, 0xE5BF6636U, 0x00BB7742U } },
      { { 0x7BFE7178U, 0xB674481BU, 0x65405868U, 0x4E1DEBAEU, 0xC48C867DU, 0x061B2821U, 0x513B30EAU, 0x69C15B35U }, { 0x36871088U, 0x3B4A1666U, 0x1220B1FFU, 0xE5E29F5DU, 0x233D9F4DU, 0x4B82BB35U, 0x18CDC675U, 0x4E076333U } },
      { { 0x31815E69U, 0x3A63C397U, 0xDCDD2802U, 0x6DF9CBD6U, 0x15B4F6AFU, 0x4C47ED4AU, 0x6AC0F978U, 0x62009D82U }, { 0x8B898FC7U, 0x664D80D2U, 0x2C17C91FU, 0x72F1EEDAU, 0x7AAE6609U, 0x9E84D3BCU, 0x28376895U, 0x58C7C195U } },
      { { 0xA3E6FCEDU, 0x0D53F5C7U, 0xF45FBDEBU, 0xE8CBBDD5U, 0x13339A70U, 0xF85C01DFU, 0x142CEB81U, 0x0FF71880U }, { 0xBD70437AU, 0x4C4E8774U, 0xBA0BDA6AU, 0x5FB32891U, 0xF18BD26EU, 0x1CDBEBD2U, 0x03A9D522U, 0x2F9526F1U } },
      { { 0xA8271D7EU, 0xA752C905U, 0x58E5810BU, 0x4735DFA5U, 0x5D925AEBU, 0xE18A44EEU, 0x13C8A853U, 0x9708697FU }, { 0xBFCC9A0BU, 0x8377D540U, 0xE574D403U, 0x7B27E01CU, 0xCF60A8A6U, 0x3D3D180CU, 0xF1C298BFU, 0xE48EF152U } },
      { { 0x0AEAA3C0U, 0x313A2E8CU, 0xABE85B0AU, 0x89F46D9EU, 0x2DA97D3AU, 0xD2889EBDU, 0x103F8CBAU, 0x9484026AU }, { 0x87D83B5FU, 0x52159F8AU, 0xB1EF0295U, 0xDB2220D6U, 0x03C01ACFU, 0xBDA0746EU, 0x14419FE3U, 0x4F97B2A7U } },
      { { 0xC880E5CAU, 0xCCBF7AC2U, 0x8D11C450U, 0x8299DBEEU, 0x0F77A6BFU, 0xBB27D11BU, 0x5EDCE793U, 0xC601630BU }, { 0x79E7F8EAU, 0xDB73B9FBU, 0xF4367288U, 0xE448BBA7U, 0xB035571BU, 0xF5B6416FU, 0xA48891A2U, 0x981B8F5DU } },
      { { 0x92C4D684U, 0x40CE3051U, 0x7612EFCDU, 0x8B04D725U, 0x6F9CAE20U, 0xB9DCDA36U, 0xF058856CU, 0x0EDC4D24U }, { 0x85427900U, 0x64F2E6BFU, 0xDC09DFEAU, 0x3DE81295U, 0x379BF26CU, 0xD41B4487U, 0x6DF135A9U, 0x50B62C6DU } } } /* window 17 */,
    { { { 0xD005832AU, 0x0DB2FB5EU, 0x91042E4FU, 0x5F5EFD3BU, 0xED70F8CAU, 0x8C4FFDC6U, 0xB52DA9CCU, 0xE4645D0BU }, { 0xC9001D1FU, 0x9596F58BU, 0x4E117205U, 0x52C8F0BCU, 0xE398A084U, 0xFD4AA0D2U, 0x104F49DEU, 0x815BFE3AU } },
      { { 0xE548B37BU, 0x54EB3ACCU, 0x84D40549U, 0xB38E7542U, 0x7B341B4FU, 0x8C3DAA51U, 0x690BF7FAU, 0x2F6928ECU }, { 0x86CE6C41U, 0x0496B323U, 0x10ADADCDU, 0x01BE1C55U, 0x4BB5FAF9U, 0xC04E67E7U, 0xE15C9985U, 0x3CBAF678U } },
      { { 0xD7AB9A2DU, 0x524D226AU, 0x7DFAE958U, 0x9C00090DU, 0x8751D8C2U, 0x0BA5F539U, 0x3AB8262DU, 0x8AFCBCDDU }, { 0xE99D043BU, 0x57392729U, 0xAEBC943AU, 0xEF51263BU, 0x20862935U, 0x9FEACE93U, 0xB06C817BU, 0x639EFC03U } },
      { { 0x341D81DCU, 0xE839BE7DU, 0x32148379U, 0xCDDB6889U, 0xF7026EADU, 0xDA6211A1U, 0xF4D1CC5EU, 0xF3B2575FU }, { 0xA7A73AE6U, 0x40CFC8F6U, 0x61D5B483U, 0x83879A5EU, 0x41A50EBCU, 0xC5ACB1EDU, 0x3C07D8FAU, 0x59A60CC8U } },
      { { 0xC3B81990U, 0xDEC98D4AU, 0x9E0CC8FEU, 0x1CB83722U, 0xD2B427B9U, 0xFE0B0491U, 0xE983A66CU, 0x0F2386ACU }, { 0xB3291213U, 0x930C4D1EU, 0x59A62AE4U, 0xA2F82B2EU, 0xF93E89E3U, 0x77233853U, 0x11777C7FU, 0x7F8063ACU } },
      { { 0x59371000U, 0x604AC97CU, 0x7F759C18U, 0xE1C48C70U, 0xA5DB6B65U, 0x3F62ECC5U, 0x38A21495U, 0x0A78B173U }, { 0xBCC8AD94U, 0x6BE1819DU, 0xD89C3400U, 0x70DC04F6U, 0xA6B4840AU, 0x462557B4U, 0x60BD21C0U, 0x544C6ADEU } },
      { { 0x02FF6072U, 0x36E607CFU, 0x8AD98CDCU, 0xA47D2CA9U, 0xF5F56609U, 0xBF471D1EU, 0xF264ADA0U, 0xBCF86623U }, { 0xAA9E5CB6U, 0xB70C0687U, 0x17401C6CU, 0xC98124F2U, 0xD4A61435U, 0x8189635FU, 0xA9D98EA6U, 0xD28FB8AFU } },
      { { 0x65C7322DU, 0x439530B6U, 0xB3C1B3FBU, 0xCF12CC01U, 0x0172F685U, 0xC70B0186U, 0x1B58391DU, 0xB915EE22U }, { 0xA317DB24U, 0x9AFDF03BU, 0x17B8FFC4U, 0x87DEC659U, 0xE4D3D050U, 0x7F46597BU, 0x006500E7U, 0x80A1C1EDU } } } /* window 18 */,
    { { { 0x97ACF4ECU, 0x3E22A7B3U, 0x5EA8B640U, 0x0426C400U, 0x4E969285U, 0x5E3295A6U, 0xA6A45670U, 0x22AABC59U }, { 0x5F5942BCU, 0xB929714CU, 0xFA3182EDU, 0x9A6168BDU, 0x104152BAU, 0x2216A665U, 0xB6926368U, 0x46908D03U } },
      { { 0x5A1251FBU, 0xA9F5D874U, 0xC72725C7U, 0x967747A8U, 0x31FFE89EU, 0x195C33E5U, 0xE964935EU, 0x609D210FU }, { 0x2FE12227U, 0xCAFD6CA8U, 0x0426469DU, 0xAF9B5B96U, 0x5693183CU, 0x2E9EE04CU, 0xC8146FEFU, 0x1084A333U } },
      { { 0x10395755U, 0xCE06B882U, 0x5EC1DF80U, 0x117CE634U, 0xEFF55E96U, 0xFEFAE513U, 0xFD7FED1EU, 0xCF36CBA6U }, { 0xA40EBF88U, 0x7340ECA9U, 0xB3D37E12U, 0xE6EC1BCFU, 0x86BBF9FFU, 0xCA51B64EU, 0x8B40E05EU, 0x4E0DBB58U } },
      { { 0xAED1D1F7U, 0x96649933U, 0x50563090U, 0x566EAFF3U, 0xAD2E39CFU, 0x345057F0U, 0x1F832124U, 0x148FF65BU }, { 0xCF94CF0DU, 0x042E89D4U, 0x520C58B3U, 0x319BEC84U, 0x5361AA0DU, 0x2A267626U, 0x8FBC87ADU, 0xC86FA302U } },
      { { 0x7EA2EE34U, 0x359D7B9CU, 0x09CC3A71U, 0x3FD0D94CU, 0x3A1EA37AU, 0xBB53C31CU, 0xCF818C87U, 0x533425FAU }, { 0x810156E0U, 0x7CD199C3U, 0x30C16448U, 0x0EA020E4U, 0x4A642542U, 0xE557BA09U, 0x9465F5EAU, 0xE657E7E7U } },
      { { 0x5C8B06D5U, 0xFC83D2ABU, 0xFE4EAC46U, 0xB1A785A2U, 0x846F7779U, 0xB99315BCU, 0xEF9EA505U, 0xCF31D816U }, { 0x15D7DC85U, 0x2391FE6AU, 0xB4016B33U, 0x2F132B04U, 0x181CB4C7U, 0x29547FE3U, 0x650155A1U, 0xDB66D8A6U } },
      { { 0x593D070FU, 0x59CD0E8BU, 0x5255625DU, 0x43757516U, 0x5B7A0399U, 0x551FDDA7U, 0x2DEC1EEBU, 0x7BB6E6B0U }, { 0x334C0922U, 0x729BB662U, 0x0CF41B79U, 0x3DF631DFU, 0x78F32402U, 0x01ABF3C5U, 0x9CD33C88U, 0xFCB4666CU } },
      { { 0xADC1696FU, 0x6B66D7E1U, 0x0ACD72D0U, 0x98EBE593U, 0xCC1B7435U, 0x65F24550U, 0xB4B9A5ECU, 0xCE231393U }, { 0xDB067DF9U, 0x234A22D4U, 0xCAFF9B00U, 0x98DDA095U, 0x6100C9C1U, 0x1BBC75A0U, 0x939CF695U, 0x1560A9C8U } } } /* window 19 */,
    { { { 0xF1C367CAU, 0xE4050F1CU, 0xC90FBC7DU, 0x9BC85A9BU, 0xE1A11032U, 0xA373C4A2U, 0xAD0393A9U, 0xB64232B7U }, { 0x167DAD29U, 0xF5577EB0U, 0x94B78AB2U, 0x1604F301U, 0xE829348BU, 0x0BAA94AFU, 0x41654342U, 0x77FBD8DDU } },
      { { 0xFCF0A7FDU, 0x31F14802U, 0x5488B01EU, 0x42FD0789U, 0x9952B498U, 0x71D78D6DU, 0x07AC5201U, 0x8EB572D9U }, { 0x4D194A88U, 0xE0A2A44CU, 0xBA017E66U, 0xD2B63FD9U, 0xF888AEFCU, 0x78EFC6C8U, 0x4A881A11U, 0xB76F6BDAU } },
      { { 0x68AF43EEU, 0xA2F7932CU, 0x703D00BDU, 0x5502468EU, 0x2FB061F5U, 0xE5DC978FU, 0x28C815ADU, 0xC9A1904AU }, { 0x470C56A4U, 0xD3AF538DU, 0x193D8CEDU, 0x159ABC5FU, 0x20108EF3U, 0x2A37245FU, 0x223F7178U, 0xFA17081EU } },
      { { 0xB4B4B67CU, 0x1FE2A9B2U, 0xE8020604U, 0xC1D10DF0U, 0xBC8058D8U, 0x9D64ABFCU, 0x712A0FBBU, 0x8943B9B2U }, { 0x3B3DEF04U, 0x90EED914U, 0x4CE775FFU, 0x85AB3AA2U, 0x7BBC9040U, 0x605FD4CAU, 0xE2C75DFBU, 0x8B34A564U } },
      { { 0x8E2F7D90U, 0x5C18ACF8U, 0x77BE32CDU, 0xFDBF33D7U, 0xD2EB5EE9U, 0x0A085CD7U, 0xB3201115U, 0x2D702CFBU }, { 0x85C88CE8U, 0xB6E0EBDBU, 0x1E01D617U, 0x23A3CE3CU, 0x567333ACU, 0x3041618EU, 0x157EDB6BU, 0x9DD0FD8FU } },
      { { 0x98FA7AAAU, 0xB2B26107U, 0xF073AA4EU, 0x41209EE4U, 0xF2D6B19BU, 0xF1570359U, 0xFC577CAFU, 0xCBE6868CU }, { 0x32C04DD3U, 0x186C4BDCU, 0xCFEEE397U, 0xA6C35FAEU, 0xF086C0CFU, 0xB4A1B312U, 0xD9461FE2U, 0xE0A5CCC6U } },
      { { 0x6FA6110CU, 0x516FF3A3U, 0xFB93561FU, 0x74FB1EB1U, 0x8457522BU, 0x6C0C9047U, 0x6BB8BDC6U, 0xCFD32104U }, { 0xCC80AD57U, 0x2D6884A2U, 0x86A9B637U, 0x7C27FC35U, 0xADF4E8CDU, 0x3461BAEDU, 0x617242F0U, 0x1D56251AU } },
      { { 0x431DD80EU, 0xB84011A9U, 0x73306CD9U, 0xEB7C7CCAU, 0xD1B3B730U, 0x20FADD29U, 0xFE37B3D3U, 0x83858B5BU }, { 0xB6251D5CU, 0xBF4CD193U, 0x1352D952U, 0x1CCA1FD3U, 0x90FBC051U, 0xC66157A4U, 0x89B98636U, 0x7990A638U } } } /* window 20 */,
    { { { 0x87DEC0E1U, 0xE5AA692AU, 0xF7B39D00U, 0x010DED8DU, 0x54CFA0B5U, 0x7B1B80C8U, 0xA0F8EA28U, 0x66BEB876U }, { 0x3476CD0EU, 0x50D7F531U, 0xB08D3949U, 0xA63D0E65U, 0x53479FC6U, 0x1A09EEA9U, 0xF499E742U, 0x82AE9891U } },
      { { 0x5CA7D866U, 0xAB58B910U, 0x3ADB3B34U, 0x582967E2U, 0xCCEAC0BCU, 0x89AE4447U, 0x7BF56AF5U, 0x919C667CU }, { 0x60F5DCD7U, 0x9AEC17B1U, 0xDDCAADBCU, 0xEC697B9FU, 0x463467F5U, 0x0B98F341U, 0xA967132FU, 0xB187F1F7U } },
      { { 0x214AEB18U, 0x90FE7A1DU, 0x741432F7U, 0x1506AF3CU, 0xE591A0C4U, 0xBB5565F9U, 0xB44F1BC3U, 0x10D41A77U }, { 0xA84BDE96U, 0xA09D65E4U, 0xF20A6A1CU, 0x42F060D8U, 0xF27F9CE7U, 0x652A3BFDU, 0x3B3D739FU, 0xB6BDB65CU } },
      { { 0xEC7FAE9FU, 0xEB5DDCB6U, 0xEFB66E5AU, 0x995F2714U, 0x69445D52U, 0xDEE95D8EU, 0x09E27620U, 0x1B6C2D46U }, { 0x8129D716U, 0x32621C31U, 0x0958C1AAU, 0xB03909F1U, 0x1AF4AF63U, 0x8C468EF9U, 0xFBA5CDF6U, 0x162C429FU } },
      { { 0x753B9371U, 0x2F682343U, 0x5F1F9CD7U, 0x29CAB45AU, 0xB245DB96U, 0x571623ABU, 0x3FD79999U, 0xC507DB09U }, { 0xAF036C32U, 0x4E2EF652U, 0x05018E5CU, 0x86F0CC78U, 0xAB8BE350U, 0xC10A73D4U, 0x7E826327U, 0x6519B397U } },
      { { 0x9C053DF7U, 0xE8CB5EEFU, 0xB300EA6FU, 0x8DE25B37U, 0xC849CFFBU, 0xDB03FA92U, 0xE84169BBU, 0x242E43A7U }, { 0xDD6F958EU, 0xE4FA51F4U, 0xF4445A8DU, 0x6925A77FU, 0xE90D8949U, 0xE6E72A50U, 0x2B1F6390U, 0xC66648E3U } },
      { { 0x173E460CU, 0xB2AB1957U, 0x30704590U, 0x1BBBCE75U, 0xDB1C7162U, 0xC0A90DBDU, 0x15CDD65DU, 0x505E399EU }, { 0x57797AB7U, 0x68434DCBU, 0x6A2CA8E8U, 0x60AD35BAU, 0xDE3336C1U, 0x4BFDB1E0U, 0xD8B39015U, 0xBBEF99EBU } },
      { { 0x1711EBECU, 0x6C3B96F3U, 0xCE98FDC4U, 0x2DA40F1FU, 0x57B4411FU, 0xB99774D3U, 0x15B65BB6U, 0x87C8BDF4U }, { 0xC2EEF12DU, 0xDA3A89E3U, 0x3C7471F3U, 0xDE95BB9BU, 0xD812C594U, 0x600F225BU, 0x2B75A56BU, 0x54907C5DU } } } /* window 21 */,
    { { { 0xF79588C0U, 0xA80D1DB6U, 0xB55768CCU, 0xFA52FC69U, 0x7F54438AU, 0x0B4DF1AEU, 0xF9B46A4FU, 0x0CADD1A7U }, { 0x1803DD6FU, 0xB40EA6B3U, 0x55EAAE35U, 0x488E4FA5U, 0x382E4E16U, 0x9F047D55U, 0x2F6E0C98U, 0xC9B5B7E0U } },
      { { 0x7C4A658AU, 0xC12738B6U, 0x40E72182U, 0xB3C47639U, 0x8798E44FU, 0x3B77BE46U, 0x17A7F85FU, 0xDC047DF2U }, { 0x5E59D92DU, 0x2439D4C5U, 0xE8E64D8DU, 0xCEDCA475U, 0x87CA9B16U, 0xA724CD0DU, 0xA5540DFEU, 0x35E4FD59U } },
      { { 0x83A7337BU, 0x4B7D0E06U, 0xFFECF249U, 0x1E3416D4U, 0x66A2B71FU, 0x24840EFFU, 0xB37CC26DU, 0xD0D9A50AU }, { 0x6FE28EF7U, 0xE2198150U, 0x23324C7FU, 0x3CC5EF16U, 0x769B5263U, 0x220F3455U, 0xA10BF475U, 0xE2ADE2F1U } },
      { { 0x3A29467AU, 0x9894344FU, 0xC51EBA6DU, 0xDE81E949U, 0xA5E5C2F2U, 0xDAEA066BU, 0x08C8C7B3U, 0x3FC8A614U }, { 0x06D0DE9FU, 0x7ADFF88FU, 0x3B75CE0AU, 0xBBC11CF5U, 0xFBBC87D5U, 0x9FBB7ACCU, 0x7BADFDE2U, 0xA1458E26U } },
      { { 0xDACDDB7DU, 0x03B6C8C7U, 0x7E1EDCADU, 0x92ED5004U, 0x54080633U, 0xA0E46C2FU, 0x46DEC1CEU, 0xCD37663DU }, { 0xF365B7CCU, 0x396984C5U, 0xE79BB95DU, 0x294E3A2AU, 0x27B1D3C1U, 0x9AA17D77U, 0xE49440F5U, 0x3FFD3CFAU } },
      { { 0xABB830D1U, 0x041C93E3U, 0x5C2C5270U, 0x2AD23532U, 0xEE4B259DU, 0xAEFD1BE2U, 0x1EADD857U, 0x3EF26777U }, { 0x9B0D7D86U, 0x2AF8F703U, 0x7B7E6F20U, 0x80F5AF2DU, 0xCEC8E295U, 0xB5FA1D3CU, 0xF68F09F6U, 0xE73F3902U } },
      { { 0x399F9CF3U, 0x26679D11U, 0x1E3C4394U, 0x78E7A48EU, 0x0D98DAF1U, 0x08722DEAU, 0x80030EA3U, 0x37E7ED58U }, { 0x3C8AAE72U, 0xF3731AD4U, 0xAC729695U, 0x7878BE95U, 0xBBC28352U, 0x6A643AFFU, 0x78759B61U, 0xEF8B801BU } },
      { { 0xE039C256U, 0x1CB43668U, 0x7C17FD5DU, 0x5F26FB8BU, 0x79AA062BU, 0xEEE426AFU, 0xD78FBF04U, 0x072002D0U }, { 0xE84FB7E3U, 0x4C9CA237U, 0x0C82133DU, 0xB401D8A1U, 0x6D7E4181U, 0xAAA52592U, 0x73DBB152U, 0xE9430833U } } } /* window 22 */,
    { { { 0xBE24319AU, 0xF92DDA31U, 0xE095A8E7U, 0x03F7D28BU, 0x98782185U, 0xA52FE840U, 0x29C24DBCU, 0x276DDAFEU }, { 0x1D7A64EBU, 0x80CD5496U, 0x7F1DBE42U, 0xE4360889U, 0x8438D2D5U, 0x2F81A877U, 0x85169036U, 0x7E4D52A8U } },
      { { 0x615FAA8FU, 0x7B15FD9DU, 0x968554EDU, 0x8FA1EB40U, 0x7AA44882U, 0x7BB4447EU, 0x029FFF32U, 0x2BB2D0D1U }, { 0x6CAA6D2FU, 0x075E2A64U, 0x22E7351BU, 0x8EB879DEU, 0x9A506C62U, 0xBCD5624EU, 0xA87E24DCU, 0x218EAEF0U } },
      { { 0x3D30A2C5U, 0x1FE647D8U, 0xF78A81DCU, 0x0857F77EU, 0x131A4A9BU, 0x11D5A334U, 0x29D393F5U, 0xC0A94AF9U }, { 0xDAA6EC1AU, 0xBC3A5C0BU, 0x88D2D7EDU, 0xBA9FE493U, 0xBB614797U, 0xBB4335B4U, 0x72F83533U, 0x991C4D68U } },
      { { 0xE978A1D3U, 0x77B868CEU, 0x7AB92D04U, 0xE3A68B33U, 0x87A5B862U, 0x51029794U, 0x3A61D41DU, 0x5F0606C3U }, { 0x6F9326F1U, 0x2814BE27U, 0xC6FE3C2EU, 0x2F521C14U, 0xACDF7351U, 0x17464D7DU, 0x777F7E44U, 0x10F5F9D3U } },
      { { 0x3D34A2E3U, 0x1FD84CE4U, 0xB43B5D61U, 0xEE3759CEU, 0x619186C7U, 0x895BC78CU, 0xCBB9725AU, 0xF19C3809U }, { 0xDE744B1FU, 0xC0BE21AAU, 0x60F8056BU, 0xA7D222B0U, 0xB23EFE11U, 0x74BE6157U, 0x0CD68253U, 0x6FAB2B4FU } },
      { { 0xA4D32282U, 0xB6E33878U, 0x48020AE7U, 0xE36E029DU, 0x37A9B750U, 0xE05847FBU, 0xB29E3819U, 0xF876812CU }, { 0xD23A17F0U, 0x84AD138EU, 0xF0B3950EU, 0x6D7B4480U, 0x2FD67AE0U, 0xDFA8AEF4U, 0x52333AF6U, 0x8D3EEA24U } },
      { { 0xB99A72CBU, 0x2101A522U, 0x87618016U, 0x06DE6E67U, 0xE6F3653EU, 0x5FF8C7CDU, 0xC7A6754AU, 0x0A821AB5U }, { 0x7CB0B5A2U, 0x7E3FA52BU, 0xC9048790U, 0xA7FB121CU, 0x06CE053AU, 0x1A725020U, 0x04E929B0U, 0xB490A31FU } },
      { { 0xC5F95CD8U, 0xB06B1244U, 0xF4AB95F4U, 0xDA8C8AF0U, 0xB9E5836DU, 0x1BAE59C2U, 0x3ACFFFFCU, 0x07D51E7EU }, { 0xC2CCBCDAU, 0x01E15E6AU, 0x8528C3E0U, 0x3BC1923FU, 0xA49FEAD4U, 0x43324577U, 0x2AA7A711U, 0x61A1B884U } } } /* window 23 */,
    { { { 0xB0E63D34U, 0x4FE7EE31U, 0xA9E54FABU, 0xF4600572U, 0xD5E7B5A4U, 0xC0493334U, 0x06D54831U, 0x8589FB92U }, { 0x6583553AU, 0xAA70F5CCU, 0xE25649E5U, 0x0879094AU, 0x10044652U, 0xCC904507U, 0x02541C4FU, 0xEBB0696DU } },
      { { 0xA2DEE7A6U, 0x758C1A3EU, 0x734B2284U, 0xDCDE2F3CU, 0x4EABA6ADU, 0xABA445D2U, 0x76CEE0A7U, 0x35AAF668U }, { 0xE5AA049AU, 0x7E0B04A9U, 0x91103E84U, 0xE74083ADU, 0x40AFECC3U, 0xBEB183CEU, 0xEA043F7AU, 0x6B89DE9FU } },
      { { 0x99375235U, 0xB99F0E03U, 0xB9917970U, 0x7614C847U, 0x524EC067U, 0xFEC93CE9U, 0x9B122520U, 0xE40E7BF8U }, { 0xEE4C4774U, 0xB5670631U, 0x3B04914CU, 0x6F03847AU, 0xDC9DD226U, 0xC96E9429U, 0x8C57C1F8U, 0x43489B6CU } },
      { { 0xFE67BA66U, 0x0E299D23U, 0x93CF2F34U, 0x91450760U, 0x97FCF913U, 0xF45B5EA9U, 0x8BD7DDDAU, 0x5BE00843U }, { 0xD53FF04DU, 0x358C3E05U, 0x5DE91EF7U, 0xBF7CCDC3U, 0xB69EC1A0U, 0xAD684DBFU, 0x801FD997U, 0x367E7CF2U } },
      { { 0xCC2338FBU, 0x46FFD227U, 0x90E26153U, 0x89FF6FA9U, 0x331A0076U, 0xBE570779U, 0x06E1F3AFU, 0x43D241C5U }, { 0xDE9B62A3U, 0xFDCDB97DU, 0xA0AE30EAU, 0x6A06E984U, 0x4FBDDF7DU, 0xC9BF1680U, 0xD36163C4U, 0x170471A2U } },
      { { 0x3113655EU, 0xFF5BA8AEU, 0x57B83180U, 0xFA2C6E2BU, 0x77E0EABEU, 0x1C482719U, 0x337FEA97U, 0xF9F3C555U }, { 0xA42581CBU, 0x340F7022U, 0x18F710E3U, 0xE1DE0BC2U, 0xF62E5AA8U, 0xEE640ADEU, 0x49428940U, 0x16B23891U } },
      { { 0x55950CC3U, 0x361619E4U, 0x56B66BB8U, 0xC71D665CU, 0xAFAC6D84U, 0xEA034B34U, 0xE5E4C7E3U, 0xA987F832U }, { 0x7A79A6A7U, 0xA0742772U, 0xE26D6C23U, 0x56E5D017U, 0x38167E10U, 0x7E50B976U, 0xE88AA84EU, 0xAA6C81EFU } },
      { { 0xB0DC8595U, 0x0CA1F3B7U, 0x9F1D9F2EU, 0x27DE4608U, 0xBADD82A7U, 0x1AF3BF39U, 0x65862448U, 0x79356A79U }, { 0xF5F9A052U, 0xC0602345U, 0x139A42F9U, 0x1A8B0F89U, 0x844D40FCU, 0xB53EEE42U, 0x4E5B6368U, 0x93B0BFE5U } } } /* window 24 */,
    { { { 0xC8DE610BU, 0x0F893A5DU, 0x67E223CEU, 0xE8C515FBU, 0x4EAD6DC5U, 0x7774BFA6U, 0x925C728FU, 0x89D20F95U }, { 0x098583CEU, 0x7A1E0966U, 0x93F2A7D7U, 0xA2EEDB94U, 0x4C304D4AU, 0x1B282097U, 0xC077282DU, 0x0842E3DAU } },
      { { 0x74CD06FFU, 0xA1010E9DU, 0xACA3EEACU, 0x9C17C7DFU, 0x8063AA2BU, 0x74C86CD3U, 0x734614FFU, 0x8595C4B3U }, { 0x990F62CCU, 0xA3DE00CAU, 0xCA0C3BE5U, 0xD9BED213U, 0xDF8CE9F5U, 0x7886078AU, 0x5CD44444U, 0xDDB27CE3U } },
      { { 0xFC15AA1EU, 0x5A3097BEU, 0xB54B0745U, 0x40D12548U, 0x519A5F12U, 0x5BAD4706U, 0xA439DEE6U, 0xED03F717U }, { 0x4A02C499U, 0x0794BB6CU, 0xCFFE71D2U, 0xF725083DU, 0x0F3ADCAFU, 0x2CAD7519U, 0x43729310U, 0x7F68EA1CU } },
      { { 0x26EE8382U, 0x9C7C581DU, 0x359D638EU, 0xCF17DCC5U, 0xB728AE3DU, 0xEE8273ABU, 0xF821F047U, 0x1D112926U }, { 0x50491A74U, 0x11498477U, 0xFDE0DFB9U, 0x687FA761U, 0x7EA435ABU, 0x2C258022U, 0x91CE7E3FU, 0x6B8BDB94U } },
      { { 0xF7F91D0FU, 0x9C806D8AU, 0xA82A5728U, 0x3B61B0F1U, 0x94D76754U, 0x4640032DU, 0x47D834C6U, 0x273EB5DEU }, { 0x7B4E4D53U, 0x2988ABF7U, 0xDE401777U, 0xB7CE66BFU, 0x715071B3U, 0x9FBA6B32U, 0xAD3A1A98U, 0x82413C24U } },
      { { 0x3CC8AC85U, 0x75537B7EU, 0xDD02753BU, 0x8D725F57U, 0xB737DF2FU, 0xFD05FF64U, 0xF6D2531DU, 0x55FE8712U }, { 0x6AB6B01CU, 0x57CE04A9U, 0x7CD93724U, 0x69A02A89U, 0xCF86699BU, 0x4F82AC35U, 0x9CB4B232U, 0x8242D3ADU } },
      { { 0x9BE47BE0U, 0x69C43526U, 0xCB28FEA1U, 0x323B7DD8U, 0x3A6C67E5U, 0xFA5538BAU, 0x1D378E46U, 0xEF921D70U }, { 0x3C4B880EU, 0xF92961FCU, 0x98940A67U, 0x3F6F914EU, 0xFEF0FF39U, 0xA990EB0AU, 0xF0EEFF9CU, 0xA6C2920FU } },
      { { 0x53FB2B56U, 0xB23A03A5U, 0x4E057F78U, 0x6CE141E7U, 0x89E490D9U, 0x796525C3U, 0xA31A7E75U, 0x0BC95725U }, { 0x1220FD06U, 0x1EC56791U, 0x408B0BD6U, 0x716E3A3CU, 0xE8EBEBA9U, 0x31CD6BF7U, 0xBEE6B670U, 0xA7326CA6U } } } /* window 25 */,
    { { { 0xCF7D62D2U, 0x20D3C982U, 0x23BA8150U, 0x1F36E29DU, 0x92763F9EU, 0x48AE0BF0U, 0x1D3A7007U, 0x7A527E6BU }, { 0x581A85E3U, 0xB4A89097U, 0xDC158BE5U, 0x1F1A520FU, 0x167D726EU, 0xF98DB37DU, 0x1113E862U, 0x8802786EU } },
      { { 0x36F09AB0U, 0xEFB2149EU, 0x4A10BB5BU, 0x03F163CAU, 0x06E20998U, 0xD0297045U, 0x1B5A3BABU, 0x56F0AF00U }, { 0x70880E0DU, 0x7AF4CFECU, 0xBE3D913FU, 0x7332A66FU, 0x7ECEB4BDU, 0x32E6C84AU, 0x9C228F55U, 0xEDC4A79AU } },
      { { 0xF4C6B6ECU, 0xF6E894D1U, 0x18B3CD9BU, 0x526B0827U, 0x12117FBFU, 0x73F952A8U, 0x11945BF5U, 0x2BE864B0U }, { 0x42099B64U, 0x86F18EA5U, 0x07548CE2U, 0x2770B28AU, 0x295C1C9CU, 0x97390F28U, 0xCB5206C3U, 0x672E6A43U } },
      { { 0xC55C4496U, 0xC37C7DD0U, 0x25BBABD2U, 0xA6A96357U, 0xADD7F363U, 0x5B7E63F2U, 0x2E73F1DFU, 0x9DCE3782U }, { 0xB2B91F71U, 0xE1E5A16AU, 0x5BA0163CU, 0xE4489823U, 0xF6E515ADU, 0xF2759C32U, 0x8615EECFU, 0xA5E2F1F8U } },
      { { 0x47C64367U, 0xCACCE2C8U, 0x45AF4EC0U, 0x6A496B9FU, 0x6034042CU, 0x2A0836F3U, 0x0B6C62EAU, 0x14A1F390U }, { 0x3EF1F540U, 0xE7FA9363U, 0x72A76D93U, 0xD323B30AU, 0x0FEAE451U, 0xFFEEC8B5U, 0xBD04EF87U, 0x4EAFC172U } },
      { { 0xABDED551U, 0x74519BE7U, 0xC8B74410U, 0x03D358B8U, 0x0E10D9A9U, 0x4D00B10BU, 0x28DA52B7U, 0x6392B0B1U }, { 0x0B75C904U, 0x6744A298U, 0xA8F7F96CU, 0xC305B0AEU, 0x182CF932U, 0x042E421DU, 0x9E4636CAU, 0xF6FC5D50U } },
      { { 0xB3E59B89U, 0xE4435A51U, 0x4133A1C9U, 0x13613955U, 0x440BEE59U, 0x87F46973U, 0x00C401E4U, 0x714710F8U }, { 0xD6C446C9U, 0xC0CF4BCEU, 0x6C4D5368U, 0xE0AA7FD6U, 0xFC68FC37U, 0xDE5D811AU, 0xB7C2A057U, 0x61FEBD72U } },
      { { 0xD64CC78CU, 0x795847C9U, 0x9B6CB27BU, 0x6C50621BU, 0xDF8022ABU, 0x07099BF8U, 0xC04EDA1DU, 0x48F862EBU }, { 0xE1603C16U, 0xD12732EDU, 0x5C9A9450U, 0x19A80E0FU, 0xB429B4FCU, 0xE2257F54U, 0x45460515U, 0x66D3B2C6U } } } /* window 26 */,
    { { { 0x453CADD6U, 0x8DE2B7BCU, 0xBC0BC1F8U, 0x203900A7U, 0xA6ABD3AFU, 0xBCD86E47U, 0x8502EFFBU, 0x911CAC12U }, { 0xEC965469U, 0x2D550242U, 0x29E0017EU, 0x0E9F7692U, 0x65979885U, 0x633F078FU, 0x4CF751EFU, 0xFB87D449U } },
      { { 0xD551EE10U, 0x6066E2A2U, 0x727E09A6U, 0x87A8F1D8U, 0x2C01148DU, 0x00D08BABU, 0x424F33FEU, 0x6DA8E4F1U }, { 0xCF9A4E71U, 0x466D17F0U, 0x3BF5CB19U, 0xFF502010U, 0xD062ECC0U, 0xDCCF97D8U, 0x81D80AC4U, 0x80C0D9AFU } },
      { { 0x1D7AADABU, 0x1A0445FFU, 0xD5F6A67CU, 0x65D38260U, 0x91CFB26FU, 0x6E62FB08U, 0x5C7D91D6U, 0xEF1E0FA5U }, { 0x33DB72CDU, 0x47E7C7BAU, 0xFA7C74B2U, 0x017CBC09U, 0xF50A503CU, 0x3C931590U, 0x616BAA42U, 0xCAC54F60U } },
      { { 0x1BF4581CU, 0x98857CEBU, 0xACA7B166U, 0xE635E186U, 0x659722ACU, 0x278DDD22U, 0x1DB68007U, 0xA0903C4CU }, { 0x48F21402U, 0x366E4589U, 0xB96ABDA2U, 0x31B49C14U, 0xE0403190U, 0x329C4B09U, 0xD29F43FEU, 0x97197CA3U } },
      { { 0x4B07E2B1U, 0x7173DD5DU, 0x8D9EA221U, 0xD144C4CBU, 0x1105AB14U, 0xE8B04EA4U, 0xFE80D8F1U, 0x92DDA542U }, { 0xCF03DCE6U, 0xE9982FA8U, 0x1A22CFFCU, 0x8B5EA965U, 0x3FAD88C4U, 0xF7F4EA7FU, 0x6A5BA95CU, 0x62DB773EU } },
      { { 0x820357C7U, 0x18BD3FB4U, 0x6F1458ADU, 0x992039AEU, 0x25B44AA1U, 0x9A1DF3C5U, 0xED3D5281U, 0x2D780357U }, { 0xC77AD4D4U, 0x58CF7E4DU, 0xF9DF4FC4U, 0xD49A7998U, 0x1D71205EU, 0x4465A8B5U, 0x649254AAU, 0xA0EE0EA6U } },
      { { 0x9C92B235U, 0x4BAAE6E8U, 0x6B3993A1U, 0xA73BBD0EU, 0x693DD031U, 0xD06D60ECU, 0x7156881CU, 0x03CAB91BU }, { 0x1DB3574BU, 0xD615862FU, 0x64BB061AU, 0x485B0185U, 0xA0181E06U, 0x27434988U, 0xC1C0C757U, 0x2CD61AD4U } },
      { { 0xF3480D4AU, 0x03E2DE1CU, 0xBC8ACF1AU, 0xF0D8EDC7U, 0x68295A9CU, 0xF23E3303U, 0xC546A97DU, 0xFADD5F68U }, { 0x96F8ACB1U, 0x895597ADU, 0x671BDAE2U, 0xBDDD49D5U, 0x21DD43F4U, 0x16FCD528U, 0x6619141AU, 0xA5A45412U } } } /* window 27 */,
    { { { 0xC360E25AU, 0x8CE9B6BFU, 0x075A1A78U, 0xE6425195U, 0x481732F4U, 0x9DC756A8U, 0x5432B57AU, 0x83C0440FU }, { 0xD720281FU, 0xC670B3F1U, 0xD135E051U, 0x2205910EU, 0xDB052BE7U, 0xDED14B0EU, 0xC568EA39U, 0x697B3D27U } },
      { { 0xFB3FF9EDU, 0x2E599B9AU, 0x17F6515CU, 0x28C2E0ABU, 0x474DA449U, 0x1CBEE4FDU, 0x4F364452U, 0x071279A4U }, { 0x01FBE855U, 0x97ABFF66U, 0x5FDA51C4U, 0x3EE394E8U, 0x67597C0BU, 0x190385F6U, 0xA27EE34BU, 0x6E9FCCC6U } },
      { { 0x14092EBBU, 0x0B89DE93U, 0x428E240CU, 0xF17256BDU, 0x93D2F064U, 0xCF89A7F3U, 0xE1ED3B14U, 0x4F57841EU }, { 0xE708D855U, 0x4EE14405U, 0x03F1C3D0U, 0x856AAE72U, 0xBDD7EED5U, 0xC8E5424FU, 0x73AB4270U, 0x3333E4EFU } },
      { { 0xDDA492F8U, 0x3BC77ADEU, 0x78297205U, 0xC11A3AEAU, 0x34931B4CU, 0x5E89A3E7U, 0x9F5694BBU, 0x17512E2EU }, { 0x177BF8B6U, 0x5DC349F3U, 0x08C7FF3EU, 0x232EA4BAU, 0xF511145DU, 0x9C4F9D16U, 0x33B379C3U, 0xCCF109A3U } },
      { { 0xA1F25897U, 0xE75E7A88U, 0xA1B5D4D8U, 0x7AC6961FU, 0x08F3ED5CU, 0xE3E10773U, 0x0A892DFBU, 0x208A54ECU }, { 0x78660710U, 0xBE826E19U, 0x237DF2C8U, 0x0CF70A97U, 0xED704DA5U, 0x418A7340U, 0x08CA33FDU, 0xA3EEB9A9U } },
      { { 0x169BCA96U, 0x49D96233U, 0x2DA6AAFBU, 0x04D286D4U, 0xA0C2FA94U, 0xC09606ECU, 0x23FF0FB3U, 0x8869D0D5U }, { 0xD0150D65U, 0xA99937E5U, 0x240C14C9U, 0xA92E2503U, 0x108E2D49U, 0x656BF945U, 0xA2F59E2BU, 0x152A733AU } },
      { { 0x8434A920U, 0xB4323D58U, 0x622103C5U, 0xC0AF8E93U, 0x938DBF9AU, 0x667518EFU, 0x83A9CDF2U, 0xA1843073U }, { 0x5447AB80U, 0x350A94AAU, 0xC75A3D61U, 0xE5E5A325U, 0x68411A9EU, 0x74BA507FU, 0x594F70C5U, 0x10581FC1U } },
      { { 0x80EB24A9U, 0x60E28570U, 0x488E0CFDU, 0x7BEDFB4DU, 0xC259CDB8U, 0x721EBBD7U, 0xBC6390A9U, 0x0B0DA855U }, { 0xDE314C70U, 0x2B4D04DBU, 0x6C32E846U, 0xCDBF1FBCU, 0xB162FC9EU, 0x33833EABU, 0xB0DD3AB7U, 0x9939B48BU } } } /* window 28 */,
    { { { 0x711B0EB9U, 0x96892C1FU, 0x780AB954U, 0xB905F2C8U, 0xA20792DBU, 0xACE26309U, 0x0684E126U, 0xEC8AC9B3U }, { 0xB40A2447U, 0x486AD8B6U, 0x9FE3FB24U, 0x60121FC1U, 0x1A8E3B3FU, 0x5626FCCFU, 0x6AD1F394U, 0x4E568622U } },
      { { 0x4A8A3D62U, 0x5A4B46C6U, 0x247743D2U, 0x8469C4D0U, 0x88F7E433U, 0x2BB3A13DU, 0x01BE5849U, 0x62B23A10U }, { 0xA63D1A4CU, 0xE83596B4U, 0x7D183F3EU, 0x454E7FEAU, 0x17AFB01CU, 0x643FCE61U, 0x1C4C3638U, 0x4E65E5E6U } },
      { { 0x6ADD8545U, 0xE5DB7717U, 0x72C49B66U, 0x1B71CB66U, 0x68421D77U, 0xD8560739U, 0x83E3AFEAU, 0x03840FE8U }, { 0x1EC69977U, 0xB391DAD5U, 0x307F6726U, 0xAE243FB9U, 0xE8CA160CU, 0xC88AC87BU, 0x4CE355F4U, 0x5174CCEDU } },
      { { 0xCBC613E5U, 0xC1E17EB6U, 0x497EA61CU, 0x33131D55U, 0xAF7EDED5U, 0x2F69D39EU, 0xDE6AF11BU, 0x73C2F434U }, { 0xA4A375FAU, 0x4CA52493U, 0xB833C5C2U, 0x5F06787CU, 0x3E6E71CFU, 0x814E091FU, 0x8B746666U, 0x76451F57U } },
      { { 0x95FE1347U, 0x5EE6AB84U, 0x6F24503CU, 0xAB0F6C39U, 0x4486DD6BU, 0x807E3FFBU, 0x8002FEF5U, 0xF00B6C74U }, { 0xA7862999U, 0x48BFF9A6U, 0xBED89E26U, 0x85E5A06CU, 0x3D8419EBU, 0x86D311AFU, 0x34733F16U, 0x24F3AD78U } },
      { { 0x6C68D687U, 0x5E3E03FCU, 0x1FF052C7U, 0x3E732C3DU, 0x6ED16E7AU, 0xF2D0EFA6U, 0xB65BB746U, 0x63D92B26U }, { 0xDD44867CU, 0xFFCD82BAU, 0xF8C081B8U, 0xA71B4A9EU, 0x736C8785U, 0x6C1676A7U, 0x9D8932D0U, 0xBE2C0616U } },
      { { 0x2BCFFBC4U, 0x53376D28U, 0x06EADB7AU, 0x708817A7U, 0xCD35AE69U, 0x6FF50E05U, 0x74BC7FDEU, 0x63B5FB75U }, { 0xE7FE08C4U, 0x71C9E953U, 0xF583CA18U, 0xB4D8BFD4U, 0x45E81C5CU, 0xDE8D7882U, 0xE0474138U, 0xA5F5E93CU } },
      { { 0x694DB7E0U, 0x80F9BDEFU, 0xB9FCDDC6U, 0xEDCA8787U, 0x03B8DCE1U, 0x51981C34U, 0x70E10BA1U, 0x4274DCF1U }, { 0x6DEF6D1AU, 0xF72743B8U, 0xEBDB1866U, 0xD25B1670U, 0x050C6F58U, 0xC4491E8CU, 0x87FBD7F5U, 0x2BE2B2ABU } } } /* window 29 */,
    { { { 0xD111F8ECU, 0x3E0E5C9DU, 0xB7C4E760U, 0xBCC33F8DU, 0xBD392A51U, 0x702F9A91U, 0xC132E92DU, 0x7DA4A795U }, { 0x0BB1151BU, 0x1A0B0AE3U, 0x02E32251U, 0x54FEBAC8U, 0x694E9E78U, 0xEA3A5082U, 0xE4FE40B8U, 0xE58FFEC1U } },
      { { 0x29C4120BU, 0xFBB8349DU, 0xC0D0D915U, 0x9F94391FU, 0x5410BA51U, 0xC4074FA7U, 0x150A5911U, 0xA66ADBF6U }, { 0x34BFCA38U, 0xC164543CU, 0xB9E1CCFCU, 0xE0F27560U, 0xE820219CU, 0x99DA0F53U, 0xC6B4997AU, 0xE8234498U } },
      { { 0x516E19E4U, 0x7B23C513U, 0xC5C4D593U, 0x56E2E847U, 0x5CE71EF6U, 0x9F727D73U, 0xF79A44C5U, 0x5B6304A6U }, { 0x3AB7E433U, 0x6638A736U, 0xFE742F83U, 0x1ADEA470U, 0x5B7FC19FU, 0xE054B854U, 0xBA1D0698U, 0xF935381AU } },
      { { 0x918E4936U, 0xB5504F9DU, 0xB2513982U, 0x65035EF6U, 0x6F4D9CB9U, 0x0553A0C2U, 0xBEA85509U, 0x6CB10D56U }, { 0xA242DA11U, 0x48D957B7U, 0x672B7268U, 0x16A4D3DDU, 0x8502A96BU, 0x3D7E637CU, 0x730D463BU, 0x27C7032BU } },
      { { 0x5846426FU, 0x55366B7DU, 0x247D441DU, 0xE7D09E89U, 0x736FBF48U, 0x510B404DU, 0xE784BD7DU, 0x7FA003D0U }, { 0x17FD9596U, 0x25F7614FU, 0x35CB98DBU, 0x49E0E0A1U, 0x2E83A76AU, 0x2C65957BU, 0xCDDBE0F8U, 0x5D40DA8DU } },
      { { 0xA595939DU, 0x37F68BB4U, 0x28740217U, 0x03556479U, 0x84AD7612U, 0x8E740E7CU, 0x9044695FU, 0xD89BC843U }, { 0x85A9184DU, 0xF7F3DA5DU, 0x9FC0B074U, 0x562563BBU, 0xF88A888EU, 0x06D2E6AAU, 0x161FBE7CU, 0x612D8643U } },
      { { 0x54530BB2U, 0x9FB3BBA3U, 0xCB0869EAU, 0xBDE3EF77U, 0x0B431163U, 0x89BC9046U, 0xE4819A35U, 0x4D03D7D2U }, { 0x43B6A782U, 0x33AE4F9EU, 0x9C88A686U, 0x216DB307U, 0x00FFEDD9U, 0x91DD88E0U, 0x12BD4840U, 0xB280DA9FU } },
      { { 0x3E538CD7U, 0x458F8691U, 0x8E08AD53U, 0xA7001F6CU, 0xBF5D15FFU, 0x52B8C6E6U, 0x011215DDU, 0x548234A4U }, { 0x3D5B4045U, 0xFF5A9D2DU, 0x4A904190U, 0xB0FFEEB6U, 0x48607F8BU, 0x55A3ACA4U, 0x30A0672AU, 0x8CBD665CU } } } /* window 30 */,
    { { { 0x33F6746CU, 0xC7F3A8F8U, 0xFEA990CAU, 0x21E46F65U, 0xCADDB0A9U, 0x915FD5C5U, 0x78614555U, 0xBD41F016U }, { 0x426FFB58U, 0x346F4434U, 0x14DBC204U, 0x80559436U, 0x5A969B7FU, 0xF3DD20FEU, 0xE899A39AU, 0x9D59E956U } },
      { { 0xB733AA5FU, 0x3C2F0BA9U, 0xF05AF235U, 0xDECE47CBU, 0xA2AC82A5U, 0xF8E3F715U, 0x2203F18AU, 0xC97BA641U }, { 0x09C11060U, 0xC3AF5504U, 0x46AF512DU, 0x56EA2C05U, 0xF3F28146U, 0xFAC28DAFU, 0x959EF494U, 0x87FAB43AU } },
      { { 0x775D6ECEU, 0xEF4F115CU, 0xE8C0E78DU, 0x69D2E3BBU, 0x145CFC81U, 0xB0264EF1U, 0x1B69788BU, 0x0A41E9FAU }, { 0x909A1F0BU, 0x0D9233BEU, 0x0AE76B30U, 0x150A8452U, 0x0632BB69U, 0xEA337537U, 0xAA25584AU, 0x15F7B3CFU } },
      { { 0xD4C5105FU, 0x09891641U, 0x6D7FBD65U, 0x1AE80F8EU, 0xBEE6BDB0U, 0x9D67225FU, 0x7FC4D860U, 0x3B433B59U }, { 0x93E85638U, 0x44E66DB6U, 0xE3E9862FU, 0xF7B59252U, 0x665C32ECU, 0xDB785157U, 0xAE362F50U, 0x702FEFD7U } },
      { { 0x1339609AU, 0x6EB4A914U, 0x3E37EABDU, 0x2B627DEEU, 0x728C8D9CU, 0xEA4083D1U, 0x518F21E4U, 0xE70814D4U }, { 0x17398D14U, 0x4CB05B57U, 0x8003F6C9U, 0x9D37D255U, 0x60829275U, 0x70577AF7U, 0xC67D7E4FU, 0xCB4A9A9AU } },
      { { 0x97290293U, 0xFE756A5CU, 0xD388ACBFU, 0xBF04A19CU, 0x5E916BDAU, 0xFBBBB9CFU, 0x91F93BECU, 0xF4895273U }, { 0x2A5923D7U, 0xDEE07EC3U, 0xFDE0C370U, 0xC7BC949BU, 0x0419D8FCU, 0xBD512175U, 0x3FDCC93FU, 0x54F5D476U } },
      { { 0xD13FB27DU, 0xC20F05F7U, 0x6C7195C0U, 0xC05B30D3U, 0x32FC56C5U, 0xA335CF18U, 0x62B3A82BU, 0xAE65BCD3U }, { 0x630D99EAU, 0xCBF6AAB8U, 0xE62CEC6CU, 0x164BE816U, 0x2FEED2F1U, 0x6D41819DU, 0x0B91BD0DU, 0xFCDC5907U } },
      { { 0x0FEFB0C3U, 0x3754475DU, 0x46D7C35DU, 0xD48FB56BU, 0x363798A4U, 0xA070B633U, 0x8FDB98E6U, 0xAE89F3D2U }, { 0x6363D14CU, 0x970B89C8U, 0x67ABD27DU, 0x89817521U, 0x44D5A021U, 0x9BF7D474U, 0xCAC72AEEU, 0xB3083BAFU } } } /* window 31 */,
    { { { 0xBFE20925U, 0x62A8C244U, 0x8FDCE867U, 0x91C19AC3U, 0xDD387063U, 0x5A96A5D5U, 0x21D324F6U, 0x61D587D4U }, { 0xA37173EAU, 0xE87673A2U, 0x53778B65U, 0x23848008U, 0x05BAB43EU, 0x10F8441EU, 0x4621EFBEU, 0xFA11FE12U } },
      { { 0xB8A24A20U, 0x23F949FEU, 0xF52CA53FU, 0x17EBFED1U, 0xBCFB4853U, 0x9B691BBEU, 0x6278A05DU, 0x5617FF6BU }, { 0xE3C99EBDU, 0x241B34C5U, 0x1784156AU, 0xFC64242EU, 0x695D67DFU, 0x4206482FU, 0xEE27C011U, 0xB967CE0EU } },
      { { 0xB2335834U, 0xC0F734A3U, 0x90EF6860U, 0x9526205AU, 0x04E2BB0DU, 0xCB8BE717U, 0x02F383FAU, 0x2418871EU }, { 0x4082C157U, 0xD7177681U, 0x29C20073U, 0xCC914AD0U, 0xE587E728U, 0xF186C1EBU, 0x61BCD5FDU, 0x6FDB3C22U } },
      { { 0x41C23FA3U, 0xB4480F04U, 0xC1989A2EU, 0xB4712EB0U, 0x93A29CA7U, 0x3CCBBA0FU, 0xD619428CU, 0x6E205C14U }, { 0xB3641686U, 0x90DB7957U, 0x45AC8B4EU, 0x0432691DU, 0xF64E0350U, 0x07A759ACU, 0x9C972517U, 0x0514D89CU } },
      { { 0x2CF9D7C1U, 0xCC7C4C1CU, 0xEE95E5ABU, 0x1320886AU, 0xBEAE170CU, 0xBB7B9056U, 0xDBC0D662U, 0xC8A5B250U }, { 0xC11D2303U, 0x4ED81432U, 0x1F03769FU, 0x7DA66912U, 0x84539828U, 0x3AC7A5FDU, 0x3BCCDD02U, 0x14DADA94U } },
      { { 0xF0DCBC49U, 0x7BB4F7AAU, 0x70BBB45BU, 0x7DE551F9U, 0x9F2CA2E5U, 0xCFD0F3E4U, 0x1F5C76EFU, 0xECE58709U }, { 0x167D79AEU, 0x32920EDDU, 0xFA7D7EC1U, 0x039DF8A2U, 0xBB30AF91U, 0xF46206C0U, 0x22676B59U, 0x1FF5E2F5U } },
      { { 0xCBAE2F70U, 0x51B90651U, 0x93AAA8EBU, 0xEFC4BC05U, 0xDD1DF499U, 0x8ECD8689U, 0x22F367A5U, 0x1AEE99A8U }, { 0xAE8274C5U, 0x95D485B9U, 0x7D30B39CU, 0x6C14D445U, 0xBCC1EF81U, 0xBAFEA90BU, 0xA459A2EDU, 0x7C5F317AU } },
      { { 0xC4FE3C39U, 0xE3B22C6BU, 0x6C7BEBDFU, 0xBA4A8153U, 0x25693459U, 0xF23AB6B7U, 0x14922B11U, 0x53BC3770U }, { 0x5AFC60DBU, 0x4645C8ABU, 0x20B9F2A3U, 0xAA022355U, 0xCE0FC507U, 0x52A2954CU, 0x7CE1C2E7U, 0x8C2731BBU } } } /* window 32 */,
    { { { 0xE48FB889U, 0x6A7091C2U, 0x7B8A9D06U, 0x26882C13U, 0x1B82A0E2U, 0xA2498663U, 0x3518152DU, 0x844ED736U }, { 0xD86E27C7U, 0x282F476FU, 0x04AFEFDCU, 0xA04EDACAU, 0x6119E34DU, 0x8B256EBCU, 0x0787D78BU, 0x56A413E9U } },
      { { 0x5A74BE50U, 0x82EE061DU, 0xDEA16FF5U, 0xE41781C4U, 0x99BFC8A2U, 0xE0B0C81EU, 0x0B547E2DU, 0x624F4D69U }, { 0xBDCC9AE4U, 0x3A83545DU, 0x409B1E8EU, 0x2573DBB6U, 0xA6C93539U, 0x482960C4U, 0x5AE18798U, 0xF01059ADU } },
      { { 0x4D559D96U, 0x38151E27U, 0xB8DB6C01U, 0x4F18C0D3U, 0x6F9921AFU, 0x49A3AA83U, 0x8C046029U, 0xDBEAB27BU }, { 0x7040BF3BU, 0x242B9EAAU, 0x1614B091U, 0x39C479E5U, 0x0E4BAF5DU, 0x338EDE2BU, 0xF0A53945U, 0x5BB192B7U } },
      { { 0x3112795FU, 0x715C9F97U, 0x984E6EE1U, 0xE8244437U, 0xECB66BCDU, 0x55CB4858U, 0xABAFFBEEU, 0x7C136735U }, { 0x5DBEC38EU, 0x54661595U, 0x388AD153U, 0x51C0782CU, 0xC6E0952FU, 0x9BA4C53AU, 0x1B21DFA8U, 0x27E6782AU } },
      { { 0xEC5D7F65U, 0x7D89C251U, 0x90394087U, 0x0C8F5616U, 0xF0691AB3U, 0x609E1CFCU, 0xE9B20B21U, 0x2A0300BFU }, { 0xB114FAF4U, 0xBF532FADU, 0x521BF5D1U, 0x328FC0B9U, 0x3BFC36DEU, 0xBD51F93CU, 0x7A4E5F60U, 0xD989050EU } },
      { { 0x4ED2DBC2U, 0x682F903DU, 0x7C3B2D83U, 0x0EBA59C8U, 0x9C7E9335U, 0x8E9DC84DU, 0x0EB226D7U, 0x5F9B21B0U }, { 0xAF267BAEU, 0xE33BD394U, 0xBE2E15AEU, 0xAA86CC25U, 0x6A8EC500U, 0x4F0BF67DU, 0xF9630658U, 0x5846AA44U } },
      { { 0xE7E0C278U, 0x6786BA38U, 0x588B2E6FU, 0x09BF87CEU, 0x465FEE3AU, 0x723B7022U, 0x64682394U, 0x08B84114U }, { 0x29E64629U, 0x0EB52CE0U, 0xCCA78E43U, 0xADB60E8FU, 0xB654A991U, 0x20DD7062U, 0xC69A6FE5U, 0x4281D428U } },
      { { 0xE2C2BF15U, 0xFEB09740U, 0xA9E99704U, 0x627A2205U, 0xC2FBC565U, 0xEC8D73D0U, 0xC20C8DE8U, 0x223EED8FU }, { 0xA8363B49U, 0x1EE32583U, 0xC9C2B0A6U, 0x1A0B6CB9U, 0x90DBC85CU, 0x49F7C3D2U, 0x1EF4C1ACU, 0xA8DFBB97U } } } /* window 33 */,
    { { { 0x846E364FU, 0xC16C236EU, 0xDEA50CA0U, 0x7F33527CU, 0x0926B86DU, 0xC4810775U, 0x0598E70CU, 0x6C2A3609U }, { 0xF024E924U, 0xA6755E52U, 0x9DB4AFCAU, 0xE0FA07A4U, 0x66831790U, 0x15C3CE7DU, 0xA6CBB0D6U, 0x5B4EF350U } },
      { { 0x0F15DDE9U, 0x05214C05U, 0x0D5F2B82U, 0xA47A76A8U, 0x62E82B62U, 0xBB254D30U, 0x3EC955EEU, 0x11A05FE0U }, { 0x9D529B36U, 0x7EAFF46EU, 0x8F9E3DF6U, 0x55AB1301U, 0x99317698U, 0xC463E371U, 0xCCDA47ADU, 0xFD251438U } },
      { { 0xA9D82ABFU, 0xE2A37598U, 0xE6C170F5U, 0x5F188CCBU, 0x5066B087U, 0x81682200U, 0xC7155ADAU, 0xDA22C212U }, { 0xFBDDB479U, 0x151E5D3AU, 0x6D715B99U, 0x4B606B84U, 0xF997CB2EU, 0x4A73B54BU, 0x3ECD8B66U, 0x9A1BFE43U } },
      { { 0xDBFB894EU, 0xE13122F3U, 0xCE274B18U, 0xBE9B79F6U, 0xCA58AADFU, 0x85A49DE5U, 0x11487351U, 0x24957758U }, { 0xBB939099U, 0x111DEF61U, 0x26D13694U, 0x1D6A974AU, 0xD3FC253BU, 0x4474B4CEU, 0x4C5DB15EU, 0x3A1485E6U } },
      { { 0x1430C9ABU, 0x5AFDDAB6U, 0x2238E997U, 0x0BDD41D3U, 0x418042AEU, 0xF0947430U, 0xCDDDC4CBU, 0x71F9ADDAU }, { 0xC52DD907U, 0x7090C016U, 0x29E2047FU, 0xD9BDF44DU, 0x1B1011A6U, 0xE6F1FE80U, 0xD9ACDC78U, 0xB63ACCBCU } },
      { { 0x4BAEF62EU, 0x7817ACABU, 0xA85B91E8U, 0x9F5A2202U, 0x6CE57610U, 0x9666EBE6U, 0xF73BFE03U, 0x32AD31F3U }, { 0x25BCF4D6U, 0x628330A4U, 0x515056E6U, 0xEA950593U, 0xE1332156U, 0x59811C89U, 0x8C11B2D7U, 0xC89CF1FEU } },
      { { 0xC0B7EFF3U, 0x0AD7337AU, 0xC5E48B3CU, 0x8552225EU, 0x73F13A5FU, 0xE6F78B0CU, 0x82349CBEU, 0x5E70062EU }, { 0xE7073969U, 0x6B8D5048U, 0xC33CB3D2U, 0x392D2A29U, 0x4ECAA20FU, 0xEE4F727CU, 0x2CCDE707U, 0xA068C99EU } },
      { { 0x1ED66F18U, 0xEBDE86ECU, 0xD61FCE43U, 0x225D906BU, 0xE8BED74DU, 0x5CAB07D6U, 0x27855AB7U, 0x16E4617FU }, { 0xB2FBC3DDU, 0x6568AADDU, 0x8AEDDF5BU, 0xEDB5484FU, 0x6DCF2FADU, 0x878F20E8U, 0x615F5699U, 0x3516497CU } } } /* window 34 */,
    { { { 0xFA181E69U, 0xEF0A3FECU, 0x30D69A98U, 0x9EA02F81U, 0x66EAB95DU, 0xB2E9CF8EU, 0x24720021U, 0x520F2BEBU }, { 0x1DF84361U, 0x621C540AU, 0x71FA6D5DU, 0x12037721U, 0x0FF5F6FFU, 0x6E3C7B51U, 0xABB2BEF3U, 0x817A069BU } },
      { { 0xB294CDA6U, 0x83572FB6U, 0xB9039F34U, 0x6CE9BF75U, 0x095CBB21U, 0x20E012F0U, 0xD063F0DAU, 0xA0AECC1BU }, { 0xF02909E5U, 0x57C21C3AU, 0x48CE9CDCU, 0xC7D59ECFU, 0x8AE336F8U, 0x2732B844U, 0x3F4F85F4U, 0x056E3723U } },
      { { 0x89E800CAU, 0x8A10B531U, 0x145208FDU, 0x50FE0C17U, 0xB714BA37U, 0x9E43C0D3U, 0x34189ACCU, 0x427D200EU }, { 0xE616E2C0U, 0x05DEE24FU, 0xEE1854C1U, 0x9C25F4C8U, 0x8F342A73U, 0x4D3222A5U, 0xA027C952U, 0x0807804FU } },
      { { 0x4F0D56F3U, 0xC222653AU, 0xCA28B805U, 0x961E4047U, 0x4A73434BU, 0x2C03F8B0U, 0xAB712A19U, 0x4C966787U }, { 0x864FEE42U, 0xCC196C42U, 0x5B0ECE5CU, 0xC1BE93DAU, 0xC131C159U, 0xA87D9F22U, 0xDCE45655U, 0x2BB6D593U } },
      { { 0xB809B7CEU, 0x22C49EC9U, 0xE2C72C2CU, 0x8A41486BU, 0xFEA0BF36U, 0x813B9420U, 0xA66DAC69U, 0xB3D36EE9U }, { 0x328CC987U, 0x6FDDC08AU, 0x3A326461U, 0x0A3BCD2CU, 0xD810DBBAU, 0x7103C49DU, 0x4B78A4C4U, 0xF9D81A28U } },
      { { 0xE4D55941U, 0x3DE865ADU, 0x30384087U, 0xDEDAFA5EU, 0x4EF18B9BU, 0x6F414ABBU, 0xFAEE5268U, 0x9EE9EA42U }, { 0x37A55A4AU, 0x260FAA16U, 0x015F93B9U, 0xEB19A514U, 0x9E9C3598U, 0x51D7EBD2U, 0x1932178EU, 0x523FC56DU } },
      { { 0xB98FE684U, 0x501D070CU, 0x124A1458U, 0xD60FBE9AU, 0x92BC6B3FU, 0xA45761C8U, 0xFE6F27CBU, 0xF5384858U }, { 0xB59E763BU, 0x4B0271F7U, 0x5B5A8E5EU, 0x3D4606A9U, 0x05A48292U, 0x1EDA5D9BU, 0xE6FEC446U, 0xDA7731D0U } },
      { { 0x90D45871U, 0xA3E33693U, 0x06166D8DU, 0xE9764040U, 0x89A90403U, 0xB5C33682U, 0x72F1D637U, 0x4BD17983U }, { 0xD5D2C53AU, 0xA616679EU, 0xFDCF3B87U, 0x5EC4BCD8U, 0xB66A694EU, 0xAE6D7613U, 0xE3FC27E5U, 0x7460FC76U } } } /* window 35 */,
    { { { 0xC63C4962U, 0x80531FE1U, 0x981FDB25U, 0x50541E89U, 0xFD4C2B6BU, 0xDC1291A1U, 0xA6DF4FCAU, 0xC0693A17U }, { 0x0117F203U, 0xB2C4604EU, 0x0A99B8D0U, 0x245F1963U, 0xC6212C44U, 0xAEDC20AAU, 0x520F52A8U, 0xB1ED4E56U } },
      { { 0x700A1ACDU, 0xB5560FB6U, 0xFD999681U, 0xE823FD73U, 0x6CB4E1BAU, 0xDA915D1FU, 0x6EBE00A3U, 0x0D030118U }, { 0x89FCA8CDU, 0x744FB0C9U, 0xF9DA0E0BU, 0x970D01DBU, 0x7931D76FU, 0x0AD8C564U, 0xF659B96AU, 0xB15737BFU } },
      { { 0x6BDF22DAU, 0x18F37A9CU, 0x90DC82DFU, 0xEFBC432FU, 0x5D703651U, 0xC52CEF8EU, 0xD99881A5U, 0x82887BA0U }, { 0xB920EC1DU, 0x7CEC9DDAU, 0xEC3E8D3BU, 0xD0D7E8C3U, 0x4CA88747U, 0x445BC395U, 0x9FD53535U, 0xEDEAA2E0U } },
      { { 0xCE53C2D0U, 0xA12B384EU, 0x5E4606DAU, 0x779D897DU, 0x73EC12B0U, 0xA53E47B0U, 0x5756F1ADU, 0x462DBBBAU }, { 0xCAFE37B6U, 0x69FE09F2U, 0xECCE2E17U, 0x273D1EBFU, 0x3CF607FDU, 0x8AC1D538U, 0x12E10C25U, 0x8035F7FFU } },
      { { 0x296C9005U, 0xB7D4CC0FU, 0x7B0AEBDBU, 0x4B9094FAU, 0xC00EC8D4U, 0xE1BF10F1U, 0xD667C101U, 0xD807B1C4U }, { 0xBE713383U, 0xA9412CDFU, 0x81142BA1U, 0x435E063EU, 0xAF0A6BDCU, 0x984C15ECU, 0x92A3DAB9U, 0x592C2460U } },
      { { 0x2093C22AU, 0xCA442D5AU, 0xD5703AEDU, 0xEBD0BD31U, 0x653287B6U, 0x308F2AFDU, 0x0D1BC8BAU, 0x9BB88BACU }, { 0x75C1E3B2U, 0xFBAF8538U, 0xCA11447CU, 0xBD2AC950U, 0xEA5C4C8DU, 0x286D816CU, 0x28DC3208U, 0xDC3AA800U } },
      { { 0x16E23E9DU, 0x93656900U, 0xA7CC41E1U, 0xCB220C6BU, 0x69D6245CU, 0xB36B20C3U, 0xB62E9A6AU, 0x2D63C348U }, { 0xCDC0BCB5U, 0xA3473E19U, 0x8F601B98U, 0x70F18B3FU, 0xCDE346E4U, 0x8AD7A2C7U, 0xBD3AAA64U, 0xAE9F6EC3U } },
      { { 0x7E6C5520U, 0x854D34C7U, 0xDCB9EA58U, 0xC27DF9EFU, 0xD686666DU, 0x405F2369U, 0x0417AA85U, 0x29D1FEBFU }, { 0x93470AFEU, 0x9846819EU, 0xE2A27F9EU, 0x3E6A9669U, 0xE31E6504U, 0x24D008A2U, 0x9CB7680AU, 0xDBA7CECFU } } } /* window 36 */,
    { { { 0x338D6E43U, 0xECAFF541U, 0x4541D5CCU, 0x56F7DD73U, 0x96BC88CAU, 0xB5D426DEU, 0x9ED3A2C3U, 0x48D94F6BU }, { 0x2EF8279CU, 0x6354A3BBU, 0x0B1867F2U, 0xD575465BU, 0x95225151U, 0xEF99B0FFU, 0xF94500D8U, 0xF3E19D88U } },
      { { 0x51EFB310U, 0x0D0DF6CEU, 0x958DF5BEU, 0xCB5B2EB4U, 0x36158E59U, 0xD6459E29U, 0x1466E336U, 0x82AAE2B9U }, { 0x411AA636U, 0xFB658A39U, 0xD4C0A933U, 0x7152ECC5U, 0x49F026B7U, 0xF10C758AU, 0xCB09311FU, 0xF4837F97U } },
      { { 0xB71698F5U, 0x7807F364U, 0x9F7B605EU, 0x6BA418D2U, 0xA03B2CBBU, 0xFD20B00FU, 0xDA54386FU, 0x883ECA37U }, { 0xF3437F24U, 0xFF0BE43FU, 0xA48BB33CU, 0xE910B432U, 0x329DF765U, 0x4963A128U, 0xBE2FE6F7U, 0xAC1DD556U } },
      { { 0x626332D5U, 0x994F523AU, 0x5561BB44U, 0x7BC38833U, 0x3D845EA2U, 0x005ED4B0U, 0xC2A1F08AU, 0xD39D3EE1U }, { 0xE7676B0DU, 0x6561FDD3U, 0xFB706017U, 0x620E35FFU, 0xF264F9A8U, 0x36CE424FU, 0xDA2681F7U, 0xC4C3419FU } },
      { { 0xF405FF06U, 0x1C30861CU, 0x486E828BU, 0xEBAC86BDU, 0x636933FCU, 0xE791A971U, 0x7AEEE947U, 0x50E7C2BEU }, { 0xFA90D767U, 0xC3D4A095U, 0xE670AB7BU, 0xAE60EB7BU, 0x397B056DU, 0x17633A64U, 0x105012AAU, 0x93A21F33U } },
      { { 0x369B87ADU, 0x857C1F22U, 0x32FCA556U, 0x3C00E5D9U, 0x90B06466U, 0x1AD74CABU, 0x550FAAF2U, 0xA7112386U }, { 0x6D9BD5F5U, 0x7435E198U, 0x59C3463FU, 0x2DCC7E38U, 0xCA7BD4B2U, 0xDC7DF748U, 0x9DEC2F31U, 0x13CD4C08U } },
      { { 0x22CAF46BU, 0x5936E460U, 0x9A96FE4FU, 0x6A45DD8FU, 0xB98F474EU, 0xF7925434U, 0x0053EF15U, 0x41410412U }, { 0x41DE97BFU, 0x71CF8D12U, 0xBD80BEF4U, 0xB8547B61U, 0xC4DB0037U, 0xB47D3970U, 0xFEF20DFFU, 0xF1BCD328U } },
      { { 0x9BB81648U, 0x00F83176U, 0x653120D0U, 0xD69EB485U, 0x4CCABC62U, 0xD17D75F4U, 0xB749FCB1U, 0x34A07F82U }, { 0xBBFB5554U, 0x2C3AF787U, 0x62E283F8U, 0xB06ED4D0U, 0xA19213A0U, 0x5722889FU, 0xDCF3C7B4U, 0x162B085EU } } } /* window 37 */,
    { { { 0x7189E71FU, 0x32670D2FU, 0x5ECF91E7U, 0xC6438748U, 0xDB757A21U, 0x15758E57U, 0x290A9CE5U, 0x427D09F8U }, { 0x38384A7AU, 0x846A308FU, 0xB0732B99U, 0xAAC3ACB4U, 0x17845819U, 0x9E941009U, 0xA7CE5E03U, 0x95CBA111U } },
      { { 0xAACA5E9BU, 0x97B7851AU, 0x56713B97U, 0x518AA521U, 0x150A61F6U, 0x3357E8C7U, 0xEC2C2B69U, 0x7842E7E2U }, { 0x6868A548U, 0x8DFFAF65U, 0xE068FC81U, 0xD963BD82U, 0x65917733U, 0x64DA5C8BU, 0x7B247328U, 0x927090FFU } },
      { { 0xA105FC8EU, 0x37A01E48U, 0x289BA48CU, 0x769D754AU, 0xD51C2180U, 0xC08C6FE1U, 0xB7BD1387U, 0xB032DD33U }, { 0x020B0AA6U, 0x953826DBU, 0x0664C73CU, 0x05137E80U, 0x660CF95DU, 0xC66302C4U, 0xB2CEF28AU, 0x99004E11U } },
      { { 0xD298C241U, 0x214BC9A7U, 0x56807CFDU, 0xE3B697BAU, 0x4564EADBU, 0xEF1C7802U, 0xB48149C5U, 0xDDE8CDCFU }, { 0x5A4D2604U, 0x946BF0A7U, 0x6C1538AFU, 0x27154D7FU, 0xDE5B1FCCU, 0x95CC9230U, 0x66864F82U, 0xD88519E9U } },
      { { 0x96EA6CA1U, 0x1013E4F7U, 0x1F792871U, 0x567CDC2AU, 0x5C658D45U, 0xADB72870U, 0xCE600E98U, 0xF7C1FF4AU }, { 0x4B6CAD39U, 0xA1BA8657U, 0xBA20B428U, 0x3D58D634U, 0xA2E6FDFBU, 0xC0011CDEU, 0x7B18960DU, 0xA832367AU } },
      { { 0x0E4938F7U, 0x47618C9FU, 0xDC83719EU, 0x58D47D69U, 0xF41A64CCU, 0xD74C1A23U, 0xB5829F66U, 0x5D28E068U }, { 0x210466F6U, 0xD8D37529U, 0xC6A64EF8U, 0x2AF1152FU, 0x19CE6A7AU, 0x55D4485CU, 0xF648E2D7U, 0x6D0BD2F5U } },
      { { 0xF416448DU, 0x1ECC032AU, 0xEC76D971U, 0x4A7E8C10U, 0xB90B6EAEU, 0x854F9805U, 0x4BED0594U, 0xFD0B1532U }, { 0xD98B5CA3U, 0x89F71848U, 0xF039B3EFU, 0xD01FE5FCU, 0x627BDA2EU, 0x4481332EU, 0xA5073E41U, 0xE67CECD7U } },
      { { 0x7CB1282CU, 0xB828DD1AU, 0xBE46973AU, 0xA08D7626U, 0xE708D6B2U, 0x6BAF8D40U, 0x4DAEB3F3U, 0x72571FA1U }, { 0xF22DFD98U, 0x85B1732FU, 0x0087108DU, 0x87AB01A7U, 0x5988207AU, 0xAAAAFEA8U, 0x69F00755U, 0xCCC832F8U } } } /* window 38 */,
    { { { 0xCA8D9D1AU, 0x488F1185U, 0xD987DED2U, 0xADF2C77DU, 0x60C46124U, 0x5F3039F0U, 0x71E095F4U, 0xE5D70B75U }, { 0x6260E70FU, 0x82D58650U, 0xF750D105U, 0x39D75EA7U, 0x75BAC364U, 0x8CF3D0B1U, 0x21D01329U, 0xF3A7564DU } },
      { { 0x3FCD3EFCU, 0xB24AA43EU, 0xB8088E9AU, 0xDD26C034U, 0xBD3D46EAU, 0xA5EF4DC9U, 0x8A4C6A6FU, 0xA2F99D58U }, { 0x2F1DA46CU, 0xDDABD355U, 0x1AFACDD1U, 0x72C3F8CEU, 0x92D40578U, 0xD90C4EEEU, 0xCA623B94U, 0xD28BB41FU } },
      { { 0xE7417CE1U, 0x242792D2U, 0x970EE7F5U, 0xFF42BC71U, 0x5C67A41EU, 0x1FF4DC6DU, 0x20882A58U, 0x77709B7BU }, { 0xBE217F2CU, 0x3554731DU, 0x5BB72177U, 0x2AF2A8CDU, 0x591DD059U, 0x58EEE769U, 0x4BBA6477U, 0xBB2930C9U } },
      { { 0xF176F2C0U, 0x1E6ADDDAU, 0xE2572658U, 0x01CA4604U, 0x85342FFBU, 0x0A404DEDU, 0x441838D6U, 0x8CF60F96U }, { 0xC9071C4AU, 0x9BBC691CU, 0x34442803U, 0xFD588744U, 0x809C0D81U, 0x97101C85U, 0x8C456F7FU, 0xA7FB754CU } },
      { { 0xAF71013FU, 0x6AF7A1D5U, 0x0BEDC946U, 0xE68216E5U, 0xD27370A0U, 0xF4CBA30BU, 0x870421CCU, 0x7981AFBFU }, { 0x9449F0E1U, 0x02496A67U, 0x0A47EDAEU, 0x86CFC4BEU, 0xB1FECA22U, 0x3073C936U, 0x03F8F8FBU, 0xF5694612U } },
      { { 0x5BDE48F8U, 0xBCADD671U, 0x2189BC7DU, 0xC9703873U, 0xC709EE8AU, 0x5D45299EU, 0x845AAFF8U, 0xD1287EE2U }, { 0xDB1DBF1FU, 0x7D1F8874U, 0x990C88D6U, 0xEA46588BU, 0x84368313U, 0x60BA649AU, 0x60D543AEU, 0xD5FDCBCEU } },
      { { 0x9890272DU, 0xCF3DE995U, 0x3E713A10U, 0x75F3432AU, 0xE28227B8U, 0x5E13479FU, 0xFEFACDC8U, 0xB8561EA9U }, { 0x8332AAFDU, 0xA6A297A0U, 0x73809B62U, 0x9B0D8BB5U, 0x0C63036FU, 0xD2FA1CFDU, 0xBD64BDA8U, 0x7A16EB55U } },
      { { 0x2AC13E27U, 0xF7E48E8AU, 0x4EB1A9F5U, 0x4494F6DFU, 0x981F0A62U, 0xEDBF84EBU, 0x536438F0U, 0x49BADC32U }, { 0x004F7571U, 0x50BEA541U, 0xDF1C94EEU, 0xBAC67D10U, 0xB727BC31U, 0x253D73A1U, 0x30686E28U, 0xB3D01CF2U } } } /* window 39 */,
    { { { 0x6D3549CFU, 0xD433E50FU, 0xFACD665EU, 0x6F33696FU, 0xCE11FCB4U, 0x695BFDACU, 0xAF7C9860U, 0x810EE252U }, { 0x7159BB2CU, 0x65450FE1U, 0x758B357BU, 0xF7DFBEBEU, 0xD69FEA72U, 0x2B057E74U, 0x92731745U, 0xD485717AU } },
      { { 0xEE36860CU, 0x896C42E8U, 0x4113C22DU, 0xDAF04DFDU, 0x44104213U, 0x1ADBB7B7U, 0x1FD394EAU, 0xE5FD5FA1U }, { 0x1A4E0551U, 0x68235D94U, 0x18D10151U, 0x6772CFBEU, 0x09984523U, 0x276071E3U, 0x5A56BA98U, 0xE4E879DEU } },
      { { 0xB898FD52U, 0x6C8D0AA9U, 0xBE9AF1A7U, 0x2FB38A57U, 0x3B4F03F8U, 0xE1F2B9A9U, 0xC3F0CC6FU, 0x2B1AAD44U }, { 0x7CF2C084U, 0x58B5332EU, 0x0367D26DU, 0x1C57D96FU, 0xFA6E4A8DU, 0x2297EABDU, 0x4A0E2B6AU, 0x65A947EEU } },
      { { 0x285B9491U, 0xAAAFAFB0U, 0x1E4C705EU, 0x01A0BE88U, 0x2AD9CAABU, 0xFF1D4F5DU, 0xC37A233FU, 0x6E349A4AU }, { 0x4A1C6A16U, 0xCF1C1246U, 0x29383260U, 0xD99E6B66U, 0x5F6D5471U, 0xEA3D4366U, 0xFF8CC89BU, 0x36974D04U } },
      { { 0xFDD5B854U, 0xF535B616U, 0x5728719FU, 0x592549C8U, 0x06921CADU, 0xE2314686U, 0x311B1EF8U, 0x98C8CE34U }, { 0xE9090B36U, 0x28B937E7U, 0x0BF7BBB7U, 0x67FC3AB9U, 0xA9D87974U, 0x12337097U, 0xF970E3FEU, 0x3E5ADCA1U } },
      { { 0xCFE89D80U, 0xC26C49A1U, 0xDA9C8371U, 0xB42C026DU, 0xDAD066D2U, 0xCA6C013AU, 0x56A4F3EEU, 0xFB8F7228U }, { 0xD850935BU, 0x08B579ECU, 0xD631E1B3U, 0x34C1A74CU, 0xAC198534U, 0xCB5FE596U, 0xE1F24F25U, 0x39FF21F6U } },
      { { 0xB3F85FF0U, 0xCDCC68A7U, 0x1A888044U, 0xACD21CDDU, 0x05DBE894U, 0xB6719B2EU, 0x8B8260D4U, 0xFAE1D3D8U }, { 0x8A1C5D92U, 0xEDFEDECEU, 0xDC52077EU, 0xBCA01A94U, 0x16DD13EDU, 0xC085549CU, 0x495EBAADU, 0xDC5C3BAEU } },
      { { 0x8F929057U, 0x27F29E14U, 0xC0C853DFU, 0x7A64AE06U, 0x58E9C5CEU, 0x256CD183U, 0xDED092A5U, 0x9D9CCE82U }, { 0x6E93B7C7U, 0xCC6E5979U, 0x31BB9E27U, 0xE1E47092U, 0xAA9E29A0U, 0xB70B3083U, 0x3785E644U, 0xBF181A75U } } } /* window 40 */,
    { { { 0x1402B9D0U, 0xD3B3A13FU, 0x2C7BC863U, 0x573441C3U, 0x578C3E6EU, 0x4B301EC4U, 0x0ADAF57EU, 0xC26FC9C4U }, { 0x7493CEA3U, 0x96E71BFDU, 0x1AF81456U, 0xD05D4B3FU, 0x6A8C608FU, 0xDACA2A8AU, 0x0725B276U, 0x53EF07F6U } },
      { { 0x46AC49D2U, 0xA6B5C9D6U, 0x83137AA9U, 0x42C77C0BU, 0x68225A38U, 0x24D000FCU, 0x2FE1E907U, 0x0F63CFC8U }, { 0xC6441F95U, 0x22D1B01BU, 0xEC8E448FU, 0x7D38F719U, 0x787FB1BAU, 0x9B33FA5FU, 0x190158DFU, 0x94DCFDA1U } },
      { { 0x526F09FDU, 0x057FED45U, 0x8128240AU, 0xE8A4F10CU, 0xFF2BFD8DU, 0x9332EFC4U, 0xBD35AA31U, 0x214E77A0U }, { 0x14FAA40EU, 0x32896D73U, 0x01E5F186U, 0x767867ECU, 0x17A1813EU, 0xC9ADF8F1U, 0x54741795U, 0xCB6CDA78U } },
      { { 0x296C36EFU, 0x211CDE10U, 0x82C4DA77U, 0x7EE89672U, 0xA57836DAU, 0xB617D270U, 0x9CB7560BU, 0xF0CD9C31U }, { 0xE455FE90U, 0x01FDCBF7U, 0x7E7334F3U, 0x3FB53CBBU, 0x4E7DE4ECU, 0x781E2EA4U, 0x0B384FD0U, 0x8ADAB3ADU } },
      { { 0x53B618C0U, 0x1C6BD47DU, 0x6A227923U, 0xC424F46CU, 0xDD92D964U, 0x7303FFDEU, 0x71B5ABF2U, 0xE9712878U }, { 0xF815561DU, 0x8F48A632U, 0xD3C055D1U, 0x85F48FF5U, 0x7525684FU, 0x222A1427U, 0x67360CC3U, 0xD0D841A0U } },
      { { 0x599FF0F9U, 0x01778A2BU, 0x8104FC6BU, 0x68A923D7U, 0xDA694FF3U, 0x5BFA44DFU, 0xF7667F12U, 0x4F7199DBU }, { 0xE46F2A79U, 0xC06D8FF6U, 0xE9F8131DU, 0x08B5DEADU, 0xABB4CE7CU, 0x02519A59U, 0xB42AEC3EU, 0xC4F710BCU } },
      { { 0x0E0B040DU, 0xB228A90FU, 0x45FF897FU, 0xBAF02D82U, 0x00FA6122U, 0x2AAC79E6U, 0x8E36F557U, 0x24828817U }, { 0x113EC356U, 0xB9521D31U, 0x15EFF1F8U, 0x9E48861EU, 0xE0D41715U, 0x2AA1D412U, 0x53F131B8U, 0x71F86203U } },
      { { 0x4ED80940U, 0x3014368BU, 0x7A6FCEDDU, 0x67E6D056U, 0xCA97579FU, 0x7C208C49U, 0xA23597F6U, 0xFE3D7A81U }, { 0x7E096AE2U, 0x5E203202U, 0x24B39366U, 0xB1F3E1E7U, 0x2FDCDFFCU, 0x26DA26F3U, 0x6097BE83U, 0x79422F1DU } } } /* window 41 */,
    { { { 0x9DB3B381U, 0x263A2CFBU, 0xD4DF0A4BU, 0x9C3A2DEEU, 0x7D04E61FU, 0x728D06E9U, 0x42449325U, 0x8B1ADFBCU }, { 0x7E053A1BU, 0x6EC1D939U, 0x66DAF707U, 0xEE2BE5C7U, 0x810AC7ABU, 0x80BA1E14U, 0xF530F174U, 0xDD2AE778U } },
      { { 0x205B9D8BU, 0x0435D97AU, 0x056756D4U, 0x6EB8F064U, 0xB6F8210EU, 0xD5E88A8BU, 0xEC9FD9EAU, 0x070EF12DU }, { 0x3BCC876AU, 0x4D849505U, 0xA7404CE3U, 0x12A75338U, 0xB8A1DB5EU, 0xD22B49E1U, 0x14BFA5ADU, 0xEC1F2051U } },
      { { 0xB6828F36U, 0xADBAEB79U, 0x01BD5B9EU, 0x9D7A0258U, 0x1E844B0CU, 0xEDA01E0DU, 0x887EDFC9U, 0x4B625175U }, { 0x9669B621U, 0x14109FDDU, 0xF6F87B98U, 0x88A2CA56U, 0x170DF6BCU, 0xFE2EB788U, 0xFFA473F9U, 0x0CEA06F4U } },
      { { 0xC4E83D33U, 0x43ED81B5U, 0x5EFD488BU, 0xD9F35879U, 0x9DEB4D0FU, 0x164A620FU, 0xAC6A7394U, 0xC6927BDBU }, { 0x9F9E0F03U, 0x45C28DF7U, 0xFCD7E1A9U, 0x2868661EU, 0xFFA348F1U, 0x7CF4E8D0U, 0x398538E0U, 0x6BD4C284U } },
      { { 0x289A8619U, 0x2618A091U, 0x6671B173U, 0xEF796E60U, 0x9090C632U, 0x664E46E5U, 0x1E66F8FBU, 0xA38062D4U }, { 0x0573274EU, 0x6C744A20U, 0xA9271394U, 0xD07B67E4U, 0x6BDC0E20U, 0x391223B2U, 0xEB0A05A7U, 0xBE2D93F1U } },
      { { 0x3F36D141U, 0xF23E2E53U, 0x4DFCA442U, 0xE84BB3D4U, 0x6B7C023AU, 0xB804A48DU, 0x76431C3BU, 0x1E16A8FAU }, { 0xDDD472E0U, 0x1B5452ADU, 0x0D1EE127U, 0x7D405EE7U, 0xFFA27599U, 0x50FC6F1DU, 0xBF391B35U, 0x351AC53CU } },
      { { 0x4444896BU, 0x7EFA14B8U, 0xF94027FBU, 0x64974D2FU, 0xDE84487DU, 0xEFDCD0E8U, 0x2B48989BU, 0x8C45B260U }, { 0xD8463487U, 0xA8FCBBC2U, 0x3FBC476CU, 0xD1B2B3F7U, 0xC8F443C0U, 0x21D005B7U, 0x40C0139CU, 0x518F2E67U } },
      { { 0x06D75FC1U, 0x56036E8CU, 0x3249A89FU, 0x2DCF7BB7U, 0xE245E7DDU, 0x81DD1D3DU, 0xEBD6E2A7U, 0xF578DC4BU }, { 0xDF2CE7A0U, 0x4C028903U, 0x9C39AFACU, 0xAEE36288U, 0x146404ABU, 0xDC847C31U, 0xA4E97818U, 0x6304C0D8U } } } /* window 42 */,
    { { { 0x070D3AABU, 0xE4AC8B33U, 0x9A2CD5E5U, 0x2643672BU, 0x1CFC9173U, 0x52EFF79BU, 0x90A7C13FU, 0x665CA49BU }, { 0xB3EFB998U, 0x5A8DDA59U, 0x052F1341U, 0x8A5B922DU, 0x3CF9A530U, 0xAE9EBBABU, 0xF56DA4D7U, 0x35986E7BU } },
      { { 0xDA79E5ACU, 0x534ACF4FU, 0x8630215FU, 0x68B83B3AU, 0xD085756EU, 0x5C748B2EU, 0xE5D37CB2U, 0xB0317258U }, { 0xC5CCC2C4U, 0x6735841AU, 0x3D9D5069U, 0x7D7DC96BU, 0xFD1754BDU, 0xA147E410U, 0xD399DDD5U, 0x65296E94U } },
      { { 0xF0290A8FU, 0x831AB3EDU, 0xCB47C387U, 0xCAE81966U, 0x184EFB4FU, 0xAAD7DECEU, 0x4749110EU, 0xDCFC53B3U }, { 0x4CB632F9U, 0x6698F23CU, 0xB91F8067U, 0xC42A1AD6U, 0x6284180AU, 0xB116A81DU, 0xE901326FU, 0xEBEDF5F8U } },
      { { 0xB30CFB3AU, 0xD7E0C4CDU, 0x6C9DB4C8U, 0x6D09B8C1U, 0x07C8D9DFU, 0x40BA1A42U, 0x1C52C66DU, 0x6FD495F7U }, { 0x275264DAU, 0xFB0E169FU, 0xE57D8362U, 0x80C2B746U, 0x49AD7222U, 0xEDD987F7U, 0x4398EC7BU, 0xFDC229AFU } },
      { { 0x59B0FF62U, 0x54A6FE5AU, 0x4094D0D4U, 0x25EC81A3U, 0x33437F1DU, 0xFCFD834EU, 0xA67604DCU, 0x8E98378BU }, { 0xF4848598U, 0x53137DD6U, 0x62FDA36AU, 0x87F2C5BFU, 0xEF74DF46U, 0x70DC1C27U, 0x0A86A056U, 0x3EBF428FU } },
      { { 0xD0D350A3U, 0x6713AC7AU, 0x105A1F2FU, 0x84F6EBF9U, 0x16254046U, 0x17A14958U, 0xAEF406F7U, 0xAFA5E9A4U }, { 0x1CDD69B6U, 0xF97BAF7CU, 0x5EE86474U, 0x64081A30U, 0x1227F62AU, 0xEB9F7F09U, 0x3485652CU, 0x3E47F1DCU } },
      { { 0xB7F01D83U, 0x6F975E7FU, 0x45CCF5CBU, 0x5F1F860BU, 0x8B70930FU, 0x22702EBAU, 0x2B5CC879U, 0xD8186DF7U }, { 0x1720468FU, 0x8C065DA0U, 0x00464C80U, 0x42477261U, 0xC277E1CAU, 0xD8C4BBBEU, 0x66BA642FU, 0x04AAEA17U } },
      { { 0x52666A58U, 0xB0D1ED84U, 0xE6A9C3C2U, 0x4BCB6E00U, 0x26906408U, 0x3C57411CU, 0x13556400U, 0xCFC20755U }, { 0x5294DBA3U, 0xA08B1C50U, 0x8B7DD31EU, 0xA30BA286U, 0x991ECA74U, 0xD70BA90EU, 0xE762C2B9U, 0x094E142CU } } } /* window 43 */,
    { { { 0x979F3925U, 0xB81D783EU, 0xAF4C89A7U, 0x1EFD130AU, 0xFD1BF7FAU, 0x525C2144U, 0x1B265A9EU, 0x4B296904U }, { 0xB9DB65B6U, 0xED8E9634U, 0x03599D8AU, 0x35C82E32U, 0x403563F3U, 0xDAA7A54FU, 0x022C38ABU, 0x9DF088ADU } },
      { { 0x4237B64BU, 0x8D084F12U, 0xE3ECFD07U, 0x688EBE99U, 0xF6845DD8U, 0x57B8A70CU, 0x5DA4A325U, 0x808FC59CU }, { 0xA3585862U, 0xA9032B2BU, 0xEDF29386U, 0xB66825D5U, 0x431EC29BU, 0xB5A5A8DBU, 0x3A1E8DC8U, 0xBB143A98U } },
      { { 0xF111661EU, 0x9E93BA24U, 0xB105EB04U, 0xEDCED484U, 0xF424B578U, 0x96DC9BA1U, 0xE83E9069U, 0xBF8F66B7U }, { 0xD7ED8216U, 0x872D4DF4U, 0x8E2CBECFU, 0xBF07F377U, 0x98E73754U, 0x4281D899U, 0x8AAB8708U, 0xFEC85FBBU } },
      { { 0x765FA7D0U, 0x13B5BF22U, 0x1D6A5370U, 0x59805BF0U, 0x4280DB98U, 0x67A5E29DU, 0x776B1CE3U, 0x4F53916FU }, { 0x33DDF626U, 0x714FF61FU, 0xA085D103U, 0x4206238EU, 0xE5809EE3U, 0x1C50D4B7U, 0x85F8EB1DU, 0x999F450DU } },
      { { 0x1A3A93BCU, 0x82EEBE73U, 0xA21ADC1AU, 0x42BBF465U, 0xEF030EFDU, 0xC10B6FA4U, 0x87B097BBU, 0x247AA4C7U }, { 0xF60C77DAU, 0x8B8DC632U, 0xC223523EU, 0x6FFBC26AU, 0x344579CFU, 0xA4F6FF11U, 0x980250F6U, 0x5825653CU } },
      { { 0x4A493B31U, 0x4BF367BAU, 0x9BF7F026U, 0x54F20A52U, 0x9795914BU, 0xB696E062U, 0x8BF236ACU, 0xCDDAB96DU }, { 0xED25EA13U, 0x4FF2C70AU, 0x81CBBBE7U, 0xFA1D09EBU, 0x468544C5U, 0x88FC8C87U, 0x696B3317U, 0x847A670DU } },
      { { 0xD314E7BCU, 0xEDA6C595U, 0x467899EDU, 0x2EE7464BU, 0x0A1ED5D3U, 0x1CEF423CU, 0x69CC7613U, 0x217E76EAU }, { 0xE7CDA917U, 0x27CCCE1FU, 0x8A893F16U, 0x12D8016BU, 0x9FC74F6BU, 0xBCD6DE84U, 0xF3144E61U, 0xFA5817E2U } },
      { { 0xAC751E7BU, 0xB79D4CC5U, 0xFD4211BDU, 0x93F96472U, 0xC8DE4FC6U, 0x8C72D3D2U, 0xDF44F064U, 0x7B69CBF5U }, { 0xF4BF94E1U, 0x3DA90CA2U, 0xF12894E2U, 0x1A5325F8U, 0x7917D60BU, 0x0A437F6CU, 0x96C9CB5DU, 0x9BE70486U } } } /* window 44 */,
    { { { 0xE1337C26U, 0x949C9976U, 0xD73D68E5U, 0x6FAADEBDU, 0xF1B768D9U, 0x9E158614U, 0x9CC4F069U, 0x22DFA557U }, { 0xBE93C6D6U, 0xCCD6DA17U, 0xA504F5B9U, 0x24866C61U, 0x8D694DA1U, 0x2121353CU, 0x0140B8C6U, 0x1C6CA580U } },
      { { 0xD4B79BB8U, 0xF1604A7DU, 0x52C878C8U, 0xAEE806FBU, 0x8D47B8E8U, 0x34144F11U, 0x949F9054U, 0x72EDF52BU }, { 0x2127015AU, 0xEBFCA84EU, 0x9CB7CEF3U, 0x9051D0C0U, 0x296DEEC8U, 0x86E8FE58U, 0x41010D74U, 0x33B28188U } },
      { { 0x9AED9F40U, 0xBD5660EDU, 0x532A8C99U, 0x70CA6AD1U, 0x95C371EAU, 0xC4978BFBU, 0x7003109DU, 0xE5464D0DU }, { 0xD9E535EFU, 0x1AF32FDFU, 0x98C9185BU, 0xABF57EA7U, 0x12B42488U, 0xED7A7417U, 0xE97286FAU, 0x8E0296A7U } },
      { { 0x171B445FU, 0x01079383U, 0x8131AD4CU, 0x9BCF21E3U, 0xC93987E8U, 0x8CDFE205U, 0xC92E8C8FU, 0xE63F4152U }, { 0x30ADD43DU, 0x729462A9U, 0xC980F05AU, 0x62EBB143U, 0x3B06E968U, 0x4F3954E5U, 0x242CF6B1U, 0xFE1D75ADU } },
      { { 0x1F017D5EU, 0x8B57416EU, 0x7674E99BU, 0x37533396U, 0xE8F488A0U, 0x6E6D94C0U, 0xDC16F95EU, 0xB93A787AU }, { 0xDCC99CCCU, 0xC3AC51A2U, 0x9AA47C1DU, 0xC134B413U, 0xAFDFD8D5U, 0xF28FCDAFU, 0x10B831EDU, 0x0D57BD8EU } },
      { { 0xF0BCFC46U, 0x9276FBCCU, 0xB5CFFEE6U, 0x3A822ACEU, 0xC75D915BU, 0x328ED2FEU, 0xC359476CU, 0xA145C113U }, { 0x8BE17BCDU, 0xF61A8153U, 0xAA6C3D8FU, 0x01E867C3U, 0x6516C82FU, 0x5634E15DU, 0x6948B9B0U, 0xC1437BD2U } },
      { { 0x6C19D4C7U, 0xD2FCD200U, 0xE1B1E976U, 0xA0F3C437U, 0x94F237E8U, 0xF0545FF6U, 0xC0BF8BB1U, 0xDD10EC3FU }, { 0xAC7CD3E1U, 0x4F89696CU, 0x5F24BFE6U, 0xED3714ECU, 0x5FAF7706U, 0x363EB1D8U, 0xC027CC32U, 0xFCBD604DU } },
      { { 0xAF8685C8U, 0x5F95C6C7U, 0x2F8F01AAU, 0xD4C1C8CEU, 0x2574692AU, 0xC44BBE32U, 0xD4A4A068U, 0xB8003478U }, { 0x2ECA3CDBU, 0x7C8FC6E5U, 0xEC04D399U, 0xEA1DB16BU, 0x8F2BC5CFU, 0xB05BC82EU, 0xF44793D2U, 0x763D517FU } } } /* window 45 */,
    { { { 0x4C830320U, 0xF3B7963FU, 0x903203E3U, 0x842C7AA0U, 0xE7327AFBU, 0xAF22CA0AU, 0x967609B6U, 0x38E13092U }, { 0x757558F1U, 0x73B8FB62U, 0xF7ECA8C1U, 0x3CC3E831U, 0xF6331627U, 0xE4174474U, 0xC3C40234U, 0xA77989CAU } },
      { { 0xB0166F7AU, 0xAE8317F4U, 0xCEEC74E6U, 0xFBD3E3F7U, 0xE0874BFDU, 0xFDB516ACU, 0xC681F3A3U, 0x3D846019U }, { 0x7C1620B0U, 0x0B12EE5CU, 0x2B63C501U, 0xBA68B4DDU, 0x6668C51EU, 0xAC03CD32U, 0x4E0BCB5BU, 0x2A6279F7U } },
      { { 0xB796D219U, 0xB32CB8B0U, 0x34741DD9U, 0xC3E95F4FU, 0x68EDF6F5U, 0x87212125U, 0xA2B9CB8EU, 0x7A03AEE4U }, { 0xF53A89AAU, 0x0CD3C376U, 0x948A28DCU, 0x0D8AF9B1U, 0x902AB04FU, 0xCF86A3F4U, 0x7F42002DU, 0x8AACB62AU } },
      { { 0x8F5FCDA8U, 0xFD8E139FU, 0xBDEE5BFDU, 0xF3E558C4U, 0xE33F9F77U, 0xD76CBAF4U, 0x71771969U, 0x3A4C97A4U }, { 0xF6DCE6A7U, 0xDA27E84BU, 0x13E6C2D1U, 0xFF373D96U, 0xD759A6E9U, 0xF115193CU, 0x63D2262CU, 0x3F9B7025U } },
      { { 0x252BD479U, 0x9CB0AE6CU, 0x12B5848FU, 0x05E0F88AU, 0xA5C97663U, 0x78F6D2B2U, 0xC162225CU, 0x6F6E149BU }, { 0xDE601A89U, 0xE602235CU, 0xF373BE1FU, 0xD17BBE98U, 0xA8471827U, 0xCAF49A5BU, 0x18AAA116U, 0x7E1A0A85U } },
      { { 0x87BAA627U, 0x12536FEAU, 0xF72AA680U, 0x58C1FEC1U, 0x601E5DC9U, 0x6C29B637U, 0xDE9E01B9U, 0x9E3C3C1CU }, { 0x2BCFE0B0U, 0xEFC8127BU, 0x2A12F50DU, 0x35107102U, 0x4879B397U, 0x6CCD6CB1U, 0xF8A82F21U, 0xF792F804U } },
      { { 0x35E6FC06U, 0x8B1E5722U, 0x0B3E13D5U, 0x3477728FU, 0xAA8A7372U, 0x150C294DU, 0x3BFA528AU, 0xC0291D43U }, { 0xCEC5A196U, 0xC6C8BC67U, 0x5C2E8A7CU, 0xDEEB31E4U, 0xFB6E1C51U, 0xBA93E244U, 0x2E28E156U, 0xB9F8B71BU } },
      { { 0x1A335CC8U, 0x8C318491U, 0x6A5913E4U, 0x563459BAU, 0xC7B32919U, 0x1B920D61U, 0xA02425ADU, 0x805AB8B6U }, { 0x8D006086U, 0x2AC512DAU, 0xBCF5C0FDU, 0x6CA4846AU, 0xAC2138D7U, 0xAFEA51D8U, 0x344CD443U, 0xCB647545U } } } /* window 46 */,
    { { { 0x53544774U, 0x511053E4U, 0x3ADBA2BCU, 0x834D0ECCU, 0xBAE371F5U, 0x4215D7F7U, 0x6C8663BCU, 0xFCFD57BFU }, { 0xD6901B1DU, 0xDED2383DU, 0xB5587DC3U, 0x3B49FBB4U, 0x07625F62U, 0xFD44A08DU, 0x9DE9B762U, 0x3EE4D65BU } },
      { { 0x0D63D1FAU, 0x64E5137DU, 0x02A9D89FU, 0x658FC052U, 0x50436309U, 0x48894874U, 0xD598DA61U, 0xE9AE30F8U }, { 0x818BAF91U, 0x2ED710D1U, 0x8B6A0C20U, 0xE27E9E06U, 0x1C1A6B44U, 0x1E28DCFBU, 0xD6AC57DCU, 0x883ACB64U } },
      { { 0x4E6DAAE2U, 0xED7F2E77U, 0x9E0A19BCU, 0x7B3AE0E3U, 0x91AE677EU, 0xD3293F8AU, 0x45C8611FU, 0xD363B0CBU }, { 0x309AE93BU, 0xBE1D1CCFU, 0x3920CAE1U, 0xA3F80BE7U, 0x498EDF01U, 0xAAACBA74U, 0xB2F5AC90U, 0x1E6D2A4AU } },
      { { 0xC2C6FF70U, 0x8735728DU, 0xC5DC2235U, 0x79D6122FU, 0x19E277F9U, 0x23F5D003U, 0xDDED8CC7U, 0x7EE84E25U }, { 0x63CD880AU, 0x91A8AFB0U, 0x3574AF60U, 0x3F3EA7C6U, 0x02DE7F42U, 0x0CFCDC84U, 0xB31AA152U, 0x62D0792FU } },
      { { 0xBECCEFB5U, 0x40FDF5AAU, 0x3621D7C7U, 0xCF56EDE9U, 0x52B576C1U, 0xB632A9CEU, 0x9A6F6027U, 0xD3403AE8U }, { 0xE8785A64U, 0x660A050DU, 0x9682652EU, 0x10F3D647U, 0x4FBCBE02U, 0x78B25EDFU, 0xB4F9315DU, 0xC9710FDEU } },
      { { 0x8A5807CEU, 0x8E1B4E43U, 0xE4109A7EU, 0xAD283893U, 0xAFD59DDAU, 0xC30CC9CBU, 0x3D8D8093U, 0xF65F36C6U }, { 0xA60D32B2U, 0xDF31469EU, 0x3E8191C8U, 0xEE93DF4BU, 0x355BDEB5U, 0x9C1017C5U, 0x8616AA28U, 0xD2623185U } },
      { { 0x3245980EU, 0xD655ADE7U, 0x81067200U, 0xA6F59657U, 0xDB136BE1U, 0xE4FC23BEU, 0xAF13D879U, 0x9F246CDCU }, { 0xF961AC0EU, 0xC2B93117U, 0xEBDB9E1AU, 0xC8A741B5U, 0x6C693BD1U, 0x82EDE246U, 0x3DD1701EU, 0xFCDE6B4FU } },
      { { 0xDEC31A21U, 0xB02C83F9U, 0x6AD9D573U, 0x988C8B23U, 0xA57BE365U, 0x53E983AEU, 0x646F834EU, 0xE968734DU }, { 0x5DA6309BU, 0x9137EA8FU, 0xC1F1CE16U, 0x10F3A624U, 0xCA440921U, 0x782A9EA2U, 0x5B46F1B5U, 0xDF94739EU } } } /* window 47 */,
    { { { 0xF4F8B16AU, 0x56F8410EU, 0xC47B266AU, 0x97241AFEU, 0x6D9C87C1U, 0x0A406B8EU, 0xCD42AB1BU, 0x803F3E02U }, { 0x04DBEC69U, 0x7F0309A8U, 0x3BBAD05FU, 0xA83B85F7U, 0xAD8E197FU, 0xC6097273U, 0x5067ADC1U, 0xC097440EU } },
      { { 0xB311898CU, 0x3F747FA0U, 0xCD0EAC65U, 0xE2A272E4U, 0xF914D0BCU, 0x4BBA5851U, 0xC4A43EE3U, 0x7A1A9660U }, { 0xA1C8CDE9U, 0xE5A367CEU, 0x7271ABE3U, 0x9D958BA9U, 0x3D1615CDU, 0xF3FF7EB6U, 0xF5AE20B0U, 0xA2280DCEU } },
      { { 0x3794F8DCU, 0x266344A4U, 0x483C5C36U, 0xDCCA923AU, 0x3F9D10A0U, 0x2D6B6BBFU, 0x81D9BDF3U, 0xB320C5CAU }, { 0x47B50A95U, 0x620E28FFU, 0xCEF03371U, 0x933E3B01U, 0x99100153U, 0xF081BF85U, 0xC3A8C8D6U, 0x183BE9A0U } },
      { { 0x41DCA566U, 0xB6C185C3U, 0xD8622AA3U, 0x7DE7FEDAU, 0x901B6DFBU, 0x99E84D92U, 0x7C4AD288U, 0x30A02B0EU }, { 0x2FD3CF36U, 0xC7C81DAAU, 0xDF89E59FU, 0xD1319547U, 0xCD496733U, 0xB2BE8184U, 0x93D3412BU, 0xD5F449EBU } },
      { { 0xE085116BU, 0x25470FABU, 0x87285310U, 0x04A43375U, 0xE2BFD52FU, 0x4E39187EU, 0x7D9EBC74U, 0x36166B44U }, { 0xFD4B322CU, 0x92AD433CU, 0xBA79AB51U, 0x726AA817U, 0xC1DB15EBU, 0xF96EACD8U, 0x0476BE63U, 0xFAF71E91U } },
      { { 0xC97E6516U, 0xD74E9BDAU, 0xC230F49EU, 0x88779360U, 0x1E74EA49U, 0xA6EC1DE3U, 0x3FB645A2U, 0x581DCEE5U }, { 0x8F483F14U, 0xBAEF2391U, 0xD137D13BU, 0x6D2DDDFCU, 0xD2743A42U, 0x54CDE50EU, 0xE4D97E67U, 0x89A34FC5U } },
      { { 0x49DEE168U, 0x72CFD2E9U, 0x3E2AF239U, 0x1AE05223U, 0x1D94066AU, 0x009E75BEU, 0x38ABF413U, 0x6CCA31C7U }, { 0x9BC49908U, 0xB50BD61DU, 0xF5E2BC1EU, 0x4A9B4A8CU, 0x946F83ACU, 0xEB6CC5F7U, 0xEBFFAB28U, 0x27DA93FCU } },
      { { 0x4CD8F64CU, 0xC492EC64U, 0x279D7B51U, 0x58A2D790U, 0x1FC75256U, 0x0CED1FC5U, 0x8F433017U, 0x3E658AEDU }, { 0x05DA59EBU, 0x0B61942EU, 0x0DDC3722U, 0xBA3D60A3U, 0x742E7F87U, 0x7C311CD1U, 0xF6B01B6EU, 0x6473FFEEU } } } /* window 48 */,
    { { { 0x692AC542U, 0x8303604FU, 0x227B91D3U, 0xF079FFE1U, 0x15AAF9BDU, 0x19F63E63U, 0xF1F344FBU, 0xF99EE565U }, { 0xD6219199U, 0x8A1D661FU, 0xD48CE41CU, 0x8C883BC6U, 0x3C74D904U, 0x1065118FU, 0x0FAF8B1BU, 0x713889EEU } },
      { { 0x81A1B3BEU, 0x972B3F8FU, 0xCE2764A0U, 0x4F3CE145U, 0x28C4F5F7U, 0xE2D0F1CCU, 0xC7F3985BU, 0xDEEE0C0DU }, { 0xD39E25C3U, 0x7DF4ADC0U, 0xC467A080U, 0x40619820U, 0x61CF5A58U, 0x440EBC93U, 0x422AD600U, 0x527729A6U } },
      { { 0xB1B76BA6U, 0xCA6C0937U, 0x4D2026DCU, 0x1A2EAB85U, 0x19D9AE0AU, 0xB1715E15U, 0xBAC4A026U, 0xF1AD9199U }, { 0x07EA7B0EU, 0x35B3DFB8U, 0x3ED9EB89U, 0xEDF5496FU, 0x2D6D08ABU, 0x8932E5FFU, 0x25BD2731U, 0xF314874EU } },
      { { 0x3F73F449U, 0xEFB26A75U, 0x8D44FC79U, 0x1D1C94F8U, 0x3BC0DC4DU, 0x49F0FBC5U, 0x3698A0D0U, 0xB747EA0BU }, { 0x228D291EU, 0x5218C3FEU, 0x43C129D6U, 0x35B804B5U, 0xD1ACC516U, 0xFAC859B8U, 0x95D6E668U, 0x6C10697DU } },
      { { 0x0876FD4EU, 0xC38E438FU, 0x83D2F383U, 0x45F0C307U, 0xB10934CBU, 0x203CC2ECU, 0x2C9D46EEU, 0x6A8F2439U }, { 0x65CCDE7BU, 0xF16B431BU, 0x27E76A6FU, 0x41E2CD18U, 0x4E3484D7U, 0xB9C8CF8FU, 0x8315244AU, 0x64426EFDU } },
      { { 0xFC94DEA3U, 0x1C0A8E44U, 0xDAD6A0B0U, 0x34C8CDBFU, 0x04113CEFU, 0x919C3840U, 0x15490FFAU, 0xFD32FBA4U }, { 0x795DCFB7U, 0x58D190F6U, 0x83588BAFU, 0xFEF01B03U, 0xCA1FC1C0U, 0x9E6D1D63U, 0xF0A41AC9U, 0x53173F96U } },
      { { 0xBA16F73BU, 0x2B1D402AU, 0x8CF9B9FCU, 0x2FB31014U, 0x446EF7BFU, 0x2D51E60EU, 0xB91E1745U, 0xC731021BU }, { 0x4FEE99D4U, 0x9D3B4724U, 0xFAC5C1EAU, 0x4BCA48B6U, 0xBBEA9AF7U, 0x70F5F514U, 0x974C283AU, 0x751F55A5U } },
      { { 0xCB452FDBU, 0x6E30251AU, 0x50F30650U, 0x31EE6965U, 0x933548D9U, 0xB0B3E508U, 0xF4B0EF5BU, 0xB8949A4FU }, { 0x3C88F3BDU, 0x208B8326U, 0xDB1D9989U, 0xAB147C30U, 0x44D4DF03U, 0xED6515FDU, 0xE72EB0C5U, 0x17A12F75U } } } /* window 49 */,
    { { { 0x81FDAD90U, 0x25914F78U, 0x0D2CF6ABU, 0xCF638F56U, 0xCC054DE5U, 0xB90BC03FU, 0x18B06350U, 0x932811A7U }, { 0x9BBD11FFU, 0x2F00B330U, 0xB4044974U, 0x76108A6FU, 0xA851D266U, 0x801BB9E0U, 0xBF8990C1U, 0x0DD099BEU } },
      { { 0x58D6CD46U, 0x14C6DD8AU, 0x8E6634D2U, 0x9CB633B5U, 0xF81BC328U, 0xC1305047U, 0x26A177E5U, 0x12EDE0E2U }, { 0x065A6F4FU, 0x332CCA62U, 0x67BE487BU, 0xC3A47ECDU, 0x0F47ED1CU, 0x741EB187U, 0xE7598B14U, 0x99E66E58U } },
      { { 0x7B0AC93DU, 0xEBD6A677U, 0x78F5E0D7U, 0xA6E37B0DU, 0x76F5492BU, 0x2516C096U, 0x9AC05F3AU, 0x1E4BF888U }, { 0x4DF0BA2BU, 0xCDB42CE0U, 0x5062341BU, 0x935D5CFDU, 0x82ACAC20U, 0x8A303333U, 0x5198B00EU, 0x429438C4U } },
      { { 0x67E573E0U, 0xFB2838BEU, 0x4084C44BU, 0x05891DB9U, 0x96C1C2C5U, 0x91311373U, 0xD958444BU, 0x6AEBFA3FU }, { 0xE56E55C1U, 0xAC9CDCE9U, 0x2CAA46D0U, 0x7148CED3U, 0xB61FE8EBU, 0x2E10C7EFU, 0xFF97CF4DU, 0x9FD835DAU } },
      { { 0xC1770616U, 0x6C626F56U, 0x09DA9A2DU, 0x5351909EU, 0xA3730E45U, 0xE58E6825U, 0x03EF0A79U, 0x9D8C8BC0U }, { 0x056BECFDU, 0x543F78B6U, 0xA090B36DU, 0x33F13253U, 0x794432F9U, 0x82AD4997U, 0x4721F502U, 0x1386493CU } },
      { { 0x5ABEA82AU, 0x3794EEFAU, 0x93FE62D4U, 0x8DC611B9U, 0x281EF606U, 0x69F1AF37U, 0x39839E69U, 0x6AF546C8U }, { 0xC977EC23U, 0x625578C7U, 0xBD5C0576U, 0xA8DE294CU, 0x7CD1A4C0U, 0xE2DDAF0FU, 0x4F95F4D4U, 0x8243FC70U } },
      { { 0xB008733AU, 0xE566F400U, 0x512E1F57U, 0xCBA0697DU, 0x40509CD0U, 0x9537C2B2U, 0x57353D8CU, 0x5F989C69U }, { 0x4C3C2B2FU, 0x7DBEC972U, 0xFF031FA8U, 0x90E02FA8U, 0xCFD5D11FU, 0xF4D15C53U, 0x48314DFCU, 0xB3404FAEU } },
      { { 0x081E9387U, 0xA36DA109U, 0x8C935828U, 0xFB9780D7U, 0xE540B015U, 0xD5940332U, 0xE0F466FAU, 0xC9D7B51BU }, { 0xD6D9F671U, 0xFAADCD41U, 0xB1A2AC17U, 0xBA6C1E28U, 0xED201E5FU, 0x066A7833U, 0xF90F462BU, 0x19D99719U } } } /* window 50 */,
    { { { 0x060B5F61U, 0xF431F462U, 0x7BD057C2U, 0xA56F46B4U, 0x47E1BF65U, 0x348DCA6CU, 0x41BCF1FFU, 0x9A38783EU }, { 0xDA710718U, 0x7A5D33A9U, 0x2E0AEAF6U, 0x5A779987U, 0x2D29D187U, 0xCA87314DU, 0xC687D733U, 0xFA0EDC3EU } },
      { { 0xCB198AC7U, 0x1C894849U, 0x0F264665U, 0xA884A93DU, 0x9B200678U, 0x2DA964EFU, 0x009834E6U, 0x3C351B87U }, { 0xE2C4B44BU, 0xAFB2EF9FU, 0x3326790CU, 0x580F6C47U, 0x0B02264AU, 0xB8480521U, 0x42A194E2U, 0x8BA6F9E2U } },
      { { 0x5EB03C0EU, 0x499B6AB6U, 0x72BC3FDEU, 0xF19B7954U, 0x6E3A80D2U, 0xA86B5B9CU, 0x6D42819FU, 0xE4377508U }, { 0xBB3EE8A3U, 0xC1663650U, 0xB132075FU, 0x75EB14FCU, 0x7AD834F6U, 0xA8CCC906U, 0xE6E92FFDU, 0xEA6A2474U } },
      { { 0xD3C095F1U, 0x39D934ABU, 0xE4B76D71U, 0x04B261BEU, 0xE73E6984U, 0x1D2E6970U, 0x5E5FCB11U, 0x879FB23BU }, { 0xDFD75490U, 0x11506C72U, 0x61BCF1C1U, 0x3A97D085U, 0xBF5E7007U, 0x43201D82U, 0x798232A7U, 0x7F0AC52FU } },
      { { 0x4B049136U, 0xCB4D20EEU, 0x356A4613U, 0x8B63BF12U, 0x70E08128U, 0x1221AEF6U, 0x4ACB6B16U, 0xE62D8C51U }, { 0x379E7896U, 0x71F64A67U, 0xCAFD7FA5U, 0xB25237A2U, 0x3841BA6AU, 0xF077BD98U, 0x3CD16E7EU, 0xC4AC0244U } },
      { { 0x319D7682U, 0xB25101FBU, 0x0A982FEEU, 0xB0293129U, 0x0261B344U, 0x51C1C9B9U, 0xBFD371FAU, 0x0E008C5BU }, { 0x0278CA33U, 0xD866DD1CU, 0xE5AA53B1U, 0x666F76A6U, 0x6013A2CFU, 0xE5CFB779U, 0xA3521836U, 0x1D3A1AADU } },
      { { 0x50F75F9CU, 0x3C5604FFU, 0x7E752B22U, 0x1D8EDDF3U, 0x3C9A1118U, 0x0EF074DDU, 0xCCB86D7BU, 0xD0FFC172U }, { 0x037D90F2U, 0xABD1ECE3U, 0x6055856CU, 0xE3F307D6U, 0x7E4C6DAFU, 0x422F9328U, 0x334879A0U, 0x902AAC66U } },
      { { 0x567193ECU, 0x76B4131AU, 0xE5F6E70BU, 0xAF3C305AU, 0x031EEBDDU, 0x9587BD39U, 0x71BBE831U, 0x5709DEF8U }, { 0x0EB2B669U, 0x57059983U, 0x875B7029U, 0x4D80CE1BU, 0x0364AC16U, 0x838A7DA8U, 0xBE1C83ABU, 0x2F431D23U } } } /* window 51 */,
    { { { 0xADF7CCCFU, 0x75D9BC15U, 0xDFA1E1B0U, 0x81A3E5D6U, 0x249BC17EU, 0x8C39E444U, 0x8EA7FD43U, 0xF37DCCB2U }, { 0x907FBA12U, 0xDA654873U, 0x4A372904U, 0x35DAA6DAU, 0x6283A6C5U, 0x0564CFC6U, 0x4A9395BFU, 0xD09FA4F6U } },
      { { 0xEB6B242DU, 0x832D7080U, 0x3B71E246U, 0xD30BD023U, 0xBE31139DU, 0x7027991BU, 0x462E4E53U, 0x68797E91U }, { 0x6B4E185AU, 0x423FE20AU, 0x42D9B707U, 0x82F2C67EU, 0x4CF7811BU, 0x25C81768U, 0x045BB95DU, 0xBD53005EU } },
      { { 0x5CFE5C48U, 0xC51AA29EU, 0x815EE096U, 0x82C020AEU, 0x7549A68AU, 0x7848AD82U, 0x60471355U, 0x7933D489U }, { 0x67C51E57U, 0x04998D2EU, 0xD9944AFCU, 0x0F64020AU, 0xA7FADAC6U, 0x7A299FE1U, 0x5AEFE92CU, 0x40C73FF4U } },
      { { 0x9D8E68FDU, 0xE5F649BEU, 0x1B044320U, 0xDB0F0533U, 0xE0C33398U, 0xF6FDE9B3U, 0x66C8CFAEU, 0x92F4209BU }, { 0x1A739D4BU, 0xE9D1AFCCU, 0xA28AB8DEU, 0x09AEA75FU, 0xEAC6F1D0U, 0x14375FB5U, 0x708F7AA5U, 0x6420B560U } },
      { { 0x5488771AU, 0xBF44FFC7U, 0x7F2F2191U, 0xCB76E3F1U, 0x94F86A42U, 0x4197BDE3U, 0x70641D9AU, 0x45C25BB9U }, { 0xF88CE6DCU, 0xD8A29E31U, 0x4BB7AC7DU, 0xBE2BECFDU, 0xB5670CC7U, 0x13094214U, 0x60AF8433U, 0xE90A8FD5U } },
      { { 0x96F37750U, 0x2D1AFD56U, 0x91507FF2U, 0x25DDA557U, 0x006543EDU, 0x2B95FD4CU, 0xA23C3911U, 0xF3C778D9U }, { 0x3B04938DU, 0x84CCF446U, 0x7EEF947BU, 0x3D9DDED6U, 0xDAE325B5U, 0xBED83735U, 0xF921455DU, 0x5BA0F75CU } },
      { { 0x4EBD3F02U, 0x0ECF9B8BU, 0x86B770EAU, 0xA47ACD9DU, 0x2DA213CEU, 0x93B84A6AU, 0x53E7C8CFU, 0xD760871BU }, { 0x36E530D7U, 0x7A5F58E5U, 0x1912AD51U, 0x7ABC52A5U, 0x2EA0252AU, 0x7AD43DB0U, 0xC176B742U, 0x498B00ECU } },
      { { 0x6254DC41U, 0x9EAE499CU, 0x7A837E7EU, 0x7E293924U, 0x090524A7U, 0x74AEC08CU, 0x8D6F55F2U, 0xF82B9219U }, { 0x1402CEC5U, 0x493C962EU, 0xFA2F30E7U, 0x9F17CA17U, 0xE9B879CBU, 0xBCD783E8U, 0x5A6F145FU, 0xEA3D8C14U } } } /* window 52 */,
    { { { 0x0EBCF726U, 0x103C46E6U, 0x6231470EU, 0x4482B831U, 0x487C2109U, 0x6F6DFACAU, 0x62E666EFU, 0x2E0ACE97U }, { 0x1F8D1F42U, 0x3246A9D3U, 0x574944D2U, 0x1B1E83F1U, 0xA57F334BU, 0x13DFA63AU, 0x9F025D81U, 0x0CF8DAEDU } },
      { { 0x1E935ABBU, 0x85DE1F0DU, 0x154DE37AU, 0xDEFD10B4U, 0x369CEBB5U, 0xB8D9E392U, 0x761324BEU, 0x54D5EF9BU }, { 0x74F17E26U, 0x4D6341BAU, 0x78C1DDE4U, 0xC0A0E3C8U, 0x87D918FDU, 0xA6D77581U, 0x02CA3A13U, 0x66876015U } },
      { { 0x207674F1U, 0xBC19180CU, 0x33AE8FDBU, 0x112E09A7U, 0x6AAEB71EU, 0x99667554U, 0xE101B1C7U, 0x79432AF1U }, { 0xDE2DDEC6U, 0xD5EB558FU, 0x5357753FU, 0x81392D1FU, 0x3AE1158AU, 0xA7A76B97U, 0x4A899991U, 0x416FBBFFU } },
      { { 0x904FC3FAU, 0xEE7332C7U, 0xC7E3636AU, 0x14A23F45U, 0xF091D9AAU, 0xC38659C3U, 0xB12D8540U, 0x4A995E5DU }, { 0xF3A5598AU, 0x20A53BECU, 0xB1EAA995U, 0x56534B17U, 0xBF04E03CU, 0x9ED3DCA4U, 0xD8D56268U, 0x716C563AU } },
      { { 0x2F3B26E7U, 0x6D956E89U, 0xDA875247U, 0xF4709860U, 0x2482DDA3U, 0x3AD15179U, 0x017D82F0U, 0xD64110E3U }, { 0xFAD414E4U, 0x14928D2CU, 0x2ED02B24U, 0x2B155F58U, 0xCB821BF1U, 0x481A141BU, 0x4F81F5DAU, 0x12E3C770U } },
      { { 0x308780F2U, 0xDD5944EAU, 0x3845F5E4U, 0xDC8DE761U, 0x7624D7A3U, 0x6BEABA7DU, 0x304DF11EU, 0x1E709AFDU }, { 0x02170456U, 0x95364376U, 0xC8F94B64U, 0xBF204B3AU, 0x5680CA68U, 0x4E53AF7CU, 0xE0C67574U, 0x0526074AU } },
      { { 0x7882F14FU, 0xE29FA63EU, 0x07C6CADCU, 0xC9F6DC35U, 0xB882BED0U, 0x46F22D6FU, 0xD118E52CU, 0x1A45755BU }, { 0x7C4608CFU, 0x9F2C7C27U, 0x568012C2U, 0x7CCBDF32U, 0x61729B0EU, 0xFCB0AEDDU, 0xF7D75DBFU, 0x7CA2CA9EU } },
      { { 0xE0F222C2U, 0x5043DEA7U, 0x72E65142U, 0x309D42ACU, 0x9216CD30U, 0x94FE9DDDU, 0x0F87FEECU, 0xD6539C7DU }, { 0x432AC7D7U, 0x03C5A57CU, 0x327FDA10U, 0x72692CF0U, 0x280698DEU, 0xEC28C85FU, 0x7EC283B1U, 0x2331FB46U } } } /* window 53 */,
    { { { 0xE457A477U, 0xA0158EEAU, 0xEE6DDC05U, 0xD19857DBU, 0x18C41671U, 0xB3265224U, 0x3C2C0D58U, 0x3FFDFC7EU }, { 0x26EE7CDAU, 0x3A3A5254U, 0xDF02C3A8U, 0x341B0869U, 0x723BBFC8U, 0xA023BF42U, 0x14452691U, 0x3D15002AU } },
      { { 0x85EDFA30U, 0x5EF7324CU, 0x87D4F3DAU, 0x25976554U, 0xDCB50C86U, 0x352F5BC0U, 0x4832A96CU, 0x8F6927B0U }, { 0x55F2F94CU, 0xD08EE1BAU, 0x344B45FAU, 0x6A996F99U, 0xA8AA455DU, 0xE133CB8DU, 0x758DC1F7U, 0x5D0721ECU } },
      { { 0x262A3539U, 0xF3CAE7E9U, 0x6670D59EU, 0x78A49D1DU, 0xC1C5E1B9U, 0x37DE0F63U, 0x69CB7C1CU, 0x3072C30CU }, { 0x77C850E6U, 0x1D278A52U, 0x1F6A3DE6U, 0x84F15F8FU, 0x592CA7ADU, 0x46A8BB45U, 0xE4D424B8U, 0x1912E3EEU } },
      { { 0x79E5FB67U, 0x6BA7A920U, 0x70AA725EU, 0xE1331FEBU, 0x7DF5D837U, 0x5080CCF5U, 0x7FF72E21U, 0xE4CAE01DU }, { 0x0412A77DU, 0xD9243EE6U, 0xDF449025U, 0x06FF7CACU, 0x23EF5A31U, 0xBE75F7CDU, 0x0DDEF7A8U, 0xBC957822U } },
      { { 0x365E668BU, 0xDC988086U, 0xAABDA5FBU, 0xADA8DCDAU, 0x255F1FBEU, 0xBC146B4CU, 0xCF34CFC3U, 0x9CFCDE29U }, { 0x7E85D1E4U, 0xACBB453EU, 0xF92358B5U, 0x9CA09679U, 0x240823FFU, 0x15FC2D96U, 0x0C11D11EU, 0x8D65ADF7U } },
      { { 0xB0CE1C55U, 0x8CF7230CU, 0x0BBFB607U, 0x5B534D05U, 0x0E16363BU, 0xEE1EF113U, 0xB4999E82U, 0x27E0AA7AU }, { 0x79362C41U, 0xCE1DAC2DU, 0x91BB6CB0U, 0x67920C90U, 0x2223DF24U, 0x1E648D63U, 0xE32E8F28U, 0x0F7D9EEFU } },
      { { 0x0296F4FDU, 0x775557F1U, 0xEA51B436U, 0x1DCA76A3U, 0xFB950805U, 0xF3E98F60U, 0x831CF7F1U, 0x31FF32EAU }, { 0x8D2C714BU, 0x643E7BF1U, 0x2E9D2ACAU, 0x64B5C339U, 0x6ADC2D23U, 0xA9FD9CCCU, 0xCC721B9BU, 0xFC2397ECU } },
      { { 0xFA833834U, 0x6943F39AU, 0xA6328562U, 0x22951722U, 0x4170FC10U, 0x81D63DD5U, 0xAECC2E6DU, 0x9F5FA58FU }, { 0xE77D9A3BU, 0xB66C8725U, 0x6384EBE0U, 0x11235CEAU, 0x5845E24AU, 0x06A8C118U, 0xEBD093B1U, 0x0137B286U } } } /* window 54 */,
    { { { 0xC42BD6D2U, 0xDB567D6AU, 0xBB1F96AEU, 0x6DF86468U, 0x4843B28EU, 0x0EFE5B1AU, 0x6379B240U, 0x961BBB05U }, { 0x70A6A26BU, 0xB6CAF5F0U, 0x328E6E39U, 0x70686C0DU, 0x895FC8D3U, 0x80DA06CFU, 0xB363FDC9U, 0x804D8810U } },
      { { 0x4462007DU, 0x63B99CE7U, 0x4CB5F5B7U, 0xB8AB48A5U, 0xF55EDDE7U, 0x9EC673D2U, 0x8CFAEFDAU, 0xD1567F74U }, { 0x0887BCECU, 0x46381B6BU, 0xE178F3C2U, 0x694497CEU, 0x1E6266CBU, 0x5E6525E3U, 0x697D6413U, 0x5931DE26U } },
      { { 0x1F17A34CU, 0x14E49DA1U, 0x235A1456U, 0x5420AB39U, 0x2F50363BU, 0xB7637241U, 0xC3FABB6EU, 0x7B15D623U }, { 0xE274E49CU, 0xA0EF40B1U, 0x96B1860AU, 0x5CF50744U, 0x66AFE5A4U, 0xD6583FBFU, 0xF47E3E9AU, 0x44240510U } },
      { { 0x1A93507AU, 0x142B5502U, 0x8D3C06CFU, 0xB4CD1187U, 0x91EC3F40U, 0xDF70E76AU, 0x4E7553C2U, 0x484E81ADU }, { 0x272E9D6EU, 0x830F87B5U, 0xC6FF514AU, 0xEA1C93E5U, 0xC4192A8EU, 0x67CC2ADCU, 0x42F4535AU, 0xC77E27E2U } },
      { { 0x48AC2840U, 0xB5358B1EU, 0xECBA9477U, 0x18311294U, 0xA6946B43U, 0xDA58F990U, 0x9AB41819U, 0x3098BAF9U }, { 0x4198DA52U, 0x66C4C158U, 0x146BFD1BU, 0xAB4FC17CU, 0xBF36A908U, 0x2F0A4C3CU, 0x58CF7838U, 0x2AE9E34BU } },
      { { 0x0CCCED58U, 0x45EB40ECU, 0x0DA44F98U, 0x25CD4B9CU, 0x871812C6U, 0x43E06458U, 0x16CEF651U, 0x99F80D55U }, { 0xCE6DC153U, 0x571340C9U, 0xD8665521U, 0x138D5117U, 0x4E07014DU, 0xACDB45BCU, 0x84B60B91U, 0x2F34BB38U } },
      { { 0x4A34F239U, 0x417499E8U, 0xB90402D5U, 0x15FDB83CU, 0x433AA832U, 0xB75F46BFU, 0x63215DB1U, 0xB61E15AFU }, { 0xA127F89AU, 0xAABE59D4U, 0x07E816DAU, 0x5D541E0CU, 0xA618B692U, 0xAABA0659U, 0x17266026U, 0x55327733U } },
      { { 0xD0C05199U, 0x8CDA9CF2U, 0xFAE78454U, 0x502FBC22U, 0xF572A182U, 0xC0BDA9DFU, 0x6158B372U, 0x5F9B71B8U }, { 0x2B82DD07U, 0xE0F33A59U, 0x9523032EU, 0x76302735U, 0xC4505A32U, 0x7FE1A721U, 0xF796409FU, 0x7B6E3E82U } } } /* window 55 */,
    { { { 0x35D0B34AU, 0xE3417BC0U, 0x8327C0A7U, 0x440B386BU, 0xAC0362D1U, 0x8FB7262DU, 0xE0CDF943U, 0x2C41114CU }, { 0xAD95A0B1U, 0x2BA5CEF1U, 0x67D54362U, 0xC09B37A8U, 0x01E486C9U, 0x26D6CDD2U, 0x42FF9297U, 0x20477ABFU } },
      { { 0x292A9287U, 0xA004DCB3U, 0x77B092C7U, 0xDDC15CF6U, 0x806C0605U, 0x083A8464U, 0x3DB997B0U, 0x4A68DF70U }, { 0x05BF7DD0U, 0x9C134E45U, 0x8CCF7F8CU, 0xA4E63D39U, 0x41B5F8AFU, 0xA6E6517FU, 0xAD7BC1CCU, 0xAA8B9342U } },
      { { 0x1E706AD9U, 0x126F35B5U, 0xC3A9EBDFU, 0xB99CEBB4U, 0xBF608D90U, 0xA75389AFU, 0xC6C89858U, 0x76113C4FU }, { 0x97E2B5AAU, 0x80DE8EB0U, 0x63B91304U, 0x7E1022CCU, 0x6CCC066CU, 0x3BDAB605U, 0xB2EDF900U, 0x33CBB144U } },
      { { 0x7AF715D2U, 0xC4176471U, 0xD0134A96U, 0xE2F7F594U, 0xA41EC956U, 0x2C1873EFU, 0x77821304U, 0xE4E7B4F6U }, { 0x88D5374AU, 0xE5C8FF97U, 0x80823D5BU, 0x2B915E63U, 0xB2EE8FE2U, 0xEA6BC755U, 0xE7112651U, 0x6657624CU } },
      { { 0xDACE5ACAU, 0x157AF101U, 0x11A6A267U, 0xC4FDBCF2U, 0xC49C8609U, 0xDADDF340U, 0xE9604A65U, 0x97E49F52U }, { 0x937E2AD5U, 0x9BE8E790U, 0x326E17F1U, 0x846E2508U, 0x0BBBC0DCU, 0x3F38007AU, 0xB11E16D6U, 0xCF03603FU } },
      { { 0x7442F1D5U, 0xD6F800E0U, 0x66E0E3ABU, 0x475607D1U, 0xB7C64047U, 0x82807F16U, 0xA749883DU, 0x8858E1E3U }, { 0x8231EE10U, 0x5859120BU, 0x638A1ECEU, 0x1B80E7EBU, 0xC6AA73A4U, 0xCB72525AU, 0x844423ACU, 0xA7CDEA3DU } },
      { { 0xF8AE7C38U, 0x5ED0C007U, 0x3D740192U, 0x6DB07A5CU, 0x5FE36DB3U, 0xBE5E9C2AU, 0x76E95046U, 0xD5B9D57AU }, { 0x8EBA20F2U, 0x54AC32E7U, 0x71B9A352U, 0xEF11CA8FU, 0xFF98A658U, 0x305E373EU, 0x823EB667U, 0xFFE5A100U } },
      { { 0xE51732D2U, 0x57477B11U, 0x2538FC0EU, 0xDFD6EB28U, 0x3B39EEC5U, 0x5C43B0CCU, 0xCB36CC57U, 0x6AF12778U }, { 0x06C425AEU, 0x70B0852DU, 0x5C221B9BU, 0x6DF92F8CU, 0xCE826D9CU, 0x6C8D4F9EU, 0xB49359C3U, 0xF59ABA7BU } } } /* window 56 */,
    { { { 0x421D3AA4U, 0xC37E2C2EU, 0xE84FA840U, 0xF926407CU, 0x1454E41CU, 0x18ABC03DU, 0x3F7AF644U, 0x26605ECDU }, { 0xD6A5EABFU, 0x242341A6U, 0x216B668EU, 0x1EDB84F4U, 0x04010102U, 0xD836EDB8U, 0x945E1D8CU, 0x5B337CE7U } },
      { { 0xD23DDC82U, 0x4C076B86U, 0x7E0143F0U, 0x03FD344CU, 0x317AF2C5U, 0xA95362FFU, 0xE18B7A4FU, 0x0ADD3DB7U }, { 0x8260E01BU, 0x9C673E3FU, 0x54A1CC91U, 0xFBEB49E5U, 0x92F2E433U, 0x91351BF2U, 0x851141EBU, 0xC755E7ECU } },
      { { 0xDA9F3804U, 0x349AE368U, 0xA164349CU, 0x470F07FEU, 0x8562BAA5U, 0xD52F4CC9U, 0x2B290DF3U, 0xC74A9E86U }, { 0x43471A24U, 0xD3A1AA35U, 0xB8194511U, 0x239446BEU, 0x81DCD44DU, 0xBEC2DD00U, 0xC42AC82DU, 0xCA3D7F0FU } },
      { { 0xF23206D5U, 0x2BF5DB47U, 0x1D260152U, 0x2F6D3420U, 0x3F8FF89AU, 0x17B87653U, 0x378FA458U, 0x5157C30CU }, { 0x2D4FB936U, 0x7517C5C5U, 0xE6518CDCU, 0xEF22F7ACU, 0xBF847A64U, 0xDEB483E6U, 0x92E0FA89U, 0xF5084558U } },
      { { 0x9B583160U, 0xB418C2A6U, 0xB4E59194U, 0xBE74FCD4U, 0x3C83E3FFU, 0xF178EEAAU, 0xE296F29BU, 0xE051F895U }, { 0x06CEB84AU, 0xD0235238U, 0xE111FE6BU, 0x5ACE48CEU, 0x1C045545U, 0x40E43A49U, 0xDD522146U, 0xF3FA86DDU } },
      { { 0x908EC5B5U, 0x959616FAU, 0xA01AB12DU, 0x882D661DU, 0x4382AE8AU, 0xC49F6082U, 0x5D133F5EU, 0x5CDF92EBU }, { 0x5EF6C9C1U, 0x98CECC42U, 0x664D84EEU, 0xB52D6682U, 0x6F25B8C4U, 0x9E285ED8U, 0x48DEBE88U, 0xEB80CDC7U } },
      { { 0xEC222BA0U, 0x2D9794C1U, 0x523E5D48U, 0xC3DFF42FU, 0x0FE4846BU, 0x4A7CD570U, 0xFF135174U, 0xEFC5B113U }, { 0xC6B05E85U, 0x2630B25BU, 0x654CD077U, 0x0A6D3029U, 0x32D8B89DU, 0xB4F1F54FU, 0x1627FC27U, 0xDE3BAFF2U } },
      { { 0xDF7304D4U, 0xAB9659D8U, 0xFF210E8EU, 0xB71BCF1BU, 0xD73FBD60U, 0xA9A2438BU, 0x5D11B4DEU, 0x4595CD1FU }, { 0x4835859DU, 0x9C0D329AU, 0x7DBB6E56U, 0x4A0F0D2DU, 0xDF928A4EU, 0xC6038E5EU, 0x8F5AD154U, 0xC9429621U } } } /* window 57 */,
    { { { 0xF23F2D92U, 0x91213462U, 0x60B94078U, 0x6CAB71BDU, 0x176CDE20U, 0x6BDD0A63U, 0xEE4D54BCU, 0x54C9B20CU }, { 0x9F2AC02FU, 0x3CD2D8AAU, 0x206EEDB0U, 0x03F8E617U, 0x93086434U, 0xC7F68E16U, 0x92DD3DB9U, 0x831469C5U } },
      { { 0x3AE9C1BDU, 0x7AA7A158U, 0xE37CE240U, 0xE0AF6D98U, 0x28AB38B4U, 0xE54342D9U, 0x0A1C98CAU, 0xE8B75007U }, { 0xE02358F2U, 0xEFCE86AFU, 0xEA921228U, 0x31B8B856U, 0x0A1C67FCU, 0x052A1912U, 0xE3AEAD59U, 0xB4069EA4U } },
      { { 0xE36D0757U, 0x4A9090CDU, 0xD9A29382U, 0xF722D7B1U, 0x04B48DDFU, 0xFB7FB04CU, 0xEBE16F43U, 0x628AD2A7U }, { 0x20226040U, 0xCD3FBFB5U, 0x5104B6C4U, 0x6C34ECB1U, 0xC903C188U, 0x30C0754EU, 0x2D23CAB0U, 0xEC336B08U } },
      { { 0x558DF019U, 0x9F51439EU, 0xAC712B27U, 0x230DA4BAU, 0x55185A24U, 0x518919E3U, 0x84B78F50U, 0x4DCEFCDDU }, { 0xA47D4C5AU, 0xA7D90FB2U, 0xB30E009EU, 0x55AC9ABFU, 0x74EED273U, 0xFD2FC359U, 0xDBEA8FAFU, 0xB72D824CU } },
      { { 0xCBB13D1BU, 0xD213F923U, 0x5BFB9BFEU, 0x98799F42U, 0x701144A9U, 0x1AE8DDC9U, 0x4C5595EEU, 0x0B8B3BB6U }, { 0x3ECEBB21U, 0x0EA9EF2EU, 0x3671F9A7U, 0x17CB6C4BU, 0x726F1D1FU, 0x47EF464FU, 0x6943A276U, 0x171B9484U } },
      { { 0xDE7E5C19U, 0x779B8552U, 0xC1C0256CU, 0xFAB28609U, 0xABD4743DU, 0x64F58EEEU, 0x7B6CC93BU, 0x4E8EF838U }, { 0x4CB1BF3DU, 0xEE650D26U, 0x73DEDF61U, 0x4C1F9D09U, 0xBFB70CEDU, 0xAEF7C9D7U, 0x1641DE1EU, 0x1EC0507EU } },
      { { 0xA607419DU, 0xC9941109U, 0xBB6BCA80U, 0xFAA71E62U, 0x07C431F3U, 0x34158C13U, 0x992BC47AU, 0x594ABEBCU }, { 0xEB78399FU, 0x6DFEA691U, 0x3F42CBA4U, 0x48AAFB35U, 0x077C04F0U, 0xEDCD65AFU, 0xE884491AU, 0x1A29A366U } },
      { { 0xEF7D9289U, 0x549DB2B5U, 0x197F015AU, 0x2480D4A8U, 0xC40493B6U, 0x61D5590BU, 0x6F780331U, 0x3A55B52EU }, { 0x309EADB0U, 0x40EB8115U, 0x92E5C625U, 0xDEA7DE5AU, 0xCC6A3D5AU, 0x64D631F0U, 0x93E8DD61U, 0x9D5E9D7CU } } } /* window 58 */,
    { { { 0x1E84E0E5U, 0x19686041U, 0xAEA34C93U, 0xA5DB84D3U, 0x7073A732U, 0xF9D5BB19U, 0x6BCFD7C0U, 0xB8D2FE56U }, { 0xF3EB82FAU, 0x45775F36U, 0xFDFF8B58U, 0x8CB20CCCU, 0x8374C110U, 0x1659B65FU, 0x330C789AU, 0xB8B4A422U } },
      { { 0xAF2EBC2FU, 0xC4F4CDA3U, 0xCB4EFE24U, 0xA0AF843DU, 0x9CCD10B1U, 0x53B857C1U, 0x914D3E04U, 0xDDC9D1EBU }, { 0x62771DEBU, 0x7BDEC8BBU, 0x91C5AA81U, 0x829277AAU, 0x832391AEU, 0x7AF18DD6U, 0xC71A84CAU, 0x1740F316U } },
      { { 0xCAB91F1EU, 0x2D500910U, 0x4D1CD216U, 0xBEDD9E44U, 0xEDD02252U, 0xD634B74FU, 0x1258617AU, 0xBD60F8E1U }, { 0x9E05614AU, 0xD8C7537BU, 0xE7AF5FC5U, 0xFD26C766U, 0x582BD926U, 0x0660B581U, 0xACF07FC8U, 0x87019244U } },
      { { 0xEEAF8C49U, 0x8928E99AU, 0x6E24D728U, 0xEE7AA73DU, 0xE72B156CU, 0x4C5007C2U, 0xED408A1DU, 0x5FCF57C5U }, { 0xB6057604U, 0x9F719E39U, 0xC2868BBFU, 0x7D343C01U, 0x7E103E2DU, 0x2CCA254BU, 0xF131BEA2U, 0xE6EB38A9U } },
      { { 0x0A981B0DU, 0x0BA4E352U, 0xBD1A41A4U, 0x1C354CB3U, 0xDF9FAB9CU, 0x1AABAA3AU, 0x53C418D5U, 0x0701A7D1U }, { 0xDCF2B921U, 0xDD1A7CEFU, 0xBCF48061U, 0x6CEEF0B3U, 0xDE25CCE6U, 0x1083B598U, 0xE90A5E34U, 0x890A54C7U } },
      { { 0x4F6D01B1U, 0x405718DBU, 0x8F11E8A0U, 0xE73C6BC2U, 0xA0591A3BU, 0xAC11BB8CU, 0x0ACC4531U, 0x12D09A5AU }, { 0xE7DE13F4U, 0xCBF174EEU, 0x044FD682U, 0x177E2BE6U, 0x1C48AF70U, 0x65F574CBU, 0x9961CB7CU, 0xCE596692U } },
      { { 0x048752A1U, 0xC59EED6CU, 0xA01341B4U, 0x41F2702EU, 0x9DC6B092U, 0x6E35903BU, 0x1F5B5B23U, 0x4291ABA8U }, { 0xA653D61DU, 0x8173AA70U, 0x4F2EB51EU, 0xD1B648D4U, 0x5AB93F8FU, 0x31B7CE06U, 0x99E2F4FEU, 0xA55408EEU } },
      { { 0x8BE762B4U, 0xB33E624FU, 0x058E3413U, 0x2A9EE4D1U, 0x67D805FAU, 0x968E6369U, 0x7DB8BFD7U, 0x9848949BU }, { 0xD23A8417U, 0x5308D7E5U, 0xF3E29DA5U, 0x892F3B1DU, 0x3DEE471FU, 0xC95C139EU, 0xD757E089U, 0x8631594DU } } } /* window 59 */,
    { { { 0x1F095615U, 0x1083E2EAU, 0x14E68C33U, 0x0A28AD77U, 0x3D8818BEU, 0x6BFC0252U, 0xF35850CDU, 0xB585113AU }, { 0x30DF8AA1U, 0x7D935F0BU, 0x4AB7E3ACU, 0xADDDA07CU, 0x552F00CBU, 0x92C34299U, 0x2909DF6CU, 0xC33ED1DEU } },
      { { 0x3E07113CU, 0x2DC40D48U, 0x7D8B63AEU, 0x6E4A5D39U, 0x79684C2BU, 0x5582A94BU, 0x622DA26CU, 0x932B33D4U }, { 0x0DBBF08DU, 0xF534F651U, 0x64C23A52U, 0x211D07C9U, 0xEE5BDC9BU, 0x0EEECE0FU, 0xF7015558U, 0xDF178168U } },
      { { 0x83CDD60EU, 0xABE7905AU, 0xA1170184U, 0x50602FB5U, 0xB023642AU, 0x689886CDU, 0xA6E1FB00U, 0xD568D090U }, { 0x0259217FU, 0x5B1922C7U, 0xC43141E4U, 0x93831CD9U, 0x0C95F86EU, 0xDFCA3587U, 0x568AE828U, 0xDEC2057AU } },
      { { 0x913CC16DU, 0x568F8925U, 0xE1A26F5AU, 0x18BC5B6DU, 0xF5F499AEU, 0xDFA413BEU, 0xC3F0AE84U, 0xF8835DECU }, { 0x65A40AB0U, 0xB6E60BD8U, 0x194B377EU, 0x65596439U, 0x92084A69U, 0xBCD85625U, 0x4F23EDE0U, 0x5CE433B9U } },
      { { 0x42E06189U, 0x860D523DU, 0x4E3AFF13U, 0xBF077941U, 0xC1B20650U, 0x0B616DCAU, 0x2131300DU, 0xE66DD6D1U }, { 0xFF99ABDEU, 0xD4A0FD67U, 0xC7AAC50DU, 0xC9903550U, 0x7C46B2D7U, 0x022ECF8BU, 0x3ABF92AFU, 0x3333B1E8U } },
      { { 0x84D6365DU, 0xC0DA65E7U, 0x8F759FB8U, 0xBCB7443FU, 0x7AE81930U, 0x35C712B1U, 0x4C6E08ABU, 0x80428DFFU }, { 0xA4FAF843U, 0xF19DAFEFU, 0xFFA9855FU, 0xCED8538DU, 0xBE3AC7CEU, 0x20AC409CU, 0x882DA71EU, 0x358C1FB6U } },
      { { 0xBE42A582U, 0xEFECDEF7U, 0x65046BE6U, 0xD3FC6080U, 0x09E8DBA9U, 0xC9AF13C8U, 0x641491FFU, 0x1E6C9847U }, { 0xD30C31F7U, 0x3B574925U, 0xAC2A2122U, 0xB7EB72BAU, 0xEF0859E7U, 0x776A0DACU, 0x21900942U, 0x06FEC314U } },
      { { 0x7E50122BU, 0x324794B0U, 0x4AF07CA5U, 0xDD744F8BU, 0xD63FC97BU, 0x30A12F08U, 0x76626D9DU, 0x39650F1AU }, { 0x1FA38477U, 0x101B47F7U, 0xD4DC124FU, 0x3D815F19U, 0xB26EB58AU, 0x1569AE95U, 0x95FB1887U, 0xC3CDE188U } } } /* window 60 */,
    { { { 0x2F41DEFFU, 0x02B37A95U, 0xE63B89B7U, 0x0E44A59AU, 0x143FF951U, 0x673257DCU, 0xD752BAF4U, 0x19C02205U }, { 0xC4B7D692U, 0x46C23069U, 0xFD1502ACU, 0x2E6392C3U, 0x1B220846U, 0x6057B1A2U, 0x0C1B5B63U, 0xE51FF946U } },
      { { 0x566C5C43U, 0x6E85CB51U, 0x3597F046U, 0xCFF9C919U, 0x4994D94AU, 0x9354E90CU, 0x2147927DU, 0xE0A39332U }, { 0x0DC1EB2BU, 0x8427FAC1U, 0x2FF319FAU, 0x88CFD8C2U, 0x01965274U, 0xE2D4E684U, 0x67AAA746U, 0xFA2E067DU } },
      { { 0x5B0F7BD4U, 0xB9DC857CU, 0x108EA1CDU, 0x6990C2C9U, 0xB984C7A9U, 0x84730B83U, 0xEAB18A78U, 0x552723D2U }, { 0x919BA0F9U, 0x9752C2E2U, 0x4BF40890U, 0x075A3BD9U, 0xA6D98212U, 0x71E52A04U, 0x9F18A4C8U, 0x3FB6607AU } },
      { { 0x3E5F9F11U, 0xB6D92A7FU, 0xD6CB3B8EU, 0x9AFE153AU, 0xDDF800BDU, 0x4D1A6DD7U, 0xCAF17E19U, 0xF6C13CC0U }, { 0x325FC3EEU, 0x15F6C58EU, 0xA31DC3B2U, 0x71095400U, 0xAFA3D3E7U, 0x168E7C07U, 0x94C7AE2DU, 0x3F8417A1U } },
      { { 0x6CE400BBU, 0xF47B7521U, 0xCAF07D99U, 0xF72919F7U, 0x00CE62E0U, 0x95B86E06U, 0x8FCFD00EU, 0x11872BAFU }, { 0x211F7DC6U, 0x049B21EBU, 0x54EBD6F6U, 0xB8900E56U, 0x162D78DAU, 0x7C38CEA4U, 0x0BFA3DA0U, 0x9A586C9EU } },
      { { 0x813B230DU, 0xEC234772U, 0x17344427U, 0x634D0F5FU, 0xD77FC56AU, 0x11548AB1U, 0xCE06AF77U, 0x7FAB1750U }, { 0x4F7C4F83U, 0xB62C10A7U, 0x220A67D9U, 0xA7D2EDC4U, 0x921209A0U, 0x1C404170U, 0xFACE59F0U, 0x0B9815A0U } },
      { { 0x51C3EBE5U, 0xAD3883E1U, 0xD25D7BE8U, 0xDB14D5C7U, 0x558EA8C9U, 0x23E44911U, 0x3F45C6ABU, 0x3A68529FU }, { 0x149F75B8U, 0xEB18A1DCU, 0x079C7CB2U, 0x9B8946A1U, 0x1157A94EU, 0x27AD2A19U, 0x1106F85AU, 0x84B14F46U } },
      { { 0x319540C3U, 0x2842589BU, 0xA283D6F8U, 0x18490F59U, 0xDAAE9FCBU, 0xA2731F84U, 0xC3683BA0U, 0x3DB6D960U }, { 0x14611069U, 0xC85C63BBU, 0x0788BF05U, 0xB19436AFU, 0x347460D2U, 0x905459DFU, 0xE11A7DB1U, 0x73F6E094U } } } /* window 61 */,
    { { { 0xEE3C76CBU, 0xF306A3C8U, 0xD32A1F6EU, 0x3CF11623U, 0x6863E956U, 0xE6D5AB64U, 0x5C005C26U, 0x3B8A4CBEU }, { 0x9CE6BB27U, 0xDCD529A5U, 0x04D4B16FU, 0xC4AFAA52U, 0x7923798DU, 0xB0624A26U, 0x6B307FABU, 0x85E56DF6U } },
      { { 0x4E4CA463U, 0xB2330FEFU, 0x3566CC63U, 0xBCEF7287U, 0xCF780900U, 0xD161D2CAU, 0x5B54827DU, 0x135DC539U }, { 0x27BF1BC6U, 0x638F052EU, 0x07DFA06CU, 0x10A224F0U, 0x6D3321DAU, 0xE973586DU, 0x26152C8FU, 0x8B0C5738U } },
      { { 0x9884AAF7U, 0x89689595U, 0x07B348A6U, 0xB1959BE3U, 0x3C147C87U, 0x96250E57U, 0xDD0C61F8U, 0xAE0EFB3AU }, { 0xCA8C325EU, 0xED00745EU, 0xECFF3F70U, 0x3C911696U, 0x319AD41DU, 0x73ACBC65U, 0xF0B1C7EFU, 0x7B01A020U } },
      { { 0x23A5D896U, 0x9910BA6BU, 0x7FE4364EU, 0x1FE19E35U, 0x9A33C677U, 0x6E1DA8C3U, 0x29FD9FD0U, 0x15B4488BU }, { 0x1A1F22BFU, 0x1F439254U, 0xAB8163E8U, 0x920A8A70U, 0x07E5658EU, 0x3FD1B249U, 0xB6EC839BU, 0xF2C4F79CU } },
      { { 0x224C08DCU, 0x262143B5U, 0x81B50C91U, 0x2BBB09B4U, 0xACA8C84FU, 0xC16ED709U, 0xB2850CA8U, 0xA6210D9DU }, { 0x09CB54D6U, 0x6D8DF67AU, 0x500919A4U, 0x91EEF6E0U, 0x0F132857U, 0x90F61381U, 0xF8D5028BU, 0x9ACEDE47U } },
      { { 0x1416A6A5U, 0x84CEA069U, 0x43EF881CU, 0x8F860C79U, 0x38038A5DU, 0x41311F8AU, 0xFC612067U, 0xE78C2EC0U }, { 0x5AD73581U, 0x494D2E81U, 0x59604097U, 0xB4CC9E00U, 0xF3612CBAU, 0xFF558AECU, 0x9E36C39EU, 0x35BEEF7AU } },
      { { 0xDE673629U, 0x45E21446U, 0x703C2D21U, 0x57F7AA1EU, 0x98C868C7U, 0xA0E99B7FU, 0x8B641676U, 0x4E42F66DU }, { 0x91077896U, 0x602884DCU, 0xC2C9885BU, 0xA0D690CFU, 0x3B9A5187U, 0xFEB4DA33U, 0x153C87EEU, 0x5F789598U } },
      { { 0x76497EE8U, 0x8B5C619CU, 0xC717370EU, 0x5D2B0AC6U, 0x4FCF68E1U, 0x98204CB6U, 0x62BC6792U, 0x0BDEC211U }, { 0xA63B1011U, 0x6973CCEFU, 0xE0DE1AC5U, 0xF9E3FA97U, 0x3D0E0C8BU, 0x5EFB693EU, 0xD2D4FCB4U, 0x037248E9U } } } /* window 62 */,
    { { { 0x1EC34F9EU, 0x80802DC9U, 0x33810603U, 0xD8772D35U, 0x530CB4F3U, 0x3F06D66CU, 0xC475C129U, 0x7BE5ED0DU }, { 0x31E82B10U, 0xCB9E3C19U, 0xC9FF6B4CU, 0xC63D2857U, 0x92A1B45EU, 0xB92118C6U, 0x7285BBCAU, 0x0AEC4414U } },
      { { 0x1E29A3EFU, 0xFC189AE7U, 0x4C93302EU, 0xCBE906F0U, 0xCEAAE10EU, 0xD0107914U, 0xB68E19F8U, 0xB7A23F34U }, { 0xEFD2119DU, 0xE9D875C2U, 0xFCADC9C8U, 0x03198C6EU, 0x4DA17113U, 0x65591BF6U, 0x3D443038U, 0x3CF0BBF8U } },
      { { 0x2B724759U, 0xAE485BB7U, 0xB2D4C63AU, 0x945353E1U, 0xDE7D6F2CU, 0x82159D07U, 0x4EC5B109U, 0x389CAEF3U }, { 0xDB65EF14U, 0x4A8EBB53U, 0xDD99DE43U, 0x2DC2CB7EU, 0x83F2405FU, 0x816FA3EDU, 0xC14208A3U, 0x73429BB9U } },
      { { 0xB01E6E27U, 0xB618D590U, 0xE180B2DCU, 0x047E2CCDU, 0x04AEA4A9U, 0xD1B299B5U, 0x9FA403A4U, 0x412C9E1EU }, { 0x79407552U, 0x88D28A36U, 0xF332B8E3U, 0x49C50136U, 0xE668DE19U, 0x3A1B6FCCU, 0x75122B97U, 0x178851BCU } },
      { { 0xFB85FA4CU, 0xB1E13752U, 0x383C8CE9U, 0xD61257CEU, 0xD2F74DAEU, 0xD43DA670U, 0xBF846BBBU, 0xA35AA23FU }, { 0x4421FC83U, 0x5E74235DU, 0xC363473BU, 0xF6DF8EE0U, 0x3C4AA158U, 0x34D7F52AU, 0x9BC6D22EU, 0x50D05AABU } },
      { { 0xA64785F4U, 0x8C56E735U, 0x5F29CD07U, 0xBC56637BU, 0x3EE35067U, 0x53B2BB80U, 0xDC919270U, 0x50235A0FU }, { 0xF2C4AA65U, 0x191AB6D8U, 0x8396023BU, 0xC3475831U, 0xF0F805BAU, 0x80400BA5U, 0x5EC0F80FU, 0x8881065BU } },
      { { 0xCC1B5E83U, 0xC370E522U, 0x860B8BFBU, 0xDE2D4AD1U, 0x67B256DFU, 0xAD364DF0U, 0xE0138997U, 0x8F12502EU }, { 0x7783920AU, 0x503FA0DCU, 0xC0BC866AU, 0xE80014ADU, 0xD3064BA6U, 0x3F89B744U, 0xCBA5DBA5U, 0x03511DCDU } },
      { { 0x95A7B1A2U, 0x197DD46DU, 0x3C6341FBU, 0x9C4E7AD6U, 0x484C2ECEU, 0x426ECA29U, 0xDE7F4F8AU, 0x9211E489U }, { 0xC78EF1F4U, 0x14997F6EU, 0x06574586U, 0x2B2C0910U, 0x1C3EEDE8U, 0x17286A6EU, 0x0F60E018U, 0x25F92E47U } } } /* window 63 */,
    { { { 0x3AEAC968U, 0xB4E370AFU, 0xC4B63266U, 0xE4F7FEE9U, 0xE3AC5664U, 0xB4ACD4C2U, 0xCEB38CBFU, 0xF8910BD2U }, { 0xC9C0726EU, 0x1C3AE50CU, 0xD97B40BFU, 0x15309569U, 0xFD5A5A1BU, 0x70884B7FU, 0xEF8314CDU, 0x3890896AU } },
      { { 0x82E4C634U, 0x5CED3C9FU, 0x3A4464F8U, 0x8EFB8314U, 0x7A1DCA25U, 0xE706381BU, 0x5A2A412BU, 0x6CD15A3CU }, { 0xBFCD8FB5U, 0x9347A8FDU, 0x6E54CD22U, 0x31DB2EEFU, 0xF8D8932FU, 0xC4AEB11EU, 0x344411AFU, 0x11E7C1EDU } },
      { { 0x903FA271U, 0x996884F5U, 0xB9DA921EU, 0xE6DA0FD2U, 0x5DB01E54U, 0xA6F2F269U, 0x6876214EU, 0x1EE3E9BDU }, { 0xE27A9497U, 0xA26E181CU, 0x8E215E04U, 0x36D254E4U, 0x252CABCAU, 0x42F32A6CU, 0x80B57614U, 0x99481487U } },
      { { 0x43228D83U, 0xAB41B43AU, 0x4AD63F99U, 0x24AE1C30U, 0x46A51229U, 0x8E525F1AU, 0xCD26D2B4U, 0x14AF860FU }, { 0x3F714AA1U, 0xD6BAEF61U, 0xEB78795EU, 0xF51865ADU, 0xE6A9D694U, 0xD3E21FCEU, 0x8A37B527U, 0x82CEB1DDU } },
      { { 0x2F9FD51AU, 0x4A665BFDU, 0x481B97F7U, 0x7F2F1FE2U, 0xAD36CE50U, 0xCAD05D69U, 0x844F4DEDU, 0x314FC2A4U }, { 0xB55FC5C6U, 0xD5593D8CU, 0xBFB1E23DU, 0xE3510CE8U, 0x37453CCEU, 0xF9B7BE69U, 0x69FAE631U, 0xD3541B79U } },
      { { 0xECA445DFU, 0x99296525U, 0x2CDFA4C6U, 0xF1AF24F2U, 0xEBA6D3BCU, 0xF5B4EB61U, 0x98972CC7U, 0x4560910CU }, { 0x093EAA32U, 0x54751C32U, 0x7D3C67BBU, 0x01831349U, 0x2D871110U, 0x3BD90CE6U, 0x538BAA7EU, 0x75FC863AU } },
      { { 0x76A9F05DU, 0x711B8A41U, 0x9011D488U, 0x06CA4E4BU, 0xA248A65EU, 0x543BC62BU, 0xC9290894U, 0x017535FFU }, { 0x406851D7U, 0x840B84CEU, 0x90E960B4U, 0xAFA3ACDFU, 0x7128FD34U, 0xAC3394AFU, 0x2AC0F92CU, 0x54EB4D5BU } },
      { { 0x55DBD4B3U, 0xDB09E873U, 0x6639BBB1U, 0x1F879928U, 0x1C651962U, 0xB83E47E5U, 0xC43FB574U, 0xD4EF0FB6U }, { 0xF1BFB12AU, 0x27D3B9D8U, 0x6E5E8B72U, 0x6AB877E8U, 0x157B9014U, 0x8EEBDC9DU, 0x3AA5CB64U, 0x4C211005U } } } /* window 64 */
};

#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)

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

static void p256_native_load(p256_native_fe output, const uint32_t input[8U])
{
    /* convert QSC's eight 32-bit words to a four-word native residue */
	size_t i;

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (uint64_t)input[2U * i] | ((uint64_t)input[2U * i + 1U] << 32U);
	}
}

static void p256_native_store(uint32_t output[8U], const p256_native_fe input)
{
    /* convert four native words to QSC's eight-word representation */
	size_t i;

	for (i = 0U; i < 4U; ++i)
	{
		output[2U * i] = (uint32_t)input[i];
		output[2U * i + 1U] = (uint32_t)(input[i] >> 32U);
	}
}

static uint64_t p256_native_is_zero(const p256_native_fe input)
{
    /* return whether a native Montgomery element equals zero */
	uint64_t bits;

	bits = input[0U] | input[1U] | input[2U] | input[3U];
	return (uint64_t)(1U ^ ((bits | (UINT64_C(0) - bits)) >> 63U));
}

static void p256_native_copy(p256_native_fe output, const p256_native_fe input)
{
    /* copy one Montgomery residue using four fixed native assignments */
	output[0U] = input[0U];
	output[1U] = input[1U];
	output[2U] = input[2U];
	output[3U] = input[3U];
}

static void p256_native_choose(p256_native_fe result, const p256_native_fe a, const p256_native_fe b, uint64_t select)
{
    /* constant-time conditional assignment of a field element */
	uint64_t mask;
	size_t i;

	mask = UINT64_C(0) - select;

	for (i = 0U; i < 4U; ++i)
	{
		result[i] = (a[i] & mask) | (b[i] & ~mask);
	}
}

static void p256_native_add(p256_native_fe output, const p256_native_fe a, const p256_native_fe b)
{
    /* add two canonical native P-256 field elements modulo p */
	uint64_t sum[4U] = { 0U };
	uint64_t reduced[4U] = { 0U };
	__uint128_t value;
	uint64_t carry;
	uint64_t borrow;
	uint64_t mask;
	size_t i;

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

	qsc_memutils_secure_erase(sum, sizeof(sum));
	qsc_memutils_secure_erase(reduced, sizeof(reduced));
}

static void p256_native_sub(p256_native_fe output, const p256_native_fe a, const p256_native_fe b)
{
    /* subtract two canonical native P-256 field elements modulo p */
	uint64_t difference[4U] = { 0U };
	__uint128_t value;
	uint64_t borrow;
	uint64_t carry;
	uint64_t mask;
	size_t i;

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
}

static void p256_native_comba_acc_product(uint64_t accumulator[3U], __uint128_t product)
{
    /* accumulate one precomputed 128-bit product in a three-word Comba column */
	__uint128_t value;

	value = (__uint128_t)accumulator[0U] + (uint64_t)product;
	accumulator[0U] = (uint64_t)value;
	value = (__uint128_t)accumulator[1U] + (uint64_t)(product >> 64U) + (uint64_t)(value >> 64U);
	accumulator[1U] = (uint64_t)value;
	accumulator[2U] += (uint64_t)(value >> 64U);
}

static void p256_native_comba_acc(uint64_t accumulator[3U], uint64_t a, uint64_t b)
{
    /* accumulate one 64-by-64 product in the Comba column */
	p256_native_comba_acc_product(accumulator, (__uint128_t)a * b);
}

static void p256_native_comba_mul(uint64_t result[15U], const p256_native_fe a, const p256_native_fe b)
{
    /* form a 512-bit Comba product of two four-word operands */
	uint64_t* accumulator;
	size_t column;
	size_t i;
	size_t j;

	accumulator = result + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;

	for (column = 0U; column < 8U; ++column)
	{
		for (i = 0U; i < 4U; ++i)
		{
			j = column - i;

			if (column >= i && j < 4U)
			{
				p256_native_comba_acc(accumulator, a[i], b[j]);
			}
		}

		result[column] = accumulator[0U];
		accumulator[0U] = accumulator[1U];
		accumulator[1U] = accumulator[2U];
		accumulator[2U] = 0U;
	}
}

static void p256_native_comba_square(uint64_t result[15U], const p256_native_fe a)
{
    /* form a 512-bit Comba square using only ten 64-bit multiplies */
	uint64_t* accumulator;
	size_t column;
	size_t i;
	size_t j;

	accumulator = result + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;

	for (column = 0U; column < 8U; ++column)
	{
		for (i = 0U; i < 4U; ++i)
		{
			j = column - i;

			if (column >= i && j < 4U && i <= j)
			{
				__uint128_t product;

				product = (__uint128_t)a[i] * a[j];
				p256_native_comba_acc_product(accumulator, product);

				if (i != j)
				{
					p256_native_comba_acc_product(accumulator, product);
				}
			}
		}

		result[column] = accumulator[0U];
		accumulator[0U] = accumulator[1U];
		accumulator[1U] = accumulator[2U];
		accumulator[2U] = 0U;
	}
}

static void p256_native_reduce(p256_native_fe output, uint64_t scratch[15U])
{
    /* reduce eight product words using specialized P-256 Montgomery formula */
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
		selected = (words[i + 4U] & mask) | (reduced[i] & ~mask);
		output[i] = selected;
	}
}

static void p256_native_mul(p256_native_fe output, const p256_native_fe a, const p256_native_fe b, uint64_t scratch[15U])
{
    /* multiply two Montgomery-native P-256 field elements */
	p256_native_comba_mul(scratch, a, b);
	p256_native_reduce(output, scratch);
}

static void p256_native_square(p256_native_fe output, const p256_native_fe a, uint64_t scratch[15U])
{
    /* square one native P-256 Montgomery element */
	p256_native_comba_square(scratch, a);
	p256_native_reduce(output, scratch);
}

static void p256_native_square_n(p256_native_fe value, size_t rounds, uint64_t scratch[15U])
{
    /* apply a fixed number of native field squarings */
	size_t i;

	for (i = 0U; i < rounds; ++i)
	{
		p256_native_square(value, value, scratch);
	}
}

static void p256_native_inverse_square(p256_native_fe output, const p256_native_fe z, uint64_t scratch[15U])
{
    /* compute Z^-2 fixed P-256 p-3 addition chain */
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

static void p256_native_point_choose(p256_native_point* output, const p256_native_point* a, const p256_native_point* b, uint64_t select)
{
    /* select one native projective point in constant time */
	p256_native_choose(output->x, a->x, b->x, select);
	p256_native_choose(output->y, a->y, b->y, select);
	p256_native_choose(output->z, a->z, b->z, select);
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

static void p256_native_add_generator(p256_native_point* output, const p256_native_point* first, const p256_native_point* second, p256_native_window_workspace* work, uint64_t scratch[15U])
{
    /* add one disjoint generator window with Jacobian mixed-add formula */
	uint64_t first_inf;
	uint64_t second_inf;

	p256_native_square(work->zz, first->z, scratch);
	p256_native_mul(work->u, second->x, work->zz, scratch);
	p256_native_mul(work->s, second->y, first->z, scratch);
	p256_native_mul(work->s, work->s, work->zz, scratch);
	p256_native_sub(work->h, work->u, first->x);
	p256_native_sub(work->delta, work->s, first->y);
	p256_native_square(work->hh, work->h, scratch);
	p256_native_mul(work->hhh, work->h, work->hh, scratch);
	p256_native_mul(work->v, first->x, work->hh, scratch);
	p256_native_square(work->added.x, work->delta, scratch);
	p256_native_sub(work->added.x, work->added.x, work->hhh);
	p256_native_add(work->tmp, work->v, work->v);
	p256_native_sub(work->added.x, work->added.x, work->tmp);
	p256_native_sub(work->tmp, work->v, work->added.x);
	p256_native_mul(work->added.y, work->delta, work->tmp, scratch);
	p256_native_mul(work->tmp, first->y, work->hhh, scratch);
	p256_native_sub(work->added.y, work->added.y, work->tmp);
	p256_native_mul(work->added.z, first->z, work->h, scratch);

	first_inf = p256_native_is_zero(first->z);
	second_inf = p256_native_is_zero(second->z);
	p256_native_point_choose(&work->added, first, &work->added, second_inf);
	p256_native_point_choose(&work->added, second, &work->added, first_inf);
	*output = work->added;
}

static void p256_native_generator(p256_jac_t* output, const uint32_t scalar[8U])
{
    /* multiply P-256 generator using the signed disjoint-window table */
	uint64_t scratch[15U] = { 0U };
	p256_native_point accumulator = { { 0U }, { 0U }, { 0U } };
	p256_native_point selected = { { 0U }, { 0U }, { 0U } };
	p256_native_point added;
	p256_native_window_workspace work;
	p256_native_fe minus_y = { 0U };
	p256_native_fe zero = { 0U };
	uint32_t value;
	uint32_t carry;
	uint32_t digit;
	uint32_t magnitude;
	uint32_t diff;
	uint32_t equal;
	uint64_t sign;
	uint64_t present;
	uint64_t mask;
	size_t i;
	size_t j;
	size_t w;

	qsc_memutils_clear(&work, sizeof(work));
	p256_native_copy(accumulator.y, P256_NATIVE_ONE);
	carry = 0U;

	for (i = 0U; i < 65U; ++i)
	{
		value = (i < 64U) ? ((scalar[i / 8U] >> ((i % 8U) * 4U)) & 15U) : 0U;
		value += carry;
		carry = (value + 7U) >> 4U;
		digit = value - (carry << 4U);
		magnitude = (digit ^ (0U - carry)) - (0U - carry);
		present = (uint64_t)((magnitude | (0U - magnitude)) >> 31U);
		sign = (uint64_t)carry;
		mask = UINT64_C(0) - present;

		for (w = 0U; w < 4U; ++w)
		{
			selected.x[w] = 0U;
			selected.y[w] = 0U;
			selected.z[w] = P256_NATIVE_ONE[w] & mask;
		}

		for (j = 0U; j < 8U; ++j)
		{
			diff = (uint32_t)(j + 1U) ^ magnitude;
			equal = 1U ^ ((diff | (0U - diff)) >> 31U);
			mask = UINT64_C(0) - (uint64_t)equal;

			for (w = 0U; w < 4U; ++w)
			{
				selected.x[w] |= ((uint64_t)P256_BOTAN_BOOTH_MONT[i][j][0U][2U * w] |
					((uint64_t)P256_BOTAN_BOOTH_MONT[i][j][0U][2U * w + 1U] << 32U)) & mask;
				selected.y[w] |= ((uint64_t)P256_BOTAN_BOOTH_MONT[i][j][1U][2U * w] |
					((uint64_t)P256_BOTAN_BOOTH_MONT[i][j][1U][2U * w + 1U] << 32U)) & mask;
			}
		}

		p256_native_sub(minus_y, zero, selected.y);
		p256_native_choose(selected.y, minus_y, selected.y, sign);
		p256_native_add_generator(&added, &accumulator, &selected, &work, scratch);
		accumulator = added;
	}

	p256_native_store(output->X, accumulator.x);
	p256_native_store(output->Y, accumulator.y);
	p256_native_store(output->Z, accumulator.z);
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&added, sizeof(added));
	qsc_memutils_secure_erase(minus_y, sizeof(minus_y));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
	qsc_memutils_secure_erase(&work, sizeof(work));
}

static void p256_native_affine_x(fe256 output, const p256_jac_t* point)
{
    /* compute affine X for one non-infinity P-256 native Montgomery point */
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

static const uint64_t P256_NATIVE_ORDER[4U] =
{
    /* P-256 subgroup modulus, little-endian four-word representation */
	UINT64_C(0xF3B9CAC2FC632551), UINT64_C(0xBCE6FAADA7179E84),
	UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFF00000000)
};

static const uint64_t P256_NATIVE_ORDER_R2[4U] =
{
    /* R-squared modulo the P-256 subgroup order for native Montgomery encoding */
	UINT64_C(0x83244C95BE79EEA2), UINT64_C(0x4699799C49BD6FA6),
	UINT64_C(0x2845B2392B6BEC59), UINT64_C(0x66E12D94F3D95620)
};

static void p256_native_order_mul(p256_native_fe output, const p256_native_fe a, const p256_native_fe b, uint64_t scratch[14U])
{
    /* one native scalar Montgomery multiplication modulo P-256 order */
	uint64_t* words;
	uint64_t* reduced;
	__uint128_t value;
	uint64_t carry;
	uint64_t borrow;
	uint64_t digit;
	uint64_t mask;
	size_t i;
	size_t j;

	words = scratch;
	reduced = scratch + 10U;

	for (i = 0U; i < 10U; ++i)
	{
		words[i] = 0U;
	}

	for (i = 0U; i < 4U; ++i)
	{
		carry = 0U;

		for (j = 0U; j < 4U; ++j)
		{
			value = (__uint128_t)a[i] * b[j] + words[i + j] + carry;
			words[i + j] = (uint64_t)value;
			carry = (uint64_t)(value >> 64U);
		}

		for (j = i + 4U; j < 10U; ++j)
		{
			value = (__uint128_t)words[j] + carry;
			words[j] = (uint64_t)value;
			carry = (uint64_t)(value >> 64U);
		}
	}

	for (i = 0U; i < 4U; ++i)
	{
		digit = words[i] * UINT64_C(0xCCD1C8AAEE00BC4F);
		carry = 0U;

		for (j = 0U; j < 4U; ++j)
		{
			value = (__uint128_t)digit * P256_NATIVE_ORDER[j] + words[i + j] + carry;
			words[i + j] = (uint64_t)value;
			carry = (uint64_t)(value >> 64U);
		}

		for (j = i + 4U; j < 10U; ++j)
		{
			value = (__uint128_t)words[j] + carry;
			words[j] = (uint64_t)value;
			carry = (uint64_t)(value >> 64U);
		}
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)words[i + 4U] - P256_NATIVE_ORDER[i] - borrow;
		reduced[i] = (uint64_t)value;
		borrow = (uint64_t)(value >> 127U);
	}

	digit = words[8U];
	mask = UINT64_C(0) - (((digit | (UINT64_C(0) - digit)) >> 63U) | (borrow ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (words[i + 4U] & ~mask) | (reduced[i] & mask);
	}

}

static void p256_native_order_add(p256_native_fe output, const p256_native_fe a, const p256_native_fe b)
{
    /* add canonical native Montgomery scalars modulo the subgroup order */
	uint64_t sum[4U] = { 0U };
	uint64_t reduced[4U] = { 0U };
	__uint128_t value;
	uint64_t carry;
	uint64_t borrow;
	uint64_t mask;
	size_t i;

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
		value = (__uint128_t)sum[i] - P256_NATIVE_ORDER[i] - borrow;
		reduced[i] = (uint64_t)value;
		borrow = (uint64_t)(value >> 127U);
	}

	mask = UINT64_C(0) - (carry | (borrow ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (reduced[i] & mask) | (sum[i] & ~mask);
	}

	qsc_memutils_secure_erase(sum, sizeof(sum));
	qsc_memutils_secure_erase(reduced, sizeof(reduced));
}

static void p256_native_order_square_n(p256_native_fe value, size_t rounds, uint64_t scratch[14U])
{
    /* square one order residue for a fixed number of Montgomery rounds */
	size_t i;

	for (i = 0U; i < rounds; ++i)
	{
		p256_native_order_mul(value, value, value, scratch);
	}
}

static void p256_native_order_inverse(p256_native_fe output, const p256_native_fe a, uint64_t scratch[14U])
{
    /* P-256 order inversion addition chain in persistent native representation */
	p256_native_fe t[15U] = { { 0U } };
	p256_native_fe z = { 0U };

	p256_native_order_mul(t[1U], a, a, scratch);
	p256_native_order_mul(t[5U], t[1U], t[1U], scratch);
	p256_native_order_mul(t[2U], t[5U], a, scratch);
	p256_native_order_mul(t[10U], t[2U], a, scratch);
	p256_native_order_mul(t[3U], t[2U], t[5U], scratch);
	p256_native_order_mul(z, t[10U], t[3U], scratch);
	p256_native_order_mul(t[9U], t[3U], t[3U], scratch);
	p256_native_order_mul(t[4U], t[10U], z, scratch);
	p256_native_order_mul(t[0U], t[10U], t[9U], scratch);
	p256_native_order_mul(t[13U], t[0U], t[1U], scratch);
	p256_native_order_mul(t[8U], t[13U], t[4U], scratch);
	p256_native_order_mul(t[4U], t[3U], t[8U], scratch);
	p256_native_order_mul(t[7U], t[2U], t[4U], scratch);
	p256_native_order_mul(t[2U], t[1U], t[7U], scratch);
	p256_native_order_mul(t[6U], t[7U], t[9U], scratch);
	p256_native_order_mul(t[3U], t[6U], t[9U], scratch);
	p256_native_order_mul(t[1U], t[1U], t[3U], scratch);
	p256_native_order_mul(t[12U], t[3U], t[9U], scratch);
	p256_native_order_mul(t[5U], t[5U], t[12U], scratch);
	p256_native_order_mul(t[11U], t[10U], t[5U], scratch);
	p256_native_order_mul(t[0U], t[0U], t[11U], scratch);
	p256_native_order_mul(t[9U], t[9U], t[0U], scratch);
	p256_native_order_mul(t[10U], t[10U], t[9U], scratch);
	p256_native_order_mul(t[4U], t[4U], t[10U], scratch);
	p256_native_order_mul(t[13U], t[13U], t[4U], scratch);
	p256_native_copy(t[14U], t[13U]);
	p256_native_order_square_n(t[14U], 8U, scratch);
	p256_native_order_mul(t[13U], t[13U], t[14U], scratch);
	p256_native_copy(t[14U], t[13U]);
	p256_native_order_square_n(t[14U], 16U, scratch);
	p256_native_order_mul(t[14U], t[14U], t[13U], scratch);
	p256_native_order_square_n(t[14U], 48U, scratch);
	p256_native_order_mul(t[14U], t[14U], t[13U], scratch);
	p256_native_order_square_n(t[14U], 16U, scratch);
	p256_native_order_mul(t[14U], t[14U], t[13U], scratch);
	p256_native_order_square_n(t[14U], 16U, scratch);
	p256_native_order_mul(t[14U], t[14U], t[13U], scratch);
	p256_native_order_square_n(t[14U], 16U, scratch);
	p256_native_order_mul(t[13U], t[13U], t[14U], scratch);
	p256_native_order_square_n(t[13U], 6U, scratch);
	p256_native_order_mul(t[13U], t[13U], t[8U], scratch);
	p256_native_order_square_n(t[13U], 9U, scratch);
	p256_native_order_mul(t[12U], t[12U], t[13U], scratch);
	p256_native_order_square_n(t[12U], 8U, scratch);
	p256_native_order_mul(t[11U], t[11U], t[12U], scratch);
	p256_native_order_square_n(t[11U], 9U, scratch);
	p256_native_order_mul(t[10U], t[10U], t[11U], scratch);
	p256_native_order_square_n(t[10U], 8U, scratch);
	p256_native_order_mul(t[9U], t[9U], t[10U], scratch);
	p256_native_order_square_n(t[9U], 9U, scratch);
	p256_native_order_mul(t[8U], t[8U], t[9U], scratch);
	p256_native_order_square_n(t[8U], 8U, scratch);
	p256_native_order_mul(t[7U], t[7U], t[8U], scratch);
	p256_native_order_square_n(t[7U], 11U, scratch);
	p256_native_order_mul(t[6U], t[6U], t[7U], scratch);
	p256_native_order_square_n(t[6U], 9U, scratch);
	p256_native_order_mul(t[5U], t[5U], t[6U], scratch);
	p256_native_order_square_n(t[5U], 10U, scratch);
	p256_native_order_mul(t[4U], t[4U], t[5U], scratch);
	p256_native_order_square_n(t[4U], 8U, scratch);
	p256_native_order_mul(t[3U], t[3U], t[4U], scratch);
	p256_native_order_square_n(t[3U], 7U, scratch);
	p256_native_order_mul(t[2U], t[2U], t[3U], scratch);
	p256_native_order_square_n(t[2U], 10U, scratch);
	p256_native_order_mul(t[1U], t[1U], t[2U], scratch);
	p256_native_order_square_n(t[1U], 10U, scratch);
	p256_native_order_mul(t[0U], t[0U], t[1U], scratch);
	p256_native_order_square_n(t[0U], 6U, scratch);
	p256_native_order_mul(z, z, t[0U], scratch);
	p256_native_copy(output, z);

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(z, sizeof(z));
}

static bool p256_native_sign_scalar(uint32_t output[8U], const uint32_t nonce[8U], const uint32_t private_scalar[8U], const uint32_t signature_r[8U], const uint32_t message_scalar[8U])
{
    /* calculate QSC's independently blinded P-256 signature scalar natively */
	uint64_t scratch[14U] = { 0U };
	uint8_t random_mask[32U] = { 0U };
	uint32_t mask[8U] = { 0U };
	p256_native_fe masking = { 0U };
	p256_native_fe nonce_mont = { 0U };
	p256_native_fe private_mont = { 0U };
	p256_native_fe hash_mont = { 0U };
	p256_native_fe r_mont = { 0U };
	p256_native_fe inverse = { 0U };
	p256_native_fe sum = { 0U };
	p256_native_fe result = { 0U };
	p256_native_fe canonical = { 0U };
	p256_native_fe one = { 1U, 0U, 0U, 0U };
	bool ok;

	ok = qsc_csp_generate(random_mask, sizeof(random_mask));

	if (ok)
	{
		sc_from_bytes_reduce(mask, random_mask);
		mask[0U] |= fe256_is_zero(mask);
		p256_native_load(canonical, mask);
		p256_native_order_mul(masking, canonical, P256_NATIVE_ORDER_R2, scratch);
		p256_native_load(canonical, nonce);
		p256_native_order_mul(nonce_mont, canonical, P256_NATIVE_ORDER_R2, scratch);
		p256_native_load(canonical, private_scalar);
		p256_native_order_mul(private_mont, canonical, P256_NATIVE_ORDER_R2, scratch);
		p256_native_load(canonical, message_scalar);
		p256_native_order_mul(hash_mont, canonical, P256_NATIVE_ORDER_R2, scratch);
		p256_native_load(canonical, signature_r);
		p256_native_order_mul(r_mont, canonical, P256_NATIVE_ORDER_R2, scratch);

		p256_native_order_mul(nonce_mont, nonce_mont, masking, scratch);
		p256_native_order_inverse(inverse, nonce_mont, scratch);
		p256_native_order_mul(private_mont, private_mont, masking, scratch);
		p256_native_order_mul(private_mont, private_mont, r_mont, scratch);
		p256_native_order_mul(hash_mont, hash_mont, masking, scratch);
		p256_native_order_add(sum, private_mont, hash_mont);
		p256_native_order_mul(result, inverse, sum, scratch);
		p256_native_order_mul(result, result, one, scratch);
		p256_native_store(output, result);
	}

	qsc_memutils_secure_erase(random_mask, sizeof(random_mask));
	qsc_memutils_secure_erase(mask, sizeof(mask));
	qsc_memutils_secure_erase(masking, sizeof(masking));
	qsc_memutils_secure_erase(nonce_mont, sizeof(nonce_mont));
	qsc_memutils_secure_erase(private_mont, sizeof(private_mont));
	qsc_memutils_secure_erase(hash_mont, sizeof(hash_mont));
	qsc_memutils_secure_erase(r_mont, sizeof(r_mont));
	qsc_memutils_secure_erase(inverse, sizeof(inverse));
	qsc_memutils_secure_erase(sum, sizeof(sum));
	qsc_memutils_secure_erase(result, sizeof(result));
	qsc_memutils_secure_erase(canonical, sizeof(canonical));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));

	return ok;
}

#endif /* native-width signing point backend */

/*! \details The signed radix-16 base table guarantees that the already
 * accumulated lower-order windows have absolute scalar magnitude less than
 * (8/15)*16^i, while each selected nonzero term has magnitude at least
 * 16^i. For validated scalars below the subgroup order they cannot be the
 * same or opposite point modulo the order. Consequently, the generic
 * doubling fallback can be omitted for this fixed-base path alone.
 * Infinity inputs are still selected with constant-time masks. The general
 * QSC mixed adder remains unchanged for all other callers.
 * \param R: [p256_jac_t*] Writable Jacobian output; aliasing allowed.
 * \param P: [const p256_jac_t*] Accumulated lower-order signed windows.
 * \param Q: [const p256_jac_t*] Selected higher-order affine table point.
 * \note Secret input may affect point values, never memory indices or branches.
 */
#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER)
static void p256_add_mixed_booth(p256_jac_t* R, const p256_jac_t* P, const p256_jac_t* Q)
{
    fe256 z1z1 = { 0U };
    fe256 u2 = { 0U };
    fe256 s2 = { 0U };
    fe256 h = { 0U };
    fe256 delta = { 0U };
    fe256 hh = { 0U };
    fe256 hhh = { 0U };
    fe256 v = { 0U };
    fe256 temp = { 0U };
    p256_jac_t sum;
    uint32_t pinf;
    uint32_t qinf;

    fe_sqr(z1z1, P->Z);
    fe_mul(u2, Q->X, z1z1);
    fe_mul(s2, Q->Y, P->Z);
    fe_mul(s2, s2, z1z1);
    fe_sub(h, u2, P->X);
    fe_sub(delta, s2, P->Y);
    fe_sqr(hh, h);
    fe_mul(hhh, h, hh);
    fe_mul(v, P->X, hh);
    fe_sqr(sum.X, delta);
    fe_sub(sum.X, sum.X, hhh);
    fe_add(temp, v, v);
    fe_sub(sum.X, sum.X, temp);
    fe_sub(temp, v, sum.X);
    fe_mul(sum.Y, delta, temp);
    fe_mul(temp, P->Y, hhh);
    fe_sub(sum.Y, sum.Y, temp);
    fe_mul(sum.Z, P->Z, h);

    pinf = p256_is_infinity(P);
    qinf = p256_is_infinity(Q);
    p256_jac_ct_select(&sum, qinf, P, &sum);
    p256_jac_ct_select(&sum, pinf, Q, &sum);
    *R = sum;

    qsc_memutils_secure_erase(z1z1, sizeof(z1z1));
    qsc_memutils_secure_erase(u2, sizeof(u2));
    qsc_memutils_secure_erase(s2, sizeof(s2));
    qsc_memutils_secure_erase(h, sizeof(h));
    qsc_memutils_secure_erase(delta, sizeof(delta));
    qsc_memutils_secure_erase(hh, sizeof(hh));
    qsc_memutils_secure_erase(hhh, sizeof(hhh));
    qsc_memutils_secure_erase(v, sizeof(v));
    qsc_memutils_secure_erase(temp, sizeof(temp));
    qsc_memutils_secure_erase(&sum, sizeof(sum));
}
#endif


#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
static void p256_scalar_mult_generator(p256_jac_t* R, const uint32_t k[8U])
{
	p256_native_generator(R, k);
}
#else
static void p256_scalar_mult_generator(p256_jac_t* R, const uint32_t k[8U])
{
    p256_jac_t accumulator;
    p256_jac_t selected;
    p256_jac_t added;
    fe256 negative_y = { 0U };
    fe256 zero = { 0U };
    uint32_t value;
    uint32_t carry;
    uint32_t signed_digit;
    uint32_t magnitude;
    uint32_t signmask;
    uint32_t present;
    uint32_t mask;
    uint32_t difference;
    uint32_t equal;
    size_t i;
    size_t j;
    size_t w;

    p256_set_infinity(&accumulator);
    carry = 0U;

    /* Secret-dependent table selection uses fixed memory traversal. */
    for (i = 0U; i < 65U; ++i)
    {
        value = (i < 64U) ? ((k[i / 8U] >> ((i % 8U) * 4U)) & 15U) : 0U;
        value += carry;
        carry = (value + 7U) >> 4U;
        signed_digit = value - (carry << 4U);
        signmask = 0U - carry;
        magnitude = (signed_digit ^ signmask) - signmask;
        present = (magnitude | (0U - magnitude)) >> 31U;
        mask = 0U - present;

        p256_set_infinity(&selected);
        for (w = 0U; w < 8U; ++w)
        {
            selected.X[w] = 0U;
            selected.Y[w] = 0U;
            selected.Z[w] = P256_MONT_ONE[w] & mask;
        }

        for (j = 0U; j < 8U; ++j)
        {
            difference = (uint32_t)(j + 1U) ^ magnitude;
            equal = 1U ^ ((difference | (0U - difference)) >> 31U);
            mask = 0U - equal;
            for (w = 0U; w < 8U; ++w)
            {
                selected.X[w] |= P256_BOTAN_BOOTH_MONT[i][j][0U][w] & mask;
                selected.Y[w] |= P256_BOTAN_BOOTH_MONT[i][j][1U][w] & mask;
            }
        }

        fe_sub(negative_y, zero, selected.Y);
        fe256_ct_select(selected.Y, carry, negative_y, selected.Y);
        p256_add_mixed_booth(&added, &accumulator, &selected);
        accumulator = added;
    }

    *R = accumulator;
    qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
    qsc_memutils_secure_erase(&selected, sizeof(selected));
    qsc_memutils_secure_erase(&added, sizeof(added));
    qsc_memutils_secure_erase(negative_y, sizeof(negative_y));
    qsc_memutils_secure_erase(zero, sizeof(zero));
}

#endif

static void p256_scalar_mult(p256_jac_t* R, const p256_aff_t* P, const uint32_t k[8U], bool fixed_generator)
{
    /* multiply a curve point by a scalar with a constant-time four-bit window */
	p256_jac_t table[16U];
	p256_aff_t encoded;
	p256_jac_t accumulator;
	p256_jac_t doubled;
	p256_jac_t selected;
	p256_jac_t added;
	uint32_t digit;
	uint32_t match;
	uint32_t difference;
	size_t i;
	size_t j;
	size_t round;

	if (fixed_generator == true)
	{
		p256_scalar_mult_generator(R, k);
		return;
	}

	p256_set_infinity(&table[0U]);

	fe256_mont_encode(encoded.X, P->X);
	fe256_mont_encode(encoded.Y, P->Y);
	p256_aff_to_jac(&table[1U], &encoded);

	for (i = 2U; i < 16U; ++i)
	{
		p256_add(&table[i], &table[i - 1U], &table[1U]);
	}

	p256_set_infinity(&accumulator);

	for (i = 64U; i > 0U; --i)
	{
		for (round = 0U; round < 4U; ++round)
		{
			p256_dbl(&doubled, &accumulator);
			accumulator = doubled;
		}

		digit = (k[(i - 1U) / 8U] >> (((uint32_t)((i - 1U) % 8U)) * 4U)) & 15U;
		p256_set_infinity(&selected);

		for (j = 0U; j < 16U; ++j)
		{
			difference = ((uint32_t)j ^ digit);
			match = (uint32_t)(1U ^ ((difference | (0U - difference)) >> 31U));
			p256_jac_ct_select(&selected, match, &table[j], &selected);
		}

		p256_add(&added, &accumulator, &selected);
		accumulator = added;
	}

	*R = accumulator;

	qsc_memutils_secure_erase(&encoded, sizeof(encoded));
	qsc_memutils_secure_erase(table, sizeof(table));
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&doubled, sizeof(doubled));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&added, sizeof(added));
}

#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static void p256_double_scalar_mult(p256_jac_t* R, const p256_aff_t* Q, const uint32_t u1[8U], const uint32_t u2[8U], const qsc_p256_verify_context* context)
{
    /* joint scalar multiplication u1*G + u2*Q with one shared doubling chain */
    (void)context;
	p256_jac_t generator_table[16U];
	p256_jac_t point_table[16U];
	p256_jac_t accumulator;
	p256_jac_t doubled;
	p256_jac_t selected_generator;
	p256_jac_t selected_point;
	p256_jac_t added;
	p256_aff_t encoded;
	uint32_t first_digit;
	uint32_t second_digit;
	uint32_t difference;
	uint32_t match_first;
	uint32_t match_second;
	size_t i;
	size_t j;
	size_t round;

	p256_set_infinity(&generator_table[0U]);
	p256_set_infinity(&point_table[0U]);
	fe256_mont_encode(encoded.X, Q->X);
	fe256_mont_encode(encoded.Y, Q->Y);
	p256_aff_to_jac(&point_table[1U], &encoded);

	for (i = 1U; i < 16U; ++i)
	{
		fe256_copy(generator_table[i].X, P256_GENERATOR_MONT[i][0U]);
		fe256_copy(generator_table[i].Y, P256_GENERATOR_MONT[i][1U]);
		fe256_one(generator_table[i].Z);
	}

	for (i = 2U; i < 16U; ++i)
	{
		p256_add(&point_table[i], &point_table[i - 1U], &point_table[1U]);
	}

	p256_set_infinity(&accumulator);

	for (i = 64U; i > 0U; --i)
	{
		for (round = 0U; round < 4U; ++round)
		{
			p256_dbl(&doubled, &accumulator);
			accumulator = doubled;
		}

		first_digit = (u1[(i - 1U) / 8U] >> (((uint32_t)((i - 1U) % 8U)) * 4U)) & 15U;
		second_digit = (u2[(i - 1U) / 8U] >> (((uint32_t)((i - 1U) % 8U)) * 4U)) & 15U;
		p256_set_infinity(&selected_generator);
		p256_set_infinity(&selected_point);

		for (j = 0U; j < 16U; ++j)
		{
			difference = ((uint32_t)j ^ first_digit);
			match_first = (uint32_t)(1U ^ ((difference | (0U - difference)) >> 31U));
			difference = ((uint32_t)j ^ second_digit);
			match_second = (uint32_t)(1U ^ ((difference | (0U - difference)) >> 31U));
			p256_jac_ct_select(&selected_generator, match_first, &generator_table[j], &selected_generator);
			p256_jac_ct_select(&selected_point, match_second, &point_table[j], &selected_point);
		}

		p256_add_mixed(&added, &accumulator, &selected_generator);
		p256_add(&accumulator, &added, &selected_point);
	}

	*R = accumulator;
	qsc_memutils_secure_erase(generator_table, sizeof(generator_table));
	qsc_memutils_secure_erase(point_table, sizeof(point_table));
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&doubled, sizeof(doubled));
	qsc_memutils_secure_erase(&selected_generator, sizeof(selected_generator));
	qsc_memutils_secure_erase(&selected_point, sizeof(selected_point));
	qsc_memutils_secure_erase(&added, sizeof(added));
	qsc_memutils_secure_erase(&encoded, sizeof(encoded));
}
#else

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER)
static void p256_add_public(p256_jac_t* result, const p256_jac_t* first, const p256_jac_t* second)
{
    /* affine-compatible Jacobian addition, restricted to public verification operands */
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
    fe256 tmp;
    p256_jac_t candidate;

    if (p256_is_infinity(first) != 0U)
    {
        *result = *second;
    }
    else if (p256_is_infinity(second) != 0U)
    {
        *result = *first;
    }
    else
    {
        fe_sqr(z1z1, first->Z);
        fe_sqr(z2z2, second->Z);
        fe_mul(u1, first->X, z2z2);
        fe_mul(u2, second->X, z1z1);
        fe_mul(s1, first->Y, second->Z);
        fe_mul(s1, s1, z2z2);
        fe_mul(s2, second->Y, first->Z);
        fe_mul(s2, s2, z1z1);
        fe_sub(h, u2, u1);
        fe_sub(r2, s2, s1);

        if (fe256_is_zero(h) != 0U)
        {
            if (fe256_is_zero(r2) != 0U)
            {
                p256_dbl(result, first);
            }
            else
            {
                p256_set_infinity(result);
            }
        }
        else
        {
            fe_mul_small(r2, r2, 2U);
            fe_mul_small(i, h, 2U);
            fe_sqr(i, i);
            fe_mul(j, h, i);
            fe_mul(v, u1, i);
            fe_sqr(candidate.X, r2);
            fe_sub(candidate.X, candidate.X, j);
            fe_sub(candidate.X, candidate.X, v);
            fe_sub(candidate.X, candidate.X, v);
            fe_sub(tmp, v, candidate.X);
            fe_mul(candidate.Y, r2, tmp);
            fe_mul(tmp, s1, j);
            fe_mul_small(tmp, tmp, 2U);
            fe_sub(candidate.Y, candidate.Y, tmp);
            fe_add(candidate.Z, first->Z, second->Z);
            fe_sqr(candidate.Z, candidate.Z);
            fe_sub(candidate.Z, candidate.Z, z1z1);
            fe_sub(candidate.Z, candidate.Z, z2z2);
            fe_mul(candidate.Z, candidate.Z, h);
            *result = candidate;
        }
    }
}

#endif

static void p256_recode_public(int8_t digits[257U], const uint32_t scalar[8U])
{
    /* convert a public scalar to width-five nonadjacent form */
    uint32_t value[9U] = { 0U };
    uint64_t carry;
    uint32_t borrow;
    uint32_t old;
    int32_t digit;
    uint32_t topbit;
    size_t i;
    size_t j;

    for (j = 0U; j < 8U; ++j)
    {
        value[j] = scalar[j];
    }

    for (i = 0U; i < 257U; ++i)
    {
        digit = 0;

        if ((value[0U] & 1U) != 0U)
        {
            digit = (int32_t)(value[0U] & 31U);

            if (digit > 15)
            {
                digit -= 32;
            }

            if (digit > 0)
            {
                borrow = (uint32_t)digit;

                for (j = 0U; j < 9U; ++j)
                {
                    old = value[j];
                    value[j] -= borrow;
                    borrow = (uint32_t)(old < borrow);
                }
            }
            else
            {
                carry = (uint64_t)(-digit);

                for (j = 0U; j < 9U; ++j)
                {
                    carry += value[j];
                    value[j] = (uint32_t)carry;
                    carry >>= 32U;
                }
            }
        }

        digits[i] = (int8_t)digit;
        topbit = 0U;

        for (j = 9U; j > 0U; --j)
        {
            old = value[j - 1U];
            value[j - 1U] = (old >> 1U) | (topbit << 31U);
            topbit = old & 1U;
        }
    }

    qsc_memutils_secure_erase(value, sizeof(value));
}

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER)
static void p256_negate_public(p256_jac_t* output, const p256_jac_t* input)
{
    /* negate the Y coordinate of a public Jacobian point */
    fe256 zero = { 0U };
    p256_jac_t tmp;

    tmp = *input;
    fe_sub(tmp.Y, zero, tmp.Y);
    *output = tmp;
}

static void p256_batch_affine_public(p256_jac_t table[8U])
{
    /* calculate u1 G + u2 Q with public-only signed-window recoding */
    fe256 prefix[8U];
    fe256 inverse;
    fe256 zinverse;
    fe256 zinverse2;
    fe256 zinverse3;
    size_t i;

    fe256_copy(prefix[0U], table[0U].Z);

    for (i = 1U; i < 8U; ++i)
    {
        fe_mul(prefix[i], prefix[i - 1U], table[i].Z);
    }

    fe_inv(inverse, prefix[7U]);

    for (i = 8U; i > 0U; --i)
    {
        if (i == 1U)
        {
            fe256_copy(zinverse, inverse);
        }
        else
        {
            fe_mul(zinverse, inverse, prefix[i - 2U]);
            fe_mul(inverse, inverse, table[i - 1U].Z);
        }

        fe_sqr(zinverse2, zinverse);
        fe_mul(zinverse3, zinverse2, zinverse);
        fe_mul(table[i - 1U].X, table[i - 1U].X, zinverse2);
        fe_mul(table[i - 1U].Y, table[i - 1U].Y, zinverse3);
        fe256_one(table[i - 1U].Z);
    }

    qsc_memutils_secure_erase(prefix, sizeof(prefix));
    qsc_memutils_secure_erase(inverse, sizeof(inverse));
    qsc_memutils_secure_erase(zinverse, sizeof(zinverse));
    qsc_memutils_secure_erase(zinverse2, sizeof(zinverse2));
    qsc_memutils_secure_erase(zinverse3, sizeof(zinverse3));
}

#endif

#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(QSC_ECDSA_DISABLE_PUBLIC_CARRY_INTRINSICS)
#include <immintrin.h>
#endif
typedef uint64_t p256_public_fe64[4U];

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(QSC_ECDSA_DISABLE_PUBLIC_CARRY_INTRINSICS)
static inline void p256_public_add64(p256_public_fe64 output, const p256_public_fe64 left, const p256_public_fe64 right)
{
    /* convert little-endian external field limbs once at the public point-engine boundary, not on every multiplication. */
    uint64_t temporary[4U];
    uint64_t reduced[4U];
    unsigned long long word;
    unsigned char carry;
    unsigned char borrow;
    uint64_t mask;
    size_t i;

    carry = 0U;
    for (i = 0U; i < 4U; ++i)
    {
        carry = _addcarry_u64(carry, left[i], right[i], &word);
        temporary[i] = (uint64_t)word;
    }

    borrow = 0U;
    for (i = 0U; i < 4U; ++i)
    {
        borrow = _subborrow_u64(borrow, temporary[i], P256_P64[i], &word);
        reduced[i] = (uint64_t)word;
    }

    mask = (uint64_t)0U - (uint64_t)(carry | (borrow ^ 1U));

    for (i = 0U; i < 4U; ++i)
    {
        output[i] = (reduced[i] & mask) | (temporary[i] & ~mask);
    }
}

static inline void p256_public_sub64(p256_public_fe64 output, const p256_public_fe64 left, const p256_public_fe64 right)
{
    /* constant-time canonical field subtraction in native-width limbs */
    uint64_t temporary[4U];
    unsigned long long word;
    unsigned char borrow;
    unsigned char carry;
    uint64_t mask;
    size_t i;

    borrow = 0U;
    for (i = 0U; i < 4U; ++i)
    {
        borrow = _subborrow_u64(borrow, left[i], right[i], &word);
        temporary[i] = (uint64_t)word;
    }

    mask = (uint64_t)0U - (uint64_t)borrow;
    carry = 0U;

    for (i = 0U; i < 4U; ++i)
    {
        carry = _addcarry_u64(carry, temporary[i], P256_P64[i] & mask, &word);
        output[i] = (uint64_t)word;
    }
}

#else
static inline void p256_public_add64(p256_public_fe64 output, const p256_public_fe64 left, const p256_public_fe64 right)
{
    uint64_t t[4U];
    uint64_t reduced[4U];
    __uint128_t value;
    uint64_t carry;
    uint64_t borrow;
    uint64_t mask;
    size_t i;

    carry = 0U;
    for (i = 0U; i < 4U; ++i)
    {
        value = (__uint128_t)left[i] + right[i] + carry;
        t[i] = (uint64_t)value;
        carry = (uint64_t)(value >> 64U);
    }

    borrow = 0U;
    for (i = 0U; i < 4U; ++i)
    {
        value = (__uint128_t)t[i] - P256_P64[i] - borrow;
        reduced[i] = (uint64_t)value;
        borrow = (uint64_t)(value >> 127U);
    }

    mask = (uint64_t)0U - (uint64_t)(carry | (borrow ^ 1U));
    for (i = 0U; i < 4U; ++i)
    {
        output[i] = (reduced[i] & mask) | (t[i] & ~mask);
    }
}

static inline void p256_public_sub64(p256_public_fe64 output, const p256_public_fe64 left, const p256_public_fe64 right)
{
    /* constant-time canonical field subtraction in native-width limbs */
    uint64_t t[4U];
    __uint128_t value;
    uint64_t borrow;
    uint64_t carry;
    uint64_t mask;
    size_t i;

    borrow = 0U;
    for (i = 0U; i < 4U; ++i)
    {
        value = (__uint128_t)left[i] - right[i] - borrow;
        t[i] = (uint64_t)value;
        borrow = (uint64_t)(value >> 127U);
    }

    mask = (uint64_t)0U - borrow;
    carry = 0U;
    for (i = 0U; i < 4U; ++i)
    {
        value = (__uint128_t)t[i] + (P256_P64[i] & mask) + carry;
        output[i] = (uint64_t)value;
        carry = (uint64_t)(value >> 64U);
    }
}

#endif /* x86-64 portable carry intrinsics */


static void p256_verify_comba_sqr4(uint64_t output[15U], const p256_public_fe64 input)
{
    /* uses the P-256 prime's sparse form, rather than generic modulus
     * multiplication. Multiplication is fixed-iteration and independent of
     * operand values. Public verification values are not key material.
     * \note Aliasing is permitted. Signing continues using QSC's original
     * constant-time arithmetic and secure-lifetime policy.
     */
    uint64_t acc[3U] = { 0U };
    __uint128_t product;
    product = (__uint128_t)input[0U] * input[0U];
    p256_native_comba_acc_product(acc, product);
    output[0U] = acc[0U];
    acc[0U] = acc[1U];
    acc[1U] = acc[2U];
    acc[2U] = 0U;
    product = (__uint128_t)input[0U] * input[1U];
    p256_native_comba_acc_product(acc, product);
    p256_native_comba_acc_product(acc, product);
    output[1U] = acc[0U];
    acc[0U] = acc[1U];
    acc[1U] = acc[2U];
    acc[2U] = 0U;
    product = (__uint128_t)input[0U] * input[2U];
    p256_native_comba_acc_product(acc, product);
    p256_native_comba_acc_product(acc, product);
    product = (__uint128_t)input[1U] * input[1U];
    p256_native_comba_acc_product(acc, product);
    output[2U] = acc[0U];
    acc[0U] = acc[1U];
    acc[1U] = acc[2U];
    acc[2U] = 0U;
    product = (__uint128_t)input[0U] * input[3U];
    p256_native_comba_acc_product(acc, product);
    p256_native_comba_acc_product(acc, product);
    product = (__uint128_t)input[1U] * input[2U];
    p256_native_comba_acc_product(acc, product);
    p256_native_comba_acc_product(acc, product);
    output[3U] = acc[0U];
    acc[0U] = acc[1U];
    acc[1U] = acc[2U];
    acc[2U] = 0U;
    product = (__uint128_t)input[1U] * input[3U];
    p256_native_comba_acc_product(acc, product);
    p256_native_comba_acc_product(acc, product);
    product = (__uint128_t)input[2U] * input[2U];
    p256_native_comba_acc_product(acc, product);
    output[4U] = acc[0U];
    acc[0U] = acc[1U];
    acc[1U] = acc[2U];
    acc[2U] = 0U;
    product = (__uint128_t)input[2U] * input[3U];
    p256_native_comba_acc_product(acc, product);
    p256_native_comba_acc_product(acc, product);
    output[5U] = acc[0U];
    acc[0U] = acc[1U];
    acc[1U] = acc[2U];
    acc[2U] = 0U;
    product = (__uint128_t)input[3U] * input[3U];
    p256_native_comba_acc_product(acc, product);
    output[6U] = acc[0U];
    acc[0U] = acc[1U];
    acc[1U] = acc[2U];
    acc[2U] = 0U;
    output[7U] = acc[0U];
    acc[0U] = acc[1U];
    acc[1U] = acc[2U];
    acc[2U] = 0U;
}

static inline void p256_public_mul64(p256_public_fe64 output, const p256_public_fe64 left, const p256_public_fe64 right)
{
    /* montgomery field multiply for public-key verification with Comba columns. */
    uint64_t product[8U] = { 0U };
    uint64_t reduced[4U];
    __uint128_t value;
    uint64_t carry;
    uint64_t borrow;
    uint64_t pending;
    uint64_t m;
    uint64_t q0;
    uint64_t q1;
    uint64_t q2;
    uint64_t q3;
    uint64_t mask;
    size_t i;
    size_t j;

    for (i = 0U; i < 4U; ++i)
    {
        carry = 0U;

        for (j = 0U; j < 4U; ++j)
        {
            value = (__uint128_t)left[i] * right[j] + product[i + j] + carry;
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

        value = (__uint128_t)product[i + 1U] + q0;
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
        value = (__uint128_t)product[i + 4U] - P256_P64[i] - borrow;
        reduced[i] = (uint64_t)value;
        borrow = (uint64_t)(value >> 127U);
    }

    mask = (uint64_t)0U - (uint64_t)(borrow & (pending ^ 1U));

    for (i = 0U; i < 4U; ++i)
    {
        output[i] = (product[i + 4U] & mask) | (reduced[i] & ~mask);
    }
}

static inline void p256_public_square64(p256_public_fe64 output, const p256_public_fe64 input)
{
    /* square a public field element using the dedicated ten-product Comba kernel*/
    uint64_t scratch[15U];

    p256_verify_comba_sqr4(scratch, input);
    p256_native_reduce(output, scratch);
}

static inline void p256_public_half64(p256_public_fe64 output, const p256_public_fe64 input)
{
    /* divide canonical public P-256 field residue by two modulo p */
    uint64_t t[4U];
    uint64_t mask;
    uint64_t carry;
    uint64_t top;
    __uint128_t value;
    size_t i;

    mask = (uint64_t)0U - (input[0U] & 1U);
    carry = 0U;

    for (i = 0U; i < 4U; ++i)
    {
        value = (__uint128_t)input[i] + (P256_P64[i] & mask) + carry;
        t[i] = (uint64_t)value;
        carry = (uint64_t)(value >> 64U);
    }

    top = carry;

    for (i = 4U; i > 0U; --i)
    {
        output[i - 1U] = (t[i - 1U] >> 1U) | (top << 63U);
        top = t[i - 1U] & 1U;
    }
}

#endif

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER)
static void p256_add_public_mixed(p256_jac_t* output, const p256_jac_t* first, const p256_jac_t* second)
{
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
    p256_add_public_mixed_native(output, first, second);
#else

    fe256 zz;
    fe256 u;
    fe256 v;
    fe256 h;
    fe256 r;
    fe256 i;
    fe256 j;
    fe256 x;
    fe256 scratch;
    p256_jac_t result;

    if (p256_is_infinity(first) != 0U)
    {
        *output = *second;
    }
    else if (p256_is_infinity(second) != 0U)
    {
        *output = *first;
    }
    else
    {
        fe_sqr(zz, first->Z);
        fe_mul(u, second->X, zz);
        fe_mul(v, second->Y, first->Z);
        fe_mul(v, v, zz);
        fe_sub(h, u, first->X);
        fe_sub(r, v, first->Y);

        if (fe256_is_zero(h) != 0U)
        {
            if (fe256_is_zero(r) != 0U)
            {
                p256_dbl(output, first);
            }
            else
            {
                p256_set_infinity(output);
            }
        }
        else
        {
            fe_mul_small(r, r, 2U);
            fe_mul_small(i, h, 2U);
            fe_sqr(i, i);
            fe_mul(j, h, i);
            fe_mul(u, first->X, i);
            fe_sqr(result.X, r);
            fe_sub(result.X, result.X, j);
            fe_sub(result.X, result.X, u);
            fe_sub(result.X, result.X, u);
            fe_sub(x, u, result.X);
            fe_mul(result.Y, r, x);
            fe_mul(scratch, first->Y, j);
            fe_mul_small(scratch, scratch, 2U);
            fe_sub(result.Y, result.Y, scratch);
            fe_mul(result.Z, first->Z, h);
            fe_mul_small(result.Z, result.Z, 2U);
            *output = result;
        }
    }
#endif
}
#endif

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER)
static void p256_half_public(fe256 output, const fe256 value)
{
    /* halve a Montgomery field residue modulo the public curve prime */
    uint32_t tmp[8U];
    uint64_t carry;
    uint64_t v;
    uint32_t high;
    uint32_t mask;
    size_t i;

    carry = 0U;
    mask = (uint32_t)(0U - (value[0U] & 1U));

    for (i = 0U; i < 8U; ++i)
    {
        v = (uint64_t)value[i] + (uint64_t)(P256_P[i] & mask) + carry;
        tmp[i] = (uint32_t)v;
        carry = v >> 32U;
    }

    high = (uint32_t)carry;

    for (i = 8U; i > 0U; --i)
    {
        output[i - 1U] = (tmp[i - 1U] >> 1U) | (high << 31U);
        high = tmp[i - 1U] & 1U;
    }

    qsc_memutils_secure_erase(tmp, sizeof(tmp));
}

#endif

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER)
static void p256_double_n_public(p256_jac_t* output, const p256_jac_t* point, size_t rounds)
{
    /* apply grouped point doubling for the a=-3 curve */
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
    p256_double_n_public_native(output, point, rounds);
#else

    p256_jac_t result;
    fe256 ny;
    fe256 w;
    fe256 ny2;
    fe256 ny4;
    fe256 t1;
    fe256 t2;
    fe256 tmp;

    result = *point;
    fe_add(ny, point->Y, point->Y);
    fe_sqr(w, point->Z);
    fe_sqr(w, w);

    while (rounds > 0U)
    {
        fe_sqr(ny2, ny);
        fe_sqr(ny4, ny2);
        fe_sqr(t1, result.X);
        fe_sub(t1, t1, w);
        fe_mul_small(t1, t1, 3U);
        fe_mul(t2, result.X, ny2);
        fe_sqr(result.X, t1);
        fe_add(tmp, t2, t2);
        fe_sub(result.X, result.X, tmp);
        fe_mul(result.Z, result.Z, ny);
        fe_sub(tmp, t2, result.X);
        fe_mul(tmp, t1, tmp);
        fe_add(tmp, tmp, tmp);
        fe_sub(ny, tmp, ny4);
        --rounds;

        if (rounds > 0U)
        {
            fe_mul(w, w, ny4);
        }
    }

    p256_half_public(result.Y, ny);
    *output = result;
    qsc_memutils_secure_erase(&result, sizeof(result));
    qsc_memutils_secure_erase(ny, sizeof(ny));
    qsc_memutils_secure_erase(w, sizeof(w));
    qsc_memutils_secure_erase(ny2, sizeof(ny2));
    qsc_memutils_secure_erase(ny4, sizeof(ny4));
    qsc_memutils_secure_erase(t1, sizeof(t1));
    qsc_memutils_secure_erase(t2, sizeof(t2));
    qsc_memutils_secure_erase(tmp, sizeof(tmp));
#endif
}

#endif /* portable verification grouped doubling */

#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
/*! brief Public verifier subgroup order in four little-endian 64-bit limbs. */
static const uint64_t P256_VERIFY_ORDER_N64[4U] = { UINT64_C(0xF3B9CAC2FC632551), UINT64_C(0xBCE6FAADA7179E84), UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFF00000000) };

static int32_t p256_verify_order_compare64(const uint64_t left[4U], const uint64_t right[4U])
{
    /* compare two public 256-bit order residues in four native limbs */
    int32_t result;
    size_t i;

    result = 0;

    for (i = 4U; i > 0U; --i)
    {
        if (left[i - 1U] != right[i - 1U])
        {
            result = (left[i - 1U] > right[i - 1U]) ? 1 : -1;
            break;
        }
    }

    return result;
}

static void p256_verify_order_sub64(uint64_t left[4U], const uint64_t right[4U])
{
    /* subtract a public 256-bit integer in place without modular reduction */
    __uint128_t value;
    uint64_t borrow;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 4U; ++i)
    {
        value = (__uint128_t)left[i] - right[i] - borrow;
        left[i] = (uint64_t)value;
        borrow = (uint64_t)(value >> 127U);
    }
}

static void p256_verify_order_modsub64(uint64_t left[4U], const uint64_t right[4U])
{
    /* subtract public canonical P-256 order residues modulo n */
    __uint128_t value;
    uint64_t borrow;
    uint64_t carry;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 4U; ++i)
    {
        value = (__uint128_t)left[i] - right[i] - borrow;
        left[i] = (uint64_t)value;
        borrow = (uint64_t)(value >> 127U);
    }

    if (borrow != 0U)
    {
        carry = 0U;

        for (i = 0U; i < 4U; ++i)
        {
            value = (__uint128_t)left[i] + P256_VERIFY_ORDER_N64[i] + carry;
            left[i] = (uint64_t)value;
            carry = (uint64_t)(value >> 64U);
        }
    }
}

static void p256_verify_order_half64(uint64_t value[4U])
{
    /* halve a public canonical order residue modulo n */
    __uint128_t sum;
    uint64_t carry;
    uint64_t high;
    uint64_t next;
    size_t i;

    carry = 0U;

    if ((value[0U] & 1U) != 0U)
    {
        for (i = 0U; i < 4U; ++i)
        {
            sum = (__uint128_t)value[i] + P256_VERIFY_ORDER_N64[i] + carry;
            value[i] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64U);
        }
    }

    high = carry;

    for (i = 4U; i > 0U; --i)
    {
        next = value[i - 1U] & 1U;
        value[i - 1U] = (value[i - 1U] >> 1U) | (high << 63U);
        high = next;
    }
}

static void sc_inv_public(uint32_t output[8U], const uint32_t input[8U])
{
    /* invert a nonzero public subgroup scalar using native-width binary GCD */
    uint64_t u[4U] = { 0U };
    uint64_t v[4U] = { 0U };
    uint64_t x1[4U] = { 0U };
    uint64_t x2[4U] = { 0U };
    uint64_t zero[4U] = { 0U };
    uint64_t one[4U] = { 1U, 0U, 0U, 0U };
    uint64_t* selected;
    size_t i;
    size_t count;
    bool valid;

    for (i = 0U; i < 4U; ++i)
    {
        u[i] = (uint64_t)input[2U * i] | ((uint64_t)input[2U * i + 1U] << 32U);
        v[i] = P256_VERIFY_ORDER_N64[i];
    }

    x1[0U] = 1U;
    valid = (p256_verify_order_compare64(u, zero) > 0) && (p256_verify_order_compare64(u, v) < 0);
    count = 0U;

    while (valid && (count < 1024U))
    {
        if ((p256_verify_order_compare64(u, one) == 0) || (p256_verify_order_compare64(v, one) == 0))
        {
            break;
        }
        else if ((u[0U] & 1U) == 0U)
        {
            p256_verify_order_half64(u);
            p256_verify_order_half64(x1);
        }
        else if ((v[0U] & 1U) == 0U)
        {
            p256_verify_order_half64(v);
            p256_verify_order_half64(x2);
        }
        else if (p256_verify_order_compare64(u, v) >= 0)
        {
            p256_verify_order_sub64(u, v);
            p256_verify_order_modsub64(x1, x2);
        }
        else
        {
            p256_verify_order_sub64(v, u);
            p256_verify_order_modsub64(x2, x1);
        }
        ++count;
    }

    selected = zero;

    if (valid && (p256_verify_order_compare64(u, one) == 0))
    {
        selected = x1;
    }
    else if (valid && (p256_verify_order_compare64(v, one) == 0))
    {
        selected = x2;
    }

    for (i = 0U; i < 4U; ++i)
    {
        output[2U * i] = (uint32_t)selected[i];
        output[2U * i + 1U] = (uint32_t)(selected[i] >> 32U);
    }

    qsc_memutils_secure_erase(u, sizeof(u));
    qsc_memutils_secure_erase(v, sizeof(v));
    qsc_memutils_secure_erase(x1, sizeof(x1));
    qsc_memutils_secure_erase(x2, sizeof(x2));
    qsc_memutils_secure_erase(zero, sizeof(zero));
    qsc_memutils_secure_erase(one, sizeof(one));
}
#else

static int32_t sc_public_256_cmp(const uint32_t a[8U], const uint32_t b[8U])
{
    /* compare two canonical subgroup residues from public verification data */
    int32_t relation;
    size_t i;

    relation = 0;

    for (i = 8U; i > 0U; --i)
    {
        if (a[i - 1U] > b[i - 1U])
        {
            relation = 1;
            break;
        }
        else if (a[i - 1U] < b[i - 1U])
        {
            relation = -1;
            break;
        }
    }

    return relation;
}

static void sc_public_256_sub(uint32_t a[8U], const uint32_t b[8U])
{
    /* subtract two public scalars in place modulo 2^256 */
    uint64_t tmp;
    uint64_t borrow;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 8U; ++i)
    {
        tmp = (uint64_t)a[i] - b[i] - borrow;
        a[i] = (uint32_t)tmp;
        borrow = tmp >> 63U;
    }
}

static void sc_public_256_mod_sub(uint32_t a[8U], const uint32_t b[8U])
{
    /* subtract two public residues modulo the subgroup order */
    uint64_t t;
    uint64_t borrow;
    uint64_t carry;
    size_t i;

    borrow = 0U;

    for (i = 0U; i < 8U; ++i)
    {
        t = (uint64_t)a[i] - b[i] - borrow;
        a[i] = (uint32_t)t;
        borrow = t >> 63U;
    }

    if (borrow != 0U)
    {
        carry = 0U;

        for (i = 0U; i < 8U; ++i)
        {
            t = (uint64_t)a[i] + P256_N[i] + carry;
            a[i] = (uint32_t)t;
            carry = t >> 32U;
        }
    }
}

static void sc_public_256_half(uint32_t a[8U])
{
    /* divide a public canonical residue by two modulo the order */
    uint64_t t;
    uint64_t carry;
    uint32_t high;
    size_t i;

    carry = 0U;

    if ((a[0U] & 1U) != 0U)
    {
        for (i = 0U; i < 8U; ++i)
        {
            t = (uint64_t)a[i] + P256_N[i] + carry;
            a[i] = (uint32_t)t;
            carry = t >> 32U;
        }
    }

    high = (uint32_t)carry;

    for (i = 8U; i > 0U; --i)
    {
        t = a[i - 1U];
        a[i - 1U] = (uint32_t)(t >> 1U) | (high << 31U);
        high = (uint32_t)t & 1U;
    }
}

static void sc_inv_public(uint32_t r[8U], const uint32_t a[8U])
{
    /* binary extended Euclidean inversion for public ECDSA verification scalars only */
    uint32_t u[8U] = { 0U };
    uint32_t v[8U] = { 0U };
    uint32_t x1[8U] = { 0U };
    uint32_t x2[8U] = { 0U };
    uint32_t zero[8U] = { 0U };
    size_t i;
    size_t steps;
    bool valid;

    sc_copy(u, a);
    sc_copy(v, P256_N);
    x1[0U] = 1U;
    valid = (sc_public_256_cmp(a, zero) > 0) && (sc_public_256_cmp(a, P256_N) < 0);
    steps = 0U;

    while (valid && steps < 1024U)
    {
        if (u[0U] == 1U)
        {
            valid = true;

            for (i = 1U; i < 8U; ++i)
            {
                if (u[i] != 0U) { valid = false; }
            }

            if (valid) 
            {
                break;
            }
        }
        if (v[0U] == 1U)
        {
            valid = true;

            for (i = 1U; i < 8U; ++i)
            {
                if (v[i] != 0U) { valid = false; }
            }

            if (valid) 
            { 
                break;
            }
        }
        valid = true;

        if ((u[0U] & 1U) == 0U)
        {
            sc_public_256_half(u); /* u even: ordinary shift, no modulus carry */
            sc_public_256_half(x1);
        }
        else if ((v[0U] & 1U) == 0U)
        {
            sc_public_256_half(v);
            sc_public_256_half(x2);
        }
        else if (sc_public_256_cmp(u, v) >= 0)
        {
            sc_public_256_sub(u, v);
            sc_public_256_mod_sub(x1, x2);
        }
        else
        {
            sc_public_256_sub(v, u);
            sc_public_256_mod_sub(x2, x1);
        }

        ++steps;
    }

    /* input validation normally guarantees gcd(a,n)=1. */
    if (valid && u[0U] == 1U)
    {
        valid = true;

        for (i = 1U; i < 8U; ++i)
        {
            if (u[i] != 0U) { valid = false; }
        }

        if (valid) 
        {
            sc_copy(r, x1); 
        }
    }
    else if (valid && v[0U] == 1U)
    {
        valid = true;

        for (i = 1U; i < 8U; ++i)
        {
            if (v[i] != 0U) { valid = false; }
        }

        if (valid) 
        {
            sc_copy(r, x2); 
        }
    }
    else
    {
        valid = false;
    }

    if (!valid) { sc_copy(r, zero); }

    qsc_memutils_secure_erase(u, sizeof(u));
    qsc_memutils_secure_erase(v, sizeof(v));
    qsc_memutils_secure_erase(x1, sizeof(x1));
    qsc_memutils_secure_erase(x2, sizeof(x2));
    qsc_memutils_secure_erase(zero, sizeof(zero));
}

#endif

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER)
static void p256_joint_public_wnaf(p256_jac_t* output, const p256_aff_t* Q, const uint32_t first[8U], const uint32_t second[8U])
{
    p256_aff_t encoded;
    p256_jac_t table_g[8U];
    p256_jac_t table_q[8U];
    p256_jac_t twice_q;
    p256_jac_t accumulator;
    p256_jac_t doubled;
    p256_jac_t added;
    p256_jac_t negative;
    int8_t dg[257U];
    int8_t dq[257U];
    int32_t g;
    int32_t q;
    size_t i;
    size_t pending;

    fe256_mont_encode(encoded.X, Q->X);
    fe256_mont_encode(encoded.Y, Q->Y);
    p256_aff_to_jac(&table_q[0U], &encoded);
    p256_dbl(&twice_q, &table_q[0U]);

    for (i = 0U; i < 8U; ++i)
    {
        fe256_copy(table_g[i].X, P256_GENERATOR_MONT[2U * i + 1U][0U]);
        fe256_copy(table_g[i].Y, P256_GENERATOR_MONT[2U * i + 1U][1U]);
        fe256_one(table_g[i].Z);
    }

    for (i = 1U; i < 8U; ++i)
    {
        p256_add_public(&table_q[i], &table_q[i - 1U], &twice_q);
    }

    p256_batch_affine_public(table_q);

    p256_recode_public(dg, first);
    p256_recode_public(dq, second);
    p256_set_infinity(&accumulator);

    pending = 0U;

    for (i = 257U; i > 0U; --i)
    {
        ++pending;
        g = (int32_t)dg[i - 1U];
        q = (int32_t)dq[i - 1U];

        if ((g != 0) || (q != 0))
        {
            if (p256_is_infinity(&accumulator) == 0U)
            {
                p256_double_n_public(&doubled, &accumulator, pending);
                accumulator = doubled;
            }
            pending = 0U;
        }

        if (g > 0)
        {
            p256_add_public_mixed(&added, &accumulator, &table_g[((uint32_t)g - 1U) / 2U]);
            accumulator = added;
        }
        else if (g < 0)
        {
            p256_negate_public(&negative, &table_g[((uint32_t)(-g) - 1U) / 2U]);
            p256_add_public_mixed(&added, &accumulator, &negative);
            accumulator = added;
        }

        if (q > 0)
        {
            p256_add_public_mixed(&added, &accumulator, &table_q[((uint32_t)q - 1U) / 2U]);
            accumulator = added;
        }
        else if (q < 0)
        {
            p256_negate_public(&negative, &table_q[((uint32_t)(-q) - 1U) / 2U]);
            p256_add_public_mixed(&added, &accumulator, &negative);
            accumulator = added;
        }
    }

    if ((pending > 0U) && (p256_is_infinity(&accumulator) == 0U))
    {
        p256_double_n_public(&doubled, &accumulator, pending);
        accumulator = doubled;
    }

    *output = accumulator;
    qsc_memutils_secure_erase(&encoded, sizeof(encoded));
    qsc_memutils_secure_erase(table_g, sizeof(table_g));
    qsc_memutils_secure_erase(table_q, sizeof(table_q));
    qsc_memutils_secure_erase(&twice_q, sizeof(twice_q));
    qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
    qsc_memutils_secure_erase(&doubled, sizeof(doubled));
    qsc_memutils_secure_erase(&added, sizeof(added));
    qsc_memutils_secure_erase(dg, sizeof(dg));
    qsc_memutils_secure_erase(dq, sizeof(dq));
}

#endif

#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)

static void p256_verify_public_add_generator(p256_native_point* output, const p256_native_point* first, const p256_native_point* second, p256_native_window_workspace* work)
{
    /* add one public affine point using the native mixed-Jacobian formula */
	uint64_t first_inf;
	uint64_t second_inf;

	p256_public_square64(work->zz, first->z);
	p256_public_mul64(work->u, second->x, work->zz);
	p256_public_mul64(work->s, second->y, first->z);
	p256_public_mul64(work->s, work->s, work->zz);
	p256_public_sub64(work->h, work->u, first->x);
	p256_public_sub64(work->delta, work->s, first->y);
	p256_public_square64(work->hh, work->h);
	p256_public_mul64(work->hhh, work->h, work->hh);
	p256_public_mul64(work->v, first->x, work->hh);
	p256_public_square64(work->added.x, work->delta);
	p256_public_sub64(work->added.x, work->added.x, work->hhh);
	p256_public_add64(work->tmp, work->v, work->v);
	p256_public_sub64(work->added.x, work->added.x, work->tmp);
	p256_public_sub64(work->tmp, work->v, work->added.x);
	p256_public_mul64(work->added.y, work->delta, work->tmp);
	p256_public_mul64(work->tmp, first->y, work->hhh);
	p256_public_sub64(work->added.y, work->added.y, work->tmp);
	p256_public_mul64(work->added.z, first->z, work->h);

	first_inf = p256_native_is_zero(first->z);
	second_inf = p256_native_is_zero(second->z);
	p256_native_point_choose(&work->added, first, &work->added, second_inf);
	p256_native_point_choose(&work->added, second, &work->added, first_inf);
	*output = work->added;
}

static void p256_verify_public_square_n(p256_native_fe value, size_t count)
{
    /* square a native public field element the specified number of times */
	size_t i;

	for (i = 0U; i < count; ++i)
	{
		p256_public_square64(value, value);
	}
}

static void p256_verify_inverse_square(p256_native_fe output, const p256_native_fe z)
{
    /* compute inverse-square of a nonzero public field element */
	p256_native_fe t[2U] = { { 0U } };
	p256_native_fe r = { 0U };

	p256_public_square64(r, z);
	p256_public_mul64(r, r, z);
	p256_public_square64(r, r);
	p256_public_mul64(r, r, z);
	p256_native_copy(t[0U], r);
	p256_verify_public_square_n(t[0U], 3U);
	p256_public_mul64(t[0U], t[0U], r);
	p256_native_copy(t[1U], t[0U]);
	p256_verify_public_square_n(t[1U], 6U);
	p256_public_mul64(t[0U], t[0U], t[1U]);
	p256_verify_public_square_n(t[0U], 3U);
	p256_public_mul64(r, r, t[0U]);
	p256_public_square64(t[0U], r);
	p256_public_mul64(t[0U], t[0U], z);
	p256_native_copy(t[1U], t[0U]);
	p256_verify_public_square_n(t[1U], 16U);
	p256_public_mul64(t[0U], t[0U], t[1U]);
	p256_verify_public_square_n(t[0U], 15U);
	p256_public_mul64(r, r, t[0U]);
	p256_verify_public_square_n(t[0U], 17U);
	p256_public_mul64(t[0U], t[0U], z);
	p256_verify_public_square_n(t[0U], 143U);
	p256_public_mul64(t[0U], t[0U], r);
	p256_verify_public_square_n(t[0U], 47U);
	p256_public_mul64(r, r, t[0U]);
	p256_verify_public_square_n(r, 2U);
	p256_native_copy(output, r);

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(r, sizeof(r));
}

static void p256_verify_native_batch(p256_native_point table[8U])
{
    /* normalize eight projective public odd multiples with one inversion */
	p256_native_fe prefix[8U] = { { 0U } };
	p256_native_fe inverse = { 0U };
	p256_native_fe invsquared = { 0U };
	p256_native_fe zinv = { 0U };
	p256_native_fe z2 = { 0U };
	p256_native_fe z3 = { 0U };
	size_t i;

	p256_native_copy(prefix[0U], table[0U].z);

	for (i = 1U; i < 8U; ++i)
	{
		p256_public_mul64(prefix[i], prefix[i - 1U], table[i].z);
	}

	p256_verify_inverse_square(invsquared, prefix[7U]);
	p256_public_mul64(inverse, invsquared, prefix[7U]);

	for (i = 8U; i > 0U; --i)
	{
		if (i == 1U)
		{
			p256_native_copy(zinv, inverse);
		}
		else
		{
			p256_public_mul64(zinv, inverse, prefix[i - 2U]);
			p256_public_mul64(inverse, inverse, table[i - 1U].z);
		}

		p256_public_square64(z2, zinv);
		p256_public_mul64(z3, z2, zinv);
		p256_public_mul64(table[i - 1U].x, table[i - 1U].x, z2);
		p256_public_mul64(table[i - 1U].y, table[i - 1U].y, z3);
		p256_native_copy(table[i - 1U].z, P256_NATIVE_ONE);
	}

	qsc_memutils_secure_erase(prefix, sizeof(prefix));
	qsc_memutils_secure_erase(inverse, sizeof(inverse));
	qsc_memutils_secure_erase(invsquared, sizeof(invsquared));
	qsc_memutils_secure_erase(zinv, sizeof(zinv));
	qsc_memutils_secure_erase(z2, sizeof(z2));
	qsc_memutils_secure_erase(z3, sizeof(z3));
}

static void p256_verify_native_double_n(p256_native_point* output, const p256_native_point* input, size_t rounds)
{
    /* apply grouped a=-3 doubling to a public native Jacobian point */
	p256_native_fe x = { 0U };
	p256_native_fe z = { 0U };
	p256_native_fe ny = { 0U };
	p256_native_fe w = { 0U };
	p256_native_fe ny2 = { 0U };
	p256_native_fe ny4 = { 0U };
	p256_native_fe t1 = { 0U };
	p256_native_fe t2 = { 0U };
	p256_native_fe tmp = { 0U };
	size_t remaining;

	*output = *input;

	if ((rounds != 0U) && (p256_native_is_zero(input->z) == 0U))
	{
		p256_native_copy(x, input->x);
		p256_native_copy(z, input->z);
		p256_public_add64(ny, input->y, input->y);
		p256_public_square64(w, z);
		p256_public_square64(w, w);
		remaining = rounds;

		while (remaining != 0U)
		{
			p256_public_square64(ny2, ny);
			p256_public_square64(ny4, ny2);
			p256_public_square64(t1, x);
			p256_public_sub64(t1, t1, w);
			p256_public_add64(tmp, t1, t1);
			p256_public_add64(t1, tmp, t1);
			p256_public_mul64(t2, x, ny2);
			p256_public_square64(x, t1);
			p256_public_add64(tmp, t2, t2);
			p256_public_sub64(x, x, tmp);
			p256_public_mul64(z, z, ny);
			p256_public_sub64(tmp, t2, x);
			p256_public_mul64(tmp, t1, tmp);
			p256_public_add64(tmp, tmp, tmp);
			p256_public_sub64(ny, tmp, ny4);
			--remaining;

			if (remaining != 0U)
			{
				p256_public_mul64(w, w, ny4);
			}
		}

		/* The grouped formula maintains ny=2Y; halve modulo p. */
		p256_public_half64(output->y, ny);
		p256_native_copy(output->x, x);
		p256_native_copy(output->z, z);
	}
}

static void p256_verify_native_add_mixed(p256_native_point* output, const p256_native_point* first, const p256_native_point* second, p256_native_window_workspace* work)
{
    /* add a public affine point using native mixed addition with exceptional cases */
	uint64_t same;
	uint64_t inverse;
	uint64_t first_inf;
	uint64_t second_inf;
	p256_native_point original;

	original = *first;
	first_inf = p256_native_is_zero(original.z);
	second_inf = p256_native_is_zero(second->z);
	p256_verify_public_add_generator(output, first, second, work);
	same = p256_native_is_zero(work->h) & p256_native_is_zero(work->delta);
	inverse = p256_native_is_zero(work->h) & (same ^ 1U);

	if ((first_inf == 0U) && (second_inf == 0U))
	{
		if (same != 0U)
		{
			p256_verify_native_double_n(output, &original, 1U);
		}
		else if (inverse != 0U)
		{
			qsc_memutils_clear(output, sizeof(*output));
			p256_native_copy(output->y, P256_NATIVE_ONE);
		}
	}
}

static void p256_verify_native_add_projective(p256_native_point* output, const p256_native_point* first, const p256_native_point* second)
{
    /* compute u1*G+u2*Q with persistent 4x64 native Montgomery points */
	p256_native_fe z1z1 = { 0U };
	p256_native_fe z2z2 = { 0U };
	p256_native_fe u1 = { 0U };
	p256_native_fe u2 = { 0U };
	p256_native_fe s1 = { 0U };
	p256_native_fe s2 = { 0U };
	p256_native_fe h = { 0U };
	p256_native_fe r = { 0U };
	p256_native_fe t = { 0U };
	p256_native_fe i = { 0U };
	p256_native_fe j = { 0U };
	p256_native_fe v = { 0U };
	p256_native_point result;

	p256_public_square64(z1z1, first->z);
	p256_public_square64(z2z2, second->z);
	p256_public_mul64(u1, first->x, z2z2);
	p256_public_mul64(u2, second->x, z1z1);
	p256_public_mul64(s1, first->y, second->z);
	p256_public_mul64(s1, s1, z2z2);
	p256_public_mul64(s2, second->y, first->z);
	p256_public_mul64(s2, s2, z1z1);
	p256_public_sub64(h, u2, u1);
	p256_public_sub64(r, s2, s1);
	p256_public_add64(r, r, r);
	p256_public_add64(t, h, h);
	p256_public_square64(i, t);
	p256_public_mul64(j, h, i);
	p256_public_mul64(v, u1, i);
	p256_public_mul64(result.x, r, r);
	p256_public_sub64(result.x, result.x, j);
	p256_public_add64(t, v, v);
	p256_public_sub64(result.x, result.x, t);
	p256_public_sub64(t, v, result.x);
	p256_public_mul64(result.y, r, t);
	p256_public_mul64(t, s1, j);
	p256_public_add64(t, t, t);
	p256_public_sub64(result.y, result.y, t);
	p256_public_add64(t, first->z, second->z);
	p256_public_square64(t, t);
	p256_public_sub64(t, t, z1z1);
	p256_public_sub64(t, t, z2z2);
	p256_public_mul64(result.z, t, h);
	*output = result;
}

static void p256_verify_native_joint(p256_jac_t* output, const p256_aff_t* public_point, const uint32_t first[8U], const uint32_t second[8U], const qsc_p256_verify_context* context)
{
	p256_aff_t encoded = { { 0U }, { 0U } };
	p256_native_point twice_q;
	p256_native_point qpoint;
	p256_native_fe zero = { 0U };
	p256_native_point gtable[8U];
	p256_native_point qnative[8U];
	p256_native_point accumulator;
	p256_native_point selected;
	p256_native_window_workspace work;
	int8_t gd[257U];
	int8_t qd[257U];
	int32_t g;
	int32_t q;
	size_t i;
	size_t j;
	size_t pending;

	qsc_memutils_clear(&accumulator, sizeof(accumulator));
	qsc_memutils_clear(&work, sizeof(work));
	p256_native_copy(accumulator.y, P256_NATIVE_ONE);

	if (context == NULL)
	{
		fe256_mont_encode(encoded.X, public_point->X);
		fe256_mont_encode(encoded.Y, public_point->Y);
		p256_native_load(qpoint.x, encoded.X);
		p256_native_load(qpoint.y, encoded.Y);
		p256_native_copy(qpoint.z, P256_NATIVE_ONE);
		qnative[0U] = qpoint;
		p256_verify_native_double_n(&twice_q, &qpoint, 1U);

		for (i = 1U; i < 8U; ++i)
		{
			p256_verify_native_add_projective(&qnative[i], &qnative[i - 1U], &twice_q);
		}
	}
	else
	{
		for (i = 0U; i < 8U; ++i)
		{
			p256_native_load(qnative[i].x, context->odd_montgomery[i][0U]);
			p256_native_load(qnative[i].y, context->odd_montgomery[i][1U]);
			p256_native_copy(qnative[i].z, P256_NATIVE_ONE);
		}
	}


	for (i = 0U; i < 8U; ++i)
	{
		for (j = 0U; j < 2U; ++j)
		{
			p256_native_load(j == 0U ? gtable[i].x : gtable[i].y,
				P256_GENERATOR_MONT[2U * i + 1U][j]);
		}

		p256_native_copy(gtable[i].z, P256_NATIVE_ONE);
	}

	if (context == NULL)
	{
		p256_verify_native_batch(qnative);
	}

	p256_recode_public(gd, first);
	p256_recode_public(qd, second);
	pending = 0U;

	for (i = 257U; i > 0U; --i)
	{
		++pending;
		g = (int32_t)gd[i - 1U];
		q = (int32_t)qd[i - 1U];

		if ((g != 0) || (q != 0))
		{
			if (p256_native_is_zero(accumulator.z) == 0U)
			{
				p256_verify_native_double_n(&accumulator, &accumulator, pending);
			}

			pending = 0U;
		}

		if (g != 0)
		{
			selected = gtable[((uint32_t)((g < 0) ? -g : g) - 1U) / 2U];

			if (g < 0)
			{
				p256_public_sub64(selected.y, zero, selected.y);
			}

			p256_verify_native_add_mixed(&accumulator, &accumulator, &selected, &work);
		}

		if (q != 0)
		{
			selected = qnative[((uint32_t)((q < 0) ? -q : q) - 1U) / 2U];

			if (q < 0)
			{
				p256_public_sub64(selected.y, zero, selected.y);
			}

			p256_verify_native_add_mixed(&accumulator, &accumulator, &selected, &work);
		}
	}

	if ((pending > 0U) && (p256_native_is_zero(accumulator.z) == 0U))
	{
		p256_verify_native_double_n(&accumulator, &accumulator, pending);
	}

	p256_native_store(output->X, accumulator.x);
	p256_native_store(output->Y, accumulator.y);
	p256_native_store(output->Z, accumulator.z);
	qsc_memutils_secure_erase(&encoded, sizeof(encoded));
	qsc_memutils_secure_erase(&twice_q, sizeof(twice_q));
	qsc_memutils_secure_erase(&qpoint, sizeof(qpoint));
	qsc_memutils_secure_erase(zero, sizeof(zero));
	qsc_memutils_secure_erase(gtable, sizeof(gtable));
	qsc_memutils_secure_erase(qnative, sizeof(qnative));
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&work, sizeof(work));
	qsc_memutils_secure_erase(gd, sizeof(gd));
	qsc_memutils_secure_erase(qd, sizeof(qd));
}
#endif

#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void p256_verify_native_batch_variable(p256_native_point* points, size_t count)
{
    /* batch-convert public Jacobian points to Montgomery affine form */
    p256_native_fe prefix[256U];
    p256_native_fe inverse = { 0U };
    p256_native_fe inverse_squared = { 0U };
    p256_native_fe zinv = { 0U };
    p256_native_fe z2 = { 0U };
    p256_native_fe z3 = { 0U };
    size_t i;

    p256_native_copy(prefix[0U], P256_NATIVE_ONE);

    for (i = 0U; i < count; ++i)
    {
        if (i != 0U)
        {
            p256_native_copy(prefix[i], prefix[i - 1U]);
        }

        if (p256_native_is_zero(points[i].z) == 0U)
        {
            p256_public_mul64(prefix[i], prefix[i], points[i].z);
        }
    }

    if (count != 0U)
    {
        p256_verify_inverse_square(inverse_squared, prefix[count - 1U]);
        p256_public_mul64(inverse, inverse_squared, prefix[count - 1U]);

        for (i = count; i > 0U; --i)
        {
            if (p256_native_is_zero(points[i - 1U].z) == 0U)
            {
                if (i == 1U)
                {
                    p256_native_copy(zinv, inverse);
                }
                else
                {
                    p256_public_mul64(zinv, inverse, prefix[i - 2U]);
                }

                p256_public_mul64(inverse, inverse, points[i - 1U].z);
                p256_public_square64(z2, zinv);
                p256_public_mul64(z3, z2, zinv);
                p256_public_mul64(points[i - 1U].x, points[i - 1U].x, z2);
                p256_public_mul64(points[i - 1U].y, points[i - 1U].y, z3);
                p256_native_copy(points[i - 1U].z, P256_NATIVE_ONE);
            }
        }
    }

    qsc_memutils_secure_erase(prefix, sizeof(prefix));
    qsc_memutils_secure_erase(inverse, sizeof(inverse));
    qsc_memutils_secure_erase(inverse_squared, sizeof(inverse_squared));
    qsc_memutils_secure_erase(zinv, sizeof(zinv));
    qsc_memutils_secure_erase(z2, sizeof(z2));
    qsc_memutils_secure_erase(z3, sizeof(z3));
}

static void p256_verify_native_joint_prepare(qsc_p256_joint_verify_context* context)
{
    /* compute a validated-key joint affine table once per context */
    p256_native_point multiples_g[16U];
    p256_native_point multiples_q[16U];
    p256_native_point combined[256U];
    p256_native_window_workspace work;
    size_t i;
    size_t j;
    size_t k;

    qsc_memutils_clear(multiples_g, sizeof(multiples_g));
    qsc_memutils_clear(multiples_q, sizeof(multiples_q));
    qsc_memutils_clear(combined, sizeof(combined));
    qsc_memutils_clear(&work, sizeof(work));
    p256_native_copy(multiples_g[0U].y, P256_NATIVE_ONE);
    p256_native_copy(multiples_q[0U].y, P256_NATIVE_ONE);

    for (i = 1U; i < 16U; ++i)
    {
        p256_native_load(multiples_g[i].x, P256_GENERATOR_MONT[i][0U]);
        p256_native_load(multiples_g[i].y, P256_GENERATOR_MONT[i][1U]);
        p256_native_copy(multiples_g[i].z, P256_NATIVE_ONE);
    }

    p256_native_load(multiples_q[1U].x, context->base.odd_montgomery[0U][0U]);
    p256_native_load(multiples_q[1U].y, context->base.odd_montgomery[0U][1U]);
    p256_native_copy(multiples_q[1U].z, P256_NATIVE_ONE);

    for (i = 2U; i < 16U; ++i)
    {
        p256_verify_native_add_mixed(&multiples_q[i], &multiples_q[i - 1U],
            &multiples_q[1U], &work);
    }

    p256_verify_native_batch_variable(multiples_q, 16U);

    for (i = 0U; i < 16U; ++i)
    {
        for (j = 0U; j < 16U; ++j)
        {
            k = (i << 4U) | j;

            if (i == 0U)
            {
                combined[k] = multiples_q[j];
            }
            else if (j == 0U)
            {
                combined[k] = multiples_g[i];
            }
            else
            {
                p256_verify_native_add_mixed(&combined[k], &multiples_g[i],
                    &multiples_q[j], &work);
            }
        }
    }

    p256_verify_native_batch_variable(combined, 256U);

    for (k = 0U; k < 256U; ++k)
    {
        context->joint_infinity[k] = (uint8_t)p256_native_is_zero(combined[k].z);
        p256_native_copy(context->joint_montgomery[k][0U], combined[k].x);
        p256_native_copy(context->joint_montgomery[k][1U], combined[k].y);
    }

    qsc_memutils_secure_erase(multiples_g, sizeof(multiples_g));
    qsc_memutils_secure_erase(multiples_q, sizeof(multiples_q));
    qsc_memutils_secure_erase(combined, sizeof(combined));
    qsc_memutils_secure_erase(&work, sizeof(work));
}

static void p256_verify_native_joint_window(p256_jac_t* output, const uint32_t first[8U], const uint32_t second[8U], const qsc_p256_joint_verify_context* context)
{
    /* verify a public double scalar using a cached radix-16 joint table */
    p256_native_point accumulator;
    p256_native_point selected;
    p256_native_window_workspace work;
    size_t i;
    size_t word;
    uint32_t shift;
    uint32_t digit_g;
    uint32_t digit_q;
    size_t index;

    qsc_memutils_clear(&accumulator, sizeof(accumulator));
    qsc_memutils_clear(&work, sizeof(work));
    p256_native_copy(accumulator.y, P256_NATIVE_ONE);

    for (i = 64U; i > 0U; --i)
    {
        word = (i - 1U) / 8U;
        shift = (uint32_t)(((i - 1U) % 8U) * 4U);
        digit_g = (first[word] >> shift) & 15U;
        digit_q = (second[word] >> shift) & 15U;
        index = (size_t)((digit_g << 4U) | digit_q);

        if (p256_native_is_zero(accumulator.z) == 0U)
        {
            p256_verify_native_double_n(&accumulator, &accumulator, 4U);
        }

        if ((index != 0U) && (context->joint_infinity[index] == 0U))
        {
            p256_native_copy(selected.x, context->joint_montgomery[index][0U]);
            p256_native_copy(selected.y, context->joint_montgomery[index][1U]);
            p256_native_copy(selected.z, P256_NATIVE_ONE);

            if (p256_native_is_zero(accumulator.z) != 0U)
            {
                accumulator = selected;
            }
            else
            {
                p256_verify_native_add_mixed(&accumulator, &accumulator, &selected, &work);
            }
        }
    }

    p256_native_store(output->X, accumulator.x);
    p256_native_store(output->Y, accumulator.y);
    p256_native_store(output->Z, accumulator.z);
    qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
    qsc_memutils_secure_erase(&selected, sizeof(selected));
    qsc_memutils_secure_erase(&work, sizeof(work));
}
#endif /* native public joint-window engine */

static void p256_double_scalar_mult(p256_jac_t* output, const p256_aff_t* public_point, const uint32_t first[8U], const uint32_t second[8U], const qsc_p256_verify_context* context)
{
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
    p256_verify_native_joint(output, public_point, first, second, context);
#else
    (void)context;
    p256_joint_public_wnaf(output, public_point, first, second);
#endif
}
#endif

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER)
static void fe_square_n(fe256 value, size_t count)
{
    /* apply a public, fixed number of P-256 field squarings */
	size_t i;

	for (i = 0U; i < count; ++i)
	{
		fe_sqr(value, value);
	}
}
#endif

#if !defined(__SIZEOF_INT128__) || defined(_MSC_VER)
static void fe_inv_squared(fe256 r, const fe256 a)
{
    /* compute Z^-2 over the P-256 field using addition chain */
	fe256 t[2U] = { { 0U } };
	fe256 z = { 0U };

	fe_mul(z, a, a);
	fe_mul(z, z, a);
	fe_mul(z, z, z);
	fe_mul(z, z, a);
	fe256_copy(t[0U], z);
	fe_square_n(t[0U], 3U);
	fe_mul(t[0U], t[0U], z);
	fe256_copy(t[1U], t[0U]);
	fe_square_n(t[1U], 6U);
	fe_mul(t[0U], t[0U], t[1U]);
	fe_square_n(t[0U], 3U);
	fe_mul(z, z, t[0U]);
	fe_mul(t[0U], z, z);
	fe_mul(t[0U], t[0U], a);
	fe256_copy(t[1U], t[0U]);
	fe_square_n(t[1U], 16U);
	fe_mul(t[0U], t[0U], t[1U]);
	fe_square_n(t[0U], 15U);
	fe_mul(z, z, t[0U]);
	fe_square_n(t[0U], 17U);
	fe_mul(t[0U], t[0U], a);
	fe_square_n(t[0U], 143U);
	fe_mul(t[0U], t[0U], z);
	fe_square_n(t[0U], 47U);
	fe_mul(z, z, t[0U]);
	fe_square_n(z, 2U);

	fe256_copy(r, z);
	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(z, sizeof(z));
}
#endif

static void p256_jac_x_to_aff(fe256 output, const p256_jac_t* point)
{
    /* recover only the affine X coordinate for an ECDSA generator multiple */
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
	p256_native_affine_x(output, point);
#else
	fe256 zinvsquared = { 0U };
	fe_inv_squared(zinvsquared, point->Z);
	fe_mul(output, point->X, zinvsquared);
	fe256_mont_decode(output, output);
	qsc_memutils_secure_erase(zinvsquared, sizeof(zinvsquared));
#endif
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

	fe256_mont_decode(R->X, R->X);
	fe256_mont_decode(R->Y, R->Y);

    return true;
}

static bool p256_point_is_on_curve(const p256_aff_t* Q)
{
    /* verify that a public key point lies on the curve.
     * checks the Weierstrass equation:  Y^2 = X^3 - 3X + b  (mod p)
     * and that the point is not the identity. */
    fe256 y2, x3, ax, rhs;
    fe256 xmont;
    fe256 ymont;
    fe256 bmont;

    fe256_mont_encode(xmont, Q->X);
    fe256_mont_encode(ymont, Q->Y);
    fe256_mont_encode(bmont, P256_B);

    /* y^2 mod p */
    fe_sqr(y2, ymont);

    /* x^3 mod p */
    fe_sqr(x3, xmont);
    fe_mul(x3, x3, xmont);

    /* -3*x mod p (a = -3) */
    fe_mul_small(ax, xmont, 3U);
    fe_sub(rhs, x3, ax);

    /* rhs = x^3 - 3x + b */
    fe_add(rhs, rhs, bmont);

    return (fe256_cmp(y2, rhs) == 0);
}

/* RFC 6979 deterministic k generation */

static void rfc6979_bits2octets_p256(uint8_t out[32U], const uint8_t hash_be[32U])
{
    uint32_t z[8U] = { 0U };

    QSC_ASSERT(out != NULL);
    QSC_ASSERT(hash_be != NULL);

    /*
     * RFC 6979 bits2octets(h1):
     *   z1 = bits2int(h1)
     *   z2 = z1 mod q
     *   return int2octets(z2)
     *
     * for P-256 with SHA-256, h1 is already 256 bits, so bits2int()
     * is simply the 32-byte big-endian integer represented by hash_be.
     */
    sc_from_bytes_reduce(z, hash_be);
    fe256_to_bytes(out, z);

    qsc_memutils_secure_erase(z, sizeof(z));
}

static void rfc6979_generate_k(uint32_t k_out[8U], const uint8_t priv_be[32U], const uint8_t h1_be[32U])
{
    /* Generate a deterministic nonce k in [1, n-1] from privkey and message hash,
     * per RFC 6979 Section 3.2 using HMAC-SHA256.
     *
     * RFC 6979 requires bits2octets(h1), not raw h1, in the HMAC input. */

    QSC_ASSERT(k_out != NULL);
    QSC_ASSERT(priv_be != NULL);
    QSC_ASSERT(h1_be != NULL);

    uint8_t V[32U] = { 0U };
    uint8_t K[32U] = { 0U };
    uint8_t bh[32U] = { 0U };
    uint8_t blob[65U] = { 0U };
    uint8_t T[32U] = { 0U };
    uint8_t msg[97U] = { 0U };
    uint8_t mac[32U] = { 0U };

    rfc6979_bits2octets_p256(bh, h1_be);

    /* V = 0x01 repeated 32 times */
    for (size_t i = 0U; i < 32U; ++i)
    {
        V[i] = 0x01U;
    }

    /* K = 0x00 repeated 32 times */
    for (size_t i = 0U; i < 32U; ++i)
    {
        K[i] = 0x00U;
    }

    /* K = HMAC(K, V || 0x00 || int2octets(x) || bits2octets(h1)) */
    blob[0U] = 0x00U;
    qsc_memutils_copy((blob + 1U), priv_be, 32U);
    qsc_memutils_copy((blob + 33U), bh, 32U);

    qsc_memutils_copy(msg, V, 32U);
    qsc_memutils_copy((msg + 32U), blob, 65U);
    qsc_hmac256_compute(mac, msg, sizeof(msg), K, sizeof(K));
    qsc_memutils_copy(K, mac, 32U);

    /* V = HMAC(K, V) */
    qsc_hmac256_compute(mac, V, sizeof(V), K, sizeof(K));
    qsc_memutils_copy(V, mac, 32U);

    /* K = HMAC(K, V || 0x01 || int2octets(x) || bits2octets(h1)) */
    blob[0U] = 0x01U;

    qsc_memutils_copy(msg, V, 32U);
    qsc_memutils_copy((msg + 32U), blob, 65U);
    qsc_hmac256_compute(mac, msg, sizeof(msg), K, sizeof(K));
    qsc_memutils_copy(K, mac, 32U);

    /* V = HMAC(K, V) */
    qsc_hmac256_compute(mac, V, sizeof(V), K, sizeof(K));
    qsc_memutils_copy(V, mac, 32U);

    /* generate candidate k values until one is in [1, n-1] */
    for (;;)
    {
        qsc_hmac256_compute(T, V, sizeof(V), K, sizeof(K));
        qsc_memutils_copy(V, T, 32U);

        fe256_from_bytes(k_out, T);

        if ((fe256_is_zero(k_out) == false) && (fe256_cmp(k_out, P256_N) < 0))
        {
            break;
        }

		qsc_memutils_copy(msg, V, sizeof(V));
		msg[sizeof(V)] = 0U;
		qsc_hmac256_compute(mac, msg, sizeof(V) + 1U, K, sizeof(K));
        qsc_memutils_copy(K, mac, 32U);

        qsc_hmac256_compute(mac, V, sizeof(V), K, sizeof(K));
        qsc_memutils_copy(V, mac, 32U);
    }

    qsc_memutils_secure_erase(V, sizeof(V));
    qsc_memutils_secure_erase(K, sizeof(K));
    qsc_memutils_secure_erase(bh, sizeof(bh));
    qsc_memutils_secure_erase(blob, sizeof(blob));
    qsc_memutils_secure_erase(T, sizeof(T));
    qsc_memutils_secure_erase(msg, sizeof(msg));
    qsc_memutils_secure_erase(mac, sizeof(mac));
}

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

/* Public API */

int32_t qsc_p256_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    p256_aff_t G;
    p256_aff_t Q;
    p256_jac_t R;
    uint32_t d[8U] = { 0U };
    int32_t ret;

    ret = -1;

    /* decode the raw 32-byte scalar */
    sc_from_bytes(d, privatekey);

    /* reject zero */
    if (fe256_is_zero(d) != 0U)
    {
        ret = -2;
    }

    /* reject d >= n */
    else if (fe256_cmp(d, P256_N) >= 0)
    {
        ret = -3;
    }
    else
    {
        /* initialize the P-256 base point */
        fe256_copy(G.X, P256_GX);
        fe256_copy(G.Y, P256_GY);

        /* compute R = dG */
        p256_scalar_mult(&R, &G, d, true);

        /* reject infinity */
        if (p256_is_infinity(&R) != 0U)
        {
            ret = -4;
        }
        /* convert to affine */
        else if (p256_jac_to_aff(&Q, &R) != true)
        {
            ret = -5;
        }
        else
        {
            /* serialize public key as Qx || Qy */
            fe256_to_bytes(publickey, Q.X);
            fe256_to_bytes(publickey + 32U, Q.Y);
            ret = 0;
        }
    }

    return ret;
}

int32_t qsc_p256_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(seed != NULL);

    uint8_t hash[32U] = { 0U };
    uint32_t d[8U] = { 0U };
    p256_aff_t Q;
    p256_jac_t Q_jac;
    p256_aff_t G_init;
    int32_t ret;

    ret = -1;

    /* clear outputs on entry */
    qsc_memutils_clear(publickey, EC_NISTP256_PUBLICKEY_SIZE);
    qsc_memutils_clear(privatekey, EC_NISTP256_PRIVATEKEY_SIZE);

    /* derive private scalar: d = SHA-256(seed) mod n */
    qsc_sha256_compute(hash, seed, EC_NISTP256_SEED_SIZE);
    sc_from_bytes_reduce(d, hash);

    /* reject d == 0 instead of silently substituting d = 1 */
    if (fe256_is_zero(d))
    {
        ret = -2;
    }
    else
    {
        /* Q = d * G */
        fe256_copy((uint32_t*)G_init.X, P256_GX);
        fe256_copy((uint32_t*)G_init.Y, P256_GY);

        p256_scalar_mult(&Q_jac, &G_init, d, true);

        if (p256_jac_to_aff(&Q, &Q_jac) != true)
        {
            ret = -3;
        }
        else
        {
            /* public key: Qx || Qy (big-endian, 32 bytes each) */
            fe256_to_bytes(publickey, Q.X);
            fe256_to_bytes(publickey + 32U, Q.Y);

            /* private key: seed[32] || pubkey[64] */
            qsc_memutils_copy(privatekey, seed, EC_NISTP256_SEED_SIZE);
            qsc_memutils_copy(privatekey + 32U, publickey, EC_NISTP256_PUBLICKEY_SIZE);

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

static bool p256_sign_scalar_blinded(uint32_t output[8U], const uint32_t nonce[8U], const uint32_t private_scalar[8U], const uint32_t signature_r[8U], const uint32_t message_scalar[8U])
{
    /* calculate a blinded ECDSA P-256 signature scalar */
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
	return p256_native_sign_scalar(output, nonce, private_scalar, signature_r, message_scalar);
#else

	uint8_t random_mask[32U] = { 0U };
	uint32_t mask[8U] = { 0U };
	uint32_t masked_mont[8U] = { 0U };
	uint32_t nonce_mont[8U] = { 0U };
	uint32_t private_mont[8U] = { 0U };
	uint32_t digest_mont[8U] = { 0U };
	uint32_t r_mont[8U] = { 0U };
	uint32_t inverse_mont[8U] = { 0U };
	uint32_t sum_mont[8U] = { 0U };
	uint32_t result_mont[8U] = { 0U };
	bool result;

	result = qsc_csp_generate(random_mask, sizeof(random_mask));

	if (result)
	{
		sc_from_bytes_reduce(mask, random_mask);
		mask[0U] |= fe256_is_zero(mask);

		sc_mont_encode(masked_mont, mask);
		sc_mont_encode(nonce_mont, nonce);
		sc_mont_encode(private_mont, private_scalar);
		sc_mont_encode(digest_mont, message_scalar);
		sc_mont_encode(r_mont, signature_r);

		sc_mont_mul(nonce_mont, nonce_mont, masked_mont);
		sc_inv_mont(inverse_mont, nonce_mont);
		sc_mont_mul(private_mont, private_mont, masked_mont);
		sc_mont_mul(private_mont, private_mont, r_mont);
		sc_mont_mul(digest_mont, digest_mont, masked_mont);
		sc_add(sum_mont, private_mont, digest_mont);
		sc_mont_mul(result_mont, inverse_mont, sum_mont);
		sc_mont_decode(output, result_mont);
	}

	qsc_memutils_secure_erase(random_mask, sizeof(random_mask));
	qsc_memutils_secure_erase(mask, sizeof(mask));
	qsc_memutils_secure_erase(masked_mont, sizeof(masked_mont));
	qsc_memutils_secure_erase(nonce_mont, sizeof(nonce_mont));
	qsc_memutils_secure_erase(private_mont, sizeof(private_mont));
	qsc_memutils_secure_erase(digest_mont, sizeof(digest_mont));
	qsc_memutils_secure_erase(r_mont, sizeof(r_mont));
	qsc_memutils_secure_erase(inverse_mont, sizeof(inverse_mont));
	qsc_memutils_secure_erase(sum_mont, sizeof(sum_mont));
	qsc_memutils_secure_erase(result_mont, sizeof(result_mont));

	return result;
#endif
}

int32_t qsc_p256_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    uint8_t hash[32U] = { 0U };
    uint8_t d_be[32U] = { 0U };
    uint8_t dhash[32U] = { 0U };
    uint32_t d[8U] = { 0U };
    uint32_t k[8U] = { 0U };
    uint32_t r[8U] = { 0U };
    uint32_t s[8U] = { 0U };
    uint32_t e[8U] = { 0U };
    p256_aff_t kG;
    p256_jac_t kG_jac;
    p256_aff_t G;
    int32_t res;

    res = -1;

    /* hash the message with SHA-256 */
    qsc_sha256_compute(hash, message, msglen);

    /* derive private scalar by hashing the private key and reducing */
    qsc_sha256_compute(dhash, privatekey, EC_NISTP256_SEED_SIZE);
    sc_from_bytes_reduce(d, dhash);

    if (fe256_is_zero(d))
    {
        res = -2;
    }
    else if (fe256_cmp(d, P256_N) < 0)
    {
        /* load message hash as scalar e */
        sc_from_bytes_reduce(e, hash);

        /* reconstruct the private scalar bytes in big-endian for RFC 6979 */
        fe256_to_bytes(d_be, d);

        /* generate deterministic k using RFC 6979 */
        rfc6979_generate_k(k, d_be, hash);

        /* R = k * G */
        fe256_copy((uint32_t*)G.X, P256_GX);
        fe256_copy((uint32_t*)G.Y, P256_GY);

        p256_scalar_mult(&kG_jac, &G, k, true);
        p256_jac_x_to_aff(kG.X, &kG_jac);

        /* r = kG.x mod n */
        fe256_copy(r, kG.X);
        fe256_cond_sub(r, P256_N);

        if (!fe256_is_zero(r))
        {
            /* independent scalar blinding; fail closed on RNG error. */
            if (!p256_sign_scalar_blinded(s, k, d, r, e))
            {
                res = -3;
            }
            else if (!fe256_is_zero(s))
            {
                fe256_to_bytes(signedmsg, r);
                fe256_to_bytes(signedmsg + 32U, s);
                qsc_memutils_copy(signedmsg + EC_NISTP256_SIGNATURE_SIZE, message, msglen);
                *smsglen = EC_NISTP256_SIGNATURE_SIZE + msglen;
                res = 0;
            }
        }
    }

    qsc_memutils_secure_erase(hash, sizeof(hash));
    qsc_memutils_secure_erase(dhash, sizeof(dhash));
    qsc_memutils_secure_erase(d_be, sizeof(d_be));
    qsc_memutils_secure_erase(d, sizeof(d));
    qsc_memutils_secure_erase(k, sizeof(k));
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

int32_t qsc_p256_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    uint8_t hash[32U] = { 0U };
    uint8_t d_be[32U] = { 0U };
    uint8_t dhash[32U] = { 0U };
    uint32_t d[8U] = { 0U };
    uint32_t k[8U] = { 0U };
    uint32_t r[8U] = { 0U };
    uint32_t s[8U] = { 0U };
    uint32_t e[8U] = { 0U };
    p256_aff_t kG;
    p256_jac_t kG_jac;
    p256_aff_t G;
    int32_t res;

    res = -1;

    /* hash the message with SHA-256 */
    qsc_sha256_compute(hash, message, msglen);

    /* derive private scalar exactly as in qsc_p256_keypair() */
    sc_from_bytes(d, privatekey);

    if (fe256_is_zero(d))
    {
        res = -2;
    }
    else if (fe256_cmp(d, P256_N) < 0)
    {
        /* load message hash as scalar e */
        sc_from_bytes_reduce(e, hash);

        /* reconstruct the private scalar bytes in big-endian for RFC 6979 */
        fe256_to_bytes(d_be, d);

        /* generate deterministic k using RFC 6979 */
        rfc6979_generate_k(k, d_be, hash);

        /* R = k * G */
        fe256_copy((uint32_t*)G.X, P256_GX);
        fe256_copy((uint32_t*)G.Y, P256_GY);

        p256_scalar_mult(&kG_jac, &G, k, true);
        p256_jac_x_to_aff(kG.X, &kG_jac);

        /* r = kG.x mod n */
        fe256_copy(r, kG.X);
        fe256_cond_sub(r, P256_N);

        if (!fe256_is_zero(r))
        {
            /* independent scalar blinding; fail closed on RNG error. */
            if (!p256_sign_scalar_blinded(s, k, d, r, e))
            {
                res = -3;
            }
            else if (!fe256_is_zero(s))
            {
                fe256_to_bytes(signedmsg, r);
                fe256_to_bytes(signedmsg + 32U, s);
                qsc_memutils_copy(signedmsg + EC_NISTP256_SIGNATURE_SIZE, message, msglen);
                *smsglen = EC_NISTP256_SIGNATURE_SIZE + msglen;
                res = 0;
            }
        }
    }

    qsc_memutils_secure_erase(hash, sizeof(hash));
    qsc_memutils_secure_erase(dhash, sizeof(dhash));
    qsc_memutils_secure_erase(d_be, sizeof(d_be));
    qsc_memutils_secure_erase(d, sizeof(d));
    qsc_memutils_secure_erase(k, sizeof(k));
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

static bool p256_verify_projective_x(const p256_jac_t* point, const uint32_t r[8U])
{
    /* compare the public signature r with the X coordinate of a Jacobian point */
    static const uint32_t P256_P_MINUS_N[8U] = { 0x039CDAAEU, 0x0C46353DU, 0x58E8617BU, 0x43190553U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U };
    fe256 z_squared = { 0U };
    fe256 canonical = { 0U };
    fe256 encoded = { 0U };
    fe256 expected = { 0U };
    bool result;

    result = false;

    if (p256_is_infinity(point) == 0U)
    {
        fe_sqr(z_squared, point->Z);
        fe256_mont_encode(encoded, r);
        fe_mul(expected, encoded, z_squared);
        result = (fe256_cmp(point->X, expected) == 0);

        if ((result == false) && (fe256_cmp(r, P256_P_MINUS_N) < 0))
        {
            fe_add(canonical, r, P256_N);
            fe256_mont_encode(encoded, canonical);
            fe_mul(expected, encoded, z_squared);
            result = (fe256_cmp(point->X, expected) == 0);
        }
    }

    qsc_memutils_secure_erase(z_squared, sizeof(z_squared));
    qsc_memutils_secure_erase(canonical, sizeof(canonical));
    qsc_memutils_secure_erase(encoded, sizeof(encoded));
    qsc_memutils_secure_erase(expected, sizeof(expected));

    return result;
}

/**
 * \brief Initialize an optional reusable P-256 public-key verifier context.
 * \param context Caller-owned writable context; zeroed on any failure.
 * \param publickey Validated 64-byte canonical uncompressed P-256 key, X || Y.
 * \return True for a valid public key and initialized immutable context.
 * \note The cached precomputation is public, never contains secret keys, and is
 * computed once per key. The caller must not modify it during verification.
 * \note After initialization, independent threads may share one read-only context;
 * initialization and clear must not race with verification. No heap allocation.
 */
bool qsc_p256_verify_context_initialize(qsc_p256_verify_context* context, const uint8_t* publickey)
{
    p256_aff_t Q = { { 0U }, { 0U } };
    bool result;

    result = false;

    if (context != NULL)
    {
        qsc_memutils_clear(context, sizeof(*context));

        if (publickey != NULL)
        {
            fe256_from_bytes(Q.X, publickey);
            fe256_from_bytes(Q.Y, publickey + 32U);

            if ((fe256_cmp(Q.X, P256_P) < 0) && (fe256_cmp(Q.Y, P256_P) < 0) &&
                p256_point_is_on_curve(&Q))
            {
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
                p256_aff_t encoded = { { 0U }, { 0U } };
                p256_native_point points[8U];
                p256_native_point doubled;
                size_t i;

                fe256_mont_encode(encoded.X, Q.X);
                fe256_mont_encode(encoded.Y, Q.Y);
                p256_native_load(points[0U].x, encoded.X);
                p256_native_load(points[0U].y, encoded.Y);
                p256_native_copy(points[0U].z, P256_NATIVE_ONE);
                p256_verify_native_double_n(&doubled, &points[0U], 1U);

                for (i = 1U; i < 8U; ++i)
                {
                    p256_verify_native_add_projective(&points[i], &points[i - 1U], &doubled);
                }

                p256_verify_native_batch(points);

                for (i = 0U; i < 8U; ++i)
                {
                    p256_native_store(context->odd_montgomery[i][0U], points[i].x);
                    p256_native_store(context->odd_montgomery[i][1U], points[i].y);
                }

                qsc_memutils_secure_erase(&encoded, sizeof(encoded));
                qsc_memutils_secure_erase(points, sizeof(points));
                qsc_memutils_secure_erase(&doubled, sizeof(doubled));
#endif
                qsc_memutils_copy(context->publickey, publickey, EC_NISTP256_PUBLICKEY_SIZE);
                context->initialized = true;
                result = true;
            }
        }
    }

    qsc_memutils_secure_erase(&Q, sizeof(Q));
    return result;
}

/**
 * \brief Clear one caller-owned reusable P-256 verification context.
 * \param context Context to erase, or NULL (no action).
 * \note Do not race with a verification using the same context.
 */
void qsc_p256_verify_context_clear(qsc_p256_verify_context* context)
{
    if (context != NULL)
    {
        qsc_memutils_secure_erase(context, sizeof(*context));
    }
}

static bool p256_verify_digest_core(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, 
    const uint8_t* digest, const qsc_p256_verify_context* context, const qsc_p256_joint_verify_context* joint_context)
{
    /* verify an ECDSA signature using the already normalized message digest */
    QSC_ASSERT(msgout != NULL);
    QSC_ASSERT(msglen != NULL);
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(publickey != NULL);

    size_t mlen;
    uint8_t hash[32U] = { 0U };
    uint32_t r[8U] = { 0U };
    uint32_t s[8U] = { 0U };
    uint32_t e[8U] = { 0U };
    uint32_t w[8U] = { 0U };
    uint32_t u1[8U] = { 0U };
    uint32_t u2[8U] = { 0U };
    p256_aff_t Q = { 0U };
    p256_jac_t Jsum = { 0U };
    bool res;

    res = false;
    mlen = 0U;

    if ((digest != NULL) && (smsglen >= EC_NISTP256_SIGNATURE_SIZE))
    {
        mlen = smsglen - EC_NISTP256_SIGNATURE_SIZE;
        fe256_from_bytes((uint32_t*)Q.X, publickey);
        fe256_from_bytes((uint32_t*)Q.Y, publickey + 32U);

        if (fe256_cmp((uint32_t*)Q.X, P256_P) < 0 &&
            fe256_cmp((uint32_t*)Q.Y, P256_P) < 0 &&
            ((context != NULL) || p256_point_is_on_curve(&Q)))
        {
            fe256_from_bytes(r, signedmsg);
            fe256_from_bytes(s, signedmsg + 32U);

            if (!fe256_is_zero(r) &&
                fe256_cmp(r, P256_N) < 0 &&
                !fe256_is_zero(s) &&
                fe256_cmp(s, P256_N) < 0)
            {
                qsc_memutils_copy(hash, digest, 32U);
                sc_from_bytes_reduce(e, hash);
                #if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
                sc_inv(w, s);
#else
                sc_inv_public(w, s);
#endif
                sc_mul(u1, e, w);
                sc_mul(u2, r, w);

                #if defined(__SIZEOF_INT128__) && !defined(_MSC_VER) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
                if (joint_context != NULL)
                {
                    p256_verify_native_joint_window(&Jsum, u1, u2, joint_context);
                }
                else
#endif
                {
                    (void)joint_context;
                    p256_double_scalar_mult(&Jsum, &Q, u1, u2, context);
                }

                if (p256_verify_projective_x(&Jsum, r) == true)
                {
                    qsc_memutils_copy(msgout, signedmsg + EC_NISTP256_SIGNATURE_SIZE, mlen);
                    *msglen = mlen;
                    res = true;
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
        qsc_memutils_secure_erase(&Q, sizeof(Q));



        qsc_memutils_secure_erase(&Jsum, sizeof(Jsum));
    }

    return res;
}

/**
 * \brief Verify an ECDSA signature with the curve's original fixed SHA-2 digest.
 * \param msgout Recovered message output with capacity for smsglen minus signature bytes.
 * \param msglen Receives recovered message length, or zero on failure.
 * \param signedmsg Signature-prefixed message input.
 * \param smsglen Length of signedmsg in bytes.
 * \param publickey Raw curve public key.
 * \return True on valid signature, false otherwise.
 * \note Caller owns all buffers. No state is retained between calls.
 */
bool qsc_p256_verify(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	uint8_t digest[32U] = { 0U };
	bool res;

	res = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if ((msgout != NULL) && (msglen != NULL) && (signedmsg != NULL) &&
		(publickey != NULL) && (smsglen >= EC_NISTP256_SIGNATURE_SIZE))
	{
		qsc_sha256_compute(digest, signedmsg + EC_NISTP256_SIGNATURE_SIZE, smsglen - EC_NISTP256_SIGNATURE_SIZE);
		res = p256_verify_digest_core(msgout, msglen, signedmsg, smsglen, publickey, digest, NULL, NULL);
	}

	/* Only the caller-declared recovered-message region can be cleared. */
	if ((res == false) && (msgout != NULL) && (smsglen > EC_NISTP256_SIGNATURE_SIZE))
	{
		qsc_memutils_clear(msgout, smsglen - EC_NISTP256_SIGNATURE_SIZE);
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));
	return res;
}

/**
 * \brief Verify ECDSA using a caller-computed SHA-256, SHA-384, or SHA-512 digest.
 * \param msgout Recovered message output with capacity for smsglen minus signature bytes.
 * \param msglen Receives recovered message length, or zero on failure.
 * \param signedmsg Signature-prefixed message input.
 * \param smsglen Length of signedmsg in bytes.
 * \param publickey Raw curve public key.
 * \param digest SHA-2 digest bytes in big-endian order.
 * \param digestlen Exactly 32, 48 or 64 bytes.
 * \return True only for a valid signature of the supplied prehashed digest.
 * \note The caller must authenticate the association between digest and message.
 * All buffers remain caller-owned. The function retains no shared mutable state.
 */
bool qsc_p256_verify_prehashed(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, size_t digestlen)
{
	uint8_t scalarhash[32U] = { 0U };
	bool res;

	res = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if ((msgout != NULL) && (msglen != NULL) && (signedmsg != NULL) && (publickey != NULL) &&
		(smsglen >= EC_NISTP256_SIGNATURE_SIZE) && (digest != NULL) &&
		((digestlen == 32U) || (digestlen == 48U) || (digestlen == 64U)))
	{
		qsc_memutils_copy(scalarhash, digest, sizeof(scalarhash));
		res = p256_verify_digest_core(msgout, msglen, signedmsg, smsglen, publickey, scalarhash, NULL, NULL);
	}

	qsc_memutils_secure_erase(scalarhash, sizeof(scalarhash));
	return res;
}

/**
 * \brief Verify signature and recover message using a precomputed validated public key.
 * \param message Recovered-message output; capacity at least signedlen minus 64.
 * \param msglen Receives recovered length, or zero if invalid.
 * \param signedmsg Signature-prefixed message (64-byte r||s, followed by message).
 * \param smsglen Total signed-message bytes.
 * \param context Initialized read-only verification context from the same public key.
 * \return True iff the signature is valid for the cached public key.
 * \note This routine is public-input-only and thread-safe for immutable contexts.
 * \note Context lifetime must exceed each concurrent call. No heap allocations.
 */
bool qsc_p256_verify_with_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p256_verify_context* context)
{
    uint8_t digest[32U] = { 0U };
    bool result;

    result = false;

    if (msglen != NULL)
    {
        *msglen = 0U;
    }

    if ((message != NULL) && (msglen != NULL) && (signedmsg != NULL) &&
        (context != NULL) && context->initialized && (smsglen >= EC_NISTP256_SIGNATURE_SIZE))
    {
        qsc_sha256_compute(digest, signedmsg + EC_NISTP256_SIGNATURE_SIZE,
            smsglen - EC_NISTP256_SIGNATURE_SIZE);
        result = p256_verify_digest_core(message, msglen, signedmsg, smsglen,
            context->publickey, digest, context, NULL);
    }

    qsc_memutils_secure_erase(digest, sizeof(digest));
    return result;
}


/**
 * \brief Initialize a public-only, reusable P-256 joint-window verification table.
 * \param context Caller-owned output, cleared on failure.
 * \param publickey Validated public-key input, 64-byte X||Y.
 * \return True on success, false on invalid arguments or public key.
 */
bool qsc_p256_joint_verify_context_initialize(qsc_p256_joint_verify_context* context, const uint8_t* publickey)
{
    bool result;

    result = false;

    if (context != NULL)
    {
        qsc_memutils_clear(context, sizeof(*context));

        if (qsc_p256_verify_context_initialize(&context->base, publickey))
        {
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
            p256_verify_native_joint_prepare(context);
#endif
            context->initialized = true;
            result = true;
        }
    }

    return result;
}

/**
 * \brief Securely erase a caller-owned public joint-window verification context.
 * \param context Context to erase; NULL is allowed.
 */
void qsc_p256_joint_verify_context_clear(qsc_p256_joint_verify_context* context)
{
    if (context != NULL)
    {
        qsc_memutils_secure_erase(context, sizeof(*context));
    }
}

/**
 * \brief Verify a P-256 signature with a previously prepared joint window.
 * \param message Recovered message output.
 * \param msglen Recovered length; set to zero on error.
 * \param signedmsg Signature-prefixed message input.
 * \param smsglen Total input length.
 * \param context Read-only, initialized joint-window verifier.
 * \return True for a valid signature, false otherwise.
 */
bool qsc_p256_verify_with_joint_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p256_joint_verify_context* context)
{
    uint8_t digest[32U] = { 0U };
    bool result;

    result = false;

    if (msglen != NULL)
    {
        *msglen = 0U;
    }

    if ((message != NULL) && (msglen != NULL) && (signedmsg != NULL) &&
        (context != NULL) && context->initialized && context->base.initialized &&
        (smsglen >= EC_NISTP256_SIGNATURE_SIZE))
    {
        qsc_sha256_compute(digest, signedmsg + EC_NISTP256_SIGNATURE_SIZE, smsglen - EC_NISTP256_SIGNATURE_SIZE);
        result = p256_verify_digest_core(message, msglen, signedmsg, smsglen, context->base.publickey, digest, &context->base, context);
    }

    qsc_memutils_secure_erase(digest, sizeof(digest));

    return result;
}
