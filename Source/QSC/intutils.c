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

#include "intutils.h"
#include "memutils.h"
#include <string.h>

bool qsc_intutils_are_equal(size_t x, size_t y)
{
	return ((x ^ y) == 0U);
}

bool qsc_intutils_are_equal8(const uint8_t* a, const uint8_t* b, size_t length)
{
	QSC_ASSERT(a != NULL);
	QSC_ASSERT(b != NULL);

	uint8_t acc;

	acc = 0U;

	for (size_t i = 0U; i < length; ++i)
	{
		acc |= (a[i] ^ b[i]);
	}

	return (acc == 0U);
}

void qsc_intutils_be8increment(uint8_t* output, size_t otplen)
{
	QSC_ASSERT(output != NULL);

	size_t i = otplen;

	if (otplen > 0U)
	{
		do
		{
			--i;
			++output[i];
		} 
		while (i != 0U && output[i] == 0U);
	}
}

void qsc_intutils_be8increment_rfc3686(uint8_t* output, size_t otplen)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(otplen >= 4U);

    /* point to the first byte of the 32-bit counter field */
    uint8_t* ctr = output + (otplen - 4);
    size_t  i   = 4U;

    /* big-endian increment of those 4 bytes, with wrap */
    do
    {
        --i;
        ++ctr[i];
    }
    while (i != 0U && ctr[i] == 0U);
}

uint16_t qsc_intutils_be8to16(const uint8_t* input)
{
	QSC_ASSERT(input != NULL);

	return (((uint16_t)input[1U]) | 
		(uint16_t)((uint16_t)input[0U] << 8));
}

uint32_t qsc_intutils_be8to32(const uint8_t* input)
{
	QSC_ASSERT(input != NULL);

	return (uint32_t)(input[3U]) |
		(((uint32_t)(input[2U])) << 8) |
		(((uint32_t)(input[1U])) << 16) |
		(((uint32_t)(input[0U])) << 24);
}

uint64_t qsc_intutils_be8to64(const uint8_t* input)
{
	QSC_ASSERT(input != NULL);

	return (uint64_t)(input[7U]) |
		(((uint64_t)(input[6U])) << 8U) |
		(((uint64_t)(input[5U])) << 16U) |
		(((uint64_t)(input[4U])) << 24U) |
		(((uint64_t)(input[3U])) << 32U) |
		(((uint64_t)(input[2U])) << 40U) |
		(((uint64_t)(input[1U])) << 48U) |
		(((uint64_t)(input[0U])) << 56U);
}

void qsc_intutils_be16to8(uint8_t* output, uint16_t value)
{
	QSC_ASSERT(output != NULL);

	output[1U] = (uint8_t)value & 0xFFU;
	output[0U] = (uint8_t)(value >> 8) & 0xFFU;
}

void qsc_intutils_be32to8(uint8_t* output, uint32_t value)
{
	QSC_ASSERT(output != NULL);

	output[3U] = (uint8_t)value & 0xFFU;
	output[2U] = (uint8_t)(value >> 8) & 0xFFU;
	output[1U] = (uint8_t)(value >> 16) & 0xFFU;
	output[0U] = (uint8_t)(value >> 24) & 0xFFU;
}

void qsc_intutils_be64to8(uint8_t* output, uint64_t value)
{
	QSC_ASSERT(output != NULL);

	output[7U] = (uint8_t)value & 0xFFU;
	output[6U] = (uint8_t)(value >> 8) & 0xFFU;
	output[5U] = (uint8_t)(value >> 16) & 0xFFU;
	output[4U] = (uint8_t)(value >> 24) & 0xFFU;
	output[3U] = (uint8_t)(value >> 32) & 0xFFU;
	output[2U] = (uint8_t)(value >> 40) & 0xFFU;
	output[1U] = (uint8_t)(value >> 48) & 0xFFU;
	output[0U] = (uint8_t)(value >> 56) & 0xFFU;
}

uint64_t qsc_intutils_bit_reverse_u64(uint64_t x)
{
    x = ((x >> 1) & 0x5555555555555555ULL) | ((x & 0x5555555555555555ULL) << 1);
    x = ((x >> 2) & 0x3333333333333333ULL) | ((x & 0x3333333333333333ULL) << 2);
    x = ((x >> 4) & 0x0F0F0F0F0F0F0F0FULL) | ((x & 0x0F0F0F0F0F0F0F0FULL) << 4);
    x = ((x >> 8) & 0x00FF00FF00FF00FFULL) | ((x & 0x00FF00FF00FF00FFULL) << 8);
    x = ((x >> 16) & 0x0000FFFF0000FFFFULL) | ((x & 0x0000FFFF0000FFFFULL) << 16);
    x = (x >> 32) | (x << 32);

    return x;
}

uint32_t qsc_intutils_bit_reverse_u32(uint32_t x) 
{
    x = ((x >> 1) & 0x55555555UL) | ((x & 0x55555555UL) << 1);
    x = ((x >> 2) & 0x33333333UL) | ((x & 0x33333333UL) << 2);
    x = ((x >> 4) & 0x0F0F0F0FUL) | ((x & 0x0F0F0F0FUL) << 4);
    x = ((x >> 8) & 0x00FF00FFUL) | ((x & 0x00FF00FFUL) << 8);
    x = (x >> 16) | (x << 16);

    return x;
}

uint16_t qsc_intutils_bit_reverse_u16(uint16_t x) 
{
    x = ((x >> 1) & 0x5555U) | ((x & 0x5555U) << 1);
    x = ((x >> 2) & 0x3333U) | ((x & 0x3333U) << 2);
    x = ((x >> 4) & 0x0F0FU) | ((x & 0x0F0FU) << 4);
    x = (x >> 8) | (x << 8);

    return x;
}

size_t qsc_intutils_bit_reverse(size_t x, uint32_t bits) 
{
    size_t y = 0;

    for (size_t i = 0U; i < (size_t)bits; ++i) 
    {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }

    return y;
}

#if defined(QSC_SYSTEM_HAS_AVX)
void qsc_intutils_bswap32(uint32_t* dest, const uint32_t* source, size_t length)
{
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(source != NULL);
	QSC_ASSERT((length % 4U) == 0U);

	__m128i mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

	for (size_t i = 0U; i + 4U <= length; i += 4U)
	{
		_mm_storeu_si128((__m128i*) & dest[i], _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*) & source[i]), mask));
	}

}

void qsc_intutils_bswap64(uint64_t* dest, const uint64_t* source, size_t length)
{
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(source != NULL);
	QSC_ASSERT((length % 2U) == 0U);

	__m128i mask = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);

	for (size_t i = 0U; i + 2U <= length; i += 2)
	{
		_mm_storeu_si128((__m128i*)&dest[i], _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)&source[i]), mask));
	}
}
#endif

double qsc_intutils_calculate_abs(double a)
{
	double r;

    if (a < 0.0)
    {
        r = -a;
    }
	else
	{
		r = a;
	}

    return r;
}

double qsc_intutils_calculate_exp(double x)
{
	double epsilon;
	double res;
    double result;
	double term;
	uint64_t bits;
	int32_t n;
    
    /* check for NaN: NaN is the only value that is not equal to itself */
    if (x != x)
    {
        result = x; /* propagate NaN */
    }
    else if (x > 709.782712893384)
    {
        /* construct positive infinity by setting the IEEE-754 bit pattern */
        bits = 0x7FF0000000000000ULL;
        qsc_memutils_copy((uint8_t*)&result, (const uint8_t*)&bits, sizeof(result));
    }
    else if (x < -745.133219101941)
    {
        result = 0.0;
    }
    else
    {
        term = 1.0;
        res = 1.0;
        n = 1;
        epsilon = 1e-12; /* relative tolerance */
        
        while (qsc_intutils_calculate_abs(term) > epsilon * qsc_intutils_calculate_abs(res))
        {
            term *= x / n;
            res += term;
            ++n;

			/* safety break to prevent infinite loop */
            if (n > 10000)
            {
                break;
            }
        }

        result = res;
    }
    
    return result;
}

double qsc_intutils_calculate_fabs(double x)
{
    uint64_t u;
    double result;

    /* copy the bits of x into u */
    memcpy(&u, &x, sizeof(u));

    /* clear the sign bit (bit 63) */
    u &= 0x7FFFFFFFFFFFFFFFULL;

    /* copy the modified bits back into a double */
    memcpy(&result, &u, sizeof(result));

    return result;
}

double qsc_intutils_calculate_log(double x)
{
	uint64_t infbits;
	uint64_t nanbits;
	uint64_t neginfbits;
    double epsilon;
    double ln2;
	double lnx;
    double result;
    double sum;
    double term;
	double y;
    double y2;
	int32_t k;
    int32_t n;

    if (x != x)  /* NaN check: NaN != NaN */
    {
        result = x;  /* propagate NaN */
    }
    else if (x < 0.0)
    {
        /* create NaN by setting the IEEE-754 quiet NaN bit pattern inline */
        nanbits = 0x7FF8000000000000ULL;
        memcpy(&result, &nanbits, sizeof(result));
    }
    else if (x == 0.0)
    {
        /* create negative infinity by setting the IEEE-754 bit pattern inline */
        neginfbits = 0xFFF0000000000000ULL;
        memcpy(&result, &neginfbits, sizeof(result));
    }
    else if (x > 1e300)
    {
        /* create positive infinity by setting the IEEE-754 bit pattern inline */
        infbits = 0x7FF0000000000000ULL;
        memcpy(&result, &infbits, sizeof(result));
    }
    else
    {
        k = 0;

        /* range reduction: scale x into [1,2] */
        while (x >= 2.0)
        {
            x /= 2.0;
            k++;
        }

        while (x < 1.0)
        {
            x *= 2.0;
            k--;
        }

        /* compute y = (x - 1)/(x + 1) and then the series for ln(x) */
        y = (x - 1.0) / (x + 1.0);
        y2 = y * y;
        sum = 0.0;
        term = y;
        n = 1;
        epsilon = 1e-12;

        while (qsc_intutils_calculate_abs(term) > epsilon)
        {
            sum += term / n;
            term *= y2;
            n += 2;
        }

        lnx = 2.0 * sum;
		/* approximation for ln(2) */
        ln2 = 0.6931471805599453;
        result = lnx + k * ln2;
    }
    
    return result;
}

double qsc_intutils_calculate_sqrt(double x)
{
	uint64_t nanbits;
	double absnguess;
	double diff;
	double epsilon;
	double guess;
    double nguess;
    double result;

    if (x < 0.0)
    {
        /* create NaN by setting the IEEE-754 quiet NaN bit pattern */
        nanbits = 0x7FF8000000000000ULL;
        memcpy(&result, &nanbits, sizeof(result));
    }
    else if (x == 0.0)
    {
        result = 0.0;
    }
    else
    {
        /* use a different initial guess if x < 1 to avoid extremely small initial guesses */
        if (x >= 1.0)
        {
            guess = x / 2.0;
        }
        else
        {
            guess = 1.0;
        }

        epsilon = 1e-12;

        while (true)
        {
            nguess = 0.5 * (guess + x / guess);
            /* calculate the absolute difference without using a helper function */
            diff = nguess - guess;

            if (diff < 0.0)
            {
                diff = -diff;
            }

            /* stop when the relative difference is below the tolerance */
            {
                absnguess = (nguess < 0.0) ? -nguess : nguess;

                if (diff < epsilon * absnguess)
                {
                    break;
                }
            }

            guess = nguess;
        }

        result = nguess;
    }
    
    return result;
}

void qsc_intutils_clear8(uint8_t* a, size_t count)
{
	QSC_ASSERT(a != NULL);

	qsc_memutils_clear(a, count);
}

void qsc_intutils_clear16(uint16_t* a, size_t count)
{
	QSC_ASSERT(a != NULL);

	qsc_memutils_clear(a, count * sizeof(uint16_t));
}

void qsc_intutils_clear32(uint32_t* a, size_t count)
{
	QSC_ASSERT(a != NULL);

	qsc_memutils_clear(a, count * sizeof(uint32_t));
}

void qsc_intutils_clear64(uint64_t* a, size_t count)
{
	QSC_ASSERT(a != NULL);

	qsc_memutils_clear(a, count * sizeof(uint64_t));
}

void qsc_intutils_cmov(uint8_t* dest, const uint8_t* source, size_t length, uint8_t cond)
{
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(source != NULL);
	
	cond = (uint8_t)((cond | (uint8_t)(-(int8_t)cond)) >> 7);
	cond = ~cond + 1U;

#if defined(__GNUC__) || defined(__clang__)
	__asm__ volatile ("" : "+r"(cond));
#endif

	for (size_t i = 0U; i < length; i++)
	{
		dest[i] ^= (uint8_t)(cond & (uint8_t)(source[i] ^ dest[i]));
	}
}

size_t qsc_intutils_expand_mask(size_t x)
{
	size_t r;

	r = x;

	/* fold r down to a single bit */
	for (size_t i = 1U; i != sizeof(size_t) * 8U; i *= 2U)
	{
		r |= r >> i;
	}

	r &= 1;
	r = ~(r - 1U);

	return r;
}

bool qsc_intutils_is_gte(size_t x, size_t y)
{
	return (x >= y);
}

void qsc_intutils_bin_to_hex(const uint8_t* input, char* hexstr, size_t inplen)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(hexstr != NULL);

	const uint8_t ENCODING_TABLE[16U] =
	{
		0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U, 0x39U, 0x61U, 0x62U, 0x63U, 0x64U, 0x65U, 0x66U
	};

	size_t ctr;
	int32_t vct;

	ctr = 0;

	for (size_t i = 0U; i < inplen; ++i)
	{
		vct = input[i];
		hexstr[ctr] = ENCODING_TABLE[vct >> 4];
		++ctr;
		hexstr[ctr] = ENCODING_TABLE[vct & 0x0FU];
		++ctr;
	}
}

void qsc_intutils_hex_to_bin(const char* hexstr, uint8_t* output, size_t outlen)
{
	QSC_ASSERT(hexstr != NULL);
	QSC_ASSERT(output != NULL);

	static const uint8_t HEX_TABLE[32U] =
	{
		0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
		0x08U, 0x09U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
		0x00U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x00U,
		0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
	};
	size_t pos;
	uint8_t high;
	uint8_t low;

	pos = 0U;

	if (hexstr != NULL && output != NULL && outlen <= (SIZE_MAX / 2U))
	{
		for (size_t i = 0U; i < outlen; ++i)
		{
			high = (uint8_t)(((uint8_t)hexstr[pos] & 0x1FU) ^ 0x10U);
			low = (uint8_t)(((uint8_t)hexstr[pos + 1U] & 0x1FU) ^ 0x10U);
			output[i] = (uint8_t)((HEX_TABLE[high] << 4U) | HEX_TABLE[low]);
			pos += 2U;
		}
	}
}

/**
 * \brief Parse one hexadecimal digit without reading past its position.
 * \param value: ASCII character to decode.
 * \return Value 0 through 15, or 255 for an invalid character.
 * \note Stateless and thread safe.
 */
static uint8_t intutils_hex_nibble(uint8_t value)
{
	uint8_t res;

	res = UINT8_MAX;

	if (value >= (uint8_t)'0' && value <= (uint8_t)'9')
	{
		res = (uint8_t)(value - (uint8_t)'0');
	}
	else if (value >= (uint8_t)'A' && value <= (uint8_t)'F')
	{
		res = (uint8_t)(value - (uint8_t)'A' + 10U);
	}
	else if (value >= (uint8_t)'a' && value <= (uint8_t)'f')
	{
		res = (uint8_t)(value - (uint8_t)'a' + 10U);
	}

	return res;
}

bool qsc_intutils_hex_to_bin_checked(const char* hexstr, size_t hexlen, uint8_t* output, size_t outlen)
{
	QSC_ASSERT(hexstr != NULL);
	QSC_ASSERT(output != NULL);

	size_t pos;
	uint8_t high;
	uint8_t low;
	bool res;

	res = false;

	if (hexstr != NULL && output != NULL && outlen <= (SIZE_MAX / 2U) && hexlen == (outlen * 2U))
	{
		res = true;

		for (size_t i = 0U; i < hexlen; ++i)
		{
			if (intutils_hex_nibble((uint8_t)hexstr[i]) == UINT8_MAX)
			{
				res = false;
				break;
			}
		}

		if (res == true)
		{
			pos = 0U;

			for (size_t i = 0U; i < outlen; ++i)
			{
				high = intutils_hex_nibble((uint8_t)hexstr[pos]);
				low = intutils_hex_nibble((uint8_t)hexstr[pos + 1U]);
				output[i] = (uint8_t)((high << 4U) | low);
				pos += 2U;
			}
		}
	}

	return res;
}

bool qsc_intutils_is_power_of_two(size_t x)
{
	return (x != 0U) && ((x & (x - 1U)) == 0U);
}

size_t qsc_intutils_next_power_of_2(size_t x)
{
	size_t power;

	power = 1U;

	while (power < x && power <= (SIZE_MAX >> 1U))
	{
		power <<= 1;
	}

	if (power < x)
	{
		power = 0U;
	}

	return power;
}

void qsc_intutils_le8increment(uint8_t* output, size_t otplen)
{
	QSC_ASSERT(output != NULL);

	size_t i;

	i = 0U;

	while (i < otplen)
	{
		++output[i];

		if (output[i] != 0U)
		{
			break;
		}

		++i;
	}
}

#if defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_AESNI_ENABLED)
void qsc_intutils_leincrement_x128(__m128i* counter)
{
	QSC_ASSERT(counter != NULL);

	*counter = _mm_add_epi64(*counter, _mm_set_epi64x(0, 1));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
void qsc_intutils_leincrement_x512(__m512i* counter)
{
	QSC_ASSERT(counter != NULL);

	*counter = _mm512_add_epi64(*counter, _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4));
}
#endif

uint16_t qsc_intutils_le8to16(const uint8_t* input)
{
	QSC_ASSERT(input != NULL);

	return (((uint16_t)input[0U]) |
		(uint16_t)((uint16_t)input[1U] << 8U));
}

uint32_t qsc_intutils_le8to32(const uint8_t* input)
{
	QSC_ASSERT(input != NULL);

	return ((uint32_t)input[0U]) |
		((uint32_t)input[1U] << 8) |
		((uint32_t)input[2U] << 16) |
		((uint32_t)input[3U] << 24);
}

uint64_t qsc_intutils_le8to64(const uint8_t* input)
{
	QSC_ASSERT(input != NULL);

	return ((uint64_t)input[0U]) |
		((uint64_t)input[1U] << 8) |
		((uint64_t)input[2U] << 16) |
		((uint64_t)input[3U] << 24) |
		((uint64_t)input[4U] << 32) |
		((uint64_t)input[5U] << 40) |
		((uint64_t)input[6U] << 48) |
		((uint64_t)input[7U] << 56);
}

void qsc_intutils_le16to8(uint8_t* output, uint16_t value)
{
	QSC_ASSERT(output != NULL);

	output[0U] = (uint8_t)value & 0xFFU;
	output[1U] = (uint8_t)(value >> 8) & 0xFFU;
}

void qsc_intutils_le32to8(uint8_t* output, uint32_t value)
{
	QSC_ASSERT(output != NULL);

	output[0U] = (uint8_t)value & 0xFFU;
	output[1U] = (uint8_t)(value >> 8) & 0xFFU;
	output[2U] = (uint8_t)(value >> 16) & 0xFFU;
	output[3U] = (uint8_t)(value >> 24) & 0xFFU;
}

void qsc_intutils_le64to8(uint8_t* output, uint64_t value)
{
	QSC_ASSERT(output != NULL);

	output[0U] = (uint8_t)value & 0xFFU;
	output[1U] = (uint8_t)(value >> 8) & 0xFFU;
	output[2U] = (uint8_t)(value >> 16) & 0xFFU;
	output[3U] = (uint8_t)(value >> 24) & 0xFFU;
	output[4U] = (uint8_t)(value >> 32) & 0xFFU;
	output[5U] = (uint8_t)(value >> 40) & 0xFFU;
	output[6U] = (uint8_t)(value >> 48) & 0xFFU;
	output[7U] = (uint8_t)(value >> 56) & 0xFFU;
}

bool qsc_intutils_lsb_is_set(size_t x)
{
	return ((x & 1U) != 0U);
}

size_t qsc_intutils_max(size_t a, size_t b)
{
	return (a > b) ? a : b;
}

size_t qsc_intutils_min(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

uint32_t qsc_intutils_popcount32(uint32_t v)
{
	v = v - ((v >> 1) & 0x55555555UL);
	v = (v & 0x33333333UL) + ((v >> 2) & 0x33333333UL);
	v = (v + (v >> 4)) & 0x0F0F0F0FUL;

	return (uint32_t)((v * 0x01010101UL) >> 24);
}

uint32_t qsc_intutils_popcount64(uint64_t value)
{
	value -= (value >> 1U) & UINT64_C(0x5555555555555555);
	value = (value & UINT64_C(0x3333333333333333)) + ((value >> 2U) & UINT64_C(0x3333333333333333));
	value = (value + (value >> 4U)) & UINT64_C(0x0F0F0F0F0F0F0F0F);

	return (uint32_t)((value * UINT64_C(0x0101010101010101)) >> 56U);
}

#if defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_AESNI_ENABLED)
void qsc_intutils_reverse_bytes_x128(const __m128i* input, __m128i* output)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	__m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

	*output = _mm_shuffle_epi8(*input, mask);
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
void qsc_intutils_reverse_bytes_x512(const __m512i* input, __m512i* output)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	__m512i mask = _mm512_set_epi8(
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 
		32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 
		48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63);

	*output = _mm512_shuffle_epi8(*input, mask);
}
#endif

uint32_t qsc_intutils_rotl32(uint32_t value, size_t shift)
{
	QSC_ASSERT(shift < 32U);

	return (value << shift) | (value >> ((32U - shift) & 31U));
}

uint64_t qsc_intutils_rotl64(uint64_t value, size_t shift)
{
	QSC_ASSERT(shift < 64U);

	return (value << shift) | (value >> ((64U - shift) & 63U));
}

uint32_t qsc_intutils_rotr32(uint32_t value, size_t shift)
{
	QSC_ASSERT(shift < 32U);

	return (value >> shift) | (value << ((32U - shift) & 31U));
}

uint64_t qsc_intutils_rotr64(uint64_t value, size_t shift)
{
	QSC_ASSERT(shift < 64U);

	return (value >> shift) | (value << ((64U - shift) & 63U));
}

int32_t qsc_intutils_verify(const uint8_t* a, const uint8_t* b, size_t length)
{
	QSC_ASSERT(a != NULL);
	QSC_ASSERT(b != NULL);

	uint8_t d;

	d = 0U;

	for (size_t i = 0U; i < length; ++i)
	{
		d |= (a[i] ^ b[i]);
	}

	return d;
}
