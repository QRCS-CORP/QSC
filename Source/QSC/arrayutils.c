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

#include "arrayutils.h"
#include <string.h>
#include <stdint.h>

size_t qsc_arrayutils_find_string(const char* str, size_t slen, const char* token)
{
	QSC_ASSERT(str != NULL);
	QSC_ASSERT(token != NULL);
	QSC_ASSERT(slen != 0U);

	const char* end;
	const char* pos;
	size_t res;
	size_t tlen;
	size_t remaining;

	res = 0U;

	if (str != NULL && token != NULL && slen != 0U)
	{
		res = (size_t)QSC_ARRAYUTILS_NPOS;
		tlen = strlen(token);

		if (tlen == 0U)
		{
			res = 1U;
		}
		else if (tlen <= slen)
		{
			end = str + (slen - tlen + 1U);
			pos = str;

			while (pos < end)
			{
				remaining = (size_t)(end - pos);
				pos = (const char*)memchr(pos, (unsigned char)token[0U], remaining);

				if (pos == NULL)
				{
					break;
				}

				if (memcmp(pos, token, tlen) == 0)
				{
					res = (size_t)(pos - str) + 1U;
					break;
				}

				++pos;
			}
		}
	}

	return res;
}

/**
 * \brief Strictly parse decimal digits with overflow detection.
 * \param str: Input containing exactly slen digits or a terminal NUL.
 * \param slen: Input buffer length; embedded NUL bytes are rejected.
 * \param maximum: Highest accepted value.
 * \param value: Set only after successful parsing; no ownership transfer.
 * \return True for a valid in-range value, otherwise false.
 * \note Stateless and thread safe; never reads beyond slen.
 */
static bool arrayutils_try_parse_decimal(const char* str, size_t slen, uint64_t maximum, uint64_t* value)
{
	uint64_t acc;
	uint64_t digit;
	uint64_t maxdiv;
	uint64_t maxrem;
	size_t count;
	bool res;

	acc = 0U;
	maxdiv = maximum / 10U;
	maxrem = maximum % 10U;
	count = 0U;
	res = false;

	if (str != NULL && value != NULL && slen != 0U)
	{
		for (size_t i = 0U; i < slen; ++i)
		{
			if (str[i] == '\0' && i == slen - 1U)
			{
				break;
			}

			if (str[i] < '0' || str[i] > '9')
			{
				count = 0U;
				break;
			}

			digit = (uint64_t)(str[i] - '0');

			if (acc > maxdiv || (acc == maxdiv && digit > maxrem))
			{
				count = 0U;
				break;
			}

			acc = (acc * 10U) + digit;
			++count;
		}

		if (count != 0U)
		{
			*value = acc;
			res = true;
		}
	}

	return res;
}

bool qsc_arrayutils_try_parse_uint8(const char* str, size_t slen, uint8_t* value)
{
	uint64_t tmp;
	bool res;

	res = arrayutils_try_parse_decimal(str, slen, UINT8_MAX, &tmp);

	if (res == true && value != NULL)
	{
		*value = (uint8_t)tmp;
	}
	else
	{
		res = false;
	}

	return res;
}

bool qsc_arrayutils_try_parse_uint16(const char* str, size_t slen, uint16_t* value)
{
	uint64_t tmp;
	bool res;

	res = arrayutils_try_parse_decimal(str, slen, UINT16_MAX, &tmp);

	if (res == true && value != NULL)
	{
		*value = (uint16_t)tmp;
	}
	else
	{
		res = false;
	}

	return res;
}

bool qsc_arrayutils_try_parse_uint32(const char* str, size_t slen, uint32_t* value)
{
	uint64_t tmp;
	bool res;

	res = arrayutils_try_parse_decimal(str, slen, UINT32_MAX, &tmp);

	if (res == true && value != NULL)
	{
		*value = (uint32_t)tmp;
	}
	else
	{
		res = false;
	}

	return res;
}

bool qsc_arrayutils_try_parse_uint64(const char* str, size_t slen, uint64_t* value)
{
	return arrayutils_try_parse_decimal(str, slen, UINT64_MAX, value);
}

uint8_t qsc_arrayutils_hex_to_uint8(const char* str, size_t slen)
{
    QSC_ASSERT(str != NULL);
    QSC_ASSERT(slen >= 2U);

    uint8_t res;
    uint8_t hi;
    uint8_t lo;
    char c;

    res = 0U;

    if (str != NULL && slen > 1U)
    {
        c = str[0U];

        if ((c >= '0') && (c <= '9'))
        {
            hi = (uint8_t)(c - '0');
        }
        else if ((c >= 'A') && (c <= 'F'))
        {
            hi = (uint8_t)(c - 'A' + 10U);
        }
        else if ((c >= 'a') && (c <= 'f'))
        {
            hi = (uint8_t)(c - 'a' + 10U);
        }
        else
        {
            hi = 0U;
        }

        c = str[1U];

        if ((c >= '0') && (c <= '9'))
        {
            lo = (uint8_t)(c - '0');
        }
        else if ((c >= 'A') && (c <= 'F'))
        {
            lo = (uint8_t)(c - 'A' + 10U);
        }
        else if ((c >= 'a') && (c <= 'f'))
        {
            lo = (uint8_t)(c - 'a' + 10U);
        }
        else
        {
            lo = 0U;
        }

        res = (uint8_t)((hi << 4U) | lo);
    }

    return res;
}

void qsc_arrayutils_uint8_to_hex(char* output, size_t otplen, uint8_t value)
{
    QSC_ASSERT(output != NULL);

    if (output != NULL && otplen >= 3U)
    {
        static const char hexmap[] = "0123456789abcdef";

        output[0U] = hexmap[(value >> 4U) & 0x0FU];
        output[1U] = hexmap[value & 0x0FU];
        output[2U] = '\0';
    }
}

void qsc_arrayutils_uint16_to_hex(char* output, size_t otplen, uint16_t value)
{
    QSC_ASSERT(output != NULL);

    if (output != NULL && otplen >= 5U)
    {
        static const char hexmap[] = "0123456789abcdef";

        for (uint8_t i = 0U; i < 4U; ++i)
        {
            output[i] = hexmap[(value >> ((3U - i) * 4U)) & 0x0FU];
        }

        output[4U] = '\0';
    }
}

void qsc_arrayutils_uint32_to_hex(char* output, size_t otplen, uint32_t value)
{
    QSC_ASSERT(output != NULL);

    if (otplen >= 9U && output != NULL)
    {
        static const char hexmap[] = "0123456789abcdef";

        for (uint8_t i = 0U; i < 8U; ++i)
        {
            output[i] = hexmap[(value >> ((7U - i) * 4U)) & 0x0FU];
        }

        output[8U] = '\0';
    }
}

void qsc_arrayutils_uint64_to_hex(char* output, size_t otplen, uint64_t value)
{
    QSC_ASSERT(output != NULL);

    if (otplen >= 17U && output != NULL)
    {
        static const char hexmap[] = "0123456789abcdef";

        for (uint8_t i = 0U; i < 16U; ++i)
        {
            output[i] = hexmap[(uint8_t)((value >> ((15U - i) * 4U)) & 0x0FU)];
        }

        output[16U] = '\0';
    }
}

uint8_t qsc_arrayutils_string_to_uint8(const char* str, size_t slen)
{
    QSC_ASSERT(str != NULL);
    QSC_ASSERT(slen != 0U);

    uint8_t res;

    res = 0U;

    if (str != NULL && slen != 0U)
    {
        for (size_t i = 0U; (i < slen) && (str[i] != '\0'); ++i)
        {
            char c = str[i];

            if ((c >= '0') && (c <= '9'))
            {
                res = (uint8_t)(res * 10U + (uint8_t)(c - '0'));
            }
            else
            {
                break;
            }
        }
    }

    return res;
}

uint16_t qsc_arrayutils_string_to_uint16(const char* str, size_t slen)
{
    QSC_ASSERT(str != NULL);
    QSC_ASSERT(slen != 0U);

    uint16_t res;

    res = 0U;

    if (str != NULL)
    {
        for (size_t i = 0U; (i < slen) && (str[i] != '\0'); ++i)
        {
            char c = str[i];

            if ((c >= '0') && (c <= '9'))
            {
                uint16_t digit = (uint16_t)(c - '0');

                if (res <= (UINT16_MAX - digit) / 10U)
                {
                    res = (uint16_t)(res * 10U + digit);
                }
                else
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }
    }

    return res;
}

uint32_t qsc_arrayutils_string_to_uint32(const char* str, size_t slen)
{
    QSC_ASSERT(str != NULL);
    QSC_ASSERT(slen != 0U);

    uint32_t digit;
    uint32_t res;

    res = 0U;

    if (str != NULL)
    {
        for (size_t i = 0U; (i < slen) && (str[i] != '\0'); ++i)
        {
            char c = str[i];

            if ((c >= '0') && (c <= '9'))
            {
                digit = c - '0';

                if (res > (UINT32_MAX - digit) / 10)
                {
                    res = UINT32_MAX;
                    break;
                }

                res = (uint32_t)(res * 10U + digit);
            }
            else
            {
                break;
            }
        }
    }

    return res;
}

uint64_t qsc_arrayutils_string_to_uint64(const char* str, size_t slen)
{
	QSC_ASSERT(str != NULL);
	QSC_ASSERT(slen != 0U);

	uint64_t digit;
	uint64_t res;

	res = 0U;

	if (str != NULL && slen != 0U)
	{
		for (size_t i = 0U; i < slen && str[i] != '\0'; ++i)
		{
			if (str[i] < '0' || str[i] > '9')
			{
				break;
			}

			digit = (uint64_t)(str[i] - '0');

			if (res > (UINT64_MAX - digit) / 10U)
			{
				res = UINT64_MAX;
				break;
			}

			res = (res * 10U) + digit;
		}
	}

	return res;
}

#if defined(QSC_DEBUG_MODE)
bool qsc_arrayutils_self_test()
{
	const char nstr[] = "1 192 32180 497683 189167334201522";
	const char slng[] = "189167334201522";
	const char sint[] = "497683";
	const char ssht[] = "32180";
	const char schr1[] = "1";
	const char schr2[] = "192";
	char shex[3U] = { 0U };
	const uint64_t nlng = 189167334201522U;
	const uint32_t nint = 497683U;
	const uint16_t nsht = 32180U;
	const uint8_t nchr1 = 1U;
	const uint8_t nchr2 = 192U;
	uint64_t x64;
	size_t pos;
	uint32_t x32;
	uint16_t x16;
	uint8_t x8;
	uint8_t y8;
	bool res;

	res = true;

	pos = qsc_arrayutils_find_string(nstr, sizeof(nstr), schr1);

	if (pos != 1U)
	{
		res = false;
	}

	pos = qsc_arrayutils_find_string(nstr, sizeof(nstr), schr2);

	if (pos != 3U)
	{
		res = false;
	}

	pos = qsc_arrayutils_find_string(nstr, sizeof(nstr), ssht);

	if (pos != 7U)
	{
		res = false;
	}

	pos = qsc_arrayutils_find_string(nstr, sizeof(nstr), sint);

	if (pos != 13U)
	{
		res = false;
	}

	pos = qsc_arrayutils_find_string(nstr, sizeof(nstr), slng);

	if (pos != 20U)
	{
		res = false;
	}

	for (size_t i = 0U; i < 256U; ++i)
	{
		x8 = (uint8_t)i;
		qsc_arrayutils_uint8_to_hex(shex, sizeof(shex), x8);
		y8 = qsc_arrayutils_hex_to_uint8(shex, sizeof(shex));

		if (x8 != y8)
		{
			res = false;
			break;
		}
	}

	x8 = qsc_arrayutils_string_to_uint8(schr1, sizeof(schr1));

	if (x8 != nchr1)
	{
		res = false;
	}

	x8 = qsc_arrayutils_string_to_uint8(schr2, sizeof(schr2));

	if (x8 != nchr2)
	{
		res = false;
	}

	x16 = qsc_arrayutils_string_to_uint16(ssht, sizeof(ssht));

	if (x16 != nsht)
	{
		res = false;
	}

	x32 = qsc_arrayutils_string_to_uint32(sint, sizeof(sint));

	if (x32 != nint)
	{
		res = false;
	}

	x64 = qsc_arrayutils_string_to_uint64(slng, sizeof(slng));

	if (x64 != nlng)
	{
		res = false;
	}

	return res;
}
#endif
