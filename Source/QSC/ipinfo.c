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

#include "ipinfo.h"
#include "memutils.h"
#include "stringutils.h"
#include <ctype.h>
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
#	define WIN32_LEAN_AND_MEAN
#	define VC_EXTRALEAN
#	include <winsock2.h>
#	include <ws2tcpip.h>
#else
#	include <arpa/inet.h>
#	include <netinet/in.h>
#endif

/**
 * \brief Parse a complete, canonical dotted-decimal IPv4 address.
 * \param input NUL-terminated IPv4 address string, at most 15 characters.
 * \param output Four bytes populated only on successful parsing.
 * \return true for four valid decimal octets with no trailing input.
 * \note No allocation; callers must supply a valid NUL-terminated string.
 */
static bool ipinfo_ipv4_parse(const char* input, uint8_t output[QSC_IPINFO_IPV4_BYTELEN])
{
	uint8_t bytes[QSC_IPINFO_IPV4_BYTELEN] = { 0U };
	const char* cur;
	uint32_t value;
	size_t octet;
	size_t digits;
	bool res;

	res = false;

	if (input != NULL && output != NULL)
	{
		cur = input;
		res = true;

		for (octet = 0U; octet < QSC_IPINFO_IPV4_BYTELEN && res == true; ++octet)
		{
			value = 0U;
			digits = 0U;

			while (cur[0U] >= '0' && cur[0U] <= '9' && digits < 3U)
			{
				if (digits == 1U && cur[-1] == '0')
				{
					res = false;
					break;
				}

				value = (value * 10U) + (uint32_t)(cur[0U] - '0');
				++cur;
				++digits;
			}

			if (digits == 0U || value > 255U)
			{
				res = false;
			}
			else if (octet < (QSC_IPINFO_IPV4_BYTELEN - 1U))
			{
				if (cur[0U] != '.')
				{
					res = false;
				}
				else
				{
					++cur;
				}
			}

			bytes[octet] = (uint8_t)value;
		}

		if (res == true && cur[0U] == '\0')
		{
			qsc_memutils_copy(output, bytes, sizeof(bytes));
		}
		else
		{
			res = false;
		}
	}

	return res;
}

qsc_ipinfo_address_types qsc_ipinfo_get_address_type(const char* address)
{
	QSC_ASSERT(address != NULL);

	qsc_ipinfo_address_types res;

	res = qsc_ipinfo_address_type_unknown;

	if (address != NULL)
	{
		if (qsc_ipinfo_ipv4_address_string_is_valid(address) == true)
		{
			res = qsc_ipinfo_address_type_ipv4;
		}
		else if (qsc_ipinfo_ipv6_address_string_is_valid(address) == true)
		{
			res = qsc_ipinfo_address_type_ipv6;
		}
	}

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_any(void)
{
	qsc_ipinfo_ipv4_address res;

	res.ipv4[0U] = 0U;
    res.ipv4[1U] = 0U;
    res.ipv4[2U] = 0U;
    res.ipv4[3U] = 0U;

	return res;
}

void qsc_ipinfo_ipv4_address_clear(qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);

	if (address != NULL)
	{
		qsc_memutils_clear(address->ipv4, QSC_IPINFO_IPV4_BYTELEN);
	}
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_array(const uint8_t* address)
{
	QSC_ASSERT(address != NULL);

	qsc_ipinfo_ipv4_address res = { 0U };

	if (address != NULL)
	{
		qsc_memutils_copy(res.ipv4, address, QSC_IPINFO_IPV4_BYTELEN);
	}

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_bytes(uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4)
{
	qsc_ipinfo_ipv4_address res = 
	{
		.ipv4[0U] = a1,
		.ipv4[1U] = a2,
		.ipv4[2U] = a3,
		.ipv4[3U] = a4 
	};

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_string(const char input[QSC_IPINFO_IPV4_STRNLEN])
{
	QSC_ASSERT(input != NULL);

	qsc_ipinfo_ipv4_address res = { 0U };

	(void)ipinfo_ipv4_parse(input, res.ipv4);

	return res;
}

bool qsc_ipinfo_ipv4_address_is_equal(const qsc_ipinfo_ipv4_address* a, const qsc_ipinfo_ipv4_address* b)
{
	QSC_ASSERT(a != NULL);
	QSC_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		res = true;

		for (size_t i = 0U; i < sizeof(a->ipv4); ++i)
		{
			if (a->ipv4[i] != b->ipv4[i])
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

bool qsc_ipinfo_ipv4_address_is_routable(const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv4[0U] == 192U && address->ipv4[1U] == 168U)
		{
			res = false;
		}
		else if (address->ipv4[0U] == 172U && (address->ipv4[1U] >= 16U && address->ipv4[1U] <= 31U))
		{
			res = false;
		}
		else if (address->ipv4[0U] == 10U)
		{
			res = false;
		}
		else if (address->ipv4[0U] == 127U)
		{
			res = false;
		}
		else if (address->ipv4[0U] > 223U)
		{
			res = false;
		}
		else
		{
			res = true;
		}
	}

	return res;
}

bool qsc_ipinfo_ipv4_address_is_valid(const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);

	uint8_t a;
	uint8_t b;
	bool res;

	res = false;

	if (address != NULL)
	{
		a = address->ipv4[0U];
		b = address->ipv4[1U];

		if (a != 0U)
		{
			if (a != 169U || b != 254U)
			{
				if (a < 224U)
				{
					res = true;
				}
			}
		}
	}

	return res;
}

bool qsc_ipinfo_ipv4_address_string_is_valid(const char* address)
{
	QSC_ASSERT(address != NULL);

	uint8_t bytes[QSC_IPINFO_IPV4_BYTELEN];
	bool res;

	res = ipinfo_ipv4_parse(address, bytes);

	return res;
}

bool qsc_ipinfo_ipv4_address_is_zeroed(const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		res = (address != NULL && address->ipv4[0U] == 0U && address->ipv4[1U] == 0U && address->ipv4[2U] == 0U && address->ipv4[3U] == 0U);
	}

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_loopback(void)
{
	qsc_ipinfo_ipv4_address res = {
		.ipv4[0U] = 127U,
		.ipv4[1U] = 0U,
		.ipv4[2U] = 0U,
		.ipv4[3U] = 1U };

	return res;
}

void qsc_ipinfo_ipv4_address_get_mask(char mask[QSC_IPINFO_IPV4_MASK_STRNLEN], const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);
	QSC_ASSERT(mask != NULL);

	if (address != NULL && mask != NULL)
	{
		qsc_memutils_clear(mask, QSC_IPINFO_IPV4_MASK_STRNLEN);

		if (address->ipv4[0U] > 0U && address->ipv4[0U] < 127U)
		{
			qsc_stringutils_copy_string(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, "255.0.0.0");
		}
		else if (address->ipv4[0U] > 127U && address->ipv4[0U] < 192U)
		{
			qsc_stringutils_copy_string(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, "255.255.0.0");
		}
		else if (address->ipv4[0U] > 191U && address->ipv4[0U] < 224U)
		{
			qsc_stringutils_copy_string(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, "255.255.255.0");
		}
		else
		{
			qsc_stringutils_copy_string(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, "255.255.255.255");
		}
	}
}

uint8_t qsc_ipinfo_ipv4_address_get_cidr_mask(const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);

	uint8_t nmsk;

	nmsk = 0;

	if (address != NULL)
	{
		if (address->ipv4[0U] > 0U && address->ipv4[0U] < 127U)
		{
			nmsk = 8U;
		}
		else if (address->ipv4[0U] > 127U && address->ipv4[0U] < 192U)
		{
			nmsk = 16U;
		}
		else if (address->ipv4[0U] > 191U && address->ipv4[0U] < 224U)
		{
			nmsk = 24U;
		}
		else
		{
			nmsk = 32U;
		}
	}

	return nmsk;
}

void qsc_ipinfo_ipv4_address_to_array(uint8_t* output, const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (address != NULL && output != NULL)
	{
		qsc_memutils_copy(output, address->ipv4, sizeof(address->ipv4));
	}
}

void qsc_ipinfo_ipv4_address_to_string(char output[QSC_IPINFO_IPV4_STRNLEN], const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (output != NULL && address != NULL)
	{
		(void)snprintf(output, QSC_IPINFO_IPV4_STRNLEN, "%u.%u.%u.%u",
			(unsigned)address->ipv4[0U], (unsigned)address->ipv4[1U],
			(unsigned)address->ipv4[2U], (unsigned)address->ipv4[3U]);
	}
}

void qsc_ipinfo_ipv4_array_to_string(char output[QSC_IPINFO_IPV4_STRNLEN], const uint8_t* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (output != NULL && address != NULL)
	{
		(void)snprintf(output, QSC_IPINFO_IPV4_STRNLEN, "%u.%u.%u.%u",
			(unsigned)address[0U], (unsigned)address[1U],
			(unsigned)address[2U], (unsigned)address[3U]);
	}
}

uint8_t qsc_ipinfo_ipv4_mask_to_cidr(const char mask[QSC_IPINFO_IPV4_MASK_STRNLEN])
{
	QSC_ASSERT(mask != NULL);

	uint8_t octets[QSC_IPINFO_IPV4_BYTELEN];
	uint8_t bits;
	size_t i;
	uint32_t value;
	bool seenzero;
	bool valid;

	bits = 0U;
	seenzero = false;
	valid = ipinfo_ipv4_parse(mask, octets);

	if (valid == true)
	{
		value = qsc_intutils_be8to32(octets);

		for (i = 0U; i < 32U; ++i)
		{
			if ((value & (UINT32_C(0x80000000) >> i)) != 0U)
			{
				if (seenzero == true)
				{
					valid = false;
					break;
				}

				++bits;
			}
			else
			{
				seenzero = true;
			}
		}
	}

	if (valid == false)
	{
		bits = 0U;
	}

	return bits;
}

void qsc_ipinfo_ipv4_cidr_to_mask(char mask[QSC_IPINFO_IPV4_MASK_STRNLEN], uint8_t cidr)
{
	QSC_ASSERT(mask != NULL);

	uint8_t bytes[QSC_IPINFO_IPV4_BYTELEN] = { 0U };
	size_t i;

	if (mask != NULL)
	{
		if (cidr > 32U)
		{
			cidr = 32U;
		}

		for (i = 0U; i < (size_t)cidr; ++i)
		{
			bytes[i / 8U] |= (uint8_t)(0x80U >> (i % 8U));
		}

		(void)snprintf(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, "%u.%u.%u.%u",
			(unsigned)bytes[0U], (unsigned)bytes[1U], (unsigned)bytes[2U], (unsigned)bytes[3U]);
	}
}

qsc_ipv6_address_prefix_types qsc_ipinfo_ipv6_address_type(const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	qsc_ipv6_address_prefix_types ptype;

	ptype = qsc_ipv6_prefix_none;

	if (address != NULL)
	{
		if (address->ipv6[0U] == 0xFFU)
		{
			ptype = qsc_ipv6_prefix_multicast;
		}
		else if (address->ipv6[0U] == 0xFEU)
		{
			ptype = qsc_ipv6_prefix_link_local;
		}
		else if (address->ipv6[0U] == 0xFDU || address->ipv6[0U] == 0xFCU)
		{
			ptype = qsc_ipv6_prefix_unique_local;
		}
		else
		{
			ptype = qsc_ipv6_prefix_global;
		}
	}

	return ptype;
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_any(void)
{
	qsc_ipinfo_ipv6_address res = { 0U };

	return res;
}

void qsc_ipinfo_ipv6_address_clear(qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	if (address != NULL)
	{
		qsc_memutils_clear(address->ipv6, QSC_IPINFO_IPV6_BYTELEN);
	}
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_from_array(const uint8_t* address)
{
	QSC_ASSERT(address != NULL);

	qsc_ipinfo_ipv6_address res = { 0U };

	if (address != NULL)
	{
		qsc_memutils_copy(res.ipv6, address, QSC_IPINFO_IPV6_BYTELEN);
	}

	return res;
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_from_string(const char input[QSC_IPINFO_IPV6_STRNLEN])
{
	QSC_ASSERT(input != NULL);

	qsc_ipinfo_ipv6_address res = { 0U };

	if (input != NULL)
	{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		struct in6_addr tmp6;

		if (InetPton(AF_INET6, input, &tmp6) == 1)
		{
			qsc_memutils_copy(res.ipv6, &tmp6, QSC_IPINFO_IPV6_BYTELEN);
		}
#else
		struct in6_addr tmp6;

		if (inet_pton(AF_INET6, input, &tmp6) == 1)
		{
			qsc_memutils_copy(res.ipv6, &tmp6, QSC_IPINFO_IPV6_BYTELEN);
		}
#endif
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_is_equal(const qsc_ipinfo_ipv6_address* a, const qsc_ipinfo_ipv6_address* b)
{
	QSC_ASSERT(a != NULL);
	QSC_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		res = qsc_memutils_are_equal(a->ipv6, b->ipv6, QSC_IPINFO_IPV6_BYTELEN);
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_is_routable(const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv6[0U] == 0U)
		{
			res = false;
		}
		else if (address->ipv6[0U] == 1U)
		{
			res = false;
		}
		else if (address->ipv6[0U] == 255U && address->ipv6[1U] == 0U)
		{
			res = false;
		}
		else if (address->ipv6[0U] == 254U && address->ipv6[1U] == 128U)
		{
			res = false;
		}
		else
		{
			qsc_ipv6_address_prefix_types ptype;

			ptype = qsc_ipinfo_ipv6_address_type(address);
			res = (ptype != qsc_ipv6_prefix_link_local && ptype != qsc_ipv6_prefix_unique_local);
		}
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_is_valid(const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv6[0U] == 0U)
		{
			res = false;
		}
		else if (address->ipv6[0U] == 1U)
		{
			res = false;
		}
		else if (address->ipv6[2U] == 219U && address->ipv6[3U] == 128U)
		{
			res = false;
		}
		else
		{
			res = true;
		}
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_string_is_valid(const char* address)
{
	QSC_ASSERT(address != NULL);

	struct in6_addr parsed;
	bool res;

	res = false;

	if (address != NULL)
	{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		res = (InetPtonA(AF_INET6, address, &parsed) == 1);
#else
		res = (inet_pton(AF_INET6, address, &parsed) == 1);
#endif
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_is_zeroed(const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv6[0U] == 0U && address->ipv6[1U] == 0U && address->ipv6[2U] == 0U && address->ipv6[3U] == 0U &&
			address->ipv6[4U] == 0U && address->ipv6[5U] == 0U && address->ipv6[6U] == 0U && address->ipv6[7U] == 0U &&
			address->ipv6[8U] == 0U && address->ipv6[9U] == 0U && address->ipv6[10U] == 0U && address->ipv6[11U] == 0U &&
			address->ipv6[12U] == 0U && address->ipv6[13U] == 0U && address->ipv6[14U] == 0U && address->ipv6[15U] == 0U)
		{
			res = true;
		}
	}

	return res;
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_loopback(void)
{
	qsc_ipinfo_ipv6_address add;

	add.ipv6[0U] = 0U;
    add.ipv6[1U] = 0U;
    add.ipv6[2U] = 0U;
    add.ipv6[3U] = 0U;
    add.ipv6[4U] = 0U;
    add.ipv6[5U] = 0U;
    add.ipv6[6U] = 0U;
    add.ipv6[7U] = 0U;
    add.ipv6[8U] = 0U;
    add.ipv6[9U] = 0U;
    add.ipv6[10U] = 0U;
    add.ipv6[11U] = 0U;
    add.ipv6[12U] = 0U;
    add.ipv6[13U] = 0U;
    add.ipv6[14U] = 0U;
    add.ipv6[15U] = 1U;

	return add;
}

void qsc_ipinfo_ipv6_address_get_mask(char mask[QSC_IPINFO_IPV6_MASK_STRNLEN], const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(mask != NULL);
	QSC_ASSERT(address != NULL);

	size_t ctr;

	if (mask != NULL && address != NULL)
	{
		ctr = QSC_IPINFO_IPV6_BYTELEN;

		do
		{
			--ctr;

			if (address->ipv6[ctr] == 0U)
			{
				mask[ctr] = 'f';
			}
			else
			{
				break;
			}
		} while (ctr != 0U);
	}
}

uint8_t qsc_ipinfo_ipv6_address_get_cidr_mask(const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	size_t ctr;
	uint8_t nmsk;

	nmsk = 0U;

	if (address != NULL)
	{
		ctr = QSC_IPINFO_IPV6_BYTELEN;

		do
		{
			--ctr;

			if (address->ipv6[ctr] == 0U)
			{
				++nmsk;
			}
			else
			{
				break;
			}
		} while (ctr != 0U);
	}

	return nmsk;
}

void qsc_ipinfo_ipv6_address_to_array(uint8_t* output, const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (address != NULL && output != NULL)
	{
		qsc_memutils_copy(output, address->ipv6, sizeof(address->ipv6));
	}
}

void qsc_ipinfo_ipv6_address_to_string(char output[QSC_IPINFO_IPV6_STRNLEN], const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (address != NULL && output != NULL)
	{
		const char DELIM = ':';
		uint16_t n;

		qsc_memutils_clear(output, QSC_IPINFO_IPV6_STRNLEN);

		n = qsc_intutils_be8to16(&address->ipv6[0U]);
		qsc_arrayutils_uint16_to_hex(&output[0U], 5, n);
		output[4U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[2U]);
		qsc_arrayutils_uint16_to_hex(&output[5U], 5U, n);
		output[9U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[4U]);
		qsc_arrayutils_uint16_to_hex(&output[10U], 5U, n);
		output[14U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[6U]);
		qsc_arrayutils_uint16_to_hex(&output[15U], 5U, n);
		output[19U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[8U]);
		qsc_arrayutils_uint16_to_hex(&output[20U], 5U, n);
		output[24U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[10U]);
		qsc_arrayutils_uint16_to_hex(&output[25U], 5U, n);
		output[29U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[12U]);
		qsc_arrayutils_uint16_to_hex(&output[30U], 5U, n);
		output[34U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[14U]);
		qsc_arrayutils_uint16_to_hex(&output[35U], 5U, n);
	}
}

void qsc_ipinfo_ipv6_array_to_string(char output[QSC_IPINFO_IPV6_STRNLEN], const uint8_t* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (address != NULL && output != NULL)
	{
		const char DELIM = ':';
		uint16_t n;

		qsc_memutils_clear(output, QSC_IPINFO_IPV6_STRNLEN);

		n = qsc_intutils_be8to16(&address[0U]);
		qsc_arrayutils_uint16_to_hex(&output[0U], 5, n);
		output[4U] = DELIM;
		n = qsc_intutils_be8to16(&address[2U]);
		qsc_arrayutils_uint16_to_hex(&output[5U], 5U, n);
		output[9U] = DELIM;
		n = qsc_intutils_be8to16(&address[4U]);
		qsc_arrayutils_uint16_to_hex(&output[10U], 5U, n);
		output[14U] = DELIM;
		n = qsc_intutils_be8to16(&address[6U]);
		qsc_arrayutils_uint16_to_hex(&output[15U], 5U, n);
		output[19U] = DELIM;
		n = qsc_intutils_be8to16(&address[8U]);
		qsc_arrayutils_uint16_to_hex(&output[20U], 5U, n);
		output[24U] = DELIM;
		n = qsc_intutils_be8to16(&address[10U]);
		qsc_arrayutils_uint16_to_hex(&output[25U], 5U, n);
		output[29U] = DELIM;
		n = qsc_intutils_be8to16(&address[12U]);
		qsc_arrayutils_uint16_to_hex(&output[30U], 5U, n);
		output[34U] = DELIM;
		n = qsc_intutils_be8to16(&address[14U]);
		qsc_arrayutils_uint16_to_hex(&output[35U], 5U, n);
	}
}

/**
 * \brief Test IPv4 CIDR prefix membership, including /0 and /32.
 * \param address Address being tested.
 * \param network Network-prefix address; host bits are ignored.
 * \param prefix Prefix length in bits, from 0 to 32.
 * \return true if the address belongs to the prefix; false for invalid inputs.
 * \note Stateless; no allocations; safe for concurrent callers.
 */
bool qsc_ipinfo_ipv4_prefix_contains(const qsc_ipinfo_ipv4_address* address, const qsc_ipinfo_ipv4_address* network, uint8_t prefix)
{
	size_t i;
	uint8_t rem;
	bool res;

	res = (address != NULL && network != NULL && prefix <= 32U);

	if (res == true)
	{
		for (i = 0U; i < (size_t)(prefix / 8U); ++i)
		{
			if (address->ipv4[i] != network->ipv4[i])
			{
				res = false;
					break;
			}
		}

		rem = (uint8_t)(prefix % 8U);

		if (res == true && rem != 0U)
		{
			uint8_t mask;

			mask = (uint8_t)(0xFFU << (8U - rem));
			res = ((address->ipv4[i] & mask) == (network->ipv4[i] & mask));
		}
	}

	return res;
}

/**
 * \brief Test IPv6 CIDR prefix membership, including /0 and /128.
 * \param address Address being tested.
 * \param network Network-prefix address; host bits are ignored.
 * \param prefix Prefix length in bits, from 0 to 128.
 * \return true if the address belongs to the prefix; false for invalid inputs.
 * \note Stateless; no allocations; safe for concurrent callers.
 */
bool qsc_ipinfo_ipv6_prefix_contains(const qsc_ipinfo_ipv6_address* address, const qsc_ipinfo_ipv6_address* network, uint8_t prefix)
{
	size_t i;
	uint8_t rem;
	bool res;

	res = (address != NULL && network != NULL && prefix <= 128U);

	if (res == true)
	{
		for (i = 0U; i < (size_t)(prefix / 8U); ++i)
		{
			if (address->ipv6[i] != network->ipv6[i])
			{
				res = false;
					break;
			}
		}

		rem = (uint8_t)(prefix % 8U);

		if (res == true && rem != 0U)
		{
			uint8_t mask;

			mask = (uint8_t)(0xFFU << (8U - rem));
			res = ((address->ipv6[i] & mask) == (network->ipv6[i] & mask));
		}
	}

	return res;
}
