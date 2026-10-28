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

#include "stringutils.h"
#include "memutils.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QSC_STRING_MAX_LEN (1024U * 1024U * 10U)

char* strsepex(char** stringp, const char* delim)
{
	char* rv = *stringp;

	if (rv != NULL)
	{
		*stringp += strcspn(*stringp, delim);

		if (**stringp != '\0')
		{
			*(*stringp)++ = '\0';
		}
		else
		{
			*stringp = NULL;
		}
	}

	return rv;
}

size_t qsc_stringutils_add_line_breaks(char* dest, size_t dstlen, size_t linelen, const char* source, size_t srclen)
{
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(linelen != 0U);

	size_t blen;
	size_t i;
	size_t j;

	j = 0;

	if (dest != NULL && source != NULL && linelen != 0U)
	{
		blen = srclen + ((srclen / linelen) + 1U);

		if (dstlen >= blen)
		{
			for (i = 0U, j = 0U; i < srclen; ++i, ++j)
			{
				dest[j] = source[i];

				if (i != 0U && (i + 1U) % linelen == 0U)
				{
					++j;
					dest[j] = '\n';
				}
			}

			++j;
			dest[j] = '\n';
		}
	}

	if (j > 0U)
	{
		return j - 1U;
	}
	else
	{
		j = 0U;
	}

	return j;
}

size_t qsc_stringutils_remove_line_breaks(char* dest, size_t dstlen, const char* source, size_t srclen)
{
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(source != NULL);

	size_t i;
	size_t j;

	j = 0U;

	if (dest != NULL && source != NULL)
	{
		for (i = 0U, j = 0U; i < srclen; ++i)
		{
			if (j > dstlen - 1)
			{
				break;
			}

			if (source[i] != '\n')
			{
				dest[j] = source[i];
				++j;
			}
		}
	}

	return j;
}

void qsc_stringutils_clear_string(char* source)
{
	QSC_ASSERT(source != NULL);

	size_t len;

	if (source != NULL)
	{
		len = strlen(source);

		if (len > 0U)
		{
			qsc_memutils_clear(source, len);
		}
	}
}

void qsc_stringutils_clear_substring(char* dest, size_t length)
{
	QSC_ASSERT(dest != NULL);

	if (dest != NULL && length != 0U)
	{
		qsc_memutils_clear(dest, length);
	}
}

bool qsc_stringutils_compare_strings(const char* str1, const char* str2, size_t length)
{
	QSC_ASSERT(str1 != NULL);
	QSC_ASSERT(str2 != NULL);

	uint8_t acc;

	acc = 0U;

	if (str1 != NULL && str2 != NULL) 
	{
		for (size_t i = 0U; i < length; ++i)
		{
			acc |= (uint8_t)(str1[i] ^ str2[i]);
		}
	}

	return (acc == 0U);
}

size_t qsc_stringutils_concat_strings(char* dest, size_t dstlen, const char* source)
{
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(source != NULL);

	size_t pos;

	pos = 0U;

	if (dest != NULL && source != NULL)
	{
		size_t dlen;
		size_t slen;

		dlen = strlen(dest);
		slen = strlen(source);

		if (slen > 0U && slen < dstlen - dlen)
		{
			errno_t err;

#if defined(QSC_SYSTEM_OS_WINDOWS)
			err = strcat_s(dest, dstlen, source);
#else
			err = (strcat(dest, source) != NULL) ? 0 : -1;
#endif
			if (err == 0)
			{
				pos = dlen + slen;
				qsc_memutils_clear(dest + pos, dstlen - pos);
			}
		}
	}

	return pos;
}

size_t qsc_stringutils_concat_and_copy(char* dest, size_t dstlen, const char* str1, const char* str2)
{
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(str1 != NULL);
	QSC_ASSERT(str2 != NULL);

	size_t res;
	size_t slen;

	res = 0;

	if (dest != NULL && str1 != NULL && str2 != NULL)
	{
		if (strlen(dest) > 0U)
		{
			qsc_stringutils_clear_string(dest);
		}

		slen = strlen(str1) + strlen(str2);

		if (slen < dstlen)
		{
			if (strlen(str1) > 0U)
			{
				slen = qsc_stringutils_copy_string(dest, dstlen, str1);
			}

			if (strlen(str2) > 0U)
			{
				qsc_stringutils_copy_string((dest + slen), dstlen, str2);
			}
		}

		res = strlen(dest);
	}

	return res;
}

size_t qsc_stringutils_copy_string(char* dest, size_t dstlen, const char* source)
{
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(source != NULL);

	errno_t err;
	size_t res;
	size_t slen;

	res = 0U;

	if (dest != NULL && source != NULL)
	{
		err = 0;
		slen = strlen(source);

		if (slen > 0U && slen < dstlen)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			err = strcpy_s(dest, slen + 1U, source);
#else
			err = (strcpy(dest, source) != NULL) ? 0 : -1;
#endif
		}

		if (err == 0)
		{
			res = strlen(dest);
		}
	}

	return res;
}

size_t qsc_stringutils_copy_substring(char* dest, size_t dstlen, const char* source, size_t srclen)
{
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(source != NULL);

	size_t res;

	res = 0U;

	if (dest != NULL && source != NULL)
	{
		if (srclen > 0U && srclen <= dstlen)
		{
			qsc_memutils_copy(dest, source, srclen);
		}

		res = strlen(dest);
	}

	return res;
}

size_t qsc_stringutils_formatting_count(const char* dest, size_t dstlen)
{
	QSC_ASSERT(dest != NULL);

	size_t ctr;

	ctr = 0;

	if (dest != NULL && dstlen > 0U)
	{
		for (size_t i = 0U; i < dstlen; ++i)
		{
			if (dest[i] != ' ' && dest[i] != '\t' && dest[i] != '\n' && dest[i] != '\r')
			{
				++ctr;
			}
		}
	}

	return ctr;
}

size_t qsc_stringutils_formatting_filter(const char* source, size_t srclen, char* dest)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(dest != NULL);

	size_t ctr;

	ctr = 0U;

	if (source != NULL && dest != NULL && srclen > 0)
	{
		for (size_t i = 0U; i < srclen; ++i)
		{
			if (source[i] != ' ' && source[i] != '\t' && source[i] != '\n' && source[i] != '\r')
			{
				dest[ctr] = source[i];
				++ctr;
			}
		}
	}

	return ctr;
}

int64_t qsc_stringutils_find_char(const char* source, const char tok)
{
	QSC_ASSERT(source != NULL);

	const char* sub;
	int64_t pos;

	pos = QSC_STRINGUTILS_TOKEN_NOT_FOUND;

	if (source != NULL)
	{
		sub = strchr(source, tok);

		if (sub != NULL)
		{
			pos = (int64_t)(sub - source);
		}
	}

	return pos;
}

int64_t qsc_stringutils_find_string(const char* source, const char* token)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(token != NULL);

	const char* sub;
	int64_t pos;

	pos = QSC_STRINGUTILS_TOKEN_NOT_FOUND;

	if (source != NULL && token != NULL)
	{
		sub = strstr(source, token);

		if (sub != NULL)
		{
			pos = (int64_t)(sub - source);
		}
	}

	return pos;
}

void qsc_stringutils_byte_to_hex(char* hex, uint8_t input)
{
	QSC_ASSERT(hex != NULL);

	static const char HEX_TABLE[] = "0123456789abcdef";

	if (hex != NULL)
	{
		hex[0U] = HEX_TABLE[input >> 4U];
		hex[1U] = HEX_TABLE[input & 0x0FU];
		hex[2U] = '\0';
	}
}

uint8_t qsc_stringutils_hex_to_byte(const char* hex)
{
	QSC_ASSERT(hex != NULL);

	uint8_t high;
	uint8_t low;
	uint8_t res;

	res = 0U;

	if (hex != NULL)
	{
		/* Keep strtol semantics for signed, prefixed, or non-two-digit input. */
		if (hex[0U] >= '0' && hex[0U] <= '9')
		{
			high = (uint8_t)(hex[0U] - '0');
		}
		else if (hex[0U] >= 'a' && hex[0U] <= 'f')
		{
			high = (uint8_t)(hex[0U] - 'a' + 10U);
		}
		else if (hex[0U] >= 'A' && hex[0U] <= 'F')
		{
			high = (uint8_t)(hex[0U] - 'A' + 10U);
		}
		else
		{
			high = UINT8_MAX;
		}

		low = UINT8_MAX;

		if (high != UINT8_MAX)
		{
			if (hex[1U] >= '0' && hex[1U] <= '9')
			{
				low = (uint8_t)(hex[1U] - '0');
			}
			else if (hex[1U] >= 'a' && hex[1U] <= 'f')
			{
				low = (uint8_t)(hex[1U] - 'a' + 10U);
			}
			else if (hex[1U] >= 'A' && hex[1U] <= 'F')
			{
				low = (uint8_t)(hex[1U] - 'A' + 10U);
			}
		}

		if (low != UINT8_MAX && hex[2U] == '\0')
		{
			res = (uint8_t)((high << 4U) | low);
		}
		else
		{
			res = (uint8_t)strtol(hex, NULL, 16);
		}
	}

	return res;
}

int64_t qsc_stringutils_insert_string(char* dest, size_t dstlen, const char* source, size_t offset)
{
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(source != NULL);

	size_t dlen;
	size_t slen;
	size_t i;
	int64_t res;

	res = QSC_STRINGUTILS_TOKEN_NOT_FOUND;

	if (dest != NULL && source != NULL)
	{
		dlen = qsc_stringutils_string_size(dest);
		slen = qsc_stringutils_string_size(source);

		if (slen != 0U && offset <= dlen && (dlen + slen) < dstlen)
		{
			i = dlen + 1U;

			while (i > offset)
			{
				dest[i + slen - 1U] = dest[i - 1U];
				--i;
			}

			qsc_memutils_copy((dest + offset), source, slen);

			res = (int64_t)(dlen + slen);
		}
	}

	return res;
}

void qsc_stringutils_int_to_string(int32_t num, char* dest, size_t destlen)
{
	QSC_ASSERT(dest != NULL);

	if (dest != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_itoa_s(num, dest, destlen, 10);
#else
		snprintf(dest, destlen, "%d", num);
#endif
	}
}

void qsc_stringutils_uint32_to_string(uint32_t num, char* dest, size_t destlen)
{
	QSC_ASSERT(dest != NULL);

	if (dest != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_ultoa_s(num, dest, destlen, 10);
#else
		snprintf(dest, destlen, "%u", num);
#endif
	}
}

void qsc_stringutils_int64_to_string(int64_t num, char* dest, size_t dstlen)
{
	QSC_ASSERT(dest != NULL);

	if (dest != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_i64toa_s(num, dest, dstlen, 10);
#elif defined(QSC_SYSTEM_OS_LINUX)
		snprintf(dest, dstlen, "%ld", num);
#else
		snprintf(dest, dstlen, "%lld", num);
#endif
	}
}

void qsc_stringutils_uint64_to_string(uint64_t num, char* dest, size_t dstlen)
{
	QSC_ASSERT(dest != NULL);

	if (dest != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_ui64toa_s(num, dest, dstlen, 10);
#elif defined(QSC_SYSTEM_OS_LINUX)
		snprintf(dest, dstlen, "%lu", num);
#else
		snprintf(dest, dstlen, "%llu", num);
#endif
	}
}

bool qsc_stringutils_is_empty(const char* source)
{
	QSC_ASSERT(source != NULL);

	bool res;

	res = false;

	if (source != NULL)
	{
		res = (qsc_stringutils_string_size(source) == 0U);
	}

	return res;
}

bool qsc_stringutils_is_hex(const char* source, size_t srclen)
{
	QSC_ASSERT(source != NULL);

	char c;
	bool res;

	if (source != NULL)
	{
		res = true;

		for (size_t i = 0U; i < srclen; ++i)
		{
			c = source[i];

			if (c < 48 || (c > 57 && c < 65) || (c > 70 && c < 97) || c > 102)
			{
				res = false;
			}

		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool qsc_stringutils_is_numeric(const char* source, size_t srclen)
{
	QSC_ASSERT(source != NULL);

	char c;
	bool res;

	if (source != NULL)
	{
		res = true;

		for (size_t i = 0U; i < srclen; ++i)
		{
			c = source[i];

			if (c < 48 || c > 57)
			{
				res = false;
			}

		}
	}
	else
	{
		res = false;
	}

	return res;
}

char* qsc_stringutils_register_string(char** source, size_t count)
{
	QSC_ASSERT(*source != NULL);

	char* nstr;
	size_t i;
	size_t len;

	nstr = NULL;

	if (*source != NULL)
	{
		len = 0U;

		for (i = 0U; i < count; ++i)
		{
			len += strlen(source[i]);
		}

		const size_t tlen = len + 1U;

		nstr = (char*)qsc_memutils_malloc(tlen);

		if (nstr != NULL)
		{
			qsc_memutils_clear(nstr, tlen);

			for (i = 0U; i < count; ++i)
			{
#if defined(QSC_SYSTEM_OS_WINDOWS)
				strcat_s(nstr, tlen, source[i]);
#else
				strcat(nstr, source[i]);
#endif
			}
		}
	}

	return nstr;
}

size_t qsc_stringutils_remove_null_chars(char* source, size_t srclen)
{
	QSC_ASSERT(source != NULL);

	char* scpy;
	size_t pos;

	pos = 0U;

	scpy = (char*)qsc_memutils_malloc(srclen);

	if (scpy != NULL)
	{
		qsc_memutils_clear(scpy, srclen);

		for (size_t i = 0U; i < srclen; ++i)
		{
			if (source[i] != 0)
			{
				scpy[pos] = source[i];
				++pos;
			}
		}

		qsc_memutils_clear(source, srclen);
		qsc_memutils_copy(source, scpy, pos);
		qsc_memutils_alloc_free(scpy);
		scpy = NULL;
	}

	return pos;
}

int64_t qsc_stringutils_reverse_find_string(const char* source, const char* token, size_t start)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(token != NULL);
	QSC_ASSERT(start != 0);

	int64_t res;

	res = -1;

	if (source != NULL && token != NULL)
	{
		size_t slen;
		size_t tlen;

		slen = strlen(source);
		tlen = strlen(token);

		if (slen != 0 && tlen != 0 && start <= slen)
		{
			size_t ss;

			ss = (start + tlen > slen) ? slen - tlen : start;

			for (size_t i = ss + 1U; i > 0; --i)
			{
				if (strncmp(&source[i - 1U], token, tlen) == 0)
				{
					res = (int64_t)(i - 1U);
					break;
				}
			}
		}
	}

	return res;
}

const char* qsc_stringutils_reverse_sub_string(const char* source, const char* token)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(token != NULL);

	const char* pch;
	const char* sub;
	size_t pos;

	sub = NULL;

	if (source != NULL && token != NULL)
	{
		pch = strrchr(source, token[0U]);

		if (pch != NULL)
		{
			pos = pch - source + 1U;
			sub = source + pos;
		}
	}

	return sub;
}

void qsc_stringutils_split_strings(char* dest1, char* dest2, size_t destlen, const char* source, const char* token)
{
	QSC_ASSERT(dest1 != NULL);
	QSC_ASSERT(dest2 != NULL);
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(token != NULL);

	const char* pstr;
	size_t plen;
	int64_t pos;

	pos = qsc_stringutils_find_string(source, token);

	if (pos > 0)
	{
		pstr = source;
		plen = (size_t)pos;

		if (destlen >= plen)
		{
			qsc_memutils_copy(dest1, pstr, plen);
			++plen;
			pstr += plen;
			plen = qsc_stringutils_string_size(pstr);

			if (destlen >= plen)
			{
				qsc_memutils_copy(dest2, pstr, plen);
			}
		}
	}
}

char** qsc_stringutils_split_string(char* source, const char* delim, size_t* count)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(delim != NULL);
	QSC_ASSERT(count != NULL);

	char** ptok;
	const char* tok;
	char* pstr;
	int64_t pln;
	int64_t pos;
	size_t ctr;
	size_t len;

	ptok = NULL;

	if (source != NULL && delim != NULL && count != NULL)
	{
		ctr = 0U;
		pos = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
		pstr = _strdup(source);
#else
		pstr = strdup(source);
#endif
		if (pstr != NULL)
		{
			do
			{
				pln = qsc_stringutils_find_string(source + pos, delim);
				pos += pln + 1;

				if (pln > 0)
				{
					++ctr;
				}
			} while (pln != -1);

			if (ctr > 0U)
			{
				ptok = (char**)qsc_memutils_malloc(ctr * sizeof(char*));
			}

			ctr = 0U;

			if (ptok != NULL)
			{
				do
				{
					tok = strsepex(&source, delim);

					if (tok != NULL)
					{
						len = strlen(tok);

						if (len > 0U)
						{
							ptok[ctr] = (char*)qsc_memutils_malloc(len + 1U);

							if (ptok[ctr] != NULL)
							{
								qsc_memutils_copy(ptok[ctr], tok, len);
								ptok[ctr][len] = '\0';
								++ctr;
							}
						}
					}
				} while (tok != NULL);

				*count = ctr;
			}

			qsc_memutils_alloc_free(pstr);
			pstr = NULL;
		}
	}

	return ptok;
}

bool qsc_stringutils_string_compare(const char* str1, const char* str2, size_t length)
{
	QSC_ASSERT(str1 != NULL);
	QSC_ASSERT(str2 != NULL);

	bool res;

	res = true;

	if (strlen(str1) == strlen(str2))
	{
		for (size_t i = 0U; i < length; ++i)
		{
			if (str1[i] != str2[i])
			{
				res = false;
			}
		}
	}
	else
	{
		res = false;
	}

	return res;
}

int32_t qsc_stringutils_string_comparison(const char* source, const char* token)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(token != NULL);

	size_t slen;
	bool res;

	res = false;

	if (source != NULL && token != NULL)
	{
		slen = strlen(source);

		if (slen != 0U)
		{
			res = strncmp(source, token, slen);
		}
	}

	return res;
}

bool qsc_stringutils_string_contains(const char* source, const char* token)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(token != NULL);

	bool res;

	res = false;

	if (source != NULL && token != NULL)
	{
		res = (qsc_stringutils_find_string(source, token) >= 0);
	}

	return res;
}

bool qsc_stringutils_strings_equal(const char* str1, const char* str2)
{
	QSC_ASSERT(str1 != NULL);
	QSC_ASSERT(str2 != NULL);

	size_t i;
	size_t slen1;
	size_t slen2;
	uint8_t acc;
	bool res;

	i = 0U;
	slen1 = 0U;
	slen2 = 0U;
	acc = 1U;
	res = false;

	if (str1 != NULL && str2 != NULL)
	{
		slen1 = qsc_stringutils_string_size(str1);
		slen2 = qsc_stringutils_string_size(str2);

		if (slen1 == slen2)
		{
			acc = 0U;

			for (i = 0U; i < slen1; ++i)
			{
				acc |= ((uint8_t)str1[i] ^ (uint8_t)str2[i]);
			}

			res = acc == 0U;
		}
	}

	return res;
}

int32_t qsc_stringutils_string_to_int(const char* source)
{
	QSC_ASSERT(source != NULL);

	size_t len;
	int32_t res;

	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	len = strnlen_s(source, 10U);
#else
	len = strlen(source);
#endif

	for (size_t i = 0U; i < len; ++i)
	{

		if (source[i] == '\0' || source[i] < 48 || source[i] > 57)
		{
			break;
		}

		int32_t digit = source[i] - '0';

		if (res > (INT32_MAX - digit) / 10) 
		{
			res = INT32_MAX; 
			break; 
		}

		res = res * 10 + digit;
	}

	return res;
}

size_t qsc_stringutils_string_size(const char* source)
{
	QSC_ASSERT(source != NULL);

	size_t res;

	res = 0U;

	if (source != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = strnlen_s(source, QSC_STRING_MAX_LEN);
#else
		res = strlen(source);
#endif
	}

	return res;
}

char* qsc_stringutils_sub_string(const char* source, const char* token)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(token != NULL);

	char* sub;

	sub = NULL;

	if (source != NULL && token != NULL)
	{
		sub = strstr(source, token);
	}

	return sub;
}

void qsc_stringutils_to_lowercase(char* source)
{
	QSC_ASSERT(source != NULL);

	if (source != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		size_t slen;

		slen = qsc_stringutils_string_size(source) + 1U;
		_strlwr_s(source, slen);
#else
		for (char* pos = source; *pos != '\0'; ++pos)
		{
			*pos = (char)tolower((unsigned char)*pos);
		}
#endif
	}
}

void qsc_stringutils_trim_newline(char* source)
{
	QSC_ASSERT(source != NULL);

	size_t slen;

	if (source != NULL)
	{
		slen = qsc_stringutils_string_size(source);

		for (int32_t i = (int32_t)slen - 1; i >= 0; --i)
		{
			if (source[i] == '\n')
			{
				source[i] = '\0';
				break;
			}
		}
	}
}

void qsc_stringutils_trim_spaces(char* source)
{
	QSC_ASSERT(source != NULL);

	size_t slen;

	if (source != NULL)
	{
		slen = qsc_stringutils_string_size(source);

		if (slen > 0U && source[slen - 1U] == ' ')
		{
			source[slen - 1U] = '\0';
		}
	}
}

void qsc_stringutils_to_uppercase(char* source)
{
	QSC_ASSERT(source != NULL);

	if (source != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		size_t slen;

		slen = qsc_stringutils_string_size(source) + 1U;
		_strupr_s(source, slen);
#else
		for (char* pos = source; *pos != '\0'; ++pos)
		{
			*pos = (char)toupper((unsigned char)*pos);
		}
#endif
	}
}

size_t qsc_stringutils_whitespace_count(const char* source, size_t srclen)
{
	QSC_ASSERT(source != NULL);

	size_t ctr;

	ctr = 0;

	if (source != NULL && srclen > 0U)
	{
		for (size_t i = 0U; i < srclen; ++i)
		{
			if (source[i] == ' ')
			{
				++ctr;
			}
		}
	}

	return ctr;
}

size_t qsc_stringutils_whitespace_filter(const char* source, size_t srclen, char* dest)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(dest != NULL);

	size_t ctr;

	ctr = 0U;

	if (source != NULL && dest != NULL && srclen > 0U)
	{
		for (size_t i = 0U; i < srclen; ++i)
		{
			if (source[i] != ' ')
			{
				dest[ctr] = source[i];
				++ctr;
			}
		}
	}

	return ctr;
}

