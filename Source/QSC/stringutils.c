#include "stringutils.h"
#include "memutils.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QSC_STRING_MAX_LEN 4096ULL

char* strsepex(char** stringp, const char* delim)
{
    char *rv = *stringp;

    if (rv != NULL)
    {
        *stringp += strcspn(*stringp, delim);

        if (**stringp != '\0')
        {
            *(*stringp)++ = '\0';
        }
        else
        {
            *stringp = 0;
        }
    }

    return rv;
}

size_t qsc_stringutils_add_line_breaks(char* dest, size_t dstlen, size_t linelen, const char* source, size_t srclen)
{
	assert(dest != NULL);
	assert(source != NULL);
	assert(linelen != 0);

	size_t blen;
	size_t i;
	size_t j;

	j = 0;

	if (dest != NULL && source != NULL && linelen != 0)
	{
		blen = srclen + ((srclen / linelen) + 1);

		if (dstlen >= blen)
		{
			for (i = 0, j = 0; i < srclen; ++i, ++j)
			{
				dest[j] = source[i];

				if (i != 0 && (i + 1) % linelen == 0)
				{
					++j;
					dest[j] = '\n';
				}
			}

			++j;
			dest[j] = '\n';
		}
	}

	return j - 1;
}

size_t qsc_stringutils_remove_line_breaks(char* dest, size_t dstlen, const char* source, size_t srclen)
{
	assert(dest != NULL);
	assert(source != NULL);

	size_t i;
	size_t j;

	j = 0;

	if (dest != NULL && source != NULL)
	{
		for (i = 0, j = 0; i < srclen; ++i)
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
	assert(source != NULL);

	size_t len;

	if (source != NULL)
	{
		len = strlen(source);

		if (len > 0)
		{
			qsc_memutils_clear(source, len);
		}
	}
}

void qsc_stringutils_clear_substring(char* dest, size_t length)
{
	assert(dest != NULL);

	if (dest != NULL && length != 0)
	{
		qsc_memutils_clear(dest, length);
	}
}

bool qsc_stringutils_compare_strings(const char* str1, const char* str2, size_t length)
{
	assert(str1 != NULL);
	assert(str1 != NULL);

	char c;

	c = 0;

	for (size_t i = 0; i < length; ++i)
	{
		c += str1[i] ^ str2[i];
	}


	return (c == 0);
}

size_t qsc_stringutils_concat_strings(char* dest, size_t dstlen, const char* source)
{
	assert(dest != NULL);
	assert(source != NULL);

	size_t pos;

	pos = 0;

	if (dest != NULL && source != NULL)
	{
		size_t dlen;
		size_t slen;

		dlen = strlen(dest);
		slen = strlen(source);

		if (slen > 0 && slen <= dstlen - dlen)
		{
			errno_t err;

#if defined(QSC_SYSTEM_OS_WINDOWS)
			err = strcat_s(dest, dstlen, source);
#else
			err = (strcat(dest, source) != NULL);
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
	assert(dest != NULL);
	assert(str1 != NULL);
	assert(str2 != NULL);

	size_t res;
	size_t slen;

	res = 0;

	if (dest != NULL && str1 != NULL && str2 != NULL)
	{
		if (strlen(dest) > 0)
		{
			qsc_stringutils_clear_string(dest);
		}

		slen = strlen(str1) + strlen(str2);

		if (slen < dstlen)
		{
			if (strlen(str1) > 0)
			{
				slen = qsc_stringutils_copy_string(dest, dstlen, str1);
			}

			if (strlen(str2) > 0)
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
	assert(dest != NULL);
	assert(source != NULL);

	errno_t err;
	size_t res;
	size_t slen;

	res = 0;

	if (dest != NULL && source != NULL)
	{
		err = 0;
		slen = strlen(source);

		if (slen > 0 && slen <= dstlen)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			err = strcpy_s(dest, slen + 1, source);
#else
			err = (strcpy(dest, source) != NULL);
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
	assert(dest != NULL);
	assert(source != NULL);

	size_t res;

	res = 0;

	if (dest != NULL && source != NULL)
	{
		if (srclen > 0 && srclen <= dstlen)
		{
			qsc_memutils_copy(dest, source, srclen);
		}

		res = strlen(dest);
	}

	return res;
}

size_t qsc_stringutils_formatting_count(const char* dest, size_t dstlen)
{
	assert(dest != NULL);

	size_t ctr;

	ctr = 0;

	if (dest != NULL && dstlen > 0)
	{
		for (size_t i = 0; i < dstlen; ++i)
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
	assert(source != NULL);
	assert(dest != NULL);

	size_t ctr;

	ctr = 0;

	if (source != NULL && dest != NULL && srclen > 0)
	{
		for (size_t i = 0; i < srclen; ++i)
		{
			if (dest[i] != ' ' && dest[i] != '\t' && dest[i] != '\n' && dest[i] != '\r')
			{
				dest[ctr] = source[ctr];
				++ctr;
			}
		}
	}

	return ctr;
}

int64_t qsc_stringutils_find_char(const char* source, const char tok)
{
	assert(source != NULL);

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
	assert(source != NULL);
	assert(token != NULL);

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
	assert(hex != NULL);

	snprintf(hex, 3, "%.2x", input);
}

uint8_t qsc_stringutils_hex_to_byte(const char* hex)
{
	assert(hex != NULL);

	uint8_t res;

	res = (uint8_t)strtol(hex, NULL, 16);

	return res;
}

int64_t qsc_stringutils_insert_string(char* dest, size_t dstlen, const char* source, size_t offset)
{
	assert(dest != NULL);
	assert(source != NULL);

	int64_t res;

	res = QSC_STRINGUTILS_TOKEN_NOT_FOUND;

	if (dest != NULL && source != NULL &&
		(strlen(dest) + strlen(source)) <= dstlen && offset < (dstlen - strlen(source)))
	{
		qsc_stringutils_concat_strings((dest + offset), dstlen, source);
		res = (int64_t)strlen(dest);
	}

	return res;
}

void qsc_stringutils_int_to_string(int32_t num, char* dest, size_t destlen)
{
	assert(dest != NULL);

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
	assert(dest != NULL);

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
	assert(dest != NULL);

	if (dest != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_i64toa_s(num, dest, dstlen, 10);
#else
		snprintf(dest, dstlen, "%ld", num);
#endif
	}
}

void qsc_stringutils_uint64_to_string(uint64_t num, char* dest, size_t dstlen)
{
	assert(dest != NULL);

	if (dest != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_ui64toa_s(num, dest, dstlen, 10);
#else
		snprintf(dest, dstlen, "%lu", num);
#endif
	}
}

bool qsc_stringutils_is_empty(const char* source)
{
	assert(source != NULL);

	return (qsc_stringutils_string_size(source) == 0);
}

bool qsc_stringutils_is_hex(const char* source, size_t srclen)
{
	assert(source != NULL);

	char c;
	bool res;

	if (source != NULL)
	{
		res = true;

		for (size_t i = 0; i < srclen; ++i)
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
	assert(source != NULL);

	char c;
	bool res;

	if (source != NULL)
	{
		res = true;

		for (size_t i = 0; i < srclen; ++i)
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
	assert(*source != NULL);

	char* nstr;
	size_t i;
	size_t len;

	nstr = NULL;

	if (*source != NULL)
	{
		len = 0;

		for (i = 0; i < count; ++i)
		{
			len += strlen(source[i]);
		}

		nstr = (char*)qsc_memutils_malloc(len + 1);

		if (nstr != NULL)
		{
			for (i = 0; i < count; ++i)
			{
#if defined(QSC_SYSTEM_OS_WINDOWS)
				len = strlen(source[i]);
				strcat_s(nstr, len, source[i]);
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
	assert(source != NULL);

	char* scpy;
	size_t pos;

	pos = 0;

	scpy = (char*)qsc_memutils_malloc(srclen);

	if (scpy != NULL)
	{
		qsc_memutils_clear(scpy, srclen);

		for (size_t i = 0; i < srclen; ++i)
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
	}

	return pos;
}

int64_t qsc_stringutils_reverse_find_string(const char* source, const char* token, size_t start)
{
	assert(source != NULL);
	assert(token != NULL);
	assert(start != 0);

	int64_t res;

	res = -1;

	if (source != NULL || token != NULL)
	{
		size_t slen;
		size_t tlen;

		slen = strlen(source);
		tlen = strlen(token);

		if (slen != 0 || tlen != 0 || start >= slen)
		{
			size_t ss;

			ss = (start + tlen > slen) ? slen - tlen : start;

			for (size_t i = ss + 1; i > 0; --i) 
			{
				if (strncmp(&source[i - 1], token, tlen) == 0) 
				{
					res = (int64_t)(i - 1);
					break;
				}
			}
		}
	}

    return res;
}

const char* qsc_stringutils_reverse_sub_string(const char* source, const char* token)
{
	assert(source != NULL);
	assert(token != NULL);

	const char* pch;
	const char* sub;
	size_t pos;

	sub = NULL;

	if (source != NULL && token != NULL)
	{
		pch = strrchr(source, token[0]);

		if (pch != NULL)
		{
			pos = pch - source + 1;
			sub = source + pos;
		}
	}

	return sub;
}

void qsc_stringutils_split_strings(char* dest1, char* dest2, size_t destlen, const char* source, const char* token)
{
	assert(dest1 != NULL);
	assert(dest2 != NULL);
	assert(source != NULL);
	assert(token != NULL);

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
	assert(source != NULL);
	assert(delim != NULL);
	assert(count != NULL);

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
		ctr = 0;
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

			if (ctr > 0)
			{
				ptok = (char**)qsc_memutils_malloc(ctr * sizeof(char*));
			}

			ctr = 0;

			if (ptok != NULL)
			{
				do
				{
					tok = strsepex(&source, delim);

					if (tok != NULL)
					{
						len = strlen(tok);

						if (len > 0)
						{
							ptok[ctr] = (char*)qsc_memutils_malloc(len + 1);

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
		}
	}

	return ptok;
}

bool qsc_stringutils_string_compare(const char* str1, const char* str2, size_t length)
{
	assert(str1 != NULL);
	assert(str2 != NULL);

	bool res;

	res = true;

	if (strlen(str1) == strlen(str2))
	{
		for (size_t i = 0; i < length; ++i)
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
	assert(source != NULL);
	assert(token  != NULL);

	size_t slen;
	bool res;

	slen = strlen(source);

	if (source != NULL && token != NULL && slen != 0)
	{
		res = strncmp(source, token, slen);
	}

	return res;
}

bool qsc_stringutils_string_contains(const char* source, const char* token)
{
	assert(source != NULL);
	assert(token != NULL);

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
	assert(str1 != NULL);
	assert(str2 != NULL);

	size_t slen;
	bool res;

	slen = qsc_stringutils_string_size(str1);
	res = (slen == qsc_stringutils_string_size(str2));

	if (res == true)
	{
		for (size_t i = 0; i < slen; ++i)
		{
			if (str1[i] != str2[i])
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

int32_t qsc_stringutils_string_to_int(const char* source)
{
	assert(source != NULL);

	size_t len;
	uint32_t res;

	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	len = strnlen_s(source, 10);
#else
	len = strlen(source);
#endif

	for (size_t i = 0; i < len; ++i)
	{
		if (source[i] == '\0' || source[i] < 48 || source[i] > 57)
		{
			break;
		}

		res = res * 10 + source[i] - '0';
	}

	return res;
}

size_t qsc_stringutils_string_size(const char* source)
{
	assert(source != NULL);

	size_t res;

	res = 0;

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
	assert(source != NULL);
	assert(token != NULL);

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
	assert(source != NULL);

	if (source != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		size_t slen;

		slen = qsc_stringutils_string_size(source) + 1;
		_strlwr_s(source, slen);
#else
		for(size_t i = 0; i < strlen(source); ++i)
		{
			source[i] = tolower(source[i]);
		}
#endif
	}
}

void qsc_stringutils_trim_newline(char* source)
{
	assert(source != NULL);

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
	assert(source != NULL);

	size_t slen;

	if (source != NULL)
	{
		slen = qsc_stringutils_string_size(source);

		if (source[slen - 1] == ' ')
		{
			source[slen - 1] = '\0';
		}
	}
}

void qsc_stringutils_to_uppercase(char* source)
{
	assert(source != NULL);

	if (source != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		size_t slen;

		slen = qsc_stringutils_string_size(source) + 1;
		_strupr_s(source, slen);
#else
		for(size_t i = 0; i < strlen(source); ++i)
		{
			source[i] = toupper(source[i]);
		}
#endif
	}
}

size_t qsc_stringutils_whitespace_count(const char* source, size_t srclen)
{
	assert(source != NULL);

	size_t ctr;

	ctr = 0;

	if (source != NULL && srclen > 0)
	{
		for (size_t i = 0; i < srclen; ++i)
		{
			if (source[i] != ' ')
			{
				++ctr;
			}
		}
	}

	return ctr;
}

size_t qsc_stringutils_whitespace_filter(const char* source, size_t srclen, char* dest)
{
	assert(source != NULL);
	assert(dest != NULL);

	size_t ctr;

	ctr = 0;

	if (source != NULL && dest != NULL && srclen > 0)
	{
		for (size_t i = 0; i < srclen; ++i)
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

