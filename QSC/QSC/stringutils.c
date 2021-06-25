#include "stringutils.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QSC_STRING_MAX_LEN 4096

#if defined(QSC_SYSTEM_OS_WINDOWS)
static char* strsep(char** stringp, const char* delim)
{
	assert(*stringp != NULL);
	assert(delim != NULL);

	char* ts = NULL;

	if (*stringp != NULL)
	{
		ts = *stringp;
		*stringp = strpbrk(ts, delim);

		if (*stringp)
		{
			**stringp = '\0';
			(*stringp)++;
		}
	}

	return ts;
}
#endif

size_t qsc_stringutils_add_line_breaks(char* buffer, size_t buflen, size_t linelen, const char* source, size_t sourcelen)
{
	assert(buffer != NULL);
	assert(source != NULL);
	assert(linelen != 0);

	size_t blen;
	size_t i;
	size_t j;

	j = 0;

	if (buffer != NULL && source != NULL && linelen != 0)
	{
		blen = sourcelen + ((sourcelen / linelen) + 1);

		if (buflen >= blen)
		{
			for (i = 0, j = 0; i < sourcelen; ++i, ++j)
			{
				buffer[j] = source[i];

				if (i != 0 && (i + 1) % linelen == 0)
				{
					++j;
					buffer[j] = '\n';
				}
			}

			++j;
			buffer[j] = '\n';
		}
	}

	return j - 1;
}

size_t qsc_stringutils_remove_line_breaks(char* buffer, size_t buflen, const char* source, size_t sourcelen)
{
	assert(buffer != NULL);
	assert(source != NULL);

	size_t i;
	size_t j;

	j = 0;

	if (buffer != NULL && source != NULL)
	{
		for (i = 0, j = 0; i < sourcelen; ++i)
		{
			if (j > buflen - 1)
			{
				break;
			}

			if (source[i] != '\n')
			{
				buffer[j] = source[i];
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
			memset(source, 0x00, len);
		}
	}
}

void qsc_stringutils_clear_substring(char* buffer, size_t count)
{
	assert(buffer != NULL);

	if (buffer != NULL && count != 0)
	{
		memset(buffer, 0x00, count);
	}
}

bool qsc_stringutils_compare_strings(char* a, const char* b, size_t length)
{
	assert(a != NULL);
	assert(b != NULL);

	size_t i;
	char c;

	c = 0;

	for (i = 0; i < length; ++i)
	{
		c += a[i] ^ b[i];
	}


	return (c == 0);
}

size_t qsc_stringutils_concat_strings(char* buffer, size_t buflen, const char* substr)
{
	assert(buffer != NULL);
	assert(substr != NULL);

	errno_t err;
	size_t res;
	size_t dlen;
	size_t slen;

	err = 0;
	res = 0;

	if (buffer != NULL && substr != NULL)
	{
		dlen = strlen(buffer);
		slen = strlen(substr);

		if (slen > 0 && slen <= buflen - dlen)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			err = strcat_s(buffer, buflen, substr);
#else
			err = (strcat(buffer, substr) != NULL);
#endif
		}

		if (err == 0)
		{
			res = strlen(buffer);
		}
	}

	return res;
}

size_t qsc_stringutils_concat_and_copy(char* buffer, size_t buflen, const char* substr1, const char* substr2)
{
	assert(buffer != NULL);
	assert(substr1 != NULL);
	assert(substr2 != NULL);

	size_t res;
	size_t slen;

	res = 0;

	if (buffer != NULL && substr1 != NULL && substr2 != NULL)
	{
		if (strlen(buffer) > 0)
		{
			qsc_stringutils_clear_string(buffer);
		}

		slen = strlen(substr1) + strlen(substr2);

		if (slen < buflen)
		{
			if (strlen(substr1) > 0)
			{
				slen = qsc_stringutils_copy_string(buffer, buflen, substr1);
			}

			if (strlen(substr2) > 0)
			{
				qsc_stringutils_copy_string(((char*)buffer + slen), buflen, substr2);
			}
		}

		res = strlen(buffer);
	}

	return res;
}

size_t qsc_stringutils_copy_string(char* buffer, size_t buflen, const char* substr)
{
	assert(buffer != NULL);
	assert(substr != NULL);

	errno_t err;
	size_t res;
	size_t slen;

	res = 0;

	if (buffer != NULL && substr != NULL)
	{
		err = 0;
		slen = strlen(substr);

		if (slen > 0 && slen <= buflen)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			err = strcpy_s(buffer, slen + 1, substr);
#else
			err = (strcpy(buffer, substr) != NULL);
#endif
		}

		if (err == 0)
		{
			res = strlen(buffer);
		}
	}

	return res;
}

size_t qsc_stringutils_copy_substring(char* buffer, size_t buflen, const char* substr, size_t sublen)
{
	assert(buffer != NULL);
	assert(substr != NULL);

	size_t res;

	res = 0;

	if (buffer != NULL && substr != NULL)
	{
		if (sublen > 0 && sublen <= buflen)
		{
			memcpy(buffer, substr, sublen);
		}

		res = strlen(buffer);
	}

	return res;
}

int32_t qsc_stringutils_find_string(const char* source, const char* token)
{
	assert(source != NULL);
	assert(token != NULL);

	char* sub;
	int32_t pos;

	pos = -1;

	if (source != NULL && token != NULL)
	{
		sub = strstr(source, token);

		if (sub != NULL)
		{
			pos = (int32_t)(sub - source);
		}
	}

	return pos;
}

int32_t qsc_stringutils_insert_string(char* buffer, size_t buflen, const char* substr, size_t offset)
{
	assert(buffer != NULL);
	assert(substr != NULL);

	int32_t res;

	res = -1;

	if (buffer != NULL && substr != NULL)
	{
		if ((strlen(buffer) + strlen(substr)) <= buflen && offset < (buflen - strlen(substr)))
		{
			qsc_stringutils_concat_strings((char*)(buffer + offset), buflen, substr);
			res = (int32_t)strlen(buffer);
		}
	}

	return res;
}

bool qsc_stringutils_is_alpha_numeric(char* source, size_t srclen)
{
	assert(source != NULL);

	size_t i;
	char c;
	bool res;

	if (source != NULL)
	{
		res = true;

		for (i = 0; i < srclen; ++i)
		{
			c = source[i];

			if (c < 48 || (c > 57 && c < 65) || (c > 90 && c < 97) || c > 122)
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

bool qsc_stringutils_is_hex(char* source, size_t srclen)
{
	assert(source != NULL);

	size_t i;
	char c;
	bool res;

	if (source != NULL)
	{
		res = true;

		for (i = 0; i < srclen; ++i)
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

bool qsc_stringutils_is_numeric(char* source, size_t srclen)
{
	assert(source != NULL);

	size_t i;
	char c;
	bool res;

	if (source != NULL)
	{
		res = true;

		for (i = 0; i < srclen; ++i)
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

void qsc_stringutils_int_to_string(int32_t num, char* output, size_t outlen)
{
	assert(output != NULL);

	if (output != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_itoa_s(num, output, outlen, 10);
#else
		_itoa(num, output, 10);
#endif
	}
}

char* qsc_stringutils_join_string(char** source, size_t count)
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

		nstr = (char*)malloc(len + 1);

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

char** qsc_stringutils_split_string(char* source, char* delim, size_t* count)
{
	assert(source != NULL);
	assert(delim != NULL);
	assert(count != NULL);

	char** ptok;
	char* tok;
	char* str;
	char* tfr;
	int32_t pln;
	int32_t pos;
	size_t ctr;
	size_t len;

	ptok = NULL;

	if (source != NULL && delim != NULL && count != NULL)
	{
		ctr = 0;
		pos = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
		str = _strdup(source);
#else
		str = strdup(source);
#endif
		tfr = str;

		do
		{
			pln = qsc_stringutils_find_string(source + pos, delim);
			pos += pln + 1;

			if (pln > 0)
			{
				++ctr;
			}
		} while (pln != -1);

		ptok = (char**)malloc(ctr * sizeof(char*));
		ctr = 0;

		if (ptok != NULL)
		{
			do
			{
				tok = strsep(&source, delim);

				if (tok != NULL)
				{
					len = strlen(tok);

					if (len > 0)
					{
						ptok[ctr] = (char*)malloc(len + 1);

						if (ptok[ctr] != NULL)
						{
							memcpy(ptok[ctr], tok, len);
							ptok[ctr][len] = '\0';
							++ctr;
						}
					}
				}
			} while (tok != NULL);

			*count = ctr;
			free(tfr);
		}
	}

	return ptok;
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

char* qsc_stringutils_reverse_sub_string(const char* source, const char* token)
{
	assert(source != NULL);
	assert(token != NULL);

	char* pch;
	char* sub;
	size_t pos;

	sub = NULL;

	if (source != NULL && token != NULL)
	{
		pch = strrchr(source, token[0]);

		if (pch != NULL)
		{
			pos = pch - source + 1;
			sub = (char*)(source + pos);
		}
	}

	return sub;
}

bool qsc_stringutils_string_compare(const char* a, const char* b, size_t length)
{
	assert(a != NULL);
	assert(b != NULL);

	size_t i;
	bool res;

	res = true;

	if (strlen(a) == strlen(b))
	{
		for (i = 0; i < length; ++i)
		{
			if (a[i] != b[i])
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

int32_t qsc_stringutils_string_to_int(const char* source)
{
	assert(source != NULL);

	int32_t res;

	res = 0;

	if (source != NULL)
	{
		res = atoi(source);
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
		res = strlen(source);
	}

	return res;
}

void qsc_stringutils_to_lowercase(char* source)
{
	assert(source != NULL);

	if (source != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		size_t slen;

		slen = strnlen_s(source, QSC_STRING_MAX_LEN) + 1;
		_strlwr_s(source, slen);
#else
		strlwr(source);
#endif
	}
}

void qsc_stringutils_trim_newline(char* source)
{
	assert(source != NULL);

	size_t slen;
	int32_t i;

	if (source != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		slen = strnlen_s(source, QSC_STRING_MAX_LEN);
#else
		slen = strnlen_s(source, QSC_STRING_MAX_LEN);
#endif

		for (i = (int32_t)slen - 1; i >= 0; --i)
		{
			if (source[i] == '\n')
			{
				source[i] = '\0';
			}
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

		slen = strnlen_s(source, QSC_STRING_MAX_LEN) + 1;
		_strupr_s(source, slen);
#else
		strupr(source);
#endif
	}
}