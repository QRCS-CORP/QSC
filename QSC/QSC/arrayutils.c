#include "arrayutils.h"
#include <stdio.h>
#include <string.h>

size_t qsc_arrayutils_find_string(const char* str, size_t slen, const char* token)
{
	assert(str != NULL);
	assert(token != 0);
	assert(slen != 0);

	char* fnd;
	size_t res;

	res = (size_t)QSC_ARRAYTILS_NPOS;
	fnd = strstr(str, token);

	if (fnd)
	{
		res = slen - strlen(fnd);
	}

	return res;
}

uint8_t qsc_arrayutils_hex_to_uint8(const char* str, size_t slen)
{
	assert(str != NULL);
	assert(slen != 0);

	uint8_t res;

	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	sscanf_s(str, "%hhx", &res);
#else
	sscanf(str, "%hhx", &res);
#endif

	return res;
}

void qsc_arrayutils_uint8_to_hex(char* output, size_t outlen, uint8_t value)
{ 
	assert(output != NULL);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	sprintf_s(output, outlen, "%hhx", value);
#else
	sprintf(output, "%hhx", value);
#endif
}

uint8_t qsc_arrayutils_string_to_uint8(const char* str, size_t slen)
{
	assert(str != NULL);
	assert(slen != 0);
	uint8_t res;

	res = 0;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	sscanf_s(str, "%hhu", &res);
#else
	sscanf(str, "%hhu", &res);
#endif

	return res;
}

uint16_t qsc_arrayutils_string_to_uint16(const char* str, size_t slen)
{
	assert(str != NULL);
	assert(slen != 0);
	uint16_t res;

	res = 0;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	sscanf_s(str, "%hu", &res);
#else
	sscanf(str, "%hu", &res);
#endif

	return res;
}

uint32_t qsc_arrayutils_string_to_uint32(const char* str, size_t slen)
{
	assert(str != NULL);
	assert(slen != 0);
	uint32_t res;

	res = 0;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	sscanf_s(str, "%d", &res);
#else
	sscanf(str, "%d", &res);
#endif

	return res;
}

uint64_t qsc_arrayutils_string_to_uint64(const char* str, size_t slen)
{
	assert(str != NULL);
	assert(slen != 0);
	uint64_t res;

	res = 0;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	sscanf_s(str, "%lld", &res);
#else
	sscanf(str, "%lld", &res);
#endif

	return res;
}

bool qsc_arrayutils_self_test()
{
	const char nstr[] = "1 192 32180 497683 189167334201522";
	const char slng[] = "189167334201522";
	const char sint[] = "497683";
	const char ssht[] = "32180";
	const char schr1[] = "1";
	const char schr2[] = "192";
	char shex[3] = { 0 };
	const uint64_t nlng = 189167334201522;
	const uint32_t nint = 497683;
	const uint16_t nsht = 32180;
	const uint8_t nchr1 = 1;
	const uint8_t nchr2 = 192;
	uint64_t x64;
	size_t i;
	size_t pos;
	uint32_t x32;
	uint16_t x16;
	uint8_t x8;
	uint8_t y8;
	bool res;

	res = true;

	pos = qsc_arrayutils_find_string(nstr, sizeof(nstr), schr1);

	if (pos != 1)
	{
		res = false;
	}

	pos = qsc_arrayutils_find_string(nstr, sizeof(nstr), schr2);

	if (pos != 3)
	{
		res = false;
	}

	pos = qsc_arrayutils_find_string(nstr, sizeof(nstr), ssht);

	if (pos != 7)
	{
		res = false;
	}

	pos = qsc_arrayutils_find_string(nstr, sizeof(nstr), sint);

	if (pos != 13)
	{
		res = false;
	}

	pos = qsc_arrayutils_find_string(nstr, sizeof(nstr), slng);

	if (pos != 20)
	{
		res = false;
	}

	for (i = 0; i < 256; ++i)
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
