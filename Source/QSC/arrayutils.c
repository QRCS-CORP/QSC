#include "arrayutils.h"
#include <string.h>

size_t qsc_arrayutils_find_string(const char* str, size_t slen, const char* token)
{
	QSC_ASSERT(str != NULL);
	QSC_ASSERT(token != NULL);
	QSC_ASSERT(slen != 0U);

	size_t res;

    res = 0U;

    if (str != NULL && slen > 0U && token != NULL)
    {
        size_t tlen;

        res = (size_t)QSC_ARRAYUTILS_NPOS;
        tlen = strlen(token);

        for (size_t i = 0U; i + tlen <= slen; ++i)
        {
            if (strncmp(&str[i], token, tlen) == 0)
            {
                res = i + 1U;
                break;
            }
        }
    }

	return res;
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

    if (str != NULL)
    {
        for (size_t i = 0U; (i < slen) && (str[i] != '\0'); ++i)
        {
            char c = str[i];

            digit = c - '0';

            if (res > (UINT64_MAX - digit) / 10)
            {
                res = UINT64_MAX;
                break;
            }

            res = (uint32_t)(res * 10U + digit);
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