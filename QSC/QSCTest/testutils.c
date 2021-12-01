#include "testutils.h"
#include "../QSC/memutils.h"
#include <stdio.h>

char qsctest_get_char()
{
	char line[8] = { 0 };
	char* res;
	char ret;

	res = fgets(line, sizeof(line), stdin);

	if (res != NULL)
	{
		ret = line[0];
	}
	else
	{
		ret = 0;
	}

	return ret;
}

uint8_t qsctest_get_wait()
{
	char ret;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	ret = getwchar();
#else
	ret = getchar();
#endif

	return (uint8_t)ret;
}

void qsctest_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	uint8_t  idx0;
	uint8_t  idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	qsc_memutils_clear(output, length);

	for (size_t  pos = 0; pos < (length * 2); pos += 2)
	{
		idx0 = ((uint8_t)hexstr[pos + 0] & 0x1FU) ^ 0x10U;
		idx1 = ((uint8_t)hexstr[pos + 1] & 0x1FU) ^ 0x10U;
		output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	}
}

void qsctest_print_hex_quot(const uint8_t* input, size_t inputlen, size_t linelen)
{
	size_t i;

	while (inputlen >= linelen)
	{
		qsctest_print_safe("\"");

		for (i = 0; i < linelen; ++i)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			printf_s("%02X", input[i]);
#else
			printf("%02X", input[i]);
#endif
		}

		qsctest_print_safe("\"");
		input += linelen;
		inputlen -= linelen;
		qsctest_print_safe("\n");
	}

	if (inputlen != 0)
	{
		qsctest_print_safe("\"");

		for (i = 0; i < inputlen; ++i)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			printf_s("%02X", input[i]);
#else
			printf("%02X", input[i]);
#endif
		}

		qsctest_print_safe("\"");
	}
}

void qsctest_print_hex_uint16(const uint16_t* input, size_t inputlen, size_t linelen)
{
	size_t i;

	while (inputlen >= linelen)
	{
		for (i = 0; i < linelen; ++i)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			printf_s("0x%04X", input[i]);
			printf_s("%s", "U, ");
#else
			printf("0x%04X", input[i]);
			printf("%s", "U, ");
#endif
		}

		input += linelen;
		inputlen -= linelen;
		qsctest_print_safe("\n");
	}

	if (inputlen != 0)
	{
		for (i = 0; i < inputlen; ++i)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			printf_s("0x%04X", input[i]);
			printf_s("%s", "U, ");
#else
			printf("0x%04X", input[i]);
			printf("%s", "U, ");
#endif
		}

	}
}

void qsctest_print_hex_uint32(const uint32_t* input, size_t inputlen, size_t linelen)
{
	size_t i;

	while (inputlen >= linelen)
	{
		for (i = 0; i < linelen; ++i)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			printf_s("0x%08lX", input[i]);
			printf_s("%s", "UL, ");
#else
			printf("0x%08lX", (long unsigned int)input[i]);
			printf("%s", "UL, ");
#endif
		}

		input += linelen;
		inputlen -= linelen;
		qsctest_print_safe("\n");
	}

	if (inputlen != 0)
	{
		for (i = 0; i < inputlen; ++i)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			printf_s("0x%08lX", input[i]);
			printf_s("%s", "UL, ");
#else
			printf("0x%08lX", (long unsigned int)input[i]);
			printf("%s", "UL, ");
#endif
		}
	}
}

void qsctest_print_hex_uint64(const uint64_t* input, size_t inputlen, size_t linelen)
{
	size_t i;

	while (inputlen >= linelen)
	{
		for (i = 0; i < linelen; ++i)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			printf_s("0x%016llX", input[i]);
			printf_s("%s", "ULL, ");
#else
			printf("0x%016llX", (long long unsigned int)input[i]);
			printf("%s", "ULL, ");
#endif
		}

		input += linelen;
		inputlen -= linelen;
		qsctest_print_safe("\n");
	}

	if (inputlen != 0)
	{
		for (i = 0; i < inputlen; ++i)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			printf_s("0x%016llX", input[i]);
			printf_s("%s", "ULL, ");
#else
			printf("0x%016llX", (long long unsigned int)input[i]);
			printf("%s", "ULL, ");
#endif
		}
	}
}

void qsctest_print_hex(const uint8_t* input, size_t inputlen, size_t linelen)
{
	size_t i;

	while (inputlen >= linelen)
	{
		for (i = 0; i < linelen; ++i)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			printf_s("%02X", input[i]);
#else
			printf("%02X", input[i]);
#endif
		}

		input += linelen;
		inputlen -= linelen;
		qsctest_print_safe("\n");
	}

	if (inputlen != 0)
	{
		for (i = 0; i < inputlen; ++i)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			printf_s("%02X", input[i]);
#else
			printf("%02X", input[i]);
#endif
		}
	}
}

void qsctest_print_safe(const char* input)
{
	if (input != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		printf_s("%s", input);
#else
		printf("%s", input);
#endif
	}
}

void qsctest_print_line(const char* input)
{
	qsctest_print_safe(input);
	qsctest_print_safe("\n");
}

void qsctest_print_ulong(uint64_t digit)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	printf_s("%llu", digit);
#else
	printf("%llu", (long long unsigned int)digit);
#endif
}

void qsctest_print_double(double digit)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	printf_s("%.*lf", 3, digit);
#else
	printf("%.*lf", 3, digit);
#endif
}

bool qsctest_test_confirm(const char* message)
{
	char ans;
	bool res;

	qsctest_print_line(message);

	res = false;
	ans = qsctest_get_char();

	if (ans == 'y' || ans == 'Y')
	{
		res = true;
	}

	return res;
}
