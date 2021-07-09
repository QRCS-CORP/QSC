#include "testutils.h"
#include <stdio.h>

char qsctest_get_char()
{
	char line[8] = { 0 };
	fgets(line, sizeof(line), stdin);

	return line[0];
}

void qsctest_get_wait()
{
	wint_t res;

	res = getwchar();
}

void qsctest_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	size_t  pos;
	uint8_t  idx0;
	uint8_t  idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	memset(output, 0, length);

	for (pos = 0; pos < (length * 2); pos += 2)
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
#if defined(_MSC_VER)
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
#if defined(_MSC_VER)
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
#if defined(_MSC_VER)
			printf_s("0x%04X", input[i]);
			printf_s("U, ");
#else
			printf("0x%04X", input[i]);
			printf("U, ");
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
#if defined(_MSC_VER)
			printf_s("0x%04X", input[i]);
			printf_s("U, ");
#else
			printf("0x%04X", input[i]);
			printf("U, ");
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
#if defined(_MSC_VER)
			printf_s("0x%08lX", input[i]);
			printf_s("UL, ");
#else
			printf("0x%08lX", input[i]);
			printf("UL, ");
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
#if defined(_MSC_VER)
			printf_s("0x%08lX", input[i]);
			printf_s("UL, ");
#else
			printf("0x%08lX", input[i]);
			printf("UL, ");
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
#if defined(_MSC_VER)
			printf_s("0x%016llX", input[i]);
			printf_s("ULL, ");
#else
			printf("0x%016llX", input[i]);
			printf("ULL, ");
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
#if defined(_MSC_VER)
			printf_s("0x%016llX", input[i]);
			printf_s("ULL, ");
#else
			printf("0x%016llX", input[i]);
			printf_s("ULL, ");
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
#if defined(_MSC_VER)
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
#if defined(_MSC_VER)
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
#if defined(_MSC_VER)
		printf_s(input);
#else
		printf(input);
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
#if defined(_MSC_VER)
	printf_s("%llu", digit);
#else
	printf("%llu", digit);
#endif
}

void qsctest_print_double(double digit)
{
#if defined(_MSC_VER)
	printf_s("%.*lf", 3, digit);
#else
	printf("%.*lf", 3, digit);
#endif
}

bool qsctest_test_confirm(char* message)
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
