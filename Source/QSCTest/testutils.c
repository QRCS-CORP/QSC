#include "testutils.h"
#include "../QSC/common.h"
#include <stdio.h>

char qsctest_get_char()
{
	char line[8] = { 0 };

	fgets(line, sizeof(line), stdin);

	return line[0];
}

char qsctest_get_wait()
{
	char res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (char)getwchar();
#else
	res = getchar();
#endif

	return res;
}

void qsctest_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	uint8_t idx0;
	uint8_t idx1;

	const uint8_t hashmap[] =
	{
		0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
		0x08U, 0x09U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
		0x00U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x00U,
		0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
	};

	memset(output, 0, length);

	for (size_t pos = 0; pos < (length * 2U); pos += 2U)
	{
		idx0 = ((uint8_t)hexstr[pos] & 0x1FU) ^ 0x10U;
		idx1 = ((uint8_t)hexstr[pos + 1U] & 0x1FU) ^ 0x10U;
		output[pos / 2U] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
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
#if defined(_MSC_VER)
	printf_s("%llu", digit);
#else
	printf("%llu", (unsigned long long)digit);
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
