#include "cavp_utils.h"


bool cavp_byte_arrays_are_equal8(const uint8_t* a, const uint8_t* b, size_t length)
{
	CAVP_ASSERT(a != NULL);
	CAVP_ASSERT(b != NULL);

	bool status;

	status = true;

	for (size_t i = 0U; i < length; ++i)
	{
		if (a[i] != b[i])
		{
			status = false;
			break;
		}
	}

	return status;
}

char cavp_get_char()
{
	char line[8U] = { 0 };

	fgets(line, sizeof(line), stdin);

	return line[0];
}

char cavp_get_wait()
{
	char res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (char)getwchar();
#else
	res = getchar();
#endif

	return res;
}

void cavp_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
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

void cavp_bin_to_hex(const char* input, size_t inplen, uint8_t* output, size_t otplen, size_t* declen)
{
    size_t req;

    req = inplen / 2;

    if (inplen % 2 == 0U && req <= otplen && input != NULL && output != NULL && declen != NULL)
    {
        for (size_t i = 0U; i < req; i++)
        {
            char c1;
            char c2;
            uint8_t nibble1;
            uint8_t nibble2;

            c1 = input[2U * i];
            c2 = input[(2U * i) + 1U];

            if (c1 >= '0' && c1 <= '9')
            {
                nibble1 = c1 - '0';
            }
            else if (c1 >= 'A' && c1 <= 'F')
            {
                nibble1 = c1 - 'A' + 10U;
            }
            else if (c1 >= 'a' && c1 <= 'f')
            {
                nibble1 = c1 - 'a' + 10U;
            }
            else
            {
                break;
            }

            if (c2 >= '0' && c2 <= '9')
            {
                nibble2 = c2 - '0';
            }
            else if (c2 >= 'A' && c2 <= 'F')
            {
                nibble2 = c2 - 'A' + 10U;
            }
            else if (c2 >= 'a' && c2 <= 'f')
            {
                nibble2 = c2 - 'a' + 10U;
            }
            else
            {
                break;
            }

            output[i] = (nibble1 << 4) | nibble2;
        }

        *declen = req;
    }
}

void cavp_print_hex(const uint8_t* input, size_t inputlen, size_t linelen)
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
		cavp_print_safe("\n");
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

void cavp_print_safe(const char* input)
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

void cavp_print_line(const char* input)
{
	cavp_print_safe(input);
	cavp_print_safe("\n");
}

void cavp_print_ulong(uint64_t digit)
{
#if defined(_MSC_VER)
	printf_s("%llu", digit);
#else
	printf("%llu", (unsigned long long)digit);
#endif
}

void cavp_print_double(double digit)
{
#if defined(_MSC_VER)
	printf_s("%.*lf", 3, digit);
#else
	printf("%.*lf", 3, digit);
#endif
}

bool cavp_test_confirm(const char* message)
{
	char ans;
	bool res;

	cavp_print_line(message);

	res = false;
	ans = cavp_get_char();

	if (ans == 'y' || ans == 'Y')
	{
		res = true;
	}

	return res;
}