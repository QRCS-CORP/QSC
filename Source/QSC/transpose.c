#include "transpose.h"
#include "memutils.h"
#include <string.h>

void qsc_transpose_bytes_to_native(uint32_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(length != 0U);

	size_t j;

	if (output != NULL && input != NULL && length != 0U)
	{
		qsc_intutils_clear32(output, (length + (4U - 1U)) / 4U);

		for (size_t i = 0U; i < length; ++i)
		{
			j = length - 1U - i;
			output[j / 4U] |= (uint32_t)input[i] << (8U * (j % 4U));
		}
	}
}

void qsc_transpose_hex_to_bin(uint8_t* output, const char* input, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(length != 0U);

	uint8_t idx0;
	uint8_t idx1;

	if (output != NULL && input != NULL && length != 0U)
	{
		size_t inlen = strlen(input);

		if (inlen >= (length * 2U))
		{
			const uint8_t HASHMAP[32U] =
			{
				0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
				0x08U, 0x09U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
				0x00U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x00U,
				0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
			};

			qsc_memutils_clear(output, length);

			for (size_t pos = 0U; pos < (length * 2U); pos += 2U)
			{
				idx0 = ((uint8_t)input[pos] & 0x1FU) ^ 0x10U;
				idx1 = ((uint8_t)input[pos + 1U] & 0x1FU) ^ 0x10U;
				output[pos / 2U] = (uint8_t)(HASHMAP[idx0] << 4) | HASHMAP[idx1];
			}
		}
	}
}

void qsc_transpose_native_to_bytes(uint8_t* output, const uint32_t* input, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(length != 0U);

	if (output != NULL && input != NULL && length != 0U)
	{
		for (size_t i = 0U; i < length; ++i)
		{
			size_t j = length - 1U - i;
			output[i] = (uint8_t)(input[j / 4U] >> (8U * (j % 4U)));
		}
	}
}

void qsc_transpose_string_to_scalar(uint32_t* output, const char* input, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(length != 0U);

	const size_t strn = strlen(input);
	uint8_t* tmp;
	size_t len;
	size_t pad;

	if (output != NULL && input != NULL && length != 0U && strn > 0U)
	{
		len = 4U * length;
		tmp = (uint8_t*)qsc_memutils_malloc(len);

		if (tmp != NULL)
		{
			size_t expected = len * 2U;

			pad = (expected > strn) ? (expected - strn) : 0U;
			qsc_memutils_clear(tmp, pad / 2U);

			qsc_transpose_hex_to_bin(tmp + (pad / 2U),
				input + ((strn > (len * 2U)) ? (strn - (len * 2U)) : 0U),
				((strn > (len * 2U)) ? (len * 2U) : strn) / 2U);

			qsc_transpose_bytes_to_native(output, tmp, len);

			qsc_memutils_alloc_free(tmp);
			tmp = NULL;
		}
	}
}
