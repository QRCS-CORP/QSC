#include "transpose.h"
#include <string.h>

/* \cond DOXYGEN_NO_DOCUMENT */

/** \brief Decode a hexadecimal digit, returning UINT8_MAX on malformed input. */
static uint8_t transpose_nibble(uint8_t input)
{
	uint8_t res;

	res = UINT8_MAX;

	if (input >= (uint8_t)'0' && input <= (uint8_t)'9')
	{
		res = (uint8_t)(input - (uint8_t)'0');
	}
	else if (input >= (uint8_t)'A' && input <= (uint8_t)'F')
	{
		res = (uint8_t)(input - (uint8_t)'A' + 10U);
	}
	else if (input >= (uint8_t)'a' && input <= (uint8_t)'f')
	{
		res = (uint8_t)(input - (uint8_t)'a' + 10U);
	}

	return res;
}

void qsc_transpose_bytes_to_native(uint32_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	size_t index;

	if (output != NULL && input != NULL && length != 0U && length <= (SIZE_MAX - 3U))
	{
		qsc_intutils_clear32(output, (length + 3U) / 4U);

		for (size_t i = 0U; i < length; ++i)
		{
			index = length - 1U - i;
			output[i / 4U] |= (uint32_t)input[index] << (8U * (i % 4U));
		}
	}
}

void qsc_transpose_hex_to_bin(uint8_t* output, const char* input, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	if (output != NULL && input != NULL && length != 0U && length <= (SIZE_MAX / 2U))
	{
		if (strlen(input) >= (length * 2U))
		{
			qsc_intutils_hex_to_bin(input, output, length);
		}
	}
}

void qsc_transpose_native_to_bytes(uint8_t* output, const uint32_t* input, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	size_t index;

	if (output != NULL && input != NULL && length != 0U)
	{
		for (size_t i = 0U; i < length; ++i)
		{
			index = length - 1U - i;
			output[i] = (uint8_t)(input[index / 4U] >> (8U * (index % 4U)));
		}
	}
}

void qsc_transpose_string_to_scalar(uint32_t* output, const char* input, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	size_t charidx;
	size_t chars;
	size_t count;
	size_t strn;
	uint8_t high;
	uint8_t low;
	bool valid;

	if (output != NULL && input != NULL && length != 0U && length <= (SIZE_MAX / 4U))
	{
		count = length * 4U;
		strn = strlen(input);
		chars = (strn / 2U) + (strn % 2U);
		chars = (chars < count) ? chars : count;
		valid = true;

		for (size_t i = 0U; i < chars; ++i)
		{
			charidx = strn - 1U - (i * 2U);
			low = transpose_nibble((uint8_t)input[charidx]);
			high = (charidx != 0U) ? transpose_nibble((uint8_t)input[charidx - 1U]) : 0U;

			if (low == UINT8_MAX || high == UINT8_MAX)
			{
				valid = false;
				break;
			}
		}

		if (valid == true)
		{
			qsc_intutils_clear32(output, length);

			for (size_t i = 0U; i < chars; ++i)
			{
				charidx = strn - 1U - (i * 2U);
				low = transpose_nibble((uint8_t)input[charidx]);
				high = (charidx != 0U) ? transpose_nibble((uint8_t)input[charidx - 1U]) : 0U;
				output[i / 4U] |= (uint32_t)((high << 4U) | low) << (8U * (i % 4U));
			}
		}
	}
}

/* \endcond DOXYGEN_NO_DOCUMENT */
