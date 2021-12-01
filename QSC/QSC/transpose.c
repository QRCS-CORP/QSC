#include "transpose.h"
#include "ecdhbase.h"
#include "memutils.h"

void qsc_transpose_bytes_to_native(uint32_t* output, const uint8_t* input, size_t length)
{
	assert(output != NULL);
	assert(input != NULL);

	size_t j;

	qsc_intutils_clear32(output, (length + (sizeof(uint32_t) - 1)) / sizeof(uint32_t));

	for (size_t i = 0; i < length; ++i)
	{
		j = length - 1 - i;
		output[j / sizeof(uint32_t)] |= (uint32_t)input[i] << (8 * (j % sizeof(uint32_t)));
	}
}

void qsc_transpose_hex_to_bin(uint8_t* output, const char* input, size_t length)
{
	assert(output != NULL);
	assert(input != NULL);

	uint8_t idx0;
	uint8_t idx1;

	const uint8_t HASHMAP[32] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	qsc_memutils_clear(output, length);

	for (size_t pos = 0; pos < (length * 2); pos += 2)
	{
		idx0 = ((uint8_t)input[pos + 0] & 0x1FU) ^ 0x10U;
		idx1 = ((uint8_t)input[pos + 1] & 0x1FU) ^ 0x10U;
		output[pos / 2] = (uint8_t)(HASHMAP[idx0] << 4) | HASHMAP[idx1];
	}
}

void qsc_transpose_native_to_bytes(uint8_t* output, const uint32_t* input, size_t length)
{
	assert(output != NULL);
	assert(input != NULL);

	for (size_t i = 0; i < length; ++i)
	{
		uint8_t b = (uint8_t)(length - 1 - i);
		output[i] = (uint8_t)input[b / sizeof(uint32_t)] >> (8 * (b % sizeof(uint32_t)));
	}
}

void qsc_transpose_string_to_scalar(uint32_t* output, const char* input, size_t length)
{
	assert(output != NULL);
	assert(input != NULL);

	const size_t HEXLEN = strlen(input);
	uint8_t* tmp;
	size_t len;
	size_t pad;

	len = 4 * length;
	tmp = (uint8_t*)qsc_memutils_malloc(len);

	if (tmp != NULL)
	{
		pad = (len * 2) - strlen(input);

		if (pad == 0)
		{
			qsc_memutils_clear(tmp, pad / 2);
			qsc_transpose_hex_to_bin(tmp + (pad / 2), input, HEXLEN);
			qsc_transpose_bytes_to_native(output, tmp, len);
		}

		qsc_memutils_alloc_free(tmp);
	}
}
