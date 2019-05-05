/*
  This file is for loading/storing data in a little-endian format
*/

#include "util.h"
/* no other option but to use memcpy here */
/*lint -save -e829 */
#include <string.h>
/*lint -restore */

/* bogus integral type warnings */
/*lint -e970 */
/*lint -e731 */

bool are_equal8(const uint8_t* a, const uint8_t* b, size_t length)
{
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < length; ++i)
	{
		if (a[i] != b[i])
		{
			status = false;
			break;
		}
	}

	return status;
}

void bin_to_hex(const uint8_t* input, char* output, size_t length)
{
	char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	size_t i;
	size_t j;

	for (i = 0, j = 0; i < length * 2; i += 2, ++j)
	{
		const char ch = (char)input[j];
		output[i] = hex[(ch & 0xF0) >> 4];
		output[i + 1] = hex[ch & 0xF];
	}
}

void clear8(uint8_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void clear32(uint32_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void clear64(uint64_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void hex_to_bin(const char* input, uint8_t* output, size_t length)
{
	size_t  pos;
	uint8_t  idx0;
	uint8_t  idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	memset(output, 0, length);

	for (pos = 0; (pos < (length * 2)); pos += 2)
	{
		idx0 = ((uint8_t)input[pos] & 0x1F) ^ 0x10;
		idx1 = ((uint8_t)input[pos + 1] & 0x1F) ^ 0x10;
		output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	}
}

uint32_t le8to32(const uint8_t* input)
{
	return ((uint64_t)input[0]) |
		((uint64_t)input[1] << 8) |
		((uint64_t)input[2] << 16) |
		((uint64_t)input[3] << 24);
}

uint64_t le8to64(const uint8_t* input) 
{
	return ((uint64_t)input[0]) |
		((uint64_t)input[1] << 8) |
		((uint64_t)input[2] << 16) |
		((uint64_t)input[3] << 24) |
		((uint64_t)input[4] << 32) |
		((uint64_t)input[5] << 40) |
		((uint64_t)input[6] << 48) |
		((uint64_t)input[7] << 56);
}

void le32to8(uint8_t* output, uint32_t value)
{
	output[0] = value & 0xFF;
	output[1] = (value >> 8) & 0xFF;
	output[2] = (value >> 16) & 0xFF;
	output[3] = (value >> 24) & 0xFF;
}

void le64to8(uint8_t* output, uint64_t value)
{
	output[0] = value & 0xFF;
	output[1] = (value >> 8) & 0xFF;
	output[2] = (value >> 16) & 0xFF;
	output[3] = (value >> 24) & 0xFF;
	output[4] = (value >> 32) & 0xFF;
	output[5] = (value >> 40) & 0xFF;
	output[6] = (value >> 48) & 0xFF;
	output[7] = (value >> 56) & 0xFF;
}
