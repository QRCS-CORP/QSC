#include "testutils.h"
#include <string.h>

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

void hex_to_bin(const char* str, uint8_t* output, size_t length)
{
	uint8_t  idx0;
	uint8_t  idx1;
	size_t  pos;

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
		idx0 = ((uint8_t)str[pos + 0] & 0x1F) ^ 0x10;
		idx1 = ((uint8_t)str[pos + 1] & 0x1F) ^ 0x10;
		output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
}
