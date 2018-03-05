#include <string.h>
#include <stdint.h>

int32_t verify(const uint8_t *a, const uint8_t *b, size_t len)
{
	int64_t r;
	size_t i;

	r = 0;

	for (i = 0; i < len; i++)
	{
		r |= a[i] ^ b[i];
	}

	r = (-r) >> 63;

	return (int32_t)r;
}

void cmov(uint8_t* r, const uint8_t* x, size_t length, uint8_t b)
{
	size_t i;

	b = -b;
	for (i = 0; i < length; i++)
	{
		r[i] ^= b & (x[i] ^ r[i]);
	}
}
