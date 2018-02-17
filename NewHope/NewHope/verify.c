#include "verify.h"

void cmov(uint8_t* r, const uint8_t* x, size_t length, uint8_t b)
{
	size_t i;

	b = ~b + 1;

	for (i = 0; i < length; i++)
	{
		r[i] ^= b & (x[i] ^ r[i]);
	}
}

int verify(const uint8_t *a, const uint8_t *b, size_t length)
{
	size_t i;
	int32_t r;

	r = 0;

	for (i = 0; i < length; i++)
	{
		r |= (a[i] ^ b[i]);
	}

	return r;
}
