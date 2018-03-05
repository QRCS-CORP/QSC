#include "small.h"
#include "params.h"

/* These functions rely on p mod 4 = 1 */


void small_encode(uint8_t* c, const int8_t* f)
{
	/* all coefficients in -1, 0, 1 */
	uint8_t c0;
	size_t i;

	for (i = 0; i < NTRU_P / 4; ++i)
	{
		c0 = *f++ + 1;
		c0 += (*f++ + 1) << 2;
		c0 += (*f++ + 1) << 4;
		c0 += (*f++ + 1) << 6;
		*c++ = c0;
	}

	c0 = *f++ + 1;
	*c++ = c0;
}

void small_decode(int8_t* f, const uint8_t* c)
{
	uint8_t c0;
	size_t i;

	for (i = 0; i < NTRU_P / 4; ++i)
	{
		c0 = *c++;
		*f++ = ((uint8_t)(c0 & 3)) - 1; c0 >>= 2;
		*f++ = ((uint8_t)(c0 & 3)) - 1; c0 >>= 2;
		*f++ = ((uint8_t)(c0 & 3)) - 1; c0 >>= 2;
		*f++ = ((uint8_t)(c0 & 3)) - 1;
	}

	c0 = *c++;
	*f++ = ((uint8_t)(c0 & 3)) - 1;
}
