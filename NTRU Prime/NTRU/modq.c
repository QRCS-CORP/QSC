#include "modq.h"

int16_t modq_freeze(int32_t a)
{
	/* input between -9000000 and 9000000 output between -2295 and 2295 */
	a -= 4591 * ((228 * a) >> 20);
	a -= 4591 * ((58470 * a + 134217728) >> 28);

	return a;
}

int16_t modq_fromuint32(uint32_t a)
{
	/* input between 0 and 4294967295 output = (input % 4591) - 2295 */
	int32_t r;

	r = (a & 524287) + (a >> 19) * 914; /* <= 8010861 */

	return modq_freeze(r - 2295);
}

int16_t modq_plusproduct(int16_t a, int16_t b, int16_t c)
{
	int32_t s = a + (b * c);

	return modq_freeze(s);
}

int16_t modq_sum(int16_t a, int16_t b)
{
	int32_t s = a + b;

	return modq_freeze(s);
}