#include "reduce.h"
#include "params.h"

static const uint32_t qinv = 12287;
static const uint32_t rlog = 18;

uint16_t montgomery_reduce(uint32_t a)
{
	uint32_t u;

	u = (a * qinv);
	u &= ((1 << rlog) - 1);
	u *= NEWHOPE_Q;
	a = a + u;

	return a >> 18;
}
