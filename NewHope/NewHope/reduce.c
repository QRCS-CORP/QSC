#include "reduce.h"
#include "params.h"

 /* -inverse_mod(p,2^18) */
static const uint32_t QINV = 12287;
static const uint32_t RLOG = 18;

uint16_t montgomery_reduce(uint32_t a)
{
	uint32_t u;

	u = (a * QINV);
	u &= ((1 << RLOG) - 1);
	u *= NEWHOPE_Q;
	a = a + u;

	return a >> 18;
}
