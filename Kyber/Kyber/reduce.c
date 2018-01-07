#include "reduce.h"
#include "params.h"

/* inverse_mod(q,2^18) */
static const uint32_t QINV = 7679;
static const uint32_t RLOG = 18;


uint16_t montgomery_reduce(uint32_t x)
{
	uint32_t u;

	u = (x * QINV);
	u &= ((1 << RLOG) - 1);
	u *= KYBER_Q;
	x = x + u;

	return x >> RLOG;
}

uint16_t barrett_reduce(uint16_t x)
{
	uint32_t u;

	/* note: newhope is this: u = (((uint32_t)x * 5) >> 16); */
	u = x >> 13;
	u *= KYBER_Q;
	x -= u;

	return x;
}

uint16_t freeze(uint16_t x)
{
	uint16_t m;
	uint16_t r;
	int16_t c;

	r = barrett_reduce(x);
	m = r - KYBER_Q;
	c = m;
	c >>= 15;
	r = m ^ ((r ^ m) & c);

	return r;
}
