#include "reduce.h"
#include "params.h"

uint32_t montgomery_reduce(uint64_t a) 
{
	uint64_t t;

	t = a * DILITHIUM_QINV;
	t &= (1ULL << 32) - 1;
	t *= DILITHIUM_Q;
	t = a + t;
	t >>= 32;

	return (uint32_t)t;
}

uint32_t reduce32(uint32_t a) 
{
	uint32_t t;

	t = a & 0x007FFFFFUL;
	a >>= 23;
	t += (a << 13) - a;

	return t;
}

uint32_t csubq(uint32_t a) 
{
	a -= DILITHIUM_Q;
	a += ((int32_t)a >> 31) & DILITHIUM_Q;

	return a;
}

uint32_t freeze(uint32_t a) 
{

	a = reduce32(a);
	a = csubq(a);

	return a;
}
