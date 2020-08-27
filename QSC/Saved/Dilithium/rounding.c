#include "rounding.h"
#include "params.h"

uint32_t power2round(uint32_t a, uint32_t* a0) 
{
	int32_t t;

	/* Centralized remainder mod 2^DILITHIUM_D */
	t = a & ((1U << DILITHIUM_D) - 1);
	t -= (1U << (DILITHIUM_D - 1)) + 1;
	t += (t >> 31) & (1U << DILITHIUM_D);
	t -= (1U << (DILITHIUM_D - 1)) - 1;
	*a0 = DILITHIUM_Q + t;
	a = (a - t) >> DILITHIUM_D;

	return a;
}

uint32_t decompose(uint32_t a, uint32_t* a0)
{
#if DILITHIUM_ALPHA != (DILITHIUM_Q-1)/16
#error "decompose assumes DILITHIUM_ALPHA == (DILITHIUM_Q-1)/16"
#endif

	int32_t t;
	int32_t u;

	/* Centralized remainder mod DILITHIUM_ALPHA */
	t = a & 0x0007FFFFUL;
	t += (a >> 19) << 9;
	t -= DILITHIUM_ALPHA / 2 + 1;
	t += (t >> 31) & DILITHIUM_ALPHA;
	t -= DILITHIUM_ALPHA / 2 - 1;
	a -= t;

	/* Divide by DILITHIUM_ALPHA (possible to avoid) */
	u = a - 1;
	u >>= 31;
	a = (a >> 19) + 1;
	a -= u & 1;

	/* Border case */
	*a0 = DILITHIUM_Q + t - (a >> 4);
	a &= 0x0FU;

	return a;
}

uint32_t make_hint(const uint32_t a0, const uint32_t a1) 
{
	uint32_t r;

	r = 1;

	if (a0 <= DILITHIUM_GAMMA2 || a0 > DILITHIUM_Q - DILITHIUM_GAMMA2 || (a0 == DILITHIUM_Q - DILITHIUM_GAMMA2 && a1 == 0))
	{
		r = 0;
	}

	return r;
}

uint32_t use_hint(const uint32_t a, const uint32_t hint) 
{
	uint32_t a0;
	uint32_t a1;

	a1 = decompose(a, &a0);

	if (hint == 0)
	{
		return a1;
	}
	else if (a0 > DILITHIUM_Q)
	{
		return (a1 + 1) & 0x0FU;
	}
	else
	{
		return (a1 - 1) & 0x0FU;
	}
}
