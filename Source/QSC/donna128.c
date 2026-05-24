#include "donna128.h"

static void Mul64x64To128(uint64_t x, uint64_t y, uint64_t* low, uint64_t* high)
{
	QSC_ASSERT(low != NULL);
	QSC_ASSERT(high != NULL);

	const size_t HWORD_BITS = 32U;
	const uint32_t HWORD_MASK = 0xFFFFFFFFU;
	const uint32_t AH = (uint32_t)(x >> HWORD_BITS);
	const uint32_t AL = (uint32_t)(x & HWORD_MASK);
	const uint32_t BH = (uint32_t)(y >> HWORD_BITS);
	const uint32_t BL = (uint32_t)(y & HWORD_MASK);
	uint64_t x0;
	uint64_t x1;
	uint64_t x2;
	uint64_t x3;

	x0 = (uint64_t)AH * BH;
	x1 = (uint64_t)AL * BH;
	x2 = (uint64_t)AH * BL;
	x3 = (uint64_t)AL * BL;

	/* this cannot overflow as(2 ^ 32 - 1) ^ 2 + 2 ^ 32 - 1 < 2 ^ 64 - 1 */
	x2 += x3 >> HWORD_BITS;
	/* this one can overflow */
	x2 += x1;
	/* propagate the carry if any */
	x0 += (uint64_t)(bool)(x2 < x1) << HWORD_BITS;

	*high = x0 + (x2 >> HWORD_BITS);
	*low = ((x2 & HWORD_MASK) << HWORD_BITS) + (x3 & HWORD_MASK);
}

uint128 qsc_donna128_add(const uint128* x, const uint128* y)
{
	QSC_ASSERT(x != NULL);
	QSC_ASSERT(y != NULL);

	uint128 r = { 0U };

	if (x != NULL && y != NULL)
	{
		r.low = x->low + y->low;
		r.high = x->high + y->high;

		const uint64_t CARRY = (r.low < x->low);
		r.high += CARRY;
	}

	return r;
}

uint64_t qsc_donna128_andl(const uint128* x, uint64_t mask)
{
	QSC_ASSERT(x != NULL);

	uint64_t res;

	res = 0U;

	if (x != NULL)
	{
		res = x->low & mask;
	}

	return res;
}

uint64_t qsc_donna128_andh(const uint128* x, uint64_t mask)
{
	QSC_ASSERT(x != NULL);

	uint64_t res;

	res = 0U;

	if (x != NULL)
	{
		res = x->high & mask;
	}

	return res;
}

uint128 qsc_donna128_multiply(const uint128* x, uint64_t Y)
{
	QSC_ASSERT(x != NULL);

	uint64_t low;
	uint64_t high;
	uint128 r = { 0U };

	if (x != NULL)
	{
		low = 0U;
		high = 0U;

		Mul64x64To128(x->low, Y, &low, &high);
		r.low = low;

		/* add the x->high * Y contribution (mod 2^64) */
		r.high = high + (x->high * Y);
	}

	return r;
}

uint128 qsc_donna128_or(const uint128 * x, const uint128 * y)
{
	QSC_ASSERT(x != NULL);
	QSC_ASSERT(y != NULL);

	uint128 r = { 0U };

	if (x != NULL && y != NULL)
	{
		r.low = x->low | y->low;
		r.high = x->high | y->high;
	}

	return r;
}

uint128 qsc_donna128_shift_left(const uint128* x, size_t shift)
{
	QSC_ASSERT(x != NULL);
	QSC_ASSERT(shift < 128U);

	uint128 r = { 0U };

	if (x != NULL && shift < 128U)
	{
		if (shift == 0U)
		{
			r = *x;
		}
		else if (shift < 64U)
		{
			r.low = x->low << shift;
			r.high = (x->high << shift) | (x->low >> (64U - shift));  // >> not 
		}
		else
		{
			r.low = 0U;
			r.high = x->low << (shift - 64U);
		}
	}

	return r;
}

uint128 qsc_donna128_shift_right(const uint128* x, size_t shift)
{
	QSC_ASSERT(x != NULL);
	QSC_ASSERT(shift < 128U);

	uint128 r = { 0U };

	if (x != NULL && shift < 128U)
	{
		if (shift == 0U)
		{
			r = *x;
		}
		else if (shift < 64U)
		{
			r.high = x->high >> shift;
			r.low = (x->low >> shift) | (x->high << (64U - shift));
		}
		else
		{
			r.high = 0U;
			r.low = x->high >> (shift - 64U);
		}
	}

	return r;
}

uint128 qsc_donna128_subtract(const uint128* x, const uint128* y)
{
	QSC_ASSERT(x != NULL);
	QSC_ASSERT(y != NULL);

	uint128 r = { 0U };

	if (x != NULL && y != NULL)
	{
		r.low = x->low - y->low;

		/* borrow: if the low subtraction underflowed, the unsigned wrap
		 * means x->low < y->low.  Propagate one borrow into the high word. */
		const uint64_t BORROW = (x->low < y->low) ? 1U : 0U;
		r.high = x->high - y->high - BORROW;
	}

	return r;
}
