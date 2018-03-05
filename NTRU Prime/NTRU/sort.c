#include "sort.h"
#include "common.h"

static void minmax(int32_t *x, int32_t *y)
{
	uint32_t xi;
	uint32_t yi;
	uint32_t xy;
	uint32_t c;

	xi = *x;
	yi = *y;
	xy = xi ^ yi;
	c = yi - xi;

	c ^= xy & (c ^ yi);
	c >>= 31;
	c = ~c + 1;
	c &= xy;
	*x = xi ^ c;
	*y = yi ^ c;
}

void sort(int32_t* x, int32_t n)
{
	int32_t top;
	int32_t p;
	int32_t q;
	int32_t i;

	if (n < 2)
	{
		return;
	}

	top = 1;

	while (top < n - top)
	{
		top += top;
	}

	for (p = top; p > 0; p >>= 1)
	{
		for (i = 0; i < n - p; ++i)
		{
			if (!(i & p))
			{
				minmax(x + i, x + i + p);
			}
		}

		for (q = top; q > p; q >>= 1)
		{
			for (i = 0; i < n - q; ++i)
			{
				if (!(i & p))
				{
					minmax(x + i + p, x + i + q);
				}
			}
		}
	}
}
