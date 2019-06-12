#include "reduce.h"
#include "params.h"

/* jgu info notice checked and suppressed */
/*lint -e702 */

int16_t montgomery_reduce(int32_t a)
{
	int32_t t;
	int16_t u;

	u = (int16_t)(a * QINV);
	t = (int32_t)(u * KYBER_Q);
	t = a - t;
	t >>= 16;

	return (int16_t)t;
}

int16_t barrett_reduce(int16_t a) 
{
	const int32_t V = (1U << 26) / KYBER_Q + 1;
	int32_t t;

	t = V * a;
	t >>= 26;
	t *= KYBER_Q;

	return (int16_t)(a - t);
}

int16_t csubq(int16_t a) 
{
	a -= KYBER_Q;
	a += (a >> 15) & KYBER_Q;

	return a;
}
