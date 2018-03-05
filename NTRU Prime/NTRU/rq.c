#include "rq.h"
#include "aesdrbg.h"
#include "common.h"
#include "modq.h"
#include "params.h"

void rq_decoderounded(int16_t* f, const uint8_t* c)
{
	uint32_t c0;
	uint32_t c1;
	uint32_t c2;
	uint32_t c3;
	uint32_t f0;
	uint32_t f1;
	uint32_t f2;
	int32_t i;

	for (i = 0; i < NTRU_P / 3; ++i)
	{
		c0 = *c++;
		c1 = *c++;
		c2 = *c++;
		c3 = *c++;

		/* f0 + f1*1536 + f2*1536^2 = c0 + c1*256 + c2*256^2 + c3*256^3
		   with each f between 0 and 1530 */

		/* f2 = (64/9)c3 + (1/36)c2 + (1/9216)c1 + (1/2359296)c0 - [0,0.99675] 
		   claim: 2^21 f2 < x < 2^21(f2+1)
		   where x = 14913081*c3 + 58254*c2 + 228*(c1+2)
		   proof: x - 2^21 f2 = 456 - (8/9)c0 + (4/9)c1 - (2/9)c2 + (1/9)c3 + 2^21 [0,0.99675]
		   at least 456 - (8/9)255 - (2/9)255 > 0
		   at most 456 + (4/9)255 + (1/9)255 + 2^21 0.99675 < 2^21 */
		f2 = (14913081 * c3 + 58254 * c2 + 228 * (c1 + 2)) >> 21;

		c2 += c3 << 8;
		c2 -= (f2 * 9) << 2;

		/* f0 + f1*1536 = c0 + c1*256 + c2*256^2
		   c2 <= 35 = floor((1530+1530*1536)/256^2)
		   f1 = (128/3)c2 + (1/6)c1 + (1/1536)c0 - (1/1536)f0
		   claim: 2^21 f1 < x < 2^21(f1+1)
		   where x = 89478485*c2 + 349525*c1 + 1365*(c0+1)
		   proof: x - 2^21 f1 = 1365 - (1/3)c2 - (1/3)c1 - (1/3)c0 + (4096/3)f0
		   at least 1365 - (1/3)35 - (1/3)255 - (1/3)255 > 0
	       at most 1365 + (4096/3)1530 < 2^21 */
		f1 = (89478485 * c2 + 349525 * c1 + 1365 * (c0 + 1)) >> 21;

		c1 += c2 << 8;
		c1 -= (f1 * 3) << 1;

		c0 += c1 << 8;
		f0 = c0;

		*f++ = modq_freeze(f0 * 3 + NTRU_Q - NTRU_QSHIFT);
		*f++ = modq_freeze(f1 * 3 + NTRU_Q - NTRU_QSHIFT);
		*f++ = modq_freeze(f2 * 3 + NTRU_Q - NTRU_QSHIFT);
	}

	c0 = *c++;
	c1 = *c++;
	c2 = *c++;

	f1 = (89478485 * c2 + 349525 * c1 + 1365 * (c0 + 1)) >> 21;

	c1 += c2 << 8;
	c1 -= (f1 * 3) << 1;

	c0 += c1 << 8;
	f0 = c0;

	*f++ = modq_freeze(f0 * 3 + NTRU_Q - NTRU_QSHIFT);
	*f++ = modq_freeze(f1 * 3 + NTRU_Q - NTRU_QSHIFT);
}

void rq_encoderounded(uint8_t* c, const int16_t* f)
{
	int32_t f0;
	int32_t f1;
	int32_t f2;
	size_t i;

	for (i = 0; i < NTRU_P / 3; ++i)
	{
		f0 = *f++ + NTRU_QSHIFT;
		f1 = *f++ + NTRU_QSHIFT;
		f2 = *f++ + NTRU_QSHIFT;
		f0 = (21846 * f0) >> 16;
		f1 = (21846 * f1) >> 16;
		f2 = (21846 * f2) >> 16;
		/* now want f0 + f1*1536 + f2*1536^2 as a 32-bit integer */
		f2 *= 3;
		f1 += f2 << 9;
		f1 *= 3;
		f0 += f1 << 9;
		*c++ = f0; f0 >>= 8;
		*c++ = f0; f0 >>= 8;
		*c++ = f0; f0 >>= 8;
		*c++ = f0;
	}

	/* using p mod 3 = 2 */
	f0 = *f++ + NTRU_QSHIFT;
	f1 = *f++ + NTRU_QSHIFT;
	f0 = (21846 * f0) >> 16;
	f1 = (21846 * f1) >> 16;
	f1 *= 3;
	f0 += f1 << 9;
	*c++ = f0; f0 >>= 8;
	*c++ = f0; f0 >>= 8;
	*c++ = f0;
}

void rq_fromseed(int16_t* h, const uint8_t* K)
{
	uint32_t buf[NTRU_P];
	size_t i;
	uint8_t n[16];

	for (i = 0; i < 16; i++)
	{
		n[i] = 0;
	}

	/*lint -e534 */
	aes256_generate((uint8_t*)buf, sizeof buf, n, K);

	for (i = 0; i < NTRU_P; ++i)
	{
		h[i] = modq_fromuint32(buf[i]);
	}
}

void rq_mult(int16_t* h, const int16_t* f, const int8_t* g)
{
	int16_t fg[NTRU_P + NTRU_P - 1];
	int16_t result;
	size_t i;
	size_t j;

	for (i = 0; i < NTRU_P; ++i)
	{
		result = 0;
		for (j = 0; j <= i; ++j)
		{
			result = modq_plusproduct(result, f[j], g[i - j]);
		}
		fg[i] = result;
	}

	for (i = NTRU_P; i < NTRU_P + NTRU_P - 1; ++i)
	{
		result = 0;
		for (j = i - NTRU_P + 1; j < NTRU_P; ++j)
		{
			result = modq_plusproduct(result, f[j], g[i - j]);
		}
		fg[i] = result;
	}

	for (i = NTRU_P + NTRU_P - 2; i >= NTRU_P; --i)
	{
		fg[i - NTRU_P] = modq_sum(fg[i - NTRU_P], fg[i]);
		fg[i - NTRU_P + 1] = modq_sum(fg[i - NTRU_P + 1], fg[i]);
	}

	for (i = 0; i < NTRU_P; ++i)
	{
		h[i] = fg[i];
	}
}

void rq_round3(int16_t* h, const int16_t* f)
{
	int32_t i;

	for (i = 0; i < NTRU_P; ++i)
	{
		h[i] = ((21846 * (f[i] + 2295) + 32768) >> 16) * 3 - 2295;
	}
}
