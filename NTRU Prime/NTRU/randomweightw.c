#include "randomweightw.h"
#include "aesdrbg.h"
#include "common.h"
#include "params.h"
#include "sort.h"
#include "sysrand.h"

void small_seeded_weightw(int8_t* f, const uint8_t* k)
{
	int32_t r[NTRU_P];
	int32_t i;
	uint8_t n[16];

	for (i = 0; i < 16; i++)
	{
		n[i] = 0;
	}

	/*lint -e534 */
	aes256_generate((uint8_t*)r, sizeof r, n, k);

	for (i = 0; i < NTRU_P; ++i)
	{
		r[i] ^= 0x80000000;
	}

	for (i = 0; i < NTRU_W; ++i)
	{
		r[i] &= -2;
	}

	for (i = NTRU_W; i < NTRU_P; ++i)
	{
		r[i] = (r[i] & -3) | 1;
	}

	sort(r, NTRU_P);

	for (i = 0; i < NTRU_P; ++i)
	{
		f[i] = ((uint8_t)(r[i] & 3)) - 1;
	}
}

void small_random_weightw(int8_t* f)
{
	uint8_t k[32];

	/*lint -e534 */
	sysrand_getbytes(k, 32);
	small_seeded_weightw(f, k);
}
