/*
  This file is for Nieddereiter decryption
*/

#include "decrypt.h"
#include "params.h"
#include "benes.h"
#include "util.h"
#include "synd.h"
#include "root.h"
#include "gf.h"
#include "bm.h"
#ifdef MPKCM13T128_KAT
#	include <stdio.h>
#endif

/* Nieddereiter decryption with the Berlekamp decoder */
/* intput: sk, secret key */
/*         c, ciphertext */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
int32_t decrypt(uint8_t* e, const uint8_t* sk, const uint8_t* c)
{
	gf g[SYS_T + 1];
	gf L[SYS_N];
	gf s[SYS_T * 2];
	gf s_cmp[SYS_T * 2];
	gf locator[SYS_T + 1];
	gf images[SYS_N];
	uint8_t r[SYS_N / 8];
	size_t i;
	gf check;
	gf t;
	gf w;

	for (i = 0; i < SYND_BYTES; i++)
	{
		r[i] = c[i];
	}

	for (i = SYND_BYTES; i < SYS_N / 8; i++)
	{
		r[i] = 0;
	}

	for (i = 0; i < SYS_T; i++)
	{
		g[i] = load2(sk);
		g[i] &= GFMASK;
		sk += 2;
	}

	g[SYS_T] = 1;
	support_gen(L, sk);
	synd(s, g, L, r);
	bm(locator, s);
	root(images, locator, L);

	for (i = 0; i < SYS_N / 8; i++)
	{
		e[i] = 0;
	}

	w = 0;

	for (i = 0; i < SYS_N; i++)
	{
		t = gf_iszero(images[i]) & 1;
		e[i / 8] |= t << (i % 8);
		w += t;
	}

#ifdef MPKCM13T128_KAT
	{
		int32_t k;

		printf("decrypt e: positions");

		for (k = 0; k < SYS_N; ++k)
		{
			if (e[k / 8] & (1 << (k & 7)))
			{
				printf(" %d", k);
			}
		}

		printf("\n");
	}
#endif

	synd(s_cmp, g, L, e);
	check = w;
	check ^= SYS_T;

	for (i = 0; i < SYS_T * 2; i++)
	{
		check |= s[i] ^ s_cmp[i];
	}

	check -= 1;
	check >>= 15;
	check ^= 1;

	return check;
}

