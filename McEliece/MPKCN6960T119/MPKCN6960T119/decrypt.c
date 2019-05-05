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
	int32_t w;
	uint16_t check;
	gf t;

	w = 0;

	for (i = 0; i < SYND_BYTES; i++)
	{
		r[i] = c[i];
	}

	r[i - 1] &= (1 << ((GFBITS * SYS_T) % 8)) - 1;

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
		e[i] = 0x00;
	}

	for (i = 0; i < SYS_N; i++)
	{
		t = gf_iszero(images[i]) & 1;
		e[i / 8] |= (uint8_t)(t << (i % 8));
		w += t;

	}

	synd(s_cmp, g, L, e);
	check = (uint16_t)w;
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
