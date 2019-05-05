/*
  This file is for syndrome computation
*/

#include "synd.h"

#include "params.h"
#include "root.h"

/* input: Goppa polynomial f, support L, received word r */
/* output: out, the syndrome of length 2t */
void synd(gf* out, const gf* f, const gf* L, const uint8_t* r)
{
	size_t i;
	size_t j;
	gf c;
	gf e;
	gf einv;

	for (j = 0; j < 2 * SYS_T; j++)
	{
		out[j] = 0;
	}

	for (i = 0; i < SYS_N; i++)
	{
		c = (r[i / 8] >> (i % 8)) & 1;
		e = eval(f, L[i]);
		einv = gf_inv(gf_mul(e, e));

		for (j = 0; j < 2 * SYS_T; j++)
		{
			out[j] = gf_add(out[j], gf_mul(einv, c));
			einv = gf_mul(einv, L[i]);
		}
	}
}

