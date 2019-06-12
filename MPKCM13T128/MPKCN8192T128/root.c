/*
  This file is for evaluating a polynomial at one or more field elements
*/

#include "params.h"
#include "gf.h"

/* input: polynomial f and field element a */
/* return f(a) */
gf eval(const gf* f, gf a)
{
	size_t i;
	gf r;

	r = f[SYS_T];
	i = SYS_T;

	do
	{
		--i;
		r = gf_mul(r, a);
		r = gf_add(r, f[i]);
	} while (i != 0);

	return r;
}

/* input: polynomial f and list of field elements L */
/* output: out = [ f(a) for a in L ] */
void root(gf* out, const gf* f, const gf* L)
{
	size_t i;

	for (i = 0; i < SYS_N; i++)
	{
		out[i] = eval(f, L[i]);
	}
}

