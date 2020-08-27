#include "polyvec.h"
#include "params.h"
#include "poly.h"

void polyvecl_freeze(polyvecl* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_L; ++i)
	{
		poly_freeze(&v->vec[i]);
	}
}

void polyvecl_add(polyvecl* w, const polyvecl* u, const polyvecl* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_L; ++i)
	{
		poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
	}
}

void polyvecl_ntt(polyvecl* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_L; ++i)
	{
		poly_ntt(&v->vec[i]);
	}
}

void polyvecl_pointwise_acc_invmontgomery(poly* w, const polyvecl* u, const polyvecl* v)
{
	poly t;
	size_t i;

	poly_pointwise_invmontgomery(w, &u->vec[0], &v->vec[0]);

	for (i = 1; i < DILITHIUM_L; ++i) 
	{
		poly_pointwise_invmontgomery(&t, &u->vec[i], &v->vec[i]);
		poly_add(w, w, &t);
	}
}

int32_t polyvecl_chknorm(const polyvecl* v, uint32_t bound) 
{
	size_t i;
	int32_t r;

	r = 0;

	for (i = 0; i < DILITHIUM_L; ++i)
	{
		if (poly_chknorm(&v->vec[i], bound))
		{
			r = 1;
			break;
		}
	}

	return r;
}

void polyveck_reduce(polyveck* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_reduce(&v->vec[i]);
	}
}

void polyveck_csubq(polyveck* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_csubq(&v->vec[i]);
	}
}

void polyveck_freeze(polyveck* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_freeze(&v->vec[i]);
	}
}

void polyveck_add(polyveck* w, const polyveck* u, const polyveck* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
	}
}

void polyveck_sub(polyveck* w, const polyveck* u, const polyveck* v)
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
	}
}

void polyveck_shiftl(polyveck* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_shiftl(&v->vec[i]);
	}
}

void polyveck_ntt(polyveck* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_ntt(&v->vec[i]);
	}
}

void polyveck_invntt_montgomery(polyveck* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_invntt_montgomery(&v->vec[i]);
	}
}

int32_t polyveck_chknorm(const polyveck* v, uint32_t bound) 
{
	size_t i;
	int32_t r;

	r = 0;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		if (poly_chknorm(&v->vec[i], bound))
		{
			r = 1;
			break;
		}
	}

	return r;
}

void polyveck_power2round(polyveck* v1, polyveck* v0, const polyveck* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
	}
}

void polyveck_decompose(polyveck* v1, polyveck* v0, const polyveck* v) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
	}
}

uint32_t polyveck_make_hint(polyveck* h, const polyveck* v0, const polyveck* v1)
{
	size_t i;
	uint32_t s;

	s = 0;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
	}

	return s;
}

void polyveck_use_hint(polyveck* w, const polyveck* u, const polyveck* h) 
{
	size_t i;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
	}
}
