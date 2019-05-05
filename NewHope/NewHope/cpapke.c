#include "poly.h"
#include "rng.h"
#include "sha3.h"

/*lint -e953 */
/*lint -e747 */

static void encode_pk(uint8_t* r, const poly* pk, const uint8_t* seed)
{
	size_t i;

	poly_tobytes(r, pk);

	for (i = 0; i < NEWHOPE_SYMBYTES; ++i)
	{
		r[NEWHOPE_POLYBYTES + i] = seed[i];
	}
}

static void decode_pk(poly* pk, uint8_t* seed, const uint8_t* r)
{
	size_t i;

	poly_frombytes(pk, r);

	for (i = 0; i < NEWHOPE_SYMBYTES; ++i)
	{
		seed[i] = r[NEWHOPE_POLYBYTES + i];
	}
}

static void encode_c(uint8_t* r, const poly* b, const poly* v)
{
	poly_tobytes(r, b);
	poly_compress(r + NEWHOPE_POLYBYTES, v);
}

static void decode_c(poly* b, poly* v, const uint8_t* r)
{
	poly_frombytes(b, r);
	poly_decompress(v, r + NEWHOPE_POLYBYTES);
}

static void gen_a(poly* a, const uint8_t* seed)
{
	poly_uniform(a, seed);
}

void cpapke_keypair(uint8_t* pk, uint8_t* sk)
{
	poly ahat;
	poly ehat;
	poly ahatshat;
	poly bhat;
	poly shat;
	uint8_t z[2 * NEWHOPE_SYMBYTES];
	/* jgu checked false 953 warning */
	const uint8_t* publicseed = z;
	const uint8_t* noiseseed = z + NEWHOPE_SYMBYTES;

	if (randombytes(z, NEWHOPE_SYMBYTES) == 0)
	{
		shake256(z, 2 * NEWHOPE_SYMBYTES, z, NEWHOPE_SYMBYTES);

		gen_a(&ahat, publicseed);

		poly_sample(&shat, noiseseed, 0);
		poly_ntt(&shat);

		poly_sample(&ehat, noiseseed, 1);
		poly_ntt(&ehat);

		poly_mul_pointwise(&ahatshat, &shat, &ahat);
		poly_add(&bhat, &ehat, &ahatshat);

		poly_tobytes(sk, &shat);
		encode_pk(pk, &bhat, publicseed);
	}
}

void cpapke_enc(uint8_t* c, const uint8_t* m, const uint8_t* pk, const uint8_t* coin)
{
	poly sprime;
	poly eprime;
	poly vprime;
	poly ahat;
	poly bhat;
	poly eprimeprime;
	poly uhat;
	poly v;
	uint8_t publicseed[NEWHOPE_SYMBYTES];

	poly_frommsg(&v, m);

	decode_pk(&bhat, publicseed, pk);
	gen_a(&ahat, publicseed);

	poly_sample(&sprime, coin, 0);
	poly_sample(&eprime, coin, 1);
	poly_sample(&eprimeprime, coin, 2);

	poly_ntt(&sprime);
	poly_ntt(&eprime);

	poly_mul_pointwise(&uhat, &ahat, &sprime);
	poly_add(&uhat, &uhat, &eprime);

	poly_mul_pointwise(&vprime, &bhat, &sprime);
	poly_invntt(&vprime);

	poly_add(&vprime, &vprime, &eprimeprime);
	// add message
	poly_add(&vprime, &vprime, &v);
	encode_c(c, &uhat, &vprime);
}

void cpapke_dec(uint8_t* m, const uint8_t* c, const uint8_t* sk)
{
	poly vprime;
	poly uhat;
	poly tmp;
	poly shat;

	poly_frombytes(&shat, sk);
	decode_c(&uhat, &vprime, c);

	poly_mul_pointwise(&tmp, &shat, &uhat);
	poly_invntt(&tmp);

	poly_sub(&tmp, &tmp, &vprime);
	poly_tomsg(m, &tmp);
}
