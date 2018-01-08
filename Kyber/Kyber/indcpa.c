#include "indcpa.h"
#include "ntt.h"
#include "polyvec.h"
#include "sysrand.h"
#include "sha3.h"
#include <assert.h>

static void clear64(uint64_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
	{
		a[i] = 0;
	}
}

static void gen_matrix(polyvec* a, const uint8_t* seed, uint8_t transposed)
{
	/* Deterministically generate matrix A (or the transpose of A) from a seed.
	Entries of the matrix are polynomials that look uniformly random. 
	Performs rejection sampling on output of simple cSHAKE-128 */

	uint64_t state[SHA3_STATESIZE];
	uint8_t buf[SHAKE128_RATE * 4];
	size_t ctr;
	size_t nblocks;
	size_t pos;
	uint16_t i;
	uint16_t j;
	uint16_t val;

	nblocks = 4;
	pos = 0;

#ifdef MATRIX_GENERATOR_CSHAKE

	uint16_t dsep;

	for (i = 0; i < KYBER_K; i++)
	{
		for (j = 0; j < KYBER_K; j++)
		{
			ctr = 0;
			pos = 0;

			if (transposed)
			{
				dsep = j + (i << 8);
			}
			else
			{
				dsep = i + (j << 8);
			}

			clear64(state, SHA3_STATESIZE);
			cshake128_simple_absorb(state, dsep, seed, KYBER_SYMBYTES);
			cshake128_simple_squeezeblocks(buf, nblocks, state);

			while (ctr < KYBER_N)
			{
				val = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1FFF;

				if (val < KYBER_Q)
				{
					a[i].vec[j].coeffs[ctr++] = val;
				}

				pos += 2;

				if (pos > SHAKE128_RATE * nblocks - 2)
				{
					nblocks = 1;
					cshake128_simple_squeezeblocks(buf, nblocks, state);
					pos = 0;
				}
			}
		}
	}

#else

	/* Performs rejection sampling on output of SHAKE-128 */

	uint8_t extseed[KYBER_SYMBYTES + 2];

	for (i = 0; i < KYBER_SYMBYTES; i++)
	{
		extseed[i] = seed[i];
	}

	for (i = 0; i < KYBER_K; i++)
	{
		for (j = 0; j < KYBER_K; j++)
		{
			ctr = 0;
			pos = 0;

			if (transposed)
			{
				extseed[KYBER_SYMBYTES] = (uint8_t)i;
				extseed[KYBER_SYMBYTES + 1] = (uint8_t)j;
			}
			else
			{
				extseed[KYBER_SYMBYTES] = (uint8_t)j;
				extseed[KYBER_SYMBYTES + 1] = (uint8_t)i;
			}

			clear64(state, SHA3_STATESIZE);
			shake128_absorb(state, extseed, KYBER_SYMBYTES + 2);
			shake128_squeezeblocks(buf, nblocks, state);

			while (ctr < KYBER_N)
			{
				val = ((buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1FFF);

				if (val < KYBER_Q)
				{
					a[i].vec[j].coeffs[ctr++] = val;
				}

				pos += 2;

				if (pos > SHAKE128_RATE * nblocks - 2)
				{
					nblocks = 1;
					shake128_squeezeblocks(buf, nblocks, state);
					pos = 0;
				}
			}
		}
	}

#endif
}

static void pack_ciphertext(uint8_t* r, const polyvec* b, const poly* v)
{
	/* Serialize the ciphertext as concatenation of the
	compressed and serialized vector of polynomials b
	and the compressed and serialized polynomial v. */

	polyvec_compress(r, b);
	poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void pack_pk(uint8_t* r, const polyvec* pk, const uint8_t* seed)
{
	/* Serialize the public key as concatenation of the
	compressed and serialized vector of polynomials pk
	and the public seed used to generate the matrix A. */

	size_t i;

	polyvec_compress(r, pk);

	for (i = 0; i < KYBER_SYMBYTES; i++)
	{
		r[i + KYBER_POLYVECCOMPRESSEDBYTES] = seed[i];
	}
}

static void pack_sk(uint8_t* r, const polyvec* sk)
{
	/* Serialize the secret key. */

	polyvec_tobytes(r, sk);
}

static void unpack_ciphertext(polyvec* b, poly* v, const uint8_t* c)
{
	/* De-serialize and decompress ciphertext from a byte array;
	approximate inverse of pack_ciphertext. */

	polyvec_decompress(b, c);
	poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

static void unpack_pk(polyvec* pk, uint8_t* seed, const uint8_t* packedpk)
{
	/* De-serialize and decompress public key from a byte array;
	approximate inverse of pack_pk. */

	size_t i;

	polyvec_decompress(pk, packedpk);

	for (i = 0; i < KYBER_SYMBYTES; i++)
	{
		seed[i] = packedpk[i + KYBER_POLYVECCOMPRESSEDBYTES];
	}
}

static void unpack_sk(polyvec* sk, const uint8_t* packedsk)
{
	/* De-serialize the secret key; inverse of pack_sk */

	polyvec_frombytes(sk, packedsk);
}

void indcpa_keypair(uint8_t* pk, uint8_t* sk)
{
	polyvec a[KYBER_K];
	uint8_t buf[KYBER_SYMBYTES + KYBER_SYMBYTES];
	polyvec e;
	polyvec pkpv; 
	polyvec skpv;
	size_t i;
	int32_t rstat;
	uint8_t* publicseed = buf;
	uint8_t* noiseseed = buf + KYBER_SYMBYTES;
	uint8_t nonce;

	rstat = sysrand_getbytes(buf, KYBER_SYMBYTES);
	assert(rstat == RAND_STATUS_SUCCESS);

	sha3_compute512(buf, buf, KYBER_SYMBYTES);

	gen_matrix(a, publicseed, 0);
	nonce = 0;

	for (i = 0; i < KYBER_K; i++)
	{
		poly_getnoise(skpv.vec + i, noiseseed, nonce++);
	}

	polyvec_ntt(&skpv);

	for (i = 0; i < KYBER_K; i++)
	{
		poly_getnoise(e.vec + i, noiseseed, nonce++);
	}

	/* matrix-vector multiplication */
	for (i = 0; i < KYBER_K; i++)
	{
		polyvec_pointwise_acc(&pkpv.vec[i], &skpv, a + i);
	}

	polyvec_invntt(&pkpv);
	polyvec_add(&pkpv, &pkpv, &e);

	pack_sk(sk, &skpv);
	pack_pk(pk, &pkpv, publicseed);
}

void indcpa_enc(uint8_t* c, const uint8_t* m, const uint8_t* pk, const uint8_t* coins)
{
	polyvec at[KYBER_K];
	uint8_t seed[KYBER_SYMBYTES];
	polyvec bp;
	polyvec ep;
	polyvec pkpv;
	polyvec sp;
	poly epp;
	poly k;
	poly v;
	size_t i;
	uint8_t nonce;

	unpack_pk(&pkpv, seed, pk);
	poly_frommsg(&k, m);
	polyvec_ntt(&pkpv);

	gen_matrix(at, seed, 1);
	nonce = 0;

	for (i = 0; i < KYBER_K; i++)
	{
		poly_getnoise(sp.vec + i, coins, nonce++);
	}

	polyvec_ntt(&sp);

	for (i = 0; i < KYBER_K; i++)
	{
		poly_getnoise(ep.vec + i, coins, nonce++);
	}

	/* matrix-vector multiplication */
	for (i = 0; i < KYBER_K; i++)
	{
		polyvec_pointwise_acc(&bp.vec[i], &sp, at + i);
	}

	polyvec_invntt(&bp);
	polyvec_add(&bp, &bp, &ep);
	polyvec_pointwise_acc(&v, &pkpv, &sp);
	poly_invntt(&v);
	poly_getnoise(&epp, coins, nonce++);
	poly_add(&v, &v, &epp);
	poly_add(&v, &v, &k);

	pack_ciphertext(c, &bp, &v);
}

void indcpa_dec(uint8_t* m, const uint8_t* c, const uint8_t* sk)
{
	polyvec bp;
	polyvec skpv;
	poly mp;
	poly v;

	unpack_ciphertext(&bp, &v, c);
	unpack_sk(&skpv, sk);

	polyvec_ntt(&bp);
	polyvec_pointwise_acc(&mp, &skpv, &bp);
	poly_invntt(&mp);
	poly_sub(&mp, &mp, &v);
	poly_tomsg(m, &mp);
}
