#include "indcpa.h"
#include "polyvec.h"
//#include "rng.h"
#include "sha3.h"

static void pack_pk(uint8_t* r, polyvec* pk, const uint8_t* seed)
{
	size_t i;

	polyvec_tobytes(r, pk);

	for (i = 0; i < KYBER_SYMBYTES; ++i)
	{
		r[i + KYBER_POLYVECBYTES] = seed[i];
	}
}

static void unpack_pk(polyvec* pk, uint8_t* seed, const uint8_t* packedpk)
{
	size_t i;

	polyvec_frombytes(pk, packedpk);

	for (i = 0; i < KYBER_SYMBYTES; ++i)
	{
		seed[i] = packedpk[i + KYBER_POLYVECBYTES];
	}
}

static void pack_sk(uint8_t* r, polyvec* sk)
{
	polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec* sk, const uint8_t* packedsk)
{
	polyvec_frombytes(sk, packedsk);
}

static void pack_ciphertext(uint8_t* r, polyvec* b, poly *v)
{
	polyvec_compress(r, b);
	poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void unpack_ciphertext(polyvec* b, poly *v, const uint8_t* c)
{
	polyvec_decompress(b, c);
	poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

static uint32_t rej_uniform(uint16_t *r, uint32_t len, const uint8_t* buf, uint32_t buflen)
{
	uint32_t ctr;
	uint32_t pos;
	uint16_t val;

	ctr = 0;
	pos = 0;

	while (ctr < len && pos + 2 <= buflen)
	{
		val = buf[pos] | ((uint16_t)buf[pos + 1] << 8U);
		pos += 2;

		if (val < 19 * KYBER_Q)
		{
			// Barrett reduction
			val -= (val >> 12) * KYBER_Q;
			r[ctr] = val;
			++ctr;
		}
	}

	return ctr;
}

void gen_matrix(polyvec* a, const uint8_t* seed, int32_t transposed)
{
	 /* 530 is expected number of required bytes */
	const uint32_t maxnblocks = (530 + QSC_SHAKE_128_RATE) / QSC_SHAKE_128_RATE;
	uint8_t buf[QSC_SHAKE_128_RATE * ((530 + QSC_SHAKE_128_RATE) / QSC_SHAKE_128_RATE) + 1];
	keccak_state kstate;
	uint8_t extseed[KYBER_SYMBYTES + 2];
	size_t i;
	size_t j;
	size_t k;
	uint32_t ctr;

	for (i = 0; i < KYBER_K; ++i)
	{
		for (j = 0; j < KYBER_K; ++j)
		{

			for (k = 0; k < KYBER_SYMBYTES; ++k)
			{
				extseed[k] = seed[k];
			}

			if (transposed) 
			{
				extseed[k] = (uint8_t)i;
				++k;
				extseed[k] = (uint8_t)j;
			}
			else 
			{
				extseed[k] = (uint8_t)j;
				++k;
				extseed[k] = (uint8_t)i;
			}

			for (k = 0; k < QSC_SHA3_STATE_SIZE; ++k)
			{
				kstate.state[k] = 0;
			}

			qsc_shake128_initialize(&kstate, extseed, KYBER_SYMBYTES + 2);
			qsc_shake128_squeezeblocks(&kstate, buf, maxnblocks);
			ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, maxnblocks * QSC_SHAKE_128_RATE);

			while (ctr < KYBER_N)
			{
				qsc_shake128_squeezeblocks(&kstate, buf, 1);
				ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, QSC_SHAKE_128_RATE);
			}
		}
	}
}

int32_t indcpa_keypair(uint8_t* pk, uint8_t* sk, void (*rng_generate)(uint8_t*, size_t))
{
	polyvec a[KYBER_K];
	polyvec e;
	polyvec pkpv;
	polyvec skpv;
	uint8_t buf[2 * KYBER_SYMBYTES];
	const uint8_t* publicseed = buf;
	const uint8_t* noiseseed = buf + KYBER_SYMBYTES;
	size_t i;
	int32_t ret;
	uint8_t nonce;

	nonce = 0;
	ret = 0; // TODO: fix this
	rng_generate(buf, KYBER_SYMBYTES);
	qsc_sha3_compute512(buf, buf, KYBER_SYMBYTES);

	gen_matrix(a, publicseed, 0);

	for (i = 0; i < KYBER_K; ++i)
	{
		poly_getnoise(skpv.vec + i, noiseseed, nonce);
		++nonce;
	}
	for (i = 0; i < KYBER_K; ++i)
	{
		poly_getnoise(e.vec + i, noiseseed, nonce);
		++nonce;
	}

	polyvec_ntt(&skpv);
	polyvec_ntt(&e);

	/* matrix-vector multiplication */
	for (i = 0; i < KYBER_K; ++i) 
	{
		polyvec_pointwise_acc(&pkpv.vec[i], &a[i], &skpv);
		poly_frommont(&pkpv.vec[i]);
	}

	polyvec_add(&pkpv, &pkpv, &e);
	polyvec_reduce(&pkpv);

	pack_sk(sk, &skpv);
	pack_pk(pk, &pkpv, publicseed);

	return ret;
}

void indcpa_enc(uint8_t* c, const uint8_t* m, const uint8_t* pk, const uint8_t* coins)
{
	uint8_t seed[KYBER_SYMBYTES];
	polyvec at[KYBER_K];
	polyvec bp;
	polyvec sp;
	polyvec pkpv;
	polyvec ep;
	poly k;
	poly epp;
	poly v;
	size_t i;
	uint8_t nonce;

	nonce = 0;
	unpack_pk(&pkpv, seed, pk);
	poly_frommsg(&k, m);
	gen_matrix(at, seed, 1);

	for (i = 0; i < KYBER_K; ++i)
	{
		poly_getnoise(sp.vec + i, coins, nonce);
		++nonce;
	}

	for (i = 0; i < KYBER_K; ++i)
	{
		poly_getnoise(ep.vec + i, coins, nonce);
		++nonce;
	}

	poly_getnoise(&epp, coins, nonce++);
	polyvec_ntt(&sp);

	/* matrix-vector multiplication */
	for (i = 0; i < KYBER_K; ++i)
	{
		polyvec_pointwise_acc(&bp.vec[i], &at[i], &sp);
	}

	polyvec_pointwise_acc(&v, &pkpv, &sp);
	polyvec_invntt(&bp);
	poly_invntt(&v);

	polyvec_add(&bp, &bp, &ep);
	poly_add(&v, &v, &epp);
	poly_add(&v, &v, &k);
	polyvec_reduce(&bp);
	poly_reduce(&v);

	pack_ciphertext(c, &bp, &v);
}

void indcpa_dec(uint8_t* m, const uint8_t* c, const uint8_t* sk)
{
	polyvec bp;
	polyvec skpv;
	poly v;
	poly mp;

	unpack_ciphertext(&bp, &v, c);
	unpack_sk(&skpv, sk);

	polyvec_ntt(&bp);
	polyvec_pointwise_acc(&mp, &skpv, &bp);
	poly_invntt(&mp);

	poly_sub(&mp, &v, &mp);
	poly_reduce(&mp);

	poly_tomsg(m, &mp);
}
