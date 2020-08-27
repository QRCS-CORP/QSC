#include "sign.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sha3.h"

void expand_mat(polyvecl mat[DILITHIUM_K], const uint8_t rho[DILITHIUM_SEED_SIZE]) 
{
	size_t i;
	size_t j;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		for (j = 0; j < DILITHIUM_L; ++j)
		{
			poly_uniform(&mat[i].vec[j], rho, (uint16_t)((i << 8) + j));
		}
	}
}

void challenge(poly* c, const uint8_t mu[DILITHIUM_CRH_SIZE], const polyveck *w1)
{
	uint8_t inbuf[DILITHIUM_CRH_SIZE + DILITHIUM_K * DILITHIUM_POLW1_SIZE_PACKED];
	uint8_t outbuf[QSC_SHAKE_256_RATE];
	keccak_state kstate;
	uint64_t signs;
	size_t b;
	size_t i;
	size_t pos;

	for (i = 0; i < QSC_SHA3_STATE_SIZE; ++i)
	{
		kstate.state[i] = 0;
	}

	for (i = 0; i < DILITHIUM_CRH_SIZE; ++i)
	{
		inbuf[i] = mu[i];
	}

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		polyw1_pack(inbuf + DILITHIUM_CRH_SIZE + (i * DILITHIUM_POLW1_SIZE_PACKED), &w1->vec[i]);
	}

	qsc_shake256_initialize(&kstate, inbuf, sizeof(inbuf));
	qsc_shake256_squeezeblocks(&kstate, outbuf, 1);
	signs = 0;

	for (i = 0; i < 8; ++i)
	{
		signs |= (uint64_t)outbuf[i] << 8 * i;
	}

	pos = 8;

	for (i = 0; i < DILITHIUM_N; ++i)
	{
		c->coeffs[i] = 0;
	}

	for (i = 196; i < 256; ++i) 
	{
		do 
		{
			if (pos >= QSC_SHAKE_256_RATE) 
			{
				qsc_shake256_squeezeblocks(&kstate, outbuf, 1);
				pos = 0;
			}

			b = (size_t)outbuf[pos];
			++pos;
		}
		while (b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = 1;
		c->coeffs[b] ^= (uint32_t)(~(signs & 1) + 1) & (1 ^ (DILITHIUM_Q - 1));
		signs >>= 1;
	}
}

void dilithium_generate(uint8_t* publickey, uint8_t* secretkey, void (*rng_generate)(uint8_t*, size_t))
{
	const uint8_t *key;
	const uint8_t *rho;
	const uint8_t *rhoprime;
	uint8_t seedbuf[3 * DILITHIUM_SEED_SIZE];
	uint8_t tr[DILITHIUM_CRH_SIZE];
	polyvecl mat[DILITHIUM_K];
	polyvecl s1;
	polyvecl s1hat;
	polyveck s2;
	polyveck t;
	polyveck t0;
	polyveck t1;
	size_t i;
	uint16_t nonce;

	/* Expand 32 bytes of randomness into rho, rhoprime and key */
	rng_generate(seedbuf, 3 * DILITHIUM_SEED_SIZE);
	rho = seedbuf;
	rhoprime = seedbuf + DILITHIUM_SEED_SIZE;
	key = seedbuf + (2 * DILITHIUM_SEED_SIZE);

	/* Expand matrix */
	expand_mat(mat, rho);
	nonce = 0;

	/* Sample short vectors s1 and s2 */
	for (i = 0; i < DILITHIUM_L; ++i)
	{
		poly_uniform_eta(&s1.vec[i], rhoprime, nonce);
		++nonce;
	}

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		poly_uniform_eta(&s2.vec[i], rhoprime, nonce);
		++nonce;
	}

	/* Matrix-vector multiplication */
	s1hat = s1;
	polyvecl_ntt(&s1hat);

	for (i = 0; i < DILITHIUM_K; ++i) 
	{
		polyvecl_pointwise_acc_invmontgomery(&t.vec[i], &mat[i], &s1hat);
		poly_reduce(&t.vec[i]);
		poly_invntt_montgomery(&t.vec[i]);
	}

	/* Add error vector s2 */
	polyveck_add(&t, &t, &s2);

	/* Extract t1 and write public key */
	polyveck_freeze(&t);
	polyveck_power2round(&t1, &t0, &t);
	pack_pk(publickey, rho, &t1);

	/* Compute CRH(rho, t1) and write secret key */
	qsc_shake256_compute(tr, DILITHIUM_CRH_SIZE, publickey, DILITHIUM_PUBLICKEY_SIZE);
	pack_sk(secretkey, rho, key, tr, &s1, &s2, &t0);
}

void dilithium_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* secretkey, void (*rng_generate)(uint8_t*, size_t))
{
	size_t i;
	uint32_t n;
	uint8_t seedbuf[2 * DILITHIUM_SEED_SIZE + 3 * DILITHIUM_CRH_SIZE];
	uint8_t *rho, *tr, *key, *mu, *rhoprime;
	uint16_t nonce = 0;
	poly c, chat;
	polyvecl mat[DILITHIUM_K], s1, y, yhat, z;
	polyveck t0, s2, w, w1, w0;
	polyveck h, cs2, ct0;
	int32_t nrej;

	rho = seedbuf;
	tr = rho + DILITHIUM_SEED_SIZE;
	key = tr + DILITHIUM_CRH_SIZE;
	mu = key + DILITHIUM_SEED_SIZE;
	rhoprime = mu + DILITHIUM_CRH_SIZE;
	unpack_sk(rho, key, tr, &s1, &s2, &t0, secretkey);

	/* Copy tr and message into the signedmsg buffer,
	 * backwards since message and signedmsg can be equal in SUPERCOP API */
	for (i = 1; i <= msglen; ++i)
	{
		signedmsg[DILITHIUM_SIGNATURE_SIZE + msglen - i] = message[msglen - i];
	}

	for (i = 0; i < DILITHIUM_CRH_SIZE; ++i)
	{
		signedmsg[DILITHIUM_SIGNATURE_SIZE - DILITHIUM_CRH_SIZE + i] = tr[i];
	}

	/* Compute CRH(tr, msg) */
	qsc_shake256_compute(mu, DILITHIUM_CRH_SIZE, signedmsg + DILITHIUM_SIGNATURE_SIZE - DILITHIUM_CRH_SIZE, DILITHIUM_CRH_SIZE + msglen);

#ifdef RANDOMIZED_SIGNING
	rng_generate(rhoprime, DILITHIUM_CRH_SIZE);
#else
	qsc_shake256_compute(rhoprime, DILITHIUM_CRH_SIZE, key, DILITHIUM_SEED_SIZE + DILITHIUM_CRH_SIZE);
#endif

	/* Expand matrix and transform vectors */
	expand_mat(mat, rho);
	polyvecl_ntt(&s1);
	polyveck_ntt(&s2);
	polyveck_ntt(&t0);
	nrej = 1;

	while (nrej != 0)
	{
		/* Sample intermediate vector y */
		for (i = 0; i < DILITHIUM_L; ++i)
		{
			poly_uniform_gamma1m1(&y.vec[i], rhoprime, nonce++);
		}

		/* Matrix-vector multiplication */
		yhat = y;
		polyvecl_ntt(&yhat);

		for (i = 0; i < DILITHIUM_K; ++i)
		{
			polyvecl_pointwise_acc_invmontgomery(&w.vec[i], &mat[i], &yhat);
			poly_reduce(&w.vec[i]);
			poly_invntt_montgomery(&w.vec[i]);
		}

		/* Decompose w and call the random oracle */
		polyveck_csubq(&w);
		polyveck_decompose(&w1, &w0, &w);
		challenge(&c, mu, &w1);
		chat = c;
		poly_ntt(&chat);

		/* Check that subtracting cs2 does not change high bits of w and low bits
		 * do not reveal secret information */
		for (i = 0; i < DILITHIUM_K; ++i)
		{
			poly_pointwise_invmontgomery(&cs2.vec[i], &chat, &s2.vec[i]);
			poly_invntt_montgomery(&cs2.vec[i]);
		}

		polyveck_sub(&w0, &w0, &cs2);
		polyveck_freeze(&w0);

		if (polyveck_chknorm(&w0, DILITHIUM_GAMMA2 - DILITHIUM_BETA) != 0)
		{
			continue;
		}

		/* Compute z, reject if it reveals secret */
		for (i = 0; i < DILITHIUM_L; ++i)
		{
			poly_pointwise_invmontgomery(&z.vec[i], &chat, &s1.vec[i]);
			poly_invntt_montgomery(&z.vec[i]);
		}

		polyvecl_add(&z, &z, &y);
		polyvecl_freeze(&z);

		if (polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA) != 0)
		{
			continue;
		}

		/* Compute hints for w1 */
		for (i = 0; i < DILITHIUM_K; ++i)
		{
			poly_pointwise_invmontgomery(&ct0.vec[i], &chat, &t0.vec[i]);
			poly_invntt_montgomery(&ct0.vec[i]);
		}

		polyveck_csubq(&ct0);

		if (polyveck_chknorm(&ct0, DILITHIUM_GAMMA2) != 0)
		{
			continue;
		}

		polyveck_add(&w0, &w0, &ct0);
		polyveck_csubq(&w0);
		n = polyveck_make_hint(&h, &w0, &w1);

		if (n > DILITHIUM_OMEGA)
		{
			continue;
		}

		/* Write signature */
		pack_sig(signedmsg, &z, &h, &c);
		*smsglen = msglen + DILITHIUM_SIGNATURE_SIZE;
		nrej = 0;
	}
}

bool dilithium_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	uint8_t rho[DILITHIUM_SEED_SIZE];
	uint8_t mu[DILITHIUM_CRH_SIZE];
	polyvecl mat[DILITHIUM_K];
	polyvecl z;
	polyveck t1;
	polyveck w1;
	polyveck h;
	polyveck tmp1;
	polyveck tmp2;
	poly c;
	poly chat;
	poly cp;
	size_t i;
	int32_t bsig;

	bsig = 0;

	if (smsglen < DILITHIUM_SIGNATURE_SIZE)
	{
		bsig = -1;
	}

	if (bsig == 0)
	{
		*msglen = smsglen - DILITHIUM_SIGNATURE_SIZE;
		unpack_pk(rho, &t1, publickey);

		if (unpack_sig(&z, &h, &c, signedmsg) != 0)
		{
			bsig = -1;
		}

		if (bsig == 0)
		{
			if (polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA) != 0)
			{
				bsig = -1;
			}

			if (bsig == 0)
			{
				/* Compute CRH(CRH(rho, t1), msg) using message as "playground" buffer */
				if (signedmsg != message)
				{
					for (i = 0; i < *msglen; ++i)
					{
						message[DILITHIUM_SIGNATURE_SIZE + i] = signedmsg[DILITHIUM_SIGNATURE_SIZE + i];
					}
				}

				qsc_shake256_compute((uint8_t*)message + (DILITHIUM_SIGNATURE_SIZE - DILITHIUM_CRH_SIZE), DILITHIUM_CRH_SIZE, publickey, DILITHIUM_PUBLICKEY_SIZE);
				qsc_shake256_compute(mu, DILITHIUM_CRH_SIZE, (uint8_t*)message + (DILITHIUM_SIGNATURE_SIZE - DILITHIUM_CRH_SIZE), DILITHIUM_CRH_SIZE + *msglen);

				/* Matrix-vector multiplication; compute Az - c2^dt1 */
				expand_mat(mat, rho);
				polyvecl_ntt(&z);

				for (i = 0; i < DILITHIUM_K; ++i)
				{
					polyvecl_pointwise_acc_invmontgomery(&tmp1.vec[i], &mat[i], &z);
				}

				chat = c;
				poly_ntt(&chat);
				polyveck_shiftl(&t1);
				polyveck_ntt(&t1);

				for (i = 0; i < DILITHIUM_K; ++i)
				{
					poly_pointwise_invmontgomery(&tmp2.vec[i], &chat, &t1.vec[i]);
				}

				polyveck_sub(&tmp1, &tmp1, &tmp2);
				polyveck_reduce(&tmp1);
				polyveck_invntt_montgomery(&tmp1);

				/* Reconstruct w1 */
				polyveck_csubq(&tmp1);
				polyveck_use_hint(&w1, &tmp1, &h);

				/* Call random oracle and verify challenge */
				challenge(&cp, mu, &w1);

				for (i = 0; i < DILITHIUM_N; ++i)
				{
					if (c.coeffs[i] != cp.coeffs[i])
					{
						bsig = -1;
						break;
					}
				}

				if (bsig == 0)
				{
					/* All good, copy msg, return 0 */
					for (i = 0; i < *msglen; ++i)
					{
						message[i] = signedmsg[DILITHIUM_SIGNATURE_SIZE + i];
					}
				}
			}
		}
	}

	if (bsig != 0)
	{
		*msglen = 0;

		for (i = 0; i < smsglen; ++i)
		{
			message[i] = 0;
		}
	}

	return (bsig == 0);
}
