#include "common.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sha3.h"
#include "sign.h"
#include "sysrand.h"

#define CRYPTO_PUBLICKEYBYTES 1760U
#define CRYPTO_SECRETKEYBYTES 3856U
#define CRYPTO_BYTES 3366U

static void expand_mat(polyvecl mat[K], const uint8_t rho[SEEDBYTES])
{
	uint8_t inbuf[SEEDBYTES + 1];
	uint8_t outbuf[5 * SHAKE128_RATE];
	uint32_t ctr;
	uint32_t i;
	uint32_t j;
	uint32_t pos;
	uint32_t val;

	for (i = 0; i < SEEDBYTES; ++i)
	{
		inbuf[i] = rho[i];
	}

	for (i = 0; i < K; ++i) 
	{
		for (j = 0; j < L; ++j) 
		{
			ctr = pos = 0;
			inbuf[SEEDBYTES] = i + (j << 4);
			shake128(outbuf, sizeof(outbuf), inbuf, SEEDBYTES + 1);

			while (ctr < N) 
			{
				val = outbuf[pos++];
				val |= (uint32_t)outbuf[pos++] << 8;
				val |= (uint32_t)outbuf[pos++] << 16;
				val &= 0x7FFFFF;

				/* Rejection sampling */
				if (val < Q)
				{
					mat[i].vec[j].coeffs[ctr++] = val;
				}
			}
		}
	}
}

static void challenge(poly* c, const uint8_t mu[CRHBYTES], const polyveck* w1)
{

	uint8_t inbuf[CRHBYTES + K * POLW1_SIZE_PACKED];
	uint8_t outbuf[SHAKE256_RATE];
	uint64_t state[25];
	uint64_t signs;
	uint64_t mask;
	uint32_t b;
	uint32_t i;
	uint32_t pos;

	for (i = 0; i < CRHBYTES; ++i)
	{
		inbuf[i] = mu[i];
	}

	for (i = 0; i < K; ++i)
	{
		polyw1_pack(inbuf + CRHBYTES + i * POLW1_SIZE_PACKED, w1->vec + i);
	}

	shake256_absorb(state, inbuf, sizeof(inbuf));
	shake256_squeezeblocks(outbuf, 1, state);

	signs = 0;
	for (i = 0; i < 8; ++i)
		signs |= (uint64_t)outbuf[i] << 8 * i;

	pos = 8;
	mask = 1;

	for (i = 0; i < N; ++i)
	{
		c->coeffs[i] = 0;
	}

	for (i = 196; i < 256; ++i) 
	{
		do {
			if (pos >= SHAKE256_RATE) 
			{
				shake256_squeezeblocks(outbuf, 1, state);
				pos = 0;
			}

			b = outbuf[pos++];
		} while (b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = (signs & mask) ? Q - 1 : 1;
		mask <<= 1;
	}
}

int dilithium_generate(uint8_t* publickey, uint8_t* secretkey)
{
	polyvecl mat[K];
	uint8_t seedbuf[3 * SEEDBYTES];
	uint8_t tr[CRHBYTES];
	uint8_t* rho;
	uint8_t* rhoprime;
	uint8_t* key;
	polyvecl s1;
	polyvecl s1hat;
	polyveck s2;
	polyvecl t;
	polyvecl t1;
	polyvecl t0;
	uint16_t nonce;
	uint32_t i;

	nonce = 0;

	/* Expand 32 bytes of randomness into rho, rhoprime and key */
	sysrand_getbytes(seedbuf, SEEDBYTES);
	shake256(seedbuf, 3 * SEEDBYTES, seedbuf, SEEDBYTES);
	rho = seedbuf;
	rhoprime = rho + SEEDBYTES;
	key = rho + 2 * SEEDBYTES;

	/* Expand matrix */
	expand_mat(mat, rho);

	/* Sample short vectors s1 and s2 */
	for (i = 0; i < L; ++i)
	{
		poly_uniform_eta(&s1.vec[i], rhoprime, nonce++);
	}
	for (i = 0; i < K; ++i)
	{
		poly_uniform_eta(&s2.vec[i], rhoprime, nonce++);
	}

	/* Matrix-vector multiplication */
	s1hat = s1;
	polyvecl_ntt(&s1hat);

	for (i = 0; i < K; ++i)
	{
		polyvecl_pointwise_acc_invmontgomery(&t.vec[i], mat + i, &s1hat);
		poly_invntt_montgomery(t.vec + i);
	}

	/* Add noise vector s2 */
	polyveck_add(&t, &t, &s2);

	/* Extract t1 and write public key */
	polyveck_freeze(&t);
	polyveck_power2round(&t1, &t0, &t);
	pack_pk(publickey, rho, &t1);

	/* Compute CRH(rho, t1) and write secret key */
	shake256(tr, CRHBYTES, publickey, CRYPTO_PUBLICKEYBYTES);
	pack_sk(secretkey, rho, key, tr, &s1, &s2, &t0);

	return 0;
}

int dilithium_sign(uint8_t* signedmsg, uint64_t* smsglen, const uint8_t* message, uint64_t msglen, const uint8_t* secretkey)
{
	uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
	uint8_t* rho;
	uint8_t* key;
	uint8_t* mu;
	uint8_t* tr;
	poly c;
	poly chat;
	polyvecl mat[K];
	polyvecl s1;
	polyvecl y;
	polyvecl  yhat;
	polyvecl z;
	polyveck s2;
	polyveck t0;
	polyveck w;
	polyveck w1;
	polyveck h;
	polyveck wcs2;
	polyveck wcs20;
	polyveck ct0;
	polyveck tmp;
	uint64_t i;
	uint64_t j;
	uint32_t n;
	uint16_t nonce;

	nonce = 0;
	rho = seedbuf;
	key = seedbuf + SEEDBYTES;
	mu = seedbuf + 2 * SEEDBYTES;
	tr = signedmsg + CRYPTO_BYTES - CRHBYTES;
	unpack_sk(rho, key, tr, &s1, &s2, &t0, secretkey);

	/* Copy message at the end of the signedmsg buffer */
	for (i = 0; i < msglen; ++i)
	{
		signedmsg[CRYPTO_BYTES + i] = message[i];
	}

	/* Compute CRH(tr, msg) */
	shake256(mu, CRHBYTES, signedmsg + CRYPTO_BYTES - CRHBYTES, CRHBYTES + msglen);

	/* Expand matrix and transform vectors */
	expand_mat(mat, rho);
	polyvecl_ntt(&s1);
	polyveck_ntt(&s2);
	polyveck_ntt(&t0);

rej:
	/* Sample intermediate vector y */
	for (i = 0; i < L; ++i)
	{
		poly_uniform_gamma1m1(y.vec + i, key, nonce++);
	}

	/* Matrix-vector multiplication */
	yhat = y;
	polyvecl_ntt(&yhat);
	for (i = 0; i < K; ++i) 
	{
		polyvecl_pointwise_acc_invmontgomery(w.vec + i, mat + i, &yhat);
		poly_invntt_montgomery(w.vec + i);
	}

	/* Decompose w and call the random oracle */
	polyveck_freeze(&w);
	polyveck_decompose(&w1, &tmp, &w);
	challenge(&c, mu, &w1);

	/* Compute z, reject if it reveals secret */
	chat = c;
	poly_ntt(&chat);
	for (i = 0; i < L; ++i) 
	{
		poly_pointwise_invmontgomery(z.vec + i, &chat, s1.vec + i);
		poly_invntt_montgomery(z.vec + i);
	}
	polyvecl_add(&z, &z, &y);
	polyvecl_freeze(&z);

	if (polyvecl_chknorm(&z, GAMMA1 - BETA))
	{
		goto rej;
	}

	/* Compute w - cs2, reject if w1 can not be computed from it */
	for (i = 0; i < K; ++i) 
	{
		poly_pointwise_invmontgomery(wcs2.vec + i, &chat, s2.vec + i);
		poly_invntt_montgomery(wcs2.vec + i);
	}
	polyveck_sub(&wcs2, &w, &wcs2);
	polyveck_freeze(&wcs2);
	polyveck_decompose(&tmp, &wcs20, &wcs2);
	polyveck_freeze(&wcs20);

	if (polyveck_chknorm(&wcs20, GAMMA2 - BETA))
	{
		goto rej;
	}

	for (i = 0; i < K; ++i)
	{
		for (j = 0; j < N; ++j)
		{
			if (tmp.vec[i].coeffs[j] != w1.vec[i].coeffs[j])
			{
				goto rej;
			}
		}
	}

	/* Compute hints for w1 */
	for (i = 0; i < K; ++i) 
	{
		poly_pointwise_invmontgomery(ct0.vec + i, &chat, t0.vec + i);
		poly_invntt_montgomery(ct0.vec + i);
	}

	polyveck_freeze(&ct0);
	if (polyveck_chknorm(&ct0, GAMMA2 - BETA))
	{
		goto rej;
	}

	polyveck_add(&tmp, &wcs2, &ct0);
	polyveck_neg(&ct0);
	polyveck_freeze(&tmp);
	n = polyveck_make_hint(&h, &tmp, &ct0);

	if (n > OMEGA)
	{
		goto rej;
	}

	/* Write signature */
	pack_sig(signedmsg, &z, &h, &c);
	*smsglen = msglen + CRYPTO_BYTES;

	return 0;
}

int dilithium_verify(uint8_t* message, uint64_t* msglen, const uint8_t* signedmsg, uint64_t smsglen, const uint8_t* publickey)
{
	uint8_t rho[SEEDBYTES];
	uint8_t mu[CRHBYTES];
	poly c;
	poly chat;
	poly cp;
	polyvecl mat[K];
	polyvecl z;
	polyveck t1;
	polyveck w1;
	polyveck h;
	polyveck tmp1;
	polyveck tmp2;
	uint64_t i;

	if (smsglen < CRYPTO_BYTES)
	{
		goto badsig;
	}

	*msglen = smsglen - CRYPTO_BYTES;

	unpack_pk(rho, &t1, publickey);
	unpack_sig(&z, &h, &c, signedmsg);

	if (polyvecl_chknorm(&z, GAMMA1 - BETA))
	{
		goto badsig;
	}

	/* Compute CRH(CRH(rho, t1), msg) using message as "playground" buffer */
	for (i = 0; i < CRYPTO_PUBLICKEYBYTES; ++i)
	{
		message[CRYPTO_BYTES - CRYPTO_PUBLICKEYBYTES + i] = publickey[i];
	}

	if (signedmsg != message)
	{
		for (i = 0; i < *msglen; ++i)
		{
			message[CRYPTO_BYTES + i] = signedmsg[CRYPTO_BYTES + i];
		}
	}

	shake256(message + CRYPTO_BYTES - CRHBYTES, CRHBYTES, message + CRYPTO_BYTES - CRYPTO_PUBLICKEYBYTES, CRYPTO_PUBLICKEYBYTES);
	shake256(mu, CRHBYTES, message + CRYPTO_BYTES - CRHBYTES, CRHBYTES + *msglen);

	expand_mat(mat, rho);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	polyvecl_ntt(&z);

	for (i = 0; i < K; ++i)
	{
		polyvecl_pointwise_acc_invmontgomery(tmp1.vec + i, mat + i, &z);
	}

	chat = c;
	poly_ntt(&chat);
	polyveck_shiftl(&t1, D);
	polyveck_ntt(&t1);

	for (i = 0; i < K; ++i)
	{
		poly_pointwise_invmontgomery(tmp2.vec + i, &chat, t1.vec + i);
	}

	polyveck_sub(&tmp1, &tmp1, &tmp2);
	polyveck_freeze(&tmp1);
	polyveck_invntt_montgomery(&tmp1);

	/* Reconstruct w1 */
	polyveck_freeze(&tmp1);
	polyveck_use_hint(&w1, &tmp1, &h);

	/* Call random oracle and verify challenge */
	challenge(&cp, mu, &w1);

	for (i = 0; i < N; ++i)
	{
		if (c.coeffs[i] != cp.coeffs[i])
		{
			goto badsig;
		}
	}

	/* All good, copy msg, return 0 */
	for (i = 0; i < *msglen; ++i)
	{
		message[i] = signedmsg[CRYPTO_BYTES + i];
	}

	return 0;

	/* Signature verification failed */
badsig:
	*msglen = (uint64_t)-1;
	for (i = 0; i < smsglen; ++i)
	{
		message[i] = 0;
	}

	return -1;
}
