#include "kyberbase.h"
#include "intutils.h"
#include "sha3.h"

/* params.h */

/*!
\def MATRIX_GENERATOR_CSHAKE
* Enable the simple cSHAKE generator for polynomial generation.
* If disabled, reverts to the SHAKE generator.
*/
#define MATRIX_GENERATOR_CSHAKE

/* Don't change parameters below this line */

/*!
\def KYBER_SHAREDSECRET_SIZE
* Read Only: The byte size of the shared secret key
*/
#define KYBER_SHAREDSECRET_SIZE 32

/*!
\def KYBER_POLYBYTES
* Read Only: The secret key base multiplier
*/
#define KYBER_POLYBYTES 384

/*!
\def KYBER_INDCPA_MSGBYTES
*  Read Only: The message size in bytes
*/
#define KYBER_INDCPA_MSGBYTES QSC_KYBER_SYMBYTES


/*!
\def KYBER_POLYVECBYTES
* Read Only: The base size of the compressed public key polynolial
*/
#if QSC_KYBER_K == 2
#define KYBER_POLYVECBASEBYTES 320
#elif QSC_KYBER_K == 3
#define KYBER_POLYVECBASEBYTES 320
#elif QSC_KYBER_K == 4
#define KYBER_POLYVECBASEBYTES 352
#endif

/*!
\def KYBER_POLYCOMPRESSEDBYTES
* Read Only: The ciphertext compressed byte size
*/
#if QSC_KYBER_K == 2
#define KYBER_POLYCOMPRESSEDBYTES 96
#elif QSC_KYBER_K == 3
#define KYBER_POLYCOMPRESSEDBYTES 128
#elif QSC_KYBER_K == 4
#define KYBER_POLYCOMPRESSEDBYTES 160
#endif

/*!
\def KYBER_POLYVECCOMPRESSEDBYTES
* Read Only: The base size of the public key
*/
#define KYBER_POLYVECCOMPRESSEDBYTES (QSC_KYBER_K * KYBER_POLYVECBASEBYTES)

/*!
\def KYBER_POLYVECBYTES
* Read Only: The base size of the secret key
*/
#define KYBER_POLYVECBYTES (QSC_KYBER_K * KYBER_POLYBYTES)

/*!
\def KYBER_INDCPA_PUBLICKEYBYTES
* Read Only: The base INDCPA formatted public key size in bytes
*/
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + QSC_KYBER_SYMBYTES)

/*!
\def KYBER_INDCPA_SECRETKEYBYTES
* Read Only: The base INDCPA formatted private key size in bytes
*/
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)

/*!
\def KYBER_INDCPA_BYTES
* Read Only: The size of the INDCPA formatted output cipher-text
*/
#define KYBER_INDCPA_BYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

/*!
\def KYBER_PUBLICKEY_SIZE
* Read Only: The public key size in bytes
*/
#define KYBER_PUBLICKEY_SIZE (KYBER_INDCPA_PUBLICKEYBYTES)

/*!
\def KYBER_INDCPA_SECRETKEYBYTES
* Read Only: The base INDCPA formatted secret key size in bytes
*/
#define KYBER_SECRETKEY_SIZE (KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + 2 * QSC_KYBER_SYMBYTES)

/*!
\def KYBER_CIPHERTEXT_SIZE
* Read Only: The cipher-text size in bytes
*/
#define KYBER_CIPHERTEXT_SIZE KYBER_INDCPA_BYTES

/* 2^16 % Q */
#define KYBER_MONT 2285

/* q^(-1) mod 2^16 */
#define KYBER_QINV 62209

/* indcpa.c */

static void pack_pk(uint8_t* r, qsc_kyber_polyvec* pk, const uint8_t* seed)
{
	size_t i;

	qsc_kyber_polyvec_tobytes(r, pk);

	for (i = 0; i < QSC_KYBER_SYMBYTES; ++i)
	{
		r[i + KYBER_POLYVECBYTES] = seed[i];
	}
}

static void unpack_pk(qsc_kyber_polyvec* pk, uint8_t* seed, const uint8_t* packedpk)
{
	size_t i;

	qsc_kyber_polyvec_frombytes(pk, packedpk);

	for (i = 0; i < QSC_KYBER_SYMBYTES; ++i)
	{
		seed[i] = packedpk[i + KYBER_POLYVECBYTES];
	}
}

static void pack_sk(uint8_t* r, qsc_kyber_polyvec* sk)
{
	qsc_kyber_polyvec_tobytes(r, sk);
}

static void unpack_sk(qsc_kyber_polyvec* sk, const uint8_t* packedsk)
{
	qsc_kyber_polyvec_frombytes(sk, packedsk);
}

static void pack_ciphertext(uint8_t* r, qsc_kyber_polyvec* b, qsc_kyber_poly *v)
{
	qsc_kyber_polyvec_compress(r, b);
	qsc_kyber_poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void unpack_ciphertext(qsc_kyber_polyvec* b, qsc_kyber_poly *v, const uint8_t* c)
{
	qsc_kyber_polyvec_decompress(b, c);
	qsc_kyber_poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
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

		if (val < 19 * QSC_KYBER_Q)
		{
			// Barrett reduction
			val -= (val >> 12) * QSC_KYBER_Q;
			r[ctr] = val;
			++ctr;
		}
	}

	return ctr;
}

void gen_matrix(qsc_kyber_polyvec* a, const uint8_t* seed, int32_t transposed)
{
	/* 530 is expected number of required bytes */
	const uint32_t maxnblocks = (530 + QSC_KECCAK_128_RATE) / QSC_KECCAK_128_RATE;
	uint8_t buf[QSC_KECCAK_128_RATE * ((530 + QSC_KECCAK_128_RATE) / QSC_KECCAK_128_RATE) + 1];
	qsc_keccak_state kstate;
	uint8_t extseed[QSC_KYBER_SYMBYTES + 2];
	size_t i;
	size_t j;
	size_t k;
	uint32_t ctr;

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		for (j = 0; j < QSC_KYBER_K; ++j)
		{

			for (k = 0; k < QSC_KYBER_SYMBYTES; ++k)
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

			for (k = 0; k < QSC_KECCAK_STATE_SIZE; ++k)
			{
				kstate.state[k] = 0;
			}

			qsc_shake_initialize(&kstate, keccak_rate_128, extseed, QSC_KYBER_SYMBYTES + 2);
			qsc_shake_squeezeblocks(&kstate, keccak_rate_128, buf, maxnblocks);
			ctr = rej_uniform(a[i].vec[j].coeffs, QSC_KYBER_N, buf, maxnblocks * QSC_KECCAK_128_RATE);

			while (ctr < QSC_KYBER_N)
			{
				qsc_shake_squeezeblocks(&kstate, keccak_rate_128, buf, 1);
				ctr += rej_uniform(a[i].vec[j].coeffs + ctr, QSC_KYBER_N - ctr, buf, QSC_KECCAK_128_RATE);
			}
		}
	}
}

void qsc_kyber_indcpa_keypair(uint8_t* pk, uint8_t* sk, void (*rng_generate)(uint8_t*, size_t))
{
	qsc_kyber_polyvec a[QSC_KYBER_K];
	qsc_kyber_polyvec e;
	qsc_kyber_polyvec pkpv;
	qsc_kyber_polyvec skpv;
	uint8_t buf[2 * QSC_KYBER_SYMBYTES];
	const uint8_t* publicseed = buf;
	const uint8_t* noiseseed = buf + QSC_KYBER_SYMBYTES;
	size_t i;
	uint8_t nonce;

	nonce = 0;
	rng_generate(buf, QSC_KYBER_SYMBYTES);
	qsc_sha3_compute512(buf, buf, QSC_KYBER_SYMBYTES);

	gen_matrix(a, publicseed, 0);

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_getnoise(skpv.vec + i, noiseseed, nonce);
		++nonce;
	}
	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_getnoise(e.vec + i, noiseseed, nonce);
		++nonce;
	}

	qsc_kyber_polyvec_ntt(&skpv);
	qsc_kyber_polyvec_ntt(&e);

	/* matrix-vector multiplication */
	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_polyvec_pointwise_acc(&pkpv.vec[i], &a[i], &skpv);
		qsc_kyber_poly_frommont(&pkpv.vec[i]);
	}

	qsc_kyber_polyvec_add(&pkpv, &pkpv, &e);
	qsc_kyber_polyvec_reduce(&pkpv);

	pack_sk(sk, &skpv);
	pack_pk(pk, &pkpv, publicseed);
}

void qsc_kyber_indcpa_enc(uint8_t* c, const uint8_t* m, const uint8_t* pk, const uint8_t* coins)
{
	uint8_t seed[QSC_KYBER_SYMBYTES];
	qsc_kyber_polyvec at[QSC_KYBER_K];
	qsc_kyber_polyvec bp;
	qsc_kyber_polyvec sp;
	qsc_kyber_polyvec pkpv;
	qsc_kyber_polyvec ep;
	qsc_kyber_poly k;
	qsc_kyber_poly epp;
	qsc_kyber_poly v;
	size_t i;
	uint8_t nonce;

	nonce = 0;
	unpack_pk(&pkpv, seed, pk);
	qsc_kyber_poly_frommsg(&k, m);
	gen_matrix(at, seed, 1);

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_getnoise(sp.vec + i, coins, nonce);
		++nonce;
	}

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_getnoise(ep.vec + i, coins, nonce);
		++nonce;
	}

	qsc_kyber_poly_getnoise(&epp, coins, nonce++);
	qsc_kyber_polyvec_ntt(&sp);

	/* matrix-vector multiplication */
	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_polyvec_pointwise_acc(&bp.vec[i], &at[i], &sp);
	}

	qsc_kyber_polyvec_pointwise_acc(&v, &pkpv, &sp);
	qsc_kyber_polyvec_invntt(&bp);
	qsc_kyber_poly_invntt(&v);

	qsc_kyber_polyvec_add(&bp, &bp, &ep);
	qsc_kyber_poly_add(&v, &v, &epp);
	qsc_kyber_poly_add(&v, &v, &k);
	qsc_kyber_polyvec_reduce(&bp);
	qsc_kyber_poly_reduce(&v);

	pack_ciphertext(c, &bp, &v);
}

void qsc_kyber_indcpa_dec(uint8_t* m, const uint8_t* c, const uint8_t* sk)
{
	qsc_kyber_polyvec bp;
	qsc_kyber_polyvec skpv;
	qsc_kyber_poly v;
	qsc_kyber_poly mp;

	unpack_ciphertext(&bp, &v, c);
	unpack_sk(&skpv, sk);

	qsc_kyber_polyvec_ntt(&bp);
	qsc_kyber_polyvec_pointwise_acc(&mp, &skpv, &bp);
	qsc_kyber_poly_invntt(&mp);

	qsc_kyber_poly_sub(&mp, &v, &mp);
	qsc_kyber_poly_reduce(&mp);

	qsc_kyber_poly_tomsg(m, &mp);
}

/* kem.h */

void qsc_kyber_crypto_kem_keypair(uint8_t* pk, uint8_t* sk, void (*rng_generate)(uint8_t*, size_t))
{
	size_t i;

	qsc_kyber_indcpa_keypair(pk, sk, rng_generate);

	for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; ++i)
	{
		sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
	}

	qsc_sha3_compute256(sk + KYBER_SECRETKEY_SIZE - 2 * QSC_KYBER_SYMBYTES, pk, KYBER_PUBLICKEY_SIZE);
	/* Value z for pseudo-random output on reject */
	rng_generate(sk + KYBER_SECRETKEY_SIZE - QSC_KYBER_SYMBYTES, QSC_KYBER_SYMBYTES);
}

void qsc_kyber_crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk, void (*rng_generate)(uint8_t*, size_t))
{
	/* Will contain key, coins */
	uint8_t  kr[2 * QSC_KYBER_SYMBYTES];
	uint8_t buf[2 * QSC_KYBER_SYMBYTES];

	rng_generate(buf, QSC_KYBER_SYMBYTES);
	/* Don't release system RNG output */
	qsc_sha3_compute256(buf, buf, QSC_KYBER_SYMBYTES);
	/* Multitarget countermeasure for coins + contributory KEM */
	qsc_sha3_compute256(buf + QSC_KYBER_SYMBYTES, pk, KYBER_PUBLICKEY_SIZE);
	qsc_sha3_compute512(kr, buf, 2 * QSC_KYBER_SYMBYTES);
	/* coins are in kr+QSC_KYBER_SYMBYTES */
	qsc_kyber_indcpa_enc(ct, buf, pk, kr + QSC_KYBER_SYMBYTES);
	/* overwrite coins in kr with H(c) */
	qsc_sha3_compute256(kr + QSC_KYBER_SYMBYTES, ct, KYBER_CIPHERTEXT_SIZE);
	/* hash concatenation of pre-k and H(c) to k */
	qsc_shake256_compute(ss, QSC_KYBER_SYMBYTES, kr, 2 * QSC_KYBER_SYMBYTES);
}

bool qsc_kyber_crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
	uint8_t cmp[KYBER_CIPHERTEXT_SIZE];
	uint8_t buf[2 * QSC_KYBER_SYMBYTES];
	/* Will contain key, coins */
	uint8_t kr[2 * QSC_KYBER_SYMBYTES];
	const uint8_t* pk = sk + KYBER_INDCPA_SECRETKEYBYTES;
	size_t i;
	int32_t fail;

	qsc_kyber_indcpa_dec(buf, ct, sk);

	/* Multitarget countermeasure for coins + contributory KEM */
	for (i = 0; i < QSC_KYBER_SYMBYTES; ++i)
	{
		/* Save hash by storing H(pk) in sk */
		buf[QSC_KYBER_SYMBYTES + i] = sk[(KYBER_SECRETKEY_SIZE - (2 * QSC_KYBER_SYMBYTES)) + i];
	}

	qsc_sha3_compute512(kr, buf, 2 * QSC_KYBER_SYMBYTES);
	/* coins are in kr+QSC_KYBER_SYMBYTES */
	qsc_kyber_indcpa_enc(cmp, buf, pk, kr + QSC_KYBER_SYMBYTES);

	fail = qsc_intutils_verify(ct, cmp, KYBER_CIPHERTEXT_SIZE);
	/* overwrite coins in kr with H(c) */
	qsc_sha3_compute256(kr + QSC_KYBER_SYMBYTES, ct, KYBER_CIPHERTEXT_SIZE);
	/* Overwrite pre-k with z on re-encryption failure */
	qsc_intutils_cmov(kr, sk + KYBER_SECRETKEY_SIZE - QSC_KYBER_SYMBYTES, QSC_KYBER_SYMBYTES, (uint8_t)fail);
	/* hash concatenation of pre-k and H(c) to k */
	qsc_shake256_compute(ss, QSC_KYBER_SYMBYTES, kr, 2 * QSC_KYBER_SYMBYTES);

	return (bool)(fail == 0);
}

/* qsc_kyber_ntt.c */

int16_t qsc_kyber_zetas[128] =
{
	0x08EDU, 0x0A0BU, 0x0B9AU, 0x0714U, 0x05D5U, 0x058EU, 0x011FU, 0x00CAU, 0x0C56U, 0x026EU, 0x0629U, 0x00B6U, 0x03C2U, 0x084FU, 0x073FU, 0x05BCU,
	0x023DU, 0x07D4U, 0x0108U, 0x017FU, 0x09C4U, 0x05B2U, 0x06BFU, 0x0C7FU, 0x0A58U, 0x03F9U, 0x02DCU, 0x0260U, 0x06FBU, 0x019BU, 0x0C34U, 0x06DEU,
	0x04C7U, 0x028CU, 0x0AD9U, 0x03F7U, 0x07F4U, 0x05D3U, 0x0BE7U, 0x06F9U, 0x0204U, 0x0CF9U, 0x0BC1U, 0x0A67U, 0x06AFU, 0x0877U, 0x007EU, 0x05BDU,
	0x09ACU, 0x0CA7U, 0x0BF2U, 0x033EU, 0x006BU, 0x0774U, 0x0C0AU, 0x094AU, 0x0B73U, 0x03C1U, 0x071DU, 0x0A2CU, 0x01C0U, 0x08D8U, 0x02A5U, 0x0806U,
	0x08B2U, 0x01AEU, 0x022BU, 0x034BU, 0x081EU, 0x0367U, 0x060EU, 0x0069U, 0x01A6U, 0x024BU, 0x00B1U, 0x0C16U, 0x0BDEU, 0x0B35U, 0x0626U, 0x0675U,
	0x0C0BU, 0x030AU, 0x0487U, 0x0C6EU, 0x09F8U, 0x05CBU, 0x0AA7U, 0x045FU, 0x06CBU, 0x0284U, 0x0999U, 0x015DU, 0x01A2U, 0x0149U, 0x0C65U, 0x0CB6U,
	0x0331U, 0x0449U, 0x025BU, 0x0262U, 0x052AU, 0x07FCU, 0x0748U, 0x0180U, 0x0842U, 0x0C79U, 0x04C2U, 0x07CAU, 0x0997U, 0x00DCU, 0x085EU, 0x0686U,
	0x0860U, 0x0707U, 0x0803U, 0x031AU, 0x071BU, 0x09ABU, 0x099BU, 0x01DEU, 0x0C95U, 0x0BCDU, 0x03E4U, 0x03DFU, 0x03BEU, 0x074DU, 0x05F2U, 0x065CU
};

int16_t zetas_inv[128] =
{
	0x06A5U, 0x070FU, 0x05B4U, 0x0943U, 0x0922U, 0x091DU, 0x0134U, 0x006CU, 0x0B23U, 0x0366U, 0x0356U, 0x05E6U, 0x09E7U, 0x04FEU, 0x05FAU, 0x04A1U,
	0x067BU, 0x04A3U, 0x0C25U, 0x036AU, 0x0537U, 0x083FU, 0x0088U, 0x04BFU, 0x0B81U, 0x05B9U, 0x0505U, 0x07D7U, 0x0A9FU, 0x0AA6U, 0x08B8U, 0x09D0U,
	0x004BU, 0x009CU, 0x0BB8U, 0x0B5FU, 0x0BA4U, 0x0368U, 0x0A7DU, 0x0636U, 0x08A2U, 0x025AU, 0x0736U, 0x0309U, 0x0093U, 0x087AU, 0x09F7U, 0x00F6U,
	0x068CU, 0x06DBU, 0x01CCU, 0x0123U, 0x00EBU, 0x0C50U, 0x0AB6U, 0x0B5BU, 0x0C98U, 0x06F3U, 0x099AU, 0x04E3U, 0x09B6U, 0x0AD6U, 0x0B53U, 0x044FU,
	0x04FBU, 0x0A5CU, 0x0429U, 0x0B41U, 0x02D5U, 0x05E4U, 0x0940U, 0x018EU, 0x03B7U, 0x00F7U, 0x058DU, 0x0C96U, 0x09C3U, 0x010FU, 0x005AU, 0x0355U,
	0x0744U, 0x0C83U, 0x048AU, 0x0652U, 0x029AU, 0x0140U, 0x0008U, 0x0AFDU, 0x0608U, 0x011AU, 0x072EU, 0x050DU, 0x090AU, 0x0228U, 0x0A75U, 0x083AU,
	0x0623U, 0x00CDU, 0x0B66U, 0x0606U, 0x0AA1U, 0x0A25U, 0x0908U, 0x02A9U, 0x0082U, 0x0642U, 0x074FU, 0x033DU, 0x0B82U, 0x0BF9U, 0x052DU, 0x0AC4U,
	0x0745U, 0x05C2U, 0x04B2U, 0x093FU, 0x0C4BU, 0x06D8U, 0x0A93U, 0x00ABU, 0x0C37U, 0x0BE2U, 0x0773U, 0x072CU, 0x05EDU, 0x0167U, 0x02F6U, 0x05A1U
};

static int16_t fqmul(int16_t a, int16_t b)
{
	return qsc_kyber_montgomery_reduce((int32_t)a * b);
}

void qsc_kyber_ntt(uint16_t* r)
{
	uint32_t j;
	uint32_t k;
	uint32_t len;
	uint32_t start;
	uint16_t t;
	int16_t zeta;

	k = 1;

	for (len = 128; len >= 2; len >>= 1)
	{
		for (start = 0; start < 256; start = j + len)
		{
			zeta = qsc_kyber_zetas[k];
			++k;

			for (j = start; j < start + len; ++j)
			{
				t = (uint16_t)fqmul(zeta, (int16_t)r[j + len]);
				r[j + len] = r[j] - t;
				r[j] = r[j] + t;
			}
		}
	}
}

void qsc_kyber_invntt(uint16_t* r)
{
	uint32_t j;
	uint32_t k;
	uint32_t len;
	uint32_t start;
	uint16_t t;
	int16_t zeta;

	k = 0;

	for (len = 2; len <= 128; len <<= 1)
	{
		for (start = 0; start < 256; start = j + len)
		{
			zeta = zetas_inv[k];
			++k;

			for (j = start; j < start + len; ++j)
			{
				t = r[j];
				r[j] = (uint16_t)qsc_kyber_barrett_reduce((int16_t)(t + r[j + len]));
				r[j + len] = t - r[j + len];
				r[j + len] = (uint16_t)fqmul(zeta, (int16_t)r[j + len]);
			}
		}
	}

	for (j = 0; j < 256; ++j)
	{
		r[j] = (uint16_t)fqmul((int16_t)r[j], zetas_inv[127]);
	}
}

void qsc_kyber_basemul(uint16_t r[2], const uint16_t a[2], const uint16_t b[2], int16_t zeta)
{
	r[0] = (uint16_t)fqmul((int16_t)a[1], (int16_t)b[1]);
	r[0] = (uint16_t)fqmul((int16_t)r[0], zeta);
	r[0] += (uint16_t)fqmul((int16_t)a[0], (int16_t)b[0]);
	r[1] = (uint16_t)fqmul((int16_t)a[0], (int16_t)b[1]);
	r[1] += (uint16_t)fqmul((int16_t)a[1], (int16_t)b[0]);
}

/* poly.c */

void qsc_kyber_cbd(qsc_kyber_poly* r, const uint8_t* buf)
{
	uint32_t d;
	uint32_t t;
	int16_t a;
	int16_t b;
	size_t i;
	size_t j;

	for (i = 0; i < QSC_KYBER_N / 8; ++i)
	{
		t = qsc_intutils_le8to32(buf + 4 * i);
		d = t & 0x55555555UL;
		d += (t >> 1) & 0x55555555UL;

		for (j = 0; j < 8; j++)
		{
			a = (d >> (4 * j)) & 0x03U;
			b = (d >> ((4 * j) + 2)) & 0x03U;
			r->coeffs[(8 * i) + j] = (uint16_t)(a - b);
		}
	}
}

void qsc_kyber_poly_compress(uint8_t* r, qsc_kyber_poly* a)
{
	uint8_t t[8];
	size_t i;
	size_t j;
	size_t k;

	k = 0;
	qsc_kyber_poly_csubq(a);

#if (KYBER_POLYCOMPRESSEDBYTES == 96)
	for (i = 0; i < QSC_KYBER_N; i += 8)
	{
		for (j = 0; j < 8; ++j)
		{
			t[j] = ((((uint32_t)a->coeffs[i + j] << 3U) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 7U;
		}

		r[k] = t[0] | (t[1] << 3U) | (t[2] << 6U);
		r[k + 1] = (t[2] >> 2U) | (t[3] << 1U) | (t[4] << 4U) | (t[5] << 7U);
		r[k + 2] = (t[5] >> 1U) | (t[6] << 2U) | (t[7] << 5U);
		k += 3;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 128)
	for (i = 0; i < QSC_KYBER_N; i += 8)
	{
		for (j = 0; j < 8; ++j)
		{
			/* jgu -false possible overflow */
			/*lint -e661 -e662 */
			t[j] = ((((uint32_t)a->coeffs[i + j] << 4U) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 15U;
		}

		r[k] = (uint8_t)(t[0] | (t[1] << 4U));
		r[k + 1] = (uint8_t)(t[2] | (t[3] << 4U));
		r[k + 2] = (uint8_t)(t[4] | (t[5] << 4U));
		r[k + 3] = (uint8_t)(t[6] | (t[7] << 4U));
		k += 4;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
	for (i = 0; i < QSC_KYBER_N; i += 8)
	{
		for (j = 0; j < 8; ++j)
		{
			t[j] = ((((uint32_t)a->coeffs[i + j] << 5U) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 31U;
		}

		r[k] = (uint8_t)(t[0] | (t[1] << 5U));
		r[k + 1] = (uint8_t)((t[1] >> 3U) | (t[2] << 2U) | (t[3] << 7U));
		r[k + 2] = (uint8_t)((t[3] >> 1U) | (t[4] << 4U));
		r[k + 3] = (uint8_t)((t[4] >> 4U) | (t[5] << 1U) | (t[6] << 6U));
		r[k + 4] = (uint8_t)((t[6] >> 2U) | (t[7] << 3U));
		k += 5;
	}
#endif
}

void qsc_kyber_poly_decompress(qsc_kyber_poly* r, const uint8_t* a)
{
	size_t i;

#if (KYBER_POLYCOMPRESSEDBYTES == 96)
	for (i = 0; i < QSC_KYBER_N; i += 8)
	{
		r->coeffs[i] = (((a[0] & 7U) * QSC_KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 1] = ((((a[0] >> 3U) & 7U) * QSC_KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 2] = ((((a[0] >> 6U) | ((a[1] << 2U) & 4U)) * QSC_KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 3] = ((((a[1] >> 1U) & 7U) * QSC_KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 4] = ((((a[1] >> 4U) & 7U) * QSC_KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 5] = ((((a[1] >> 7U) | ((a[2] << 1U) & 6U)) * QSC_KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 6] = ((((a[2] >> 2U) & 7U) * QSC_KYBER_Q) + 4) >> 3U;
		r->coeffs[i + 7] = ((((a[2] >> 5U)) * QSC_KYBER_Q) + 4) >> 3U;
		a += 3;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 128)
	for (i = 0; i < QSC_KYBER_N; i += 8)
	{
		r->coeffs[i] = (((a[0] & 15U) * QSC_KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 1] = (((a[0] >> 4U) * QSC_KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 2] = (((a[1] & 15U) * QSC_KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 3] = (((a[1] >> 4U) * QSC_KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 4] = (((a[2] & 15U) * QSC_KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 5] = (((a[2] >> 4U) * QSC_KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 6] = (((a[3] & 15U) * QSC_KYBER_Q) + 8) >> 4U;
		r->coeffs[i + 7] = (((a[3] >> 4U) * QSC_KYBER_Q) + 8) >> 4U;
		a += 4;
	}
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
	for (i = 0; i < QSC_KYBER_N; i += 8)
	{
		r->coeffs[i] = (((a[0] & 31U) * QSC_KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 1] = ((((a[0] >> 5U) | ((a[1] & 3U) << 3U)) * QSC_KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 2] = ((((a[1] >> 2U) & 31U) * QSC_KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 3] = ((((a[1] >> 7U) | ((a[2] & 15U) << 1U)) * QSC_KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 4] = ((((a[2] >> 4U) | ((a[3] & 1U) << 4U)) * QSC_KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 5] = ((((a[3] >> 1U) & 31U) * QSC_KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 6] = ((((a[3] >> 6U) | ((a[4] & 7U) << 2U)) * QSC_KYBER_Q) + 16) >> 5U;
		r->coeffs[i + 7] = (((a[4] >> 3U) * QSC_KYBER_Q) + 16) >> 5U;
		a += 5;
	}
#endif
}

void qsc_kyber_poly_tobytes(uint8_t* r, qsc_kyber_poly* a)
{
	size_t i;
	uint16_t t0;
	uint16_t t1;

	qsc_kyber_poly_csubq(a);

	for (i = 0; i < QSC_KYBER_N / 2; ++i)
	{
		t0 = a->coeffs[2 * i];
		t1 = a->coeffs[2 * i + 1];
		r[3 * i] = t0 & 0xFFU;
		r[3 * i + 1] = (t0 >> 8U) | ((t1 & 0x0FU) << 4U);
		r[3 * i + 2] = (uint8_t)(t1 >> 4U);
	}
}

void qsc_kyber_poly_frombytes(qsc_kyber_poly* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_N / 2; ++i)
	{
		r->coeffs[2 * i] = a[3 * i] | ((uint16_t)a[3 * i + 1] & 0x0FU) << 8;
		r->coeffs[2 * i + 1] = a[3 * i + 1] >> 4U | ((uint16_t)a[3 * i + 2] & 0xFFU) << 4U;
	}
}

void qsc_kyber_poly_getnoise(qsc_kyber_poly* r, const uint8_t* seed, uint8_t nonce)
{
	uint8_t buf[QSC_KYBER_ETA * QSC_KYBER_N / 4];
	uint8_t extkey[QSC_KYBER_SYMBYTES + 1];
	size_t i;

	for (i = 0; i < QSC_KYBER_SYMBYTES; ++i)
	{
		extkey[i] = seed[i];
	}

	extkey[i] = nonce;
	qsc_shake256_compute(buf, QSC_KYBER_ETA * QSC_KYBER_N / 4, extkey, QSC_KYBER_SYMBYTES + 1);

	qsc_kyber_cbd(r, buf);
}

void qsc_kyber_poly_ntt(qsc_kyber_poly* r)
{
	qsc_kyber_ntt(r->coeffs);
	qsc_kyber_poly_reduce(r);
}

void qsc_kyber_poly_invntt(qsc_kyber_poly* r)
{
	qsc_kyber_invntt(r->coeffs);
}

void qsc_kyber_poly_basemul(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_N / 4; ++i)
	{
		qsc_kyber_basemul(r->coeffs + (4 * i), a->coeffs + (4 * i), b->coeffs + (4 * i), qsc_kyber_zetas[64 + i]);
		qsc_kyber_basemul(r->coeffs + (4 * i) + 2, a->coeffs + (4U * i) + 2, b->coeffs + (4U * i) + 2, -qsc_kyber_zetas[64 + i]);
	}
}

void qsc_kyber_poly_frommont(qsc_kyber_poly* r)
{
	const int16_t f = (1ULL << 32) % QSC_KYBER_Q;
	size_t i;

	for (i = 0; i < QSC_KYBER_N; ++i)
	{
		r->coeffs[i] = (uint16_t)qsc_kyber_montgomery_reduce((int32_t)r->coeffs[i] * f);
	}
}

void qsc_kyber_poly_reduce(qsc_kyber_poly* r)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_N; ++i)
	{
		r->coeffs[i] = (uint16_t)qsc_kyber_barrett_reduce((int16_t)r->coeffs[i]);
	}
}

void qsc_kyber_poly_csubq(qsc_kyber_poly* r)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_N; ++i)
	{
		r->coeffs[i] = (uint16_t)qsc_kyber_csubq((int16_t)r->coeffs[i]);
	}
}

void qsc_kyber_poly_add(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_N; ++i)
	{
		r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
	}
}

void qsc_kyber_poly_sub(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_N; ++i)
	{
		r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
	}
}

void qsc_kyber_poly_frommsg(qsc_kyber_poly* r, const uint8_t msg[QSC_KYBER_SYMBYTES])
{
	size_t i;
	size_t j;
	uint16_t mask;

	for (i = 0; i < QSC_KYBER_SYMBYTES; ++i)
	{
		for (j = 0; j < 8; ++j)
		{
			mask = ~((msg[i] >> j) & 1U) + 1;
			r->coeffs[(8 * i) + j] = mask & ((QSC_KYBER_Q + 1) / 2);
		}
	}
}

void qsc_kyber_poly_tomsg(uint8_t msg[QSC_KYBER_SYMBYTES], qsc_kyber_poly* a)
{
	size_t i;
	size_t j;
	uint16_t t;

	qsc_kyber_poly_csubq(a);

	for (i = 0; i < QSC_KYBER_SYMBYTES; ++i)
	{
		msg[i] = 0;

		for (j = 0; j < 8; ++j)
		{
			t = (((a->coeffs[(8 * i) + j] << 1U) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 1U;
			/* jgu -suprressed false signed shift info */
			/*lint -e701 */
			msg[i] |= (uint8_t)(t << j);
		}
	}
}

/* polyvec.c */

void qsc_kyber_polyvec_compress(uint8_t* r, qsc_kyber_polyvec* a)
{
	size_t i;
	size_t j;
	size_t k;

	qsc_kyber_polyvec_csubq(a);

#if (KYBER_POLYVECBASEBYTES == 352)

	uint16_t t[8];

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		for (j = 0; j < QSC_KYBER_N / 8; ++j)
		{
			for (k = 0; k < 8; ++k)
			{
				t[k] = ((((uint32_t)a->vec[i].coeffs[(8 * j) + k] << 11) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 0x7FF;
			}

			r[11 * j] = t[0] & 0xFF;
			r[(11 * j) + 1] = (t[0] >> 8) | ((t[1] & 0x1F) << 3);
			r[(11 * j) + 2] = (t[1] >> 5) | ((t[2] & 0x03) << 6);
			r[(11 * j) + 3] = (t[2] >> 2) & 0xFF;
			r[(11 * j) + 4] = (t[2] >> 10) | ((t[3] & 0x7F) << 1);
			r[(11 * j) + 5] = (t[3] >> 7) | ((t[4] & 0x0F) << 4);
			r[(11 * j) + 6] = (t[4] >> 4) | ((t[5] & 0x01) << 7);
			r[(11 * j) + 7] = (t[5] >> 1) & 0xff;
			r[(11 * j) + 8] = (t[5] >> 9) | ((t[6] & 0x3F) << 2);
			r[(11 * j) + 9] = (t[6] >> 6) | ((t[7] & 0x07) << 5);
			r[(11 * j) + 10] = (t[7] >> 3);
		}

		r += KYBER_POLYVECBASEBYTES;
	}

#elif (KYBER_POLYVECBASEBYTES == 320)

	uint16_t t[4];

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		for (j = 0; j < QSC_KYBER_N / 4; ++j)
		{
			for (k = 0; k < 4; ++k)
			{
				t[k] = ((((uint32_t)a->vec[i].coeffs[(4 * j) + k] << 10) + QSC_KYBER_Q / 2) / QSC_KYBER_Q) & 0x3FFU;
			}

			r[5 * j] = (uint8_t)(t[0] & 0xFFU);
			r[(5 * j) + 1] = (uint8_t)((t[0] >> 8U) | ((t[1] & 0x3FU) << 2U));
			r[(5 * j) + 2] = (uint8_t)((t[1] >> 6U) | ((t[2] & 0x0FU) << 4U));
			r[(5 * j) + 3] = (uint8_t)((t[2] >> 4U) | ((t[3] & 0x03U) << 6U));
			r[(5 * j) + 4] = (uint8_t)((t[3] >> 2U));
		}

		r += KYBER_POLYVECBASEBYTES;
	}

#endif
}

void qsc_kyber_polyvec_decompress(qsc_kyber_polyvec* r, const uint8_t* a)
{
	size_t i;
	size_t j;

#if (KYBER_POLYVECBASEBYTES == 352)

	for (i = 0; i < QSC_KYBER_K; i++)
	{
		for (j = 0; j < QSC_KYBER_N / 8; j++)
		{
			r->vec[i].coeffs[(8 * j)] = (((a[(11 * j)] | (((uint32_t)a[(11 * j) + 1] & 0x07) << 8)) * QSC_KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 1] = ((((a[(11 * j) + 1] >> 3) | (((uint32_t)a[(11 * j) + 2] & 0x3F) << 5)) * QSC_KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 2] = ((((a[(11 * j) + 2] >> 6) | (((uint32_t)a[(11 * j) + 3] & 0xFF) << 2) | (((uint32_t)a[(11 * j) + 4] & 0x01) << 10)) * QSC_KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 3] = ((((a[(11 * j) + 4] >> 1) | (((uint32_t)a[(11 * j) + 5] & 0x0F) << 7)) * QSC_KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 4] = ((((a[(11 * j) + 5] >> 4) | (((uint32_t)a[(11 * j) + 6] & 0x7F) << 4)) * QSC_KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 5] = ((((a[(11 * j) + 6] >> 7) | (((uint32_t)a[(11 * j) + 7] & 0xFF) << 1) | (((uint32_t)a[(11 * j) + 8] & 0x03) << 9)) * QSC_KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 6] = ((((a[(11 * j) + 8] >> 2) | (((uint32_t)a[(11 * j) + 9] & 0x1F) << 6)) * QSC_KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[(8 * j) + 7] = ((((a[(11 * j) + 9] >> 5) | (((uint32_t)a[(11 * j) + 10] & 0xFF) << 3)) * QSC_KYBER_Q) + 1024) >> 11;
		}

		a += KYBER_POLYVECBASEBYTES;
	}

#elif (KYBER_POLYVECBASEBYTES == 320)

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		for (j = 0; j < QSC_KYBER_N / 4; ++j)
		{
			r->vec[i].coeffs[4 * j] = (((a[5 * j] | (((uint32_t)a[(5 * j) + 1] & 0x03U) << 8U)) * QSC_KYBER_Q) + 512) >> 10U;
			r->vec[i].coeffs[(4 * j) + 1] = ((((a[(5 * j) + 1] >> 2U) | (((uint32_t)a[(5 * j) + 2] & 0x0FU) << 6U)) * QSC_KYBER_Q) + 512) >> 10U;
			r->vec[i].coeffs[(4 * j) + 2] = ((((a[(5 * j) + 2] >> 4U) | (((uint32_t)a[(5 * j) + 3] & 0x3FU) << 4U)) * QSC_KYBER_Q) + 512) >> 10U;
			r->vec[i].coeffs[(4 * j) + 3] = ((((a[(5 * j) + 3] >> 6U) | (((uint32_t)a[(5 * j) + 4] & 0xFFU) << 2U)) * QSC_KYBER_Q) + 512) >> 10U;
		}

		a += KYBER_POLYVECBASEBYTES;
	}

#endif
}

void qsc_kyber_polyvec_tobytes(uint8_t* r, qsc_kyber_polyvec* a)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_tobytes(r + (i * KYBER_POLYBYTES), &a->vec[i]);
	}
}

void qsc_kyber_polyvec_frombytes(qsc_kyber_polyvec* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_frombytes(&r->vec[i], a + (i * KYBER_POLYBYTES));
	}
}

void qsc_kyber_polyvec_ntt(qsc_kyber_polyvec* r)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_ntt(&r->vec[i]);
	}
}

void qsc_kyber_polyvec_invntt(qsc_kyber_polyvec* r)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_invntt(&r->vec[i]);
	}
}

void qsc_kyber_polyvec_pointwise_acc(qsc_kyber_poly* r, const qsc_kyber_polyvec* a, const qsc_kyber_polyvec* b)
{
	qsc_kyber_poly t;
	size_t i;

	qsc_kyber_poly_basemul(r, &a->vec[0], &b->vec[0]);

	for (i = 1; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_basemul(&t, &a->vec[i], &b->vec[i]);
		qsc_kyber_poly_add(r, r, &t);
	}

	qsc_kyber_poly_reduce(r);
}

void qsc_kyber_polyvec_reduce(qsc_kyber_polyvec* r)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_reduce(&r->vec[i]);
	}
}

void qsc_kyber_polyvec_csubq(qsc_kyber_polyvec* r)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_csubq(&r->vec[i]);
	}
}

void qsc_kyber_polyvec_add(qsc_kyber_polyvec* r, const qsc_kyber_polyvec* a, const qsc_kyber_polyvec* b)
{
	size_t i;

	for (i = 0; i < QSC_KYBER_K; ++i)
	{
		qsc_kyber_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
	}
}

/* reduce.c */

int16_t qsc_kyber_montgomery_reduce(int32_t a)
{
	int32_t t;
	int16_t u;

	u = (int16_t)(a * KYBER_QINV);
	t = (int32_t)(u * QSC_KYBER_Q);
	t = a - t;
	t >>= 16;

	return (int16_t)t;
}

int16_t qsc_kyber_barrett_reduce(int16_t a)
{
	const int32_t V = (1U << 26) / QSC_KYBER_Q + 1;
	int32_t t;

	t = V * a;
	t >>= 26U;
	t *= QSC_KYBER_Q;

	return (int16_t)(a - t);
}

int16_t qsc_kyber_csubq(int16_t a)
{
	a -= QSC_KYBER_Q;
	a += (a >> 15U) & QSC_KYBER_Q;

	return a;
}