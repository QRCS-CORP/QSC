#include "cpapke.h"
#include "sha3.h"
#include "kem.h"
#include "rng.h"
#include "verify.h"

/* bogus integral type warnings */
/*lint -e970 */
/*lint -e731 */
/*lint -e953 */
/*lint -e747 */

bool crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
{
	size_t i;
	int32_t ret;

	/* put the actual secret key into sk */
	cpapke_keypair(pk, sk);
	sk += NEWHOPE_CPAPKE_SECRETKEYBYTES;

	/* append the public key for re-encryption */
	for (i = 0; i < NEWHOPE_CPAPKE_PUBLICKEYBYTES; ++i)
	{
		sk[i] = pk[i];
	}

	sk += NEWHOPE_CPAPKE_PUBLICKEYBYTES;
	/* append the hash of the public key */
	shake256(sk, NEWHOPE_SYMBYTES, pk, NEWHOPE_CPAPKE_PUBLICKEYBYTES);
	sk += NEWHOPE_SYMBYTES;
	/* append the value s for pseudo-random output on reject */
	ret = randombytes(sk, NEWHOPE_SYMBYTES);                                        

	return ret == 0;
}

bool crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
	/* contains key, coins, qrom-hash */
	uint8_t kcoinsd[3 * NEWHOPE_SYMBYTES];
	uint8_t buf[2 * NEWHOPE_SYMBYTES];
	size_t i;
	int32_t ret;

	/* don't release system RNG output */
	ret = randombytes(buf, NEWHOPE_SYMBYTES);

	shake256(buf, NEWHOPE_SYMBYTES, buf, NEWHOPE_SYMBYTES);
	/* multitarget countermeasure for coins + contributory KEM */
	shake256(buf + NEWHOPE_SYMBYTES, NEWHOPE_SYMBYTES, pk, NEWHOPE_PUBLICKEY_SIZE);
	shake256(kcoinsd, 3 * NEWHOPE_SYMBYTES, buf, 2 * NEWHOPE_SYMBYTES);
	/* coins are in kcoinsd+NEWHOPE_SYMBYTES */
	cpapke_enc(ct, buf, pk, kcoinsd + NEWHOPE_SYMBYTES);

	/* copy Targhi-Unruh hash into ct */
	for (i = 0; i < NEWHOPE_SYMBYTES; i++)
	{
		ct[i + NEWHOPE_CPAPKE_CIPHERTEXTBYTES] = kcoinsd[i + 2 * NEWHOPE_SYMBYTES];
	}

	/* overwrite coins in kcoinsd with h(c) */
	shake256(kcoinsd + NEWHOPE_SYMBYTES, NEWHOPE_SYMBYTES, ct, NEWHOPE_CIPHERTEXT_SIZE);
	/* hash concatenation of pre-k and h(c) to ss */
	shake256(ss, NEWHOPE_SYMBYTES, kcoinsd, 2 * NEWHOPE_SYMBYTES);

	return (ret == 0);
}

bool crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
	uint8_t ctcmp[NEWHOPE_CIPHERTEXT_SIZE];
	uint8_t buf[2 * NEWHOPE_SYMBYTES];
	/* contains key, coins, qrom-hash */
	uint8_t kcoinsd[3 * NEWHOPE_SYMBYTES];
	/* jgu checked false 953 warning */
	const uint8_t* pk = sk + NEWHOPE_CPAPKE_SECRETKEYBYTES;
	size_t i;
	int fail;

	cpapke_dec(buf, ct, sk);

	/* use hash of pk stored in sk */
	for (i = 0; i < NEWHOPE_SYMBYTES; ++i)
	{
		buf[NEWHOPE_SYMBYTES + i] = sk[(NEWHOPE_SECRETKEY_SIZE - (2 * NEWHOPE_SYMBYTES)) + i];
	}

	shake256(kcoinsd, 3 * NEWHOPE_SYMBYTES, buf, 2 * NEWHOPE_SYMBYTES);
	/* coins are in kcoinsd+NEWHOPE_SYMBYTES */
	cpapke_enc(ctcmp, buf, pk, kcoinsd + NEWHOPE_SYMBYTES);

	for (i = 0; i < NEWHOPE_SYMBYTES; ++i)
	{
		ctcmp[i + NEWHOPE_CPAPKE_CIPHERTEXTBYTES] = kcoinsd[i + 2 * NEWHOPE_SYMBYTES];
	}

	fail = verify(ct, ctcmp, NEWHOPE_CIPHERTEXT_SIZE);
	/* overwrite coins in kcoinsd with h(c)  */
	shake256(kcoinsd + NEWHOPE_SYMBYTES, NEWHOPE_SYMBYTES, ct, NEWHOPE_CIPHERTEXT_SIZE);
	/* overwrite pre-k with z on re-encryption failure */
	cmov(kcoinsd, sk + NEWHOPE_SECRETKEY_SIZE - NEWHOPE_SYMBYTES, NEWHOPE_SYMBYTES, (uint8_t)fail);
	/* hash concatenation of pre-k and h(c) to k */
	shake256(ss, NEWHOPE_SYMBYTES, kcoinsd, 2 * NEWHOPE_SYMBYTES);

	return (fail == 0);
}
