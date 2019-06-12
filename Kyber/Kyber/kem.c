#include "kem.h"
#include "indcpa.h"
#include "rng.h"
#include "sha3.h"
#include "verify.h"

bool crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
{
	size_t i;
	int32_t ret;

	ret = indcpa_keypair(pk, sk);

	for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; ++i)
	{
		sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
	}

	sha3_compute256(sk + KYBER_SECRETKEY_SIZE - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEY_SIZE);
    /* Value z for pseudo-random output on reject */
	ret += randombytes(sk + KYBER_SECRETKEY_SIZE - KYBER_SYMBYTES, KYBER_SYMBYTES);

	return (bool)(ret == 0);
}

bool crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
    /* Will contain key, coins */
	uint8_t  kr[2 * KYBER_SYMBYTES];
	uint8_t buf[2 * KYBER_SYMBYTES];
	int32_t ret;

	ret = randombytes(buf, KYBER_SYMBYTES);
    /* Don't release system RNG output */
	sha3_compute256(buf, buf, KYBER_SYMBYTES);
    /* Multitarget countermeasure for coins + contributory KEM */
	sha3_compute256(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEY_SIZE);
	sha3_compute512(kr, buf, 2 * KYBER_SYMBYTES);
    /* coins are in kr+KYBER_SYMBYTES */
	indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);
    /* overwrite coins in kr with H(c) */
	sha3_compute256(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXT_SIZE);
    /* hash concatenation of pre-k and H(c) to k */
	shake256(ss, KYBER_SYMBYTES, kr, 2 * KYBER_SYMBYTES);

	return (bool)(ret == 0);
}

bool crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
	uint8_t cmp[KYBER_CIPHERTEXT_SIZE];
	uint8_t buf[2 * KYBER_SYMBYTES];
    /* Will contain key, coins */
	uint8_t kr[2 * KYBER_SYMBYTES];
	const uint8_t* pk = sk + KYBER_INDCPA_SECRETKEYBYTES;
	size_t i;
	int32_t fail;

	indcpa_dec(buf, ct, sk);

    /* Multitarget countermeasure for coins + contributory KEM */
	for (i = 0; i < KYBER_SYMBYTES; ++i)
	{
		/* Save hash by storing H(pk) in sk */
		buf[KYBER_SYMBYTES + i] = sk[(KYBER_SECRETKEY_SIZE - (2 * KYBER_SYMBYTES)) + i];
	}

	sha3_compute512(kr, buf, 2 * KYBER_SYMBYTES);
    /* coins are in kr+KYBER_SYMBYTES */
	indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

	fail = verify(ct, cmp, KYBER_CIPHERTEXT_SIZE);
    /* overwrite coins in kr with H(c) */
	sha3_compute256(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXT_SIZE);
	/* Overwrite pre-k with z on re-encryption failure */
	cmov(kr, sk + KYBER_SECRETKEY_SIZE - KYBER_SYMBYTES, KYBER_SYMBYTES, (uint8_t)fail);
    /* hash concatenation of pre-k and H(c) to k */
	shake256(ss, KYBER_SYMBYTES, kr, 2 * KYBER_SYMBYTES);

	return (bool)(fail == 0);
}
