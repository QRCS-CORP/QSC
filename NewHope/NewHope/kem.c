/*lint -e537 */
#include "kem.h"
#include "cpapke.h"
#include "sysrand.h"
#include "sha3.h"
#include "verify.h"

newhope_status crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
{
	newhope_status status;
	size_t i;

	/* First put the actual secret key into sk */
	if (cpapke_keypair(pk, sk) == NEWHOPE_STATE_SUCCESS)
	{
		sk += NEWHOPE_CPAPKE_SECRETKEYBYTES;

		/* Append the public key for re-encryption */
		for (i = 0; i < NEWHOPE_CPAPKE_PUBLICKEYBYTES; i++)
		{
			sk[i] = pk[i];
		}

		sk += NEWHOPE_CPAPKE_PUBLICKEYBYTES;
		/* Append the hash of the public key */
		shake256(sk, NEWHOPE_SYMBYTES, pk, NEWHOPE_CPAPKE_PUBLICKEYBYTES);
		sk += NEWHOPE_SYMBYTES;
		/* Append the value s for pseudo-random output on reject */
		if (sysrand_getbytes(sk, NEWHOPE_SYMBYTES) == NEWHOPE_STATE_SUCCESS)
		{
			status = NEWHOPE_STATE_SUCCESS;
		}
		else
		{
			status = NEWHOPE_ERROR_RANDFAIL;
		}
	}
	else
	{
		status = NEWHOPE_STATE_FAILURE;
	}

	return status;
}

newhope_status crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
	/* Will contain key, coins, qrom-hash */
	uint8_t kcoins[3 * NEWHOPE_SYMBYTES];
	uint8_t buf[2 * NEWHOPE_SYMBYTES];
	newhope_status status;
	size_t i;

	if (sysrand_getbytes(buf, NEWHOPE_SYMBYTES) == NEWHOPE_STATE_SUCCESS)
	{
		/* Don't release system RNG output */
		shake256(buf, NEWHOPE_SYMBYTES, buf, NEWHOPE_SYMBYTES);
		/* Multitarget countermeasure for coins + contributory KEM */
		shake256(buf + NEWHOPE_SYMBYTES, NEWHOPE_SYMBYTES, pk, NEWHOPE_CCAKEM_PUBLICKEYBYTES);
		shake256(kcoins, 3 * NEWHOPE_SYMBYTES, buf, 2 * NEWHOPE_SYMBYTES);
		/* coins are in kcoins+NEWHOPE_SYMBYTES */
		cpapke_enc(ct, buf, pk, kcoins + NEWHOPE_SYMBYTES);

		/* copy Targhi-Unruh hash into ct */
		for (i = 0; i < NEWHOPE_SYMBYTES; i++)
		{
			ct[i + NEWHOPE_CPAPKE_CIPHERTEXTBYTES] = kcoins[i + 2 * NEWHOPE_SYMBYTES];
		}

		/* overwrite coins in kcoins with h(c) */
		shake256(kcoins + NEWHOPE_SYMBYTES, NEWHOPE_SYMBYTES, ct, NEWHOPE_CCAKEM_CIPHERTEXTBYTES);
		/* hash concatenation of pre-k and h(c) to ss */
		shake256(ss, NEWHOPE_SYMBYTES, kcoins, 2 * NEWHOPE_SYMBYTES);
		status = NEWHOPE_STATE_SUCCESS;
	}
	else
	{
		status = NEWHOPE_STATE_FAILURE;
	}

	return status;
}

newhope_status crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
	uint8_t ctcmp[NEWHOPE_CCAKEM_CIPHERTEXTBYTES];
	uint8_t buf[2 * NEWHOPE_SYMBYTES];
	/* Will contain key, coins, qrom-hash */
	uint8_t kcoins[3 * NEWHOPE_SYMBYTES];
	const uint8_t *pk = sk + NEWHOPE_CPAPKE_SECRETKEYBYTES;
	size_t i;
	int32_t fail;

	cpapke_dec(buf, ct, sk);

	/* Use hash of pk stored in sk */
	for (i = 0; i < NEWHOPE_SYMBYTES; i++)
	{
		buf[NEWHOPE_SYMBYTES + i] = sk[NEWHOPE_CCAKEM_SECRETKEYBYTES - 2 * NEWHOPE_SYMBYTES + i];
	}

	shake256(kcoins, 3 * NEWHOPE_SYMBYTES, buf, 2 * NEWHOPE_SYMBYTES);
	/* coins are in kcoins+NEWHOPE_SYMBYTES */
	cpapke_enc(ctcmp, buf, pk, kcoins + NEWHOPE_SYMBYTES);

	for (i = 0; i < NEWHOPE_SYMBYTES; i++)
	{
		ctcmp[i + NEWHOPE_CPAPKE_CIPHERTEXTBYTES] = kcoins[i + 2 * NEWHOPE_SYMBYTES];
	}

	fail = verify(ct, ctcmp, NEWHOPE_CCAKEM_CIPHERTEXTBYTES);
	/* overwrite coins in kcoins with h(c) */
	shake256(kcoins + NEWHOPE_SYMBYTES, NEWHOPE_SYMBYTES, ct, NEWHOPE_CCAKEM_CIPHERTEXTBYTES);
	/* Overwrite pre-k with z on re-encryption failure */
	cmov(kcoins, sk + NEWHOPE_CCAKEM_SECRETKEYBYTES - NEWHOPE_SYMBYTES, NEWHOPE_SYMBYTES, fail);
	/* hash concatenation of pre-k and h(c) to k */
	shake256(ss, NEWHOPE_SYMBYTES, kcoins, 2 * NEWHOPE_SYMBYTES);

	return (fail == 0) ? NEWHOPE_STATE_SUCCESS : NEWHOPE_ERROR_AUTHFAIL;
}
