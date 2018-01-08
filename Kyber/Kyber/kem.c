#include "api.h"
#include "indcpa.h"
#include "sysrand.h"
#include "sha3.h"
#include "verify.h"
#include <assert.h>

int32_t crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
{
	size_t i;
	int32_t rstat;

	indcpa_keypair(pk, sk);

	/* si = pk+sk+smb*2
	   si= k2-1632, k3-2400, k4-3168
	   pk= k2-736, k3-1088, k4-1440
	   sk= k2-832, k3-1248, k4-1664 
	*/

	for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++)
	{
		sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
	}

	sha3_compute256(sk + (KYBER_SECRETKEYBYTES - (2 * KYBER_SYMBYTES)), pk, KYBER_PUBLICKEYBYTES);

	/* value z for pseudo-random output on reject */
	rstat = sysrand_getbytes(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);
	assert(rstat == RAND_STATUS_SUCCESS);

	return 0;
}

int32_t crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
	/* will contain key, coins */
	uint8_t  kr[2 * KYBER_SYMBYTES];
	uint8_t buf[2 * KYBER_SYMBYTES];
	int32_t rstat;

	rstat = sysrand_getbytes(buf, KYBER_SYMBYTES);
	assert(rstat == RAND_STATUS_SUCCESS);

	/* don't release system RNG output */
	sha3_compute256(buf, buf, KYBER_SYMBYTES);
	/* multitarget countermeasure for coins + contributory KEM */
	sha3_compute256(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
	sha3_compute512(kr, buf, 2 * KYBER_SYMBYTES);
	/* coins are in kr+KYBER_SYMBYTES */
	indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);
	/* overwrite coins in kr with H(c) */
	sha3_compute256(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
	/* hash concatenation of pre-k and H(c) to k */
	sha3_compute256(ss, kr, 2 * KYBER_SYMBYTES);

	return 0;
}

int32_t crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
	const uint8_t* pk = sk + KYBER_INDCPA_SECRETKEYBYTES;
	uint8_t buf[2 * KYBER_SYMBYTES];
	uint8_t cmp[KYBER_CIPHERTEXTBYTES];
	/* will contain key, coins, qrom-hash */
	uint8_t kr[2 * KYBER_SYMBYTES];
	size_t i;
	int32_t fail;

	indcpa_dec(buf, ct, sk);

	/* multitarget countermeasure for coins + contributory KEM */
	for (i = 0; i < KYBER_SYMBYTES; i++)
	{
		/* save hash by storing H(pk) in sk */
		buf[KYBER_SYMBYTES + i] = sk[(KYBER_SECRETKEYBYTES - (2 * KYBER_SYMBYTES)) + i];
	}

	sha3_compute512(kr, buf, 2 * KYBER_SYMBYTES);
	/* coins are in kr+KYBER_SYMBYTES */
	indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);
	/* verify the code */
	fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);
	/* overwrite coins in kr with H(c)  */
	sha3_compute256(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
	/* overwrite pre-k with z on re-encryption failure */
	cmov(kr, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES, fail);
	/* hash concatenation of pre-k and H(c) to k */
	sha3_compute256(ss, kr, 2 * KYBER_SYMBYTES);

	return fail;
}
