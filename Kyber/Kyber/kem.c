/*lint -e537 */
#include "kem.h"
#include "indcpa.h"
#include "sysrand.h"
#include "sha3.h"
#include "verify.h"

qcc_status crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
{
	size_t i;
	qcc_status status;

	if (indcpa_keypair(pk, sk) == QCC_STATUS_SUCCESS)
	{
		/* si = pk+sk+smb*2
		   si= k2-1632, k3-2400, k4-3168
		   pk= k2-736, k3-1088, k4-1440
		   sk= k2-832, k3-1248, k4-1664 */

		for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++)
		{
			sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
		}

		/* add the hash of the public key to the secret key */
		sha3_compute256(sk + (KYBER_SECRETKEYBYTES - (2 * KYBER_KEYBYTES)), pk, KYBER_PUBLICKEYBYTES);

		/* value z for pseudo-random output on reject */
		status = sysrand_getbytes(sk + KYBER_SECRETKEYBYTES - KYBER_KEYBYTES, KYBER_KEYBYTES);
	}
	else
	{
		status = QCC_ERROR_KEYGEN;
	}

	return status;
}

qcc_status crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
	/* will contain key, coins */
	uint8_t  kr[2 * KYBER_KEYBYTES];
	uint8_t buf[2 * KYBER_KEYBYTES];
	qcc_status status;

	status = sysrand_getbytes(buf, KYBER_KEYBYTES);
	/* don't release system RNG output */
	sha3_compute256(buf, buf, KYBER_KEYBYTES);
	/* multitarget countermeasure for coins + contributory KEM */
	sha3_compute256(buf + KYBER_KEYBYTES, pk, KYBER_PUBLICKEYBYTES);
	sha3_compute512(kr, buf, 2 * KYBER_KEYBYTES);
	/* coins are in kr+KYBER_KEYBYTES */
	indcpa_enc(ct, buf, pk, kr + KYBER_KEYBYTES);
	/* overwrite coins in kr with H(c) */
	sha3_compute256(kr + KYBER_KEYBYTES, ct, KYBER_CIPHERTEXTBYTES);
	/* hash concatenation of pre-k and H(c) to k */
	sha3_compute256(ss, kr, 2 * KYBER_KEYBYTES);

	return status;
}

qcc_status crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
	const uint8_t* pk = sk + KYBER_INDCPA_SECRETKEYBYTES;
	uint8_t buf[2 * KYBER_KEYBYTES];
	uint8_t cmp[KYBER_CIPHERTEXTBYTES];
	int32_t fail;
	/* will contain key, coins, qrom-hash */
	uint8_t kr[2 * KYBER_KEYBYTES];
	size_t i;

	indcpa_dec(buf, ct, sk);

	/* multitarget countermeasure for coins + contributory KEM */
	for (i = 0; i < KYBER_KEYBYTES; i++)
	{
		/* save hash by storing H(pk) in sk */
		buf[KYBER_KEYBYTES + i] = sk[(KYBER_SECRETKEYBYTES - (2 * KYBER_KEYBYTES)) + i];
	}

	sha3_compute512(kr, buf, 2 * KYBER_KEYBYTES);
	/* coins are in kr+KYBER_KEYBYTES */
	indcpa_enc(cmp, buf, pk, kr + KYBER_KEYBYTES);
	/* verify the code */
	fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);
	/* overwrite coins in kr with H(c) */
	sha3_compute256(kr + KYBER_KEYBYTES, ct, KYBER_CIPHERTEXTBYTES);
	/* overwrite pre-k with z on re-encryption failure */
	cmov(kr, sk + KYBER_SECRETKEYBYTES - KYBER_KEYBYTES, KYBER_KEYBYTES, fail);
	/* hash concatenation of pre-k and H(c) to k */
	sha3_compute256(ss, kr, 2 * KYBER_KEYBYTES);

	return (fail == 0) ? QCC_STATUS_SUCCESS : QCC_STATUS_AUTHFAIL;
}
