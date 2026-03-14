#include "eddsabase.h"
#include "csp.h"
#include "ed25519.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"

static int32_t ecdsa_ed25519_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen, const uint8_t* sk)
{
	uint8_t az[64U] = { 0U };
	uint8_t nonce[64U] = { 0U };
	uint8_t hram[64U] = { 0U };
	qsc_sha512_state ctx;
	qsc_ge25519_p3 R;

	/* hash 1st half of sk to az */
	qsc_sha512_compute(az, sk, 32U);

	qsc_sha512_initialize(&ctx);
	/* update with 2nd half of az */
	qsc_sha512_update(&ctx, az + 32U, 32U);
	/* update hash with m */
	qsc_sha512_update(&ctx, m, mlen);
	/* finalize to nonce */
	qsc_sha512_finalize(&ctx, nonce);

	/* move 2nd half of sk to 2nd half of sig */
	qsc_memutils_copy(sm + 32U, sk + 32U, 32U);
    /* reduce nonce */
	qsc_sc25519_reduce(nonce);
    /* scalar on nonce */
	qsc_ge25519_scalarmult_base(&R, nonce);
	/* scalar to 1st half of sig */
	qsc_ge25519_p3_to_bytes(sm, &R);

	qsc_sha512_initialize(&ctx);
	/* update hash with sig */
	qsc_sha512_update(&ctx, sm, 64);
	/* update hash with message */
	qsc_sha512_update(&ctx, m, mlen);
	/* finalize to hram */
	qsc_sha512_finalize(&ctx, hram);
    /* reduce hram */
	qsc_sc25519_reduce(hram);
	/* clamp az */
	qsc_sc25519_clamp(az);
	/* muladd hram, az, nonce to 2nd half of sig */
	qsc_sc25519_muladd(sm + 32, hram, az, nonce);
	/* cleanup */
	qsc_memutils_secure_erase(az, sizeof(az));
	qsc_memutils_secure_erase(nonce, sizeof(nonce));

	if (smlen != NULL)
	{
		*smlen = 64U;
	}

	return 0;
}

static bool ecdsa_ed25519_verify(const uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* pk)
{
	qsc_sha512_state ctx;
	uint8_t h[64U] = { 0U };
	uint8_t rcheck[32U] = { 0U };
	qsc_ge25519_p3 A;
	qsc_ge25519_p2 R;
	bool res;

	if ((sig[63U] & 240) && qsc_sc25519_is_canonical(sig + 32U) == 0)
	{
		res = false;
	}
	else if (qsc_ge25519_has_small_order(sig) != 0) 
	{
		res = false;
	}
	else if (qsc_ge25519_is_canonical(pk) == 0 || qsc_ge25519_has_small_order(pk) != 0)
	{
		res = false;
	}
	else if (qsc_ge25519_from_bytes_negate_vartime(&A, pk) != 0)
	{
		res = false;
	}
	else
	{
		res = true;
	}

	if (res == true)
	{
		qsc_sha512_initialize(&ctx);
		qsc_sha512_update(&ctx, sig, 32U);
		qsc_sha512_update(&ctx, pk, 32U);
		qsc_sha512_update(&ctx, m, mlen);
		qsc_sha512_finalize(&ctx, h);
		qsc_sc25519_reduce(h);

		qsc_ge25519_double_scalarmult_vartime(&R, h, &A, sig + 32U);
		qsc_ge25519_to_bytes(rcheck, &R);

		if (qsc_sc25519_verify(rcheck, sig, 32U) || qsc_memutils_are_equal(sig, rcheck, 32U) == false)
		{
			res = false;
		}
	}

	return res;
}

/* public api */

void qsc_ed25519_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(seed != NULL);

	qsc_ge25519_p3 A;

	qsc_sha512_compute(privatekey, seed, ED25519_SEED_SIZE);
	qsc_sc25519_clamp(privatekey);

	qsc_ge25519_scalarmult_base(&A, privatekey);
	qsc_ge25519_p3_to_bytes(publickey, &A);

	qsc_memutils_copy(privatekey, seed, ED25519_SEED_SIZE);
	qsc_memutils_copy(privatekey + ED25519_SEED_SIZE, publickey, ED25519_PUBLICKEY_SIZE);
}

int32_t qsc_ed25519_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);

	size_t slen;
	int32_t res;

	qsc_memutils_copy(signedmsg + ED25519_SIGNATURE_SIZE, message, msglen);

	if (ecdsa_ed25519_sign(signedmsg, &slen, signedmsg + ED25519_SIGNATURE_SIZE, msglen, privatekey) != 0 || slen != ED25519_SIGNATURE_SIZE)
	{
		if (smsglen != NULL)
		{
			*smsglen = 0;
		}

		qsc_memutils_clear(signedmsg, msglen + ED25519_SIGNATURE_SIZE);
		res = -1;
	}
	else
	{
		if (smsglen != NULL)
		{
			*smsglen = msglen + slen;
		}

		res = 0;
	}

	return res;
}

int32_t qsc_ed25519_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(msglen != NULL);
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(smsglen > ED25519_SIGNATURE_SIZE);
	QSC_ASSERT(smsglen - ED25519_SIGNATURE_SIZE < QSC_SIZE_MAX);

	int32_t res;

	if (message != NULL && msglen != NULL && signedmsg != NULL && publickey != NULL && 
		smsglen > ED25519_SIGNATURE_SIZE && smsglen - ED25519_SIGNATURE_SIZE < QSC_SIZE_MAX)
	{
		const size_t MSGLEN = smsglen - ED25519_SIGNATURE_SIZE;

		if (ecdsa_ed25519_verify(signedmsg, signedmsg + ED25519_SIGNATURE_SIZE, MSGLEN, publickey) == false)
		{
			qsc_memutils_clear(message, MSGLEN);
			*msglen = 0;
			res = -1;
		}
		else
		{
			*msglen = MSGLEN;
			qsc_memutils_copy(message, signedmsg + ED25519_SIGNATURE_SIZE, MSGLEN);
			res = 0;
		}
	}

	return res;
}
