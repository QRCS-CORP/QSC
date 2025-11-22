#include "ecdsabase.h"
#include "csp.h"
#include "ec25519.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"

static int32_t ecdsa_ed25519_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen, const uint8_t* sk)
{
	QSC_CACHE_ALIGNED uint8_t az[64U] = { 0U };
	QSC_CACHE_ALIGNED uint8_t nonce[64U] = { 0U };
	QSC_CACHE_ALIGNED uint8_t hram[64U] = { 0U };
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
	qsc_memutils_clear(az, sizeof(az));
	qsc_memutils_clear(nonce, sizeof(nonce));

	if (smlen != NULL)
	{
		*smlen = 64U;
	}

	return 0;
}

static bool ecdsa_ed25519_verify(const uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* pk)
{
	qsc_sha512_state ctx;
	QSC_CACHE_ALIGNED uint8_t h[64U] = { 0U };
	QSC_CACHE_ALIGNED uint8_t rcheck[32U] = { 0U };
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

		if ((qsc_sc25519_verify(rcheck, sig, 32) | (-(rcheck == sig))) != 0 || qsc_intutils_are_equal8(sig, rcheck, 32) == false)
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

	qsc_sha512_compute(privatekey, seed, EC25519_SEED_SIZE);
	qsc_sc25519_clamp(privatekey);

	qsc_ge25519_scalarmult_base(&A, privatekey);
	qsc_ge25519_p3_to_bytes(publickey, &A);

	qsc_memutils_copy(privatekey, seed, EC25519_SEED_SIZE);
	qsc_memutils_copy(privatekey + EC25519_SEED_SIZE, publickey, EC25519_PUBLICKEY_SIZE);
}

int32_t qsc_ed25519_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);

	size_t slen;
	int32_t res;

	qsc_memutils_copy(signedmsg + EC25519_SIGNATURE_SIZE, message, msglen);

	if (ecdsa_ed25519_sign(signedmsg, &slen, signedmsg + EC25519_SIGNATURE_SIZE, msglen, privatekey) != 0 || slen != EC25519_SIGNATURE_SIZE)
	{
		if (smsglen != NULL)
		{
			*smsglen = 0;
		}

		qsc_memutils_clear(signedmsg, msglen + EC25519_SIGNATURE_SIZE);
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
	QSC_ASSERT(smsglen > EC25519_SIGNATURE_SIZE);
	QSC_ASSERT(smsglen - EC25519_SIGNATURE_SIZE < QSC_SIZE_MAX);

	const size_t MSGLEN = smsglen - EC25519_SIGNATURE_SIZE;
	int32_t res;

	if (ecdsa_ed25519_verify(signedmsg, signedmsg + EC25519_SIGNATURE_SIZE, MSGLEN, publickey) == false)
	{
		if (message != NULL)
		{
			qsc_memutils_clear(message, MSGLEN);
		}

		if (msglen != NULL)
		{
			*msglen = 0;
		}

		res = -1;
	}
	else
	{
		if (msglen != NULL)
		{
			*msglen = MSGLEN;
		}

		if (message != NULL)
		{
			qsc_memutils_copy(message, signedmsg + EC25519_SIGNATURE_SIZE, MSGLEN);
		}

		res = 0;
	}

	return res;
}
