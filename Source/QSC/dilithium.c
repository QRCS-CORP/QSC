#include "dilithium.h"

#if defined(QSC_SYSTEM_HAS_AVX2)
#	include "dilithiumbase_avx2.h"
#else
#	include "dilithiumbase.h"
#endif

bool qsc_dilithium_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	bool res;

	res = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		res = qsc_dilithium_avx2_generate_keypair(publickey, privatekey, rng_generate);
#else
		res = qsc_dilithium_ref_generate_keypair(publickey, privatekey, rng_generate);
#endif
	}

	return res;
}

void qsc_dilithium_seeded_generate_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(seed != NULL);

	if (publickey != NULL && privatekey != NULL && seed != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		qsc_dilithium_avx2_seeded_generate_keypair(publickey, privatekey, seed);
#else
		qsc_dilithium_ref_seeded_generate_keypair(publickey, privatekey, seed);
#endif
	}
}

bool qsc_dilithium_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);
#if defined(QSC_DILITHIUM_RANDOMIZED_SIGNING)
	QSC_ASSERT(rng_generate != NULL);
#endif

	bool res;

	res = false;

	if (signedmsg != NULL && smsglen != NULL && message != NULL && privatekey != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		res = qsc_dilithium_avx2_sign(signedmsg, smsglen, message, msglen, NULL, 0U, privatekey, rng_generate);
#else
		res = qsc_dilithium_ref_sign(signedmsg, smsglen, message, msglen, NULL, 0U, privatekey, rng_generate);
#endif
	}

	return res;
}

bool qsc_dilithium_sign_ex(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);
#if defined(QSC_DILITHIUM_RANDOMIZED_SIGNING)
	QSC_ASSERT(rng_generate != NULL);
#endif
	
	bool res;

	res = false;

	if (signedmsg != NULL && smsglen != NULL && message != NULL && privatekey != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		res = qsc_dilithium_avx2_sign(signedmsg, smsglen, message, msglen, context, ctxlen, privatekey, rng_generate);
#else
		res = qsc_dilithium_ref_sign(signedmsg, smsglen, message, msglen, context, ctxlen, privatekey, rng_generate);
#endif
	}
	
	return res;
}

bool qsc_dilithium_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(msglen != NULL);
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

	res = false;

	if (message != NULL && msglen != NULL && signedmsg != NULL && publickey != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		res = qsc_dilithium_avx2_open(message, msglen, NULL, 0U, signedmsg, smsglen, publickey);
#else
		res = qsc_dilithium_ref_open(message, msglen, NULL, 0U, signedmsg, smsglen, publickey);
#endif
	}

	return res;
}

bool qsc_dilithium_verify_ex(uint8_t* message, size_t* msglen, const uint8_t* context, size_t ctxlen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(msglen != NULL);
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

	res = false;

	if (message != NULL && msglen != NULL && signedmsg != NULL && publickey != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		res = qsc_dilithium_avx2_open(message, msglen, context, ctxlen, signedmsg, smsglen, publickey);
#else
		res = qsc_dilithium_ref_open(message, msglen, context, ctxlen, signedmsg, smsglen, publickey);
#endif
	}

	return res;
}
