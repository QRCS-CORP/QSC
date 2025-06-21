#include "sphincsplus.h"
#include "sphincsplusbase.h"

bool qsc_sphincsplus_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);
	
	bool res;

	res = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		res = sphincsplus_ref_generate_keypair(publickey, privatekey, rng_generate);
	}

	return res;
}

bool qsc_sphincsplus_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t seed[QSC_SPHINCSPLUS_GENERATE_SEED_SIZE])
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(seed != NULL);
	
	bool res;

	res = false;

	if (publickey != NULL && privatekey != NULL && seed != NULL)
	{
		res = sphincsplus_ref_generate_seeded_keypair(publickey, privatekey, seed);
	}

	return res;
}

bool qsc_sphincsplus_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);
	
	uint8_t seed[QSC_SPHINCSPLUS_SIGN_SEED_SIZE] = { 0 };
	bool res;

	res = false;

	if (signedmsg != NULL && smsglen != NULL && message != NULL && privatekey != NULL && rng_generate != NULL)
	{
		if (rng_generate(seed, sizeof(seed)))
		{
			res = sphincsplus_ref_sign(signedmsg, smsglen, message, msglen, NULL, 0U, privatekey, seed);
		}
	}

	return res;
}

bool qsc_sphincsplus_sign_ex(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t cxtlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(context != NULL);
	
	uint8_t seed[QSC_SPHINCSPLUS_SIGN_SEED_SIZE] = { 0 };
	bool res;

	res = false;

	if (signedmsg != NULL && smsglen != NULL && message != NULL && privatekey != NULL)
	{
		if (rng_generate(seed, sizeof(seed)))
		{
			res = sphincsplus_ref_sign(signedmsg, smsglen, message, msglen, context, cxtlen, privatekey, seed);
		}
	}
	
	return res;
}

bool qsc_sphincsplus_seeded_sign_ex(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t cxtlen, const uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(seed != NULL);
	
	bool res;

	res = false;

	if (signedmsg != NULL && smsglen != NULL && message != NULL && privatekey != NULL && seed != NULL)
	{
		res = sphincsplus_ref_sign(signedmsg, smsglen, message, msglen, context, cxtlen, privatekey, seed);
	}
	
	return res;
}

bool qsc_sphincsplus_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(msglen != NULL);
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

	res = false;

	if (message != NULL && msglen != NULL && signedmsg != NULL && publickey != NULL)
	{
		res = sphincsplus_ref_open(message, msglen, NULL, 0U, signedmsg, smsglen, publickey);
	}

	return res;
}


bool qsc_sphincsplus_verify_ex(uint8_t* message, size_t* msglen, const uint8_t* context, size_t cxtlen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(msglen != NULL);
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

	res = false;

	if (message != NULL && msglen != NULL && signedmsg != NULL && publickey != NULL)
	{
		res = sphincsplus_ref_open(message, msglen, context, cxtlen, signedmsg, smsglen, publickey);
	}

	return res;
}
