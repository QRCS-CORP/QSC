#include "eddsa.h"
#include "eddsabase.h"
#include "memutils.h"
#include "sha2.h"

void qsc_eddsa_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(seed != NULL);

	qsc_ed25519_keypair(publickey, privatekey, seed);
}

bool qsc_eddsa_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	uint8_t seed[QSC_ECDSA_SEED_SIZE] = { 0U };
	bool res;

	res = rng_generate(seed, sizeof(seed));

	if (res == true)
	{
		qsc_ed25519_keypair(publickey, privatekey, seed);
		qsc_memutils_secure_erase(seed, sizeof(seed));
	}

	return res;
}

void qsc_eddsa_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);

	qsc_ed25519_sign(signedmsg, smsglen, message, msglen, privatekey);
}

bool qsc_eddsa_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(msglen != NULL);
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(publickey != NULL);

	int32_t ret;

	ret = qsc_ed25519_verify(message, msglen, signedmsg, smsglen, publickey);

	return (ret == 0);
}
