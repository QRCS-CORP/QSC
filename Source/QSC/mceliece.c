#include "mceliece.h"
#include "mceliecebase.h"
#include "secrand.h"

bool qsc_mceliece_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(privatekey != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
		res = (qsc_mceliece_ref_decapsulate(secret, ciphertext, privatekey) == 0);
	}

	return res;
}

bool qsc_mceliece_decrypt(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(privatekey != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
		res = qsc_mceliece_decapsulate(secret, ciphertext, privatekey);
	}

	return res;
}

void qsc_mceliece_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	if (secret != NULL && ciphertext != NULL && publickey != NULL && rng_generate != NULL)
	{
		qsc_mceliece_ref_encapsulate(ciphertext, secret, publickey, rng_generate);
	}
}

void qsc_mceliece_encrypt(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_MCELIECE_SEED_SIZE])
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(seed != NULL);

	if (secret != NULL && ciphertext != NULL && publickey != NULL && seed != NULL)
	{
		qsc_secrand_initialize(seed, QSC_MCELIECE_SEED_SIZE, NULL, 0);
		qsc_mceliece_encapsulate(secret, ciphertext, publickey, &qsc_secrand_generate);
		qsc_secrand_dispose();
	}
}

void qsc_mceliece_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		qsc_mceliece_ref_generate_keypair(publickey, privatekey, rng_generate);
	}
}
