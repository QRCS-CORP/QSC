#include "ecdh.h"
#include "ecdhbase.h"
#include "memutils.h"

bool qsc_ecdh_key_exchange(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

	res = false;

	if (secret != NULL && privatekey != NULL && publickey != NULL)
	{
		res = qsc_x25519_key_exchange(secret, publickey, privatekey);
	}

	return res;
}

bool qsc_ecdh_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	uint8_t seed[QSC_ECDH_SEED_SIZE] = { 0U };
	bool res;

	res = false;

	if (privatekey != NULL && publickey != NULL && rng_generate != NULL)
	{
		if (rng_generate(seed, sizeof(seed)))
		{
			qsc_x25519_generate_keypair(publickey, privatekey, seed);
			qsc_memutils_secure_erase(seed, QSC_ECDH_SEED_SIZE);
			res = true;
		}
	}

	return res;
}

void qsc_x25519_public_from_private(uint8_t* publickey, const uint8_t* privatekey)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);

	if (publickey != NULL && privatekey != NULL)
	{
		/* Derive public key from private key using X25519 basepoint mult.
		   This call clamps internally (it copies sk to a temp, clamps temp). */
		(void)qsc_crypto_scalarmult_curve25519_ref10_base(publickey, privatekey);
	}
}

bool qsc_ecdh_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(seed != NULL);

	bool res;

	res = false;

	if (privatekey != NULL && publickey != NULL && seed != NULL)
	{
		qsc_x25519_generate_keypair(publickey, privatekey, seed);
		res = true;
	}

	return res;
}

