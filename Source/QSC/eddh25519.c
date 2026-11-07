#include "eddh25519.h"
#include "ed25519.h"
#include "memutils.h"

/* \cond DOXYGEN_NO_DOCUMENT */

int32_t qsc_crypto_scalarmult_curve25519(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
	uint8_t combined;
	int32_t result;
	size_t i;

	QSC_ASSERT(q != NULL);
	QSC_ASSERT(n != NULL);
	QSC_ASSERT(p != NULL);

	result = -1;

	if (q != NULL && n != NULL && p != NULL)
	{
		result = qsc_crypto_scalarmult_curve25519_ref10(q, n, p);
		combined = 0U;

		for (i = 0U; i < QSC_X25519_SECRET_SIZE; ++i)
		{
			combined |= q[i];
		}

		result = -1 + (int32_t)((uint32_t)(result == 0) & (uint32_t)(combined != 0U));
	}
	else if (q != NULL)
	{
		qsc_memutils_clear(q, QSC_X25519_SECRET_SIZE);
	}

	return result;
}

int32_t qsc_crypto_scalarmult_curve25519_ref10(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
	int32_t result;

	QSC_ASSERT(q != NULL);
	QSC_ASSERT(n != NULL);
	QSC_ASSERT(p != NULL);

	result = -1;

	if (q != NULL && n != NULL && p != NULL)
	{
		result = -(int32_t)(qsc_ed25519_small_order(p) != 0);
		qsc_ed25519_x25519_exchange(q, n, p);
	}
	else if (q != NULL)
	{
		qsc_memutils_clear(q, QSC_X25519_SECRET_SIZE);
	}

	return result;
}

int32_t qsc_crypto_scalarmult_curve25519_ref10_base(uint8_t* q, const uint8_t* n)
{
	int32_t result;

	QSC_ASSERT(q != NULL);
	QSC_ASSERT(n != NULL);

	result = -1;

	if (q != NULL && n != NULL)
	{
		qsc_ed25519_x25519_generate(q, n);
		result = 0;
	}
	else if (q != NULL)
	{
		qsc_memutils_clear(q, QSC_X25519_PUBLICKEY_SIZE);
	}

	return result;
}

void qsc_x25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	bool generated;

	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	generated = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		generated = rng_generate(privatekey, QSC_X25519_PRIVATEKEY_SIZE);

		if (generated == true)
		{
			qsc_x25519_public_from_private(publickey, privatekey);
		}
	}

	if (generated == false)
	{
		if (publickey != NULL)
		{
			qsc_memutils_clear(publickey, QSC_X25519_PUBLICKEY_SIZE);
		}

		if (privatekey != NULL)
		{
			qsc_memutils_secure_erase(privatekey, QSC_X25519_PRIVATEKEY_SIZE);
		}
	}
}

void qsc_x25519_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(seed != NULL);

	if (publickey != NULL && privatekey != NULL && seed != NULL)
	{
		if (privatekey != seed)
		{
			qsc_memutils_copy(privatekey, seed, QSC_X25519_PRIVATEKEY_SIZE);
		}

		qsc_x25519_public_from_private(publickey, privatekey);
	}
	else
	{
		if (publickey != NULL)
		{
			qsc_memutils_clear(publickey, QSC_X25519_PUBLICKEY_SIZE);
		}

		if (privatekey != NULL)
		{
			qsc_memutils_secure_erase(privatekey, QSC_X25519_PRIVATEKEY_SIZE);
		}
	}
}

bool qsc_x25519_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey)
{
	bool result;

	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);

	result = false;

	if (secret != NULL && privatekey != NULL && publickey != NULL)
	{
		result = (qsc_crypto_scalarmult_curve25519(secret, privatekey, publickey) == 0);
	}
	else if (secret != NULL)
	{
		qsc_memutils_clear(secret, QSC_X25519_SECRET_SIZE);
	}

	return result;
}

void qsc_x25519_public_from_private(uint8_t* publickey, const uint8_t* privatekey)
{
	(void)qsc_crypto_scalarmult_curve25519_ref10_base(publickey, privatekey);
}

/* \endcond DOXYGEN_NO_DOCUMENT */