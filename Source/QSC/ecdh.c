#include "ecdh.h"
#include "memutils.h"
#if defined(QSC_ECDH_S1P256)
#	include "ecdhp256base.h"
#elif defined(QSC_ECDH_S3P384)
#	include "ecdhp384base.h"
#elif defined(QSC_ECDH_S5P521)
#	include "ecdhp521base.h"
#else
#   error "No ECDH parameter set defined. Define QSC_ECDH_S1P256, QSC_ECDH_S3P384, or QSC_ECDH_S5P521."
#endif

bool qsc_ecdh_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	bool res;

	res = false;

	if (privatekey != NULL && publickey != NULL && rng_generate != NULL)
	{
#if defined(QSC_ECDH_S1P256)
		qsc_p256_generate_keypair(publickey, privatekey, rng_generate);
#elif defined(QSC_ECDH_S3P384)
		qsc_p384_generate_keypair(publickey, privatekey, rng_generate);
#else
		qsc_p521_generate_keypair(publickey, privatekey, rng_generate);
#endif

		if (qsc_memutils_zeroed(publickey, QSC_ECDH_PUBLICKEY_SIZE) == false && 
			qsc_memutils_zeroed(privatekey, QSC_ECDH_PRIVATEKEY_SIZE) == false)
		{
			res = true;
		}
	}

	return res;
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
#if defined(QSC_ECDH_S1P256)
		qsc_p256_generate_seeded_keypair(publickey, privatekey, seed);
#elif defined(QSC_ECDH_S3P384)
		qsc_p384_generate_seeded_keypair(publickey, privatekey, seed);
#else
		qsc_p521_generate_seeded_keypair(publickey, privatekey, seed);
#endif

		if (qsc_memutils_zeroed(publickey, QSC_ECDH_PUBLICKEY_SIZE) == false && 
			qsc_memutils_zeroed(privatekey, QSC_ECDH_PRIVATEKEY_SIZE) == false)
		{
			res = true;
		}
	}

	return res;
}

bool qsc_ecdh_key_exchange(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

	res = false;

	if (secret != NULL && privatekey != NULL && publickey != NULL)
	{
#if defined(QSC_ECDH_S1P256)
		res = qsc_p256_key_exchange(secret, publickey, privatekey);
#elif defined(QSC_ECDH_S3P384)
		res = qsc_p384_key_exchange(secret, publickey, privatekey);
#else
		res = qsc_p521_key_exchange(secret, publickey, privatekey);
#endif
	}

	return res;
}

void qsc_ecdh_public_from_private(uint8_t* publickey, const uint8_t* privatekey)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);

	if (publickey != NULL && privatekey != NULL)
	{
#if defined(QSC_ECDH_S1P256)
		qsc_p256_public_from_private(publickey, privatekey);
#elif defined(QSC_ECDH_S3P384)
		qsc_p384_public_from_private(publickey, privatekey);
#else
		qsc_p521_public_from_private(publickey, privatekey);
#endif
	}
}
