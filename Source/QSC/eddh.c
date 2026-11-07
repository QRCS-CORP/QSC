#include "eddh.h"
#include "memutils.h"
#if defined(QSC_EDDH_S1EC25519)
#	include "eddh25519.h"
#elif defined(QSC_EDDH_S3EC448)
#	include "eddh448.h"
#else
#   error "No EDDH parameter set defined. Define QSC_EDDH_S1EC25519 or QSC_EDDH_S3EC448."
#endif

/* \cond DOXYGEN_NO_DOCUMENT */

bool qsc_eddh_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	bool res;

	res = false;

	if (privatekey != NULL && publickey != NULL && rng_generate != NULL)
	{
#if defined(QSC_EDDH_S1EC25519)
		qsc_x25519_generate_keypair(publickey, privatekey, rng_generate);
#else
		qsc_x448_generate_keypair(publickey, privatekey, rng_generate);
#endif

		if (qsc_memutils_zeroed(publickey, QSC_EDDH_PUBLICKEY_SIZE) == false && 
			qsc_memutils_zeroed(privatekey, QSC_EDDH_PRIVATEKEY_SIZE) == false)
		{
			res = true;
		}
	}

	return res;
}

bool qsc_eddh_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(seed != NULL);

	bool res;

	res = false;

	if (privatekey != NULL && publickey != NULL && seed != NULL)
	{
#if defined(QSC_EDDH_S1EC25519)
		qsc_x25519_generate_seeded_keypair(publickey, privatekey, seed);
#else
		qsc_x448_generate_seeded_keypair(publickey, privatekey, seed);
#endif

		if (qsc_memutils_zeroed(publickey, QSC_EDDH_PUBLICKEY_SIZE) == false &&
			qsc_memutils_zeroed(privatekey, QSC_EDDH_PRIVATEKEY_SIZE) == false)
		{
			res = true;
		}
	}

	return res;
}

bool qsc_eddh_key_exchange(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

	res = false;

	if (secret != NULL && privatekey != NULL && publickey != NULL)
	{
#if defined(QSC_EDDH_S1EC25519)
		res = qsc_x25519_key_exchange(secret, publickey, privatekey);
#else
		res = qsc_x448_key_exchange(secret, publickey, privatekey);
#endif

	}

	return res;
}

void qsc_eddh_public_from_private(uint8_t* publickey, const uint8_t* privatekey)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);

	if (publickey != NULL && privatekey != NULL)
	{
		/* Public derivation is parameter-specific; both modules clamp internally. */
#if defined(QSC_EDDH_S1EC25519)
		qsc_x25519_public_from_private(publickey, privatekey);
#else
		qsc_x448_public_from_private(publickey, privatekey);
#endif
	}
}

/* \endcond DOXYGEN_NO_DOCUMENT */
