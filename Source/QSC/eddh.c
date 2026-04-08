#include "eddh.h"
#if defined(QSC_EDDH_S1EC25519)
#	include "eddh25519base.h"
#elif defined(QSC_EDDH_S3EC448)
#	include "eddh448base.h"
#else
#   error "No EDDH parameter set defined. Define QSC_EDDH_S1EC25519 or QSC_EDDH_S3EC448."
#endif
#include "memutils.h"

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
		/* Derive public key from private key using X25519 basepoint mult.
		   This call clamps internally (it copies sk to a temp, clamps temp). */
#if defined(QSC_EDDH_S1EC25519)
		(void)qsc_crypto_scalarmult_curve25519_ref10_base(publickey, privatekey);
#else
		uint8_t ktmp[QSC_EDDH_PRIVATEKEY_SIZE] = { 0U };

		qsc_memutils_copy(ktmp, privatekey, QSC_EDDH_PRIVATEKEY_SIZE);
		qsc_crypto_sc448_clamp(ktmp);
		qsc_crypto_scalarmult_curve448_ref10_base(publickey, ktmp);
		qsc_memutils_clear(ktmp, sizeof(ktmp));
#endif
	}
}
