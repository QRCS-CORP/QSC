#include "kyber.h"
#include "sha3.h"
#if defined(QSC_SYSTEM_HAS_AVX2)
#	include "kyberbase_avx2.h"
#else
#	include "kyberbase.h"
#endif

bool qsc_kyber_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(privatekey != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		res = qsc_kyber_avx2_decapsulate(secret, ciphertext, privatekey);
#else
		res = qsc_kyber_ref_decapsulate(secret, ciphertext, privatekey);
#endif
	}

	return res;
}

bool qsc_kyber_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	bool res;
	
	res = false;

	if (secret != NULL && ciphertext != NULL && publickey != NULL && rng_generate != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		res = qsc_kyber_avx2_encapsulate(ciphertext, secret, publickey, rng_generate);
#else
		res = qsc_kyber_ref_encapsulate(ciphertext, secret, publickey, rng_generate);
#endif
	}

	return res;
}

void qsc_kyber_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t* m)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(m != NULL);

	if (secret != NULL && ciphertext != NULL && publickey != NULL && m != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		qsc_kyber_avx2_seeded_encapsulate(ciphertext, secret, publickey, m);
#else
		qsc_kyber_ref_seeded_encapsulate(ciphertext, secret, publickey, m);
#endif
	}
}

bool qsc_kyber_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);
	
	bool res;

	res = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		res = qsc_kyber_avx2_generate_keypair(publickey, privatekey, rng_generate);
#else
		res = qsc_kyber_ref_generate_keypair(publickey, privatekey, rng_generate);
#endif
	}
	
	return res;
}

void qsc_kyber_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* d, uint8_t* z)
{
#if defined(QSC_SYSTEM_HAS_AVX2)
	qsc_kyber_avx2_generate_seeded_keypair(publickey, privatekey, d, z);
#else
	qsc_kyber_ref_generate_seeded_keypair(publickey, privatekey, d, z);
#endif
}
