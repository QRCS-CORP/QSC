#include "hqc.h"
#include "sha3.h"

bool qsc_hqc_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(privatekey != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		res = qsc_hqc_avx2_decapsulate(secret, ciphertext, privatekey);
#else
		res = qsc_hqc_ref_decapsulate(secret, ciphertext, privatekey);
#endif
	}

	return res;
}

bool qsc_hqc_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t))
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
		res = qsc_hqc_avx2_encapsulate(secret, ciphertext, publickey, rng_generate);
#else
		res = qsc_hqc_ref_encapsulate(secret, ciphertext, publickey, rng_generate);
#endif
	}

	return res;
}

void qsc_hqc_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_HQC_SEED_SIZE])
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(seed != NULL);

	if (secret != NULL && ciphertext != NULL && publickey != NULL && seed != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		qsc_hqc_avx2_seeded_encapsulate(secret, ciphertext, publickey, seed);
#else
		qsc_hqc_ref_seeded_encapsulate(secret, ciphertext, publickey, seed);
#endif
	}
}

bool qsc_hqc_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	bool res;

	res = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		res = qsc_hqc_avx2_generate_keypair(publickey, privatekey, rng_generate);
#else
		res = qsc_hqc_ref_generate_keypair(publickey, privatekey, rng_generate);
#endif
	}

	return res;
}

void qsc_hqc_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* seed)
{
#if defined(QSC_SYSTEM_HAS_AVX2)
	qsc_hqc_avx2_generate_seeded_keypair(publickey, privatekey, seed);
#else
	qsc_hqc_ref_generate_seeded_keypair(publickey, privatekey, seed);
#endif
}
