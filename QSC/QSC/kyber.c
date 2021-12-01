#include "kyber.h"
#include "secrand.h"

bool qsc_kyber_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	assert(secret != NULL);
	assert(ciphertext != NULL);
	assert(privatekey != NULL);

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

bool qsc_kyber_decrypt(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	assert(secret != NULL);
	assert(ciphertext != NULL);
	assert(privatekey != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
		res = qsc_kyber_decapsulate(secret, ciphertext, privatekey);
	}

	return res;
}

void qsc_kyber_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t))
{
	assert(secret != NULL);
	assert(ciphertext != NULL);
	assert(publickey != NULL);
	assert(rng_generate != NULL);

	if (secret != NULL && ciphertext != NULL && publickey != NULL && rng_generate != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		qsc_kyber_avx2_encapsulate(ciphertext, secret, publickey, rng_generate);
#else
		qsc_kyber_ref_encapsulate(ciphertext, secret, publickey, rng_generate);	
#endif
	}
}

void qsc_kyber_encrypt(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_KYBER_SEED_SIZE])
{
	assert(secret != NULL);
	assert(ciphertext != NULL);
	assert(publickey != NULL);
	assert(seed != NULL);

	if (secret != NULL && ciphertext != NULL && publickey != NULL && seed != NULL)
	{
		qsc_secrand_initialize(seed, QSC_KYBER_SEED_SIZE, NULL, 0);
		qsc_kyber_encapsulate(secret, ciphertext, publickey, &qsc_secrand_generate);
		qsc_secrand_destroy();
	}
}

void qsc_kyber_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	assert(publickey != NULL);
	assert(privatekey != NULL);
	assert(rng_generate != NULL);

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		qsc_kyber_avx2_generate_keypair(publickey, privatekey, rng_generate);
#else
		qsc_kyber_ref_generate_keypair(publickey, privatekey, rng_generate);
#endif
	}
}
