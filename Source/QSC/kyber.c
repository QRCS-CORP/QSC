#include "kyber.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#if defined(QSC_SYSTEM_HAS_AVX2)
#	include "kyberbase_avx2.h"
#else
#	include "kyberbase.h"
#endif

static bool kyber_decapsulation_key_is_valid(const uint8_t* privatekey)
{
	uint8_t hash[QSC_KYBER_SYMBYTES] = { 0U };
	const uint8_t* publickey;
	const uint8_t* storedhash;
	bool res;

	res = false;

	if (privatekey != NULL)
	{
		publickey = privatekey + QSC_KYBER_INDCPA_SECRETKEY_BYTES;
		storedhash = privatekey + QSC_KYBER_SECRETKEY_BYTES - (2U * QSC_KYBER_SYMBYTES);
		qsc_sha3_compute256(hash, publickey, QSC_KYBER_PUBLICKEY_BYTES);
		res = (qsc_intutils_verify(hash, storedhash, QSC_KYBER_SYMBYTES) == 0);
		qsc_memutils_secure_erase(hash, sizeof(hash));
	}

	return res;
}

static bool kyber_encapsulation_key_is_valid(const uint8_t* publickey)
{
	size_t i;
	uint16_t c0;
	uint16_t c1;
	bool res;

	res = (publickey != NULL);

	if (res == true)
	{
		for (i = 0U; i < QSC_KYBER_PUBLICKEY_BYTES - QSC_KYBER_SYMBYTES; i += 3U)
		{
			c0 = (uint16_t)publickey[i] | ((uint16_t)(publickey[i + 1U] & 0x0FU) << 8U);
			c1 = ((uint16_t)publickey[i + 1U] >> 4U) | ((uint16_t)publickey[i + 2U] << 4U);

			if (c0 >= QSC_KYBER_Q || c1 >= QSC_KYBER_Q)
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

bool qsc_kyber_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(privatekey != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
		if (kyber_decapsulation_key_is_valid(privatekey) == true)
		{
#if defined(QSC_SYSTEM_HAS_AVX2)
			res = qsc_kyber_avx2_decapsulate(secret, ciphertext, privatekey);
#else
			res = qsc_kyber_ref_decapsulate(secret, ciphertext, privatekey);
#endif
		}
		else
		{
			qsc_memutils_secure_erase(secret, QSC_KYBER_SHAREDSECRET_SIZE);
		}
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
		if (kyber_encapsulation_key_is_valid(publickey) == true)
		{
#if defined(QSC_SYSTEM_HAS_AVX2)
			res = qsc_kyber_avx2_encapsulate(ciphertext, secret, publickey, rng_generate);
#else
			res = qsc_kyber_ref_encapsulate(ciphertext, secret, publickey, rng_generate);
#endif
		}
		else
		{
			qsc_memutils_secure_erase(secret, QSC_KYBER_SHAREDSECRET_SIZE);
			qsc_memutils_clear(ciphertext, QSC_KYBER_CIPHERTEXT_SIZE);
		}
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
