#include "mceliece.h"
#include "mceliecebase.h"

bool qsc_mceliece_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	assert(secret != NULL);
	assert(ciphertext != NULL);
	assert(privatekey != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
		res = (qsc_mceliece_ref_decapsulate(secret, ciphertext, privatekey) == 0);
	}

	return res;
}

void qsc_mceliece_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, void (*rng_generate)(uint8_t*, size_t))
{
	assert(secret != NULL);
	assert(ciphertext != NULL);
	assert(publickey != NULL);

	if (secret != NULL && ciphertext != NULL && publickey != NULL)
	{
		qsc_mceliece_ref_encapsulate(ciphertext, secret, publickey, rng_generate);
	}
}

void qsc_mceliece_generate_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t))
{
	assert(publickey != NULL);
	assert(privatekey != NULL);
	assert(rng_generate != NULL);

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		qsc_mceliece_ref_generate_keypair(publickey, privatekey, rng_generate);
	}
}