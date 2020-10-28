#include "kyber.h"
#include "kyberbase.h"

bool qsc_kyber_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	assert(secret != NULL);
	assert(ciphertext != NULL);
	assert(privatekey != NULL);

	bool res;

	res = qsc_kyber_crypto_kem_dec(secret, ciphertext, privatekey);

	return res;
}

void qsc_kyber_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, void (*rng_generate)(uint8_t*, size_t))
{
	assert(secret != NULL);
	assert(ciphertext != NULL);
	assert(publickey != NULL);
	assert(rng_generate != NULL);

	qsc_kyber_crypto_kem_enc(ciphertext, secret, publickey, rng_generate);
}

void qsc_kyber_generate_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t))
{
	assert(publickey != NULL);
	assert(privatekey != NULL);
	assert(rng_generate != NULL);

	qsc_kyber_crypto_kem_keypair(publickey, privatekey, rng_generate);
}