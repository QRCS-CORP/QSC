#include "ecdh.h"
#include "ecdhbase.h"

bool qsc_ecdh_key_exchange(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey)
{
	bool res;

	res = qsc_ed25519_key_exchange(secret, publickey, privatekey);

	return res;
}

void qsc_ecdh_generate_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t))
{
	uint8_t seed[QSC_ECDH_SEED_SIZE] = { 0 };

	rng_generate(seed, sizeof(seed));
	qsc_ed25519_generate_keypair(publickey, privatekey, seed);
}

void qsc_ecdh_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* seed)
{
	qsc_ed25519_generate_keypair(publickey, privatekey, seed);
}

