#include "ecdsa.h"
#include "ecdsabase.h"
#include "memutils.h"
#include "sha2.h"

void qsc_ecdsa_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	qsc_ed25519_keypair(publickey, privatekey, seed);
}

void qsc_ecdsa_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	uint8_t seed[QSC_ECDSA_SEED_SIZE] = { 0 };

	rng_generate(seed, sizeof(seed));
	qsc_ed25519_keypair(publickey, privatekey, seed);
	qsc_memutils_clear(seed, sizeof(seed));
}

void qsc_ecdsa_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	qsc_ed25519_sign(signedmsg, smsglen, message, msglen, privatekey);
}

bool qsc_ecdsa_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	int32_t ret;

	ret = qsc_ed25519_verify(message, msglen, signedmsg, smsglen, publickey);

	return (ret == 0);
}
