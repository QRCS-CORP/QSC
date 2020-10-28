#include "sphincsplus.h"
#include "sphincsplusbase.h"

void qsc_sphincsplus_generate_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t))
{
	assert(publickey != NULL);
	assert(privatekey != NULL);
	assert(rng_generate != NULL);

	sphincsplus_generate(publickey, privatekey, rng_generate);
}

void qsc_sphincsplus_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t))
{
	assert(signedmsg != NULL);
	assert(smsglen != NULL);
	assert(message != NULL);
	assert(privatekey != NULL);
	assert(rng_generate != NULL);

	sphincsplus_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate);
}

bool qsc_sphincsplus_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	assert(message != NULL);
	assert(msglen != NULL);
	assert(signedmsg != NULL);
	assert(publickey != NULL);

	bool res;

	res = sphincsplus_verify(message, msglen, signedmsg, smsglen, publickey);

	return res;
}