#include "falcon.h"

#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_FALCON_S5SHAKE256F1024)
#	define QSC_FALCON_AVX2
#endif

#if defined(QSC_FALCON_AVX2)
#	include "falconbase_avx2.h"
#else
#	include "falconbase.h"
#endif

void qsc_falcon_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	assert(publickey != NULL);
	assert(privatekey != NULL);
	assert(rng_generate != NULL);

#if defined(QSC_FALCON_AVX2)
	qsc_falcon_avx2_generate_keypair(publickey, privatekey, rng_generate);
#else
	qsc_falcon_ref_generate_keypair(publickey, privatekey, rng_generate);
#endif
}

void qsc_falcon_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	assert(signedmsg != NULL);
	assert(smsglen != NULL);
	assert(message != NULL);
	assert(privatekey != NULL);
	assert(rng_generate != NULL);

#if defined(QSC_FALCON_AVX2)
	qsc_falcon_avx2_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate);
#else
	qsc_falcon_ref_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate);
#endif
}

bool qsc_falcon_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	assert(message != NULL);
	assert(msglen != NULL);
	assert(signedmsg != NULL);
	assert(publickey != NULL);

	bool res;

#if defined(QSC_FALCON_AVX2)
	res = qsc_falcon_avx2_open(message, msglen, signedmsg, smsglen, publickey);
#else
	res = qsc_falcon_ref_open(message, msglen, signedmsg, smsglen, publickey);
#endif

	return res;
}
