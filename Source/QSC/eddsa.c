#include "eddsa.h"
#if defined(QSC_EDDSA_S1EC25519)
#	include "eddsa25519base.h"
#elif defined(QSC_EDDSA_S3EC448)
#	include "eddsa448base.h"
#else
#   error "No EDDH parameter set defined. Define QSC_EDDH_S1EC25519 or QSC_EDDH_S3EC448."
#endif
#include "memutils.h"

void qsc_eddsa_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);

#if defined(QSC_EDDSA_S1EC25519)
	qsc_ed25519_generate_keypair(publickey, privatekey, rng_generate);
#else
	qsc_ed448_generate_keypair(publickey, privatekey, rng_generate);
#endif
}

void qsc_eddsa_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(seed != NULL);

#if defined(QSC_EDDSA_S1EC25519)
	qsc_ed25519_generate_seeded_keypair(publickey, privatekey, seed);
#else
	qsc_ed448_generate_seeded_keypair(publickey, privatekey, seed);
#endif
}

void qsc_eddsa_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);

#if defined(QSC_EDDSA_S1EC25519)
	qsc_ed25519_sign(signedmsg, smsglen, message, msglen, privatekey);
#else
	qsc_ed448_sign(signedmsg, smsglen, message, msglen, privatekey);
#endif
}

bool qsc_eddsa_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(msglen != NULL);
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

#if defined(QSC_EDDSA_S1EC25519)
	res = qsc_ed25519_verify(message, msglen, signedmsg, smsglen, publickey);
#else
	res = qsc_ed448_verify(message, msglen, signedmsg, smsglen, publickey);
#endif

	return res;
}
