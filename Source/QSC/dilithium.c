#include "dilithium.h"

#if defined(QSC_SYSTEM_HAS_AVX2)
#	include "dilithiumbase_avx2.h"
#else
#	include "dilithiumbase.h"
#endif

void qsc_dilithium_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);

#if defined(QSC_SYSTEM_HAS_AVX2)
	qsc_dilithium_avx2_generate_keypair(publickey, privatekey, rng_generate);
#else
	qsc_dilithium_ref_generate_keypair(publickey, privatekey, rng_generate);
#endif
}

void qsc_dilithium_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);

#if defined(QSC_SYSTEM_HAS_AVX2)
	qsc_dilithium_avx2_sign(signedmsg, smsglen, message, msglen, NULL, 0U, privatekey, rng_generate);
#else
	qsc_dilithium_ref_sign(signedmsg, smsglen, message, msglen, NULL, 0U, privatekey, rng_generate);
#endif
}

void qsc_dilithium_sign_ex(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t contextlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);

#if defined(QSC_SYSTEM_HAS_AVX2)
	qsc_dilithium_avx2_sign(signedmsg, smsglen, message, msglen, context, contextlen, privatekey, rng_generate);
#else
	qsc_dilithium_ref_sign(signedmsg, smsglen, message, msglen, context, contextlen, privatekey, rng_generate);
#endif
}

bool qsc_dilithium_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(msglen != NULL);
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

#if defined(QSC_SYSTEM_HAS_AVX2)
	res = qsc_dilithium_avx2_open(message, msglen, signedmsg, smsglen, NULL, 0U, publickey);
#else
	res = qsc_dilithium_ref_open(message, msglen, signedmsg, smsglen, NULL, 0U, publickey);
#endif

	return res;
}

bool qsc_dilithium_verify_ex(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* context, size_t contextlen, const uint8_t* publickey)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(msglen != NULL);
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

#if defined(QSC_SYSTEM_HAS_AVX2)
	res = qsc_dilithium_avx2_open(message, msglen, signedmsg, smsglen, context, contextlen, publickey);
#else
	res = qsc_dilithium_ref_open(message, msglen, signedmsg, smsglen, context, contextlen, publickey);
#endif

	return res;
}
