#include "falcon.h"
#include "falcon512.h"
#include "falcon1024.h"

#if defined(QSC_SYSTEM_HAS_AVX2)
#include "falconbase_avx2.h"

/* \cond DOXYGEN_NO_DOCUMENT */

/**
* \brief Scalar key generation ensures Round 3 deterministic KAT reproducibility.
* \param pk Destination public key of the selected parameter set.
* \param sk Destination secret key of the selected parameter set.
* \param rng_generate Non-NULL random generator.
* \return Zero on success; nonzero on failure.
* \note Both scalar and AVX2 backends are linked. Does not retain pointers.
*/
extern int32_t qsc_falcon_ref_512_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));
extern int32_t qsc_falcon_ref_1024_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

#else
#include "falconbase.h"
#endif

/**
* \brief Validate caller-provided signed-message capacity bound.
* \param msglen Input message size.
* \param overhead Maximum signature overhead.
* \return True if the size_t total cannot overflow.
* \note No global state; safe for concurrent calls.
*/
static bool falcon_valid_msgsize(size_t msglen, size_t overhead)
{
	return (msglen <= (SIZE_MAX - overhead));
}

bool qsc_falcon512_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	if (publickey == NULL || privatekey == NULL || rng_generate == NULL)
	{
		return false;
	}
#if defined(QSC_SYSTEM_HAS_AVX2)
	return (qsc_falcon_ref_512_generate_keypair(publickey, privatekey, rng_generate) == 0);
#else
	return (qsc_falcon_ref_512_generate_keypair(publickey, privatekey, rng_generate) == 0);
#endif
}

bool qsc_falcon512_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	if (smsglen != NULL)
	{
		*smsglen = 0U;
	}
	if (signedmsg == NULL || smsglen == NULL || message == NULL || privatekey == NULL || rng_generate == NULL || !falcon_valid_msgsize(msglen, 666U))
	{
		return false;
	}
#if defined(QSC_SYSTEM_HAS_AVX2)
	return (qsc_falcon_avx2_512_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate, 666U) == 0);
#else
	return (qsc_falcon_ref_512_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate, 666U) == 0);
#endif
}

bool qsc_falcon512_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	if (msglen != NULL)
	{
		*msglen = 0U;
	}
	if (message == NULL || msglen == NULL || signedmsg == NULL || publickey == NULL)
	{
		return false;
	}
#if defined(QSC_SYSTEM_HAS_AVX2)
	return qsc_falcon_avx2_512_open(message, msglen, signedmsg, smsglen, publickey);
#else
	return qsc_falcon_ref_512_open(message, msglen, signedmsg, smsglen, publickey);
#endif
}

bool qsc_falcon1024_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	if (publickey == NULL || privatekey == NULL || rng_generate == NULL)
	{
		return false;
	}
#if defined(QSC_SYSTEM_HAS_AVX2)
	return (qsc_falcon_ref_1024_generate_keypair(publickey, privatekey, rng_generate) == 0);
#else
	return (qsc_falcon_ref_1024_generate_keypair(publickey, privatekey, rng_generate) == 0);
#endif
}

bool qsc_falcon1024_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	if (smsglen != NULL)
	{
		*smsglen = 0U;
	}
	if (signedmsg == NULL || smsglen == NULL || message == NULL || privatekey == NULL || rng_generate == NULL || !falcon_valid_msgsize(msglen, 1280U))
	{
		return false;
	}
#if defined(QSC_SYSTEM_HAS_AVX2)
	return (qsc_falcon_avx2_1024_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate, 1280U) == 0);
#else
	return (qsc_falcon_ref_1024_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate, 1280U) == 0);
#endif
}

bool qsc_falcon1024_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	if (msglen != NULL)
	{
		*msglen = 0U;
	}
	if (message == NULL || msglen == NULL || signedmsg == NULL || publickey == NULL)
	{
		return false;
	}
#if defined(QSC_SYSTEM_HAS_AVX2)
	return qsc_falcon_avx2_1024_open(message, msglen, signedmsg, smsglen, publickey);
#else
	return qsc_falcon_ref_1024_open(message, msglen, signedmsg, smsglen, publickey);
#endif
}

bool qsc_falcon_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
#if defined(QSC_FALCON_S5SHAKE256F1024) && !defined(QSC_FALCON_S3SHAKE256F512)
	return qsc_falcon1024_generate_keypair(publickey, privatekey, rng_generate);
#else
	return qsc_falcon512_generate_keypair(publickey, privatekey, rng_generate);
#endif
}

bool qsc_falcon_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	if (smsglen != NULL)
	{
		*smsglen = 0U;
	}
#if defined(QSC_FALCON_S5SHAKE256F1024) && !defined(QSC_FALCON_S3SHAKE256F512)
	if (signedmsg == NULL || smsglen == NULL || message == NULL || privatekey == NULL || rng_generate == NULL || !falcon_valid_msgsize(msglen, 1276U))
	{
		return false;
	}
#if defined(QSC_SYSTEM_HAS_AVX2)
	return (qsc_falcon_avx2_1024_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate, 1276U) == 0);
#else
	return (qsc_falcon_ref_1024_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate, 1276U) == 0);
#endif
#else
	if (signedmsg == NULL || smsglen == NULL || message == NULL || privatekey == NULL || rng_generate == NULL || !falcon_valid_msgsize(msglen, 658U))
	{
		return false;
	}
#if defined(QSC_SYSTEM_HAS_AVX2)
	return (qsc_falcon_avx2_512_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate, 658U) == 0);
#else
	return (qsc_falcon_ref_512_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate, 658U) == 0);
#endif
#endif
}

bool qsc_falcon_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
#if defined(QSC_FALCON_S5SHAKE256F1024) && !defined(QSC_FALCON_S3SHAKE256F512)
	return qsc_falcon1024_verify(message, msglen, signedmsg, smsglen, publickey);
#else
	return qsc_falcon512_verify(message, msglen, signedmsg, smsglen, publickey);
#endif
}

/* \endcond DOXYGEN_NO_DOCUMENT */
