#if defined(QSC_MCELIECE_S5N6688T128)
#	undef QSC_MCELIECE_S5N6688T128
#endif
#if defined(QSC_MCELIECE_S6N6960T119)
#	undef QSC_MCELIECE_S6N6960T119
#endif
#if defined(QSC_MCELIECE_S7N8192T128)
#	undef QSC_MCELIECE_S7N8192T128
#endif
#define QSC_MCELIECE_S3N4608T96
#include "mceliece_multi.h"

#define qsc_mceliece_ref_decapsulate qsc_mceliece_460896pc_ref_decapsulate
#define qsc_mceliece_ref_encapsulate qsc_mceliece_460896pc_ref_encapsulate
#define qsc_mceliece_ref_generate_keypair qsc_mceliece_460896pc_ref_generate_keypair

#include "mceliecebase.c"

#undef qsc_mceliece_ref_decapsulate
#undef qsc_mceliece_ref_encapsulate
#undef qsc_mceliece_ref_generate_keypair

/* \cond DOXYGEN_NO_DOCUMENT */

/**
 * \brief Decapsulates 460896pc via its independently compiled core.
 * \param secret: Caller-owned 32-byte output.
 * \param ciphertext: Caller-owned 188-byte input.
 * \param privatekey: Caller-owned 13608-byte input.
 * \return True when processed; false for null inputs or rejected padding.
 * \note Reentrant with distinct buffers.
 */
bool qsc_mceliece_460896pc_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
		res = qsc_mceliece_460896pc_ref_decapsulate(secret, ciphertext, privatekey);
	}

	return res;
}

/**
 * \brief Encapsulates 460896pc using the provided RNG.
 * \param secret: Caller-owned 32-byte output.
 * \param ciphertext: Caller-owned 188-byte output.
 * \param publickey: Caller-owned 524160-byte input.
 * \param rng_generate: Secure RNG callback; must synchronize shared state.
 * \return True on success, otherwise false.
 * \note Reentrant for distinct buffers and RNG state.
 */
bool qsc_mceliece_460896pc_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && publickey != NULL && rng_generate != NULL)
	{
		res = qsc_mceliece_460896pc_ref_encapsulate(ciphertext, secret, publickey, rng_generate);
	}

	return res;
}

/**
 * \brief Generates a 460896pc key pair.
 * \param publickey: Caller-owned 524160-byte output.
 * \param privatekey: Caller-owned 13608-byte output.
 * \param rng_generate: Secure RNG callback; must synchronize shared state.
 * \return True on success, otherwise false.
 * \note Requires a large stack; reentrant with independent RNG and buffers.
 */
bool qsc_mceliece_460896pc_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		res = qsc_mceliece_460896pc_ref_generate_keypair(publickey, privatekey, rng_generate);
	}

	return res;
}

/* \endcond DOXYGEN_NO_DOCUMENT */
