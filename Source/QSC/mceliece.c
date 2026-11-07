#include "mceliece.h"
#include "mceliecebase.h"

/* \cond DOXYGEN_NO_DOCUMENT */

/**
 * \brief Recovers a session key from a plaintext-confirmation ciphertext.
 * \param secret: Caller-owned output, QSC_MCELIECE_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false for invalid
 * arguments or rejected public padding where applicable.
 * \note Reentrant for disjoint buffers; all memory remains caller-owned.
 */
bool qsc_mceliece_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(privatekey != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
		res = qsc_mceliece_ref_decapsulate(secret, ciphertext, privatekey);
	}

	return res;
}

/**
 * \brief Encapsulates a plaintext-confirmation session key.
 * \param secret: Caller-owned output, QSC_MCELIECE_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Caller-owned output, QSC_MCELIECE_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Cryptographically secure RNG callback.
 * \return True on success; false for invalid inputs, RNG failure, or invalid padding.
 * \note Reentrant with separate buffers and thread-safe RNG state.
 */
bool qsc_mceliece_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && publickey != NULL && rng_generate != NULL)
	{
		res = qsc_mceliece_ref_encapsulate(ciphertext, secret, publickey, rng_generate);
	}

	return res;
}

/**
 * \brief Creates a compatibility-facade plaintext-confirmation keypair.
 * \param publickey: Caller-owned output, QSC_MCELIECE_PUBLICKEY_SIZE bytes.
 * \param privatekey: Caller-owned output, QSC_MCELIECE_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Cryptographically secure RNG callback.
 * \return True on successful key generation; false on invalid arguments or RNG failure.
 * \note Key generation requires a sufficiently large caller thread stack.
 *       Reentrant with independent buffers and thread-safe RNG state.
 */
bool qsc_mceliece_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);
	
	bool res;

	res = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		res = qsc_mceliece_ref_generate_keypair(publickey, privatekey, rng_generate);
	}

	return res;
}

/* \endcond DOXYGEN_NO_DOCUMENT */
