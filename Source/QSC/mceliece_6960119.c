/*
 * Compile-time instantiation of the shared Classic McEliece implementation.
 * Only the literal parameter selector and exported names differ.
 */
#if defined(QSC_MCELIECE_S3N4608T96)
#	undef QSC_MCELIECE_S3N4608T96
#endif
#if defined(QSC_MCELIECE_S5N6688T128)
#	undef QSC_MCELIECE_S5N6688T128
#endif
#if defined(QSC_MCELIECE_S7N8192T128)
#	undef QSC_MCELIECE_S7N8192T128
#endif
#define QSC_MCELIECE_S6N6960T119
#include "mceliece_multi.h"

#define qsc_mceliece_ref_decapsulate qsc_mceliece_6960119_ref_decapsulate
#define qsc_mceliece_ref_encapsulate qsc_mceliece_6960119_ref_encapsulate
#define qsc_mceliece_ref_generate_keypair qsc_mceliece_6960119_ref_generate_keypair

/**
 * \def QSC_MCELIECE_NO_PLAINTEXT_CONFIRMATION
 * \brief Selects the ordinary ISO ciphertext and session-key derivation.
 * \note Defined only while instantiating this translation unit.
 */
#define QSC_MCELIECE_NO_PLAINTEXT_CONFIRMATION
#include "mceliecebase.c"
#undef QSC_MCELIECE_NO_PLAINTEXT_CONFIRMATION

#undef qsc_mceliece_ref_decapsulate
#undef qsc_mceliece_ref_encapsulate
#undef qsc_mceliece_ref_generate_keypair

/* \cond DOXYGEN_NO_DOCUMENT */

/**
 * \brief Decapsulates 6960119 via its independently compiled core.
 * \param secret: Caller-owned 32-byte output.
 * \param ciphertext: Caller-owned 194-byte input.
 * \param privatekey: Caller-owned 13948-byte input.
 * \return True when processed; false for null inputs or rejected padding.
 * \note Reentrant with distinct buffers.
 */
bool qsc_mceliece_6960119_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
		res = qsc_mceliece_6960119_ref_decapsulate(secret, ciphertext, privatekey);
	}

	return res;
}

/**
 * \brief Encapsulates 6960119 using the provided RNG.
 * \param secret: Caller-owned 32-byte output.
 * \param ciphertext: Caller-owned 194-byte output.
 * \param publickey: Caller-owned 1047319-byte input.
 * \param rng_generate: Secure RNG callback; must synchronize shared state.
 * \return True on success, otherwise false.
 * \note Reentrant for distinct buffers and RNG state.
 */
bool qsc_mceliece_6960119_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && publickey != NULL && rng_generate != NULL)
	{
		res = qsc_mceliece_6960119_ref_encapsulate(ciphertext, secret, publickey, rng_generate);
	}

	return res;
}

/**
 * \brief Generates a 6960119 key pair.
 * \param publickey: Caller-owned 1047319-byte output.
 * \param privatekey: Caller-owned 13948-byte output.
 * \param rng_generate: Secure RNG callback; must synchronize shared state.
 * \return True on success, otherwise false.
 * \note Requires a large stack; reentrant with independent RNG and buffers.
 */
bool qsc_mceliece_6960119_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		res = qsc_mceliece_6960119_ref_generate_keypair(publickey, privatekey, rng_generate);
	}

	return res;
}

/* \cond DOXYGEN_NO_DOCUMENT */
