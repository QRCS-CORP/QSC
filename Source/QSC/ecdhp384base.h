#ifndef QSC_ECDHP384BASE_H
#define QSC_ECDHP384BASE_H

#include "qsccommon.h"

/**
 * \file ecdhp384base.h
 * \brief Elliptic Curve Diffie-Hellman over the NIST P-384 domain.
 *
 * \details
 * This header exposes the low-level public interface for the QSC P-384
 * Elliptic Curve Diffie-Hellman implementation. The functions in this module
 * provide private to public key derivation, random or seed-based key-pair
 * generation, and shared secret derivation using a peer public key and a
 * local private key.
 *
 * The public key is encoded as a fixed-size byte array of
 * QSC_ECDHP384_PUBLICKEY_SIZE bytes. The private key, shared secret, and
 * deterministic seed are each encoded as fixed-size byte arrays of their
 * respective constant sizes.
 *
 * This interface is intended for base ECDH key establishment operations.
 * Callers are responsible for providing correctly sized buffers and, where
 * applicable, a cryptographically secure random generator callback.
 *
 * Example:
 * \code
 * uint8_t puba[QSC_ECDHP384_PUBLICKEY_SIZE];
 * uint8_t pria[QSC_ECDHP384_PRIVATEKEY_SIZE];
 * uint8_t pubb[QSC_ECDHP384_PUBLICKEY_SIZE];
 * uint8_t prib[QSC_ECDHP384_PRIVATEKEY_SIZE];
 * uint8_t seca[QSC_ECDHP384_SHAREDSECRET_SIZE];
 * uint8_t secb[QSC_ECDHP384_SHAREDSECRET_SIZE];
 *
 * qsc_p384_generate_keypair(puba, pria, rng_generate);
 * qsc_p384_generate_keypair(pubb, prib, rng_generate);
 *
 * if (qsc_p384_key_exchange(seca, pubb, pria) == true &&
 *     qsc_p384_key_exchange(secb, puba, prib) == true)
 * {
 *     // seca and secb should contain the same shared secret
 * }
 * \endcode
 */

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \def QSC_ECDHP384_PUBLICKEY_SIZE
 * \brief The byte size of a serialized P-384 public key.
 */
#define QSC_ECDHP384_PUBLICKEY_SIZE 96U

/*!
 * \def QSC_ECDHP384_PRIVATEKEY_SIZE
 * \brief The byte size of a P-384 private key.
 */
#define QSC_ECDHP384_PRIVATEKEY_SIZE 48U

/*!
 * \def QSC_ECDHP384_SHAREDSECRET_SIZE
 * \brief The byte size of the derived P-384 shared secret.
 */
#define QSC_ECDHP384_SHAREDSECRET_SIZE 48U

/*!
 * \def QSC_ECDHP384_SEED_SIZE
 * \brief The byte size of the deterministic seed used to derive a P-384 key-pair.
 */
#define QSC_ECDHP384_SEED_SIZE 48U

/**
 * \brief Derive a serialized P-384 public key from a private key.
 *
 * \param publickey: [uint8_t*] The output buffer that receives the serialized public key;
 * must be at least QSC_ECDHP384_PUBLICKEY_SIZE bytes.
 * \param privatekey: [const uint8_t*] The input private key buffer;
 * must contain QSC_ECDHP384_PRIVATEKEY_SIZE bytes.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_p384_public_from_private(uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Generate a random P-384 public and private key-pair.
 *
 * \param publickey: [uint8_t*] The output buffer that receives the serialized public key;
 * must be at least QSC_ECDHP384_PUBLICKEY_SIZE bytes.
 * \param privatekey: [uint8_t*] The output buffer that receives the private key;
 * must be at least QSC_ECDHP384_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] A pointer to a cryptographically secure
 * random generator function that fills a buffer with random bytes and returns true on success.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_p384_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generate a deterministic P-384 public and private key-pair from a seed.
 *
 * \param publickey: [uint8_t*] The output buffer that receives the serialized public key;
 * must be at least QSC_ECDHP384_PUBLICKEY_SIZE bytes.
 * \param privatekey: [uint8_t*] The output buffer that receives the private key;
 * must be at least QSC_ECDHP384_PRIVATEKEY_SIZE bytes.
 * \param seed: [const uint8_t*] The input seed buffer;
 * must contain QSC_ECDHP384_SEED_SIZE bytes.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_p384_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Derive a P-384 shared secret using a peer public key and a local private key.
 *
 * \param secret: [uint8_t*] The output buffer that receives the shared secret;
 * must be at least QSC_ECDHP384_SHAREDSECRET_SIZE bytes.
 * \param publickey: [const uint8_t*] The peer serialized public key;
 * must contain QSC_ECDHP384_PUBLICKEY_SIZE bytes.
 * \param privatekey: [const uint8_t*] The local private key;
 * must contain QSC_ECDHP384_PRIVATEKEY_SIZE bytes.
 *
 * \return [bool] Returns true if the shared secret was generated successfully;
 * returns false on failure.
 */
QSC_EXPORT_API bool qsc_p384_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

QSC_CPLUSPLUS_ENABLED_END

#endif
