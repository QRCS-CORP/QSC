#ifndef QSC_SPHINCSPLUSBASE_H
#define QSC_SPHINCSPLUSBASE_H

/* \cond DOXYGEN_IGNORE */

#include "common.h"

/* api.h */

/**
 * \brief Returns the length of a secret key, in bytes
 */
size_t sphincsplus_ref_sign_secretkeybytes(void);

/**
 * \brief Returns the length of a public key, in bytes
 */
size_t sphincsplus_ref_sign_publickeybytes(void);

/**
 * \brief Returns the length of a signature, in bytes
 */
size_t sphincsplus_ref_sign_bytes(void);

/**
 * \brief Returns the length of the seed required to generate a key pair, in bytes
 */
size_t sphincsplus_ref_sign_seedbytes(void);

/**
* \brief Generates a SphincsPlus public/private key-pair from a seed
*
* \param pk: The public verification key
* \param sk: The private signature key
* \param seed: A pointer to the seed array
*/
int32_t sphincsplus_ref_generate_seed_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed);

/**
* \brief Generates a SphincsPlus public/private key-pair
*
* \param pk: The public verification key
* \param sk: The private signature key
* \param rng_generate: A pointer to the random generator function
*/
void sphincsplus_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature
*
* \param sig: The signature
* \param siglen: The signature length
* \param m: The message to be signed
* \param mlen: The message length
* \param sk: The private signature key
* \param rng_generate: A pointer to the random generator function
*/
void sphincsplus_ref_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key
*
* \param sig: The signature array
* \param siglen: The length of the signature array
* \param m: The message array
* \param mlen: The length of the message array
* \param pk: The public verification key
* \return Returns true for success
*/
bool sphincsplus_ref_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \param sm: The signed message
* \param smlen: The signed message length
* \param m: The message to be signed
* \param mlen: The message length
* \param sk: The private signature key
* \param rng_generate: A pointer to the random generator function
*/
void sphincsplus_ref_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature with the public key
*
* \param m: The message to be signed
* \param mlen: The message length
* \param sm: The signed message
* \param smlen: The signed message length
* \param pk: The public verification key
* \return Returns true for success
*/
bool sphincsplus_ref_sign_open(uint8_t* m, size_t* mlen, const uint8_t* sm, size_t smlen, const uint8_t* pk);

/* \endcond DOXYGEN_IGNORE */

#endif
