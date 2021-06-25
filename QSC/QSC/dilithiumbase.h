#ifndef QSC_DILITHIUMBASE_2_H
#define QSC_DILITHIUMBASE_2_H

#include "common.h"

//#define QSC_DILITHIUM_RANDOMIZED_SIGNING

#if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#   define QSC_DILITHIUM_MODE 2
#elif defined(QSC_DILITHIUM_S3N256Q8380417K6) 
#   define QSC_DILITHIUM_MODE 3
#elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#   define QSC_DILITHIUM_MODE 5
#else
#error The dilithium mode is not sdupported!
#endif

#define QSC_DILITHIUM_N 256

#if (QSC_DILITHIUM_MODE == 2)
#   define QSC_DILITHIUM_K 4
#   define QSC_DILITHIUM_L 4
#elif (QSC_DILITHIUM_MODE == 3)
#   define QSC_DILITHIUM_K 6
#   define QSC_DILITHIUM_L 5
#elif (QSC_DILITHIUM_MODE == 5)
#   define QSC_DILITHIUM_K 8
#   define QSC_DILITHIUM_L 7
#endif

/* Array of coefficients of length N */
typedef struct
{
    int32_t coeffs[QSC_DILITHIUM_N];
} qsc_dilithium_poly;

/* Vectors of polynomials of length L */
typedef struct
{
    qsc_dilithium_poly vec[QSC_DILITHIUM_L];
} qsc_dilithium_polyvecl;

/* Vectors of polynomials of length K */
typedef struct
{
    qsc_dilithium_poly vec[QSC_DILITHIUM_K];
} qsc_dilithium_polyveck;

/**
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to DILITHIUM_PUBLICKEY_SIZE and DILITHIUM_SECRETKEY_SIZE.
*
* \param publickey: The public verification key
* \param secretkey: The private signature key
* \param rng_generate: The random generator
*/
void qsc_dilithium_ref_generate_keypair(uint8_t *pk, uint8_t *sk, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature
*
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param message: The message to be signed
* \param msglen: The message length
* \param privatekey: The private signature key
* \param rng_generate: The random generator
*/
void qsc_dilithium_ref_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message
*
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param message: The message to be signed
* \param msglen: The message length
* \param privatekey: The private signature key
* \param rng_generate: The random generator
*/
void qsc_dilithium_ref_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: The message to be signed
* \param msglen: The message length
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param publickey: The public verification key
* \return Returns true for success
*/
bool qsc_dilithium_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: The message to be signed
* \param msglen: The message length
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param publickey: The public verification key
* \return Returns true for success
*/
bool qsc_dilithium_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif