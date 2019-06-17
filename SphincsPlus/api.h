#ifndef SPX_API_H
#define SPX_API_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#ifndef SPHINCSPLUS_MODE
#	define SPHINCSPLUS_MODE 3
#endif

#define SPHINCSPLUS_ALGNAME "SPHINCS+"
#define SPHINCSPLUS_SECRETKEY_SIZE SPX_SK_BYTES
#define SPHINCSPLUS_PUBLICKEY_SIZE SPX_PK_BYTES
#define SPHINCSPLUS_SIGNATURE_SIZE SPX_BYTES
#define RNG_SEED_SIZE 3 * SPX_N

/*
 * Returns the length of a secret key, in bytes
 */
size_t crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
size_t crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
size_t crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
size_t crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int32_t crypto_sign_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int32_t sphincsplus_generate(uint8_t *pk, uint8_t *sk);

/**
 * Returns an array containing a detached signature.
 */
int32_t crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int32_t crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
int32_t sphincsplus_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int32_t sphincsplus_verify(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif
