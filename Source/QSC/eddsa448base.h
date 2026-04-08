/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: See ed448.h for full license text.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_EDDSA448BASE_H
#define QSC_EDDSA448BASE_H

#include "qsccommon.h"

/* \cond NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file eddsabase448.h
 * \brief Internal Ed448 signature functions.
 *
 * \details
 * This file provides the low-level Ed448 (RFC 8032 5.2) key generation,
 * signing, and verification primitives called by the public EdDSA wrapper
 * in eddsa.c when the QSC_EDDSA_S3EC448 parameter set is active.
 *
 * Hash function: SHAKE256 with a 114-byte digest (RFC 8032 5.2.6).
 * The dom4(0, "") prefix is included in all hash computations per the RFC.
 *
 * Sizes:
 *   seed (private)    : 57 bytes
 *   public key        : 57 bytes
 *   private key store : 114 bytes (seed || public key)
 *   signature         : 114 bytes (R || S)
 */

/*!
 * \def QSC_ED448_SEED_SIZE
 * \brief Ed448 seed size in bytes.
 */
#define QSC_ED448_SEED_SIZE 57U

/*!
 * \def QSC_ED448_PUBLICKEY_SIZE
 * \brief Ed448 public key size in bytes.
 */
#define QSC_ED448_PUBLICKEY_SIZE 57U

/*!
 * \def QSC_ED448_PRIVATEKEY_SIZE
 * \brief Ed448 private key size in bytes (seed || public key).
 */
#define QSC_ED448_PRIVATEKEY_SIZE 114U

/*!
 * \def QSC_ED448_SIGNATURE_SIZE
 * \brief Ed448 signature size in bytes (R || S, each 57 bytes).
 */
#define QSC_ED448_SIGNATURE_SIZE 114U

/**
 * \brief Generates public and private keys for the ECDSA key encapsulation mechanism using a random function pointer.
 *
 * \warning Arrays must be sized to QSC_EDDH_PUBLICKEY_SIZE and QSC_EDDH_SECRETKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param rng_generate: [bool (uint8_t*, size_t)] Pointer to the random generator function.
 */
void qsc_ed448_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Combine an external public key with an internal private key to produce a shared secret using a seed.
 *
 * \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param seed: [const uint8_t*] Pointer to the random seed.
 */
void qsc_ed448_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Takes the message as input and returns an array containing the signature followed by the message.
 *
 * \param signedmsg: [uint8_t*] Pointer to the signed message.
 * \param smsglen: [size_t*] Pointer to the signed message length.
 * \param message: [const uint8_t*] Pointer to the message to be signed.
 * \param msglen: [size_t] The message length.
 * \param privatekey: [const uint8_t*] Pointer to the private signature key.
 * \return [int32_t] Returns 0 for success.
 */
bool qsc_ed448_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Verifies a signature-message pair with the public key.
 *
 * \param message: [uint8_t*] Pointer to the message to be verified.
 * \param msglen: [size_t*] Pointer to the message length.
 * \param signedmsg: [const uint8_t*] Pointer to the signed message.
 * \param smsglen: [size_t] The signed message length.
 * \param publickey: [const uint8_t*] Pointer to the public verification key.
 * \return [int32_t]Returns 0 for success.
 */
bool qsc_ed448_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

/* \endcond NO_DOCUMENT */

#endif
