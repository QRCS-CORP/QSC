/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: See ed448.h for full license text.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_ECDH448BASE_H
#define QSC_ECDH448BASE_H

#include "qsccommon.h"

/* \cond NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file eddhbase448.h
 * \brief Internal X448 key-exchange functions.
 *
 * \details
 * This file provides the low-level X448 Diffie-Hellman scalar multiplication
 * functions, mirroring the eddhbase.h interface but for the Ed448-Goldilocks
 * curve (RFC 7748 5).  These functions are called by the public ECDH wrapper
 * in eddh.c when the QSC_EDDH_S3EC448 parameter set is selected.
 */

/*!
 * \def QSC_X448_PUBLICKEY_SIZE
 * \brief X448 public key size in bytes (u-coordinate).
 */
#define QSC_X448_PUBLICKEY_SIZE 56U

/*!
 * \def QSC_X448_PRIVATEKEY_SIZE
 * \brief X448 private key size in bytes (clamped scalar).
 */
#define QSC_X448_PRIVATEKEY_SIZE 56U

/*!
 * \def QSC_X448_SECRET_SIZE
 * \brief X448 shared secret size in bytes.
 */
#define QSC_X448_SECRET_SIZE 56U

/**
 * \brief Multiply the X448 base point by a scalar (scalar * G).
 *
 * Performs the fixed-base scalar multiplication u = a * G on the
 * Montgomery curve Curve448, returning the u-coordinate as the
 * 56-byte public key.
 *
 * \param q: [uint8_t*] Output 56-byte u-coordinate.
 * \param n: [const uint8_t*] Input 56-byte clamped scalar.
 */
void qsc_crypto_scalarmult_curve448_ref10_base(uint8_t* q, const uint8_t* n);

/**
 * \brief Multiply an arbitrary X448 point by a scalar.
 *
 * Performs variable-base scalar multiplication u = n * q on
 * Curve448, returning the 56-byte u-coordinate.
 *
 * \param r: [uint8_t*] Output 56-byte u-coordinate.
 * \param n: [const uint8_t*] Input 56-byte clamped scalar.
 * \param q: [const uint8_t*] Input 56-byte u-coordinate of the base.
 */
void qsc_crypto_scalarmult_curve448_ref10(uint8_t* r, const uint8_t* n, const uint8_t* q);

/**
 * \brief Clamp a secret scalar for X448/Ed448.
 *
 * Clears the two low-order bits and sets the high bit of byte 55, per RFC 7748 / RFC 8032.
 *
 * \param k: [uint8_t*] Pointer to the 57-byte scalar to be clamped.
 */
void qsc_crypto_sc448_clamp(uint8_t* k);

/**
 * \brief Perform an X448 Diffie-Hellman scalar multiplication.
 *
 * Wrapper around qsc_crypto_scalarmult_curve448_ref10 that applies
 * RFC 7748 clamping before the multiplication.
 *
 * \param q: [uint8_t*] Output 56-byte shared secret.
 * \param n: [const uint8_t*] Input 56-byte private scalar (unclamped).
 * \param p: [const uint8_t*] Input 56-byte peer public key.
 */
void qsc_crypto_scalarmult_curve448(uint8_t* q, const uint8_t* n, const uint8_t* p);

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism using a random function pointer.
 *
 * \warning Arrays must be sized to QSC_EDDH_PUBLICKEY_SIZE and QSC_EDDH_SECRETKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param rng_generate: [bool (uint8_t*, size_t)] Pointer to the random generator function.
 */
void qsc_x448_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism using a seed.
 *
 * \warning Arrays must be sized to QSC_EDDH_PUBLICKEY_SIZE and QSC_EDDH_SECRETKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param seed: [const uint8_t*] Pointer to the random seed.
 */
void qsc_x448_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Perform an X448 key exchange.
 *
 * Computes the 56-byte shared secret from the local private key and
 * the remote public key.
 *
 * \param secret: [uint8_t*] Output 56-byte shared secret.
 * \param publickey: [const uint8_t*] Remote 56-byte public key.
 * \param privatekey: [const uint8_t*] Local 56-byte private key.
 * 
 * \return [bool] Returns true if the exchange succeeded; false if the peer public key is the all-zero point (invalid).
 */
bool qsc_x448_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

QSC_CPLUSPLUS_ENABLED_END

/* \endcond NO_DOCUMENT */

#endif
