/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_ECDSA_H
#define QSC_ECDSA_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file ecdsa.h
 * \brief Contains the public API for the Elliptic Curve Digital Signature Algorithm
 * implementation over the NIST prime-field curves P-256, P-384, and P-521.
 *
 * \details
 * This header defines the external interface to the QSC ECDSA implementation. The
 * module supports one NIST prime-field parameter set selected at compile time. The
 * supported parameter sets are P-256, P-384, and P-521, corresponding to the widely
 * deployed secp256r1, secp384r1, and secp521r1 domain parameters. The active curve
 * selection determines all encoded key, scalar, coordinate, and signature lengths
 * through the QSC_ECDSA_*_SIZE constants defined in this header.
 *
 * The implementation exposes functions for key-pair generation, public-key derivation
 * from a private scalar, deterministic and randomized signing, signature verification,
 * public-key encoding and decoding, and DER conversion of ECDSA signatures. Public keys
 * are represented internally in raw affine form as the concatenation Qx || Qy, where
 * each coordinate is a fixed-width big-endian integer whose width is determined by the
 * active parameter set. Signatures are represented in raw form as r || s, where both
 * values are fixed-width big-endian integers of the active subgroup order size.
 *
 * The private-key container used by the high-level API is a serialized structure of the
 * form seed || Qx || Qy. The seed field contains the curve-sized private scalar input in
 * big-endian form. The public coordinates stored after the seed are the affine public key
 * corresponding to that scalar. This format allows the module to retain the private scalar
 * together with its associated public key in a compact fixed-size buffer. Functions that
 * derive a public key directly from a private scalar expect the scalar alone, encoded as a
 * curve-sized big-endian integer, rather than the full private-key container.
 *
 * The module supports conversion between the internal raw public-key format and SEC 1
 * uncompressed point encoding. In SEC 1 form, a public key is serialized as the uncompressed
 * point tag 0x04 followed by the fixed-width big-endian x and y affine coordinates. The
 * module also supports conversion between the internal raw public-key form and the X.509
 * SubjectPublicKeyInfo DER encoding for the selected curve. These conversion functions are
 * intended for interoperability with certificate processing, public-key exchange, and other
 * protocol layers that use standard ASN.1 encodings.
 *
 * Signature conversion functions are provided for the ECDSA ASN.1 DER representation. The
 * internal raw signature form is always fixed width and consists of the direct concatenation
 * of r and s. The DER representation instead encodes r and s as signed ASN.1 INTEGER values
 * wrapped in a SEQUENCE. Because DER INTEGER values may require a leading zero octet when the
 * most significant bit would otherwise indicate a negative value, the encoded DER signature
 * length is variable and depends on the specific signature values. The maximum DER size is
 * therefore parameter-set dependent and is defined by QSC_ECDSA_SIGNATURE_DER_MAX_SIZE.
 *
 * The implementation is intended for message authentication and public verification in systems
 * that require standardized NIST elliptic-curve signatures. Verification functions recover the
 * appended message from the signed-message format used by the QSC API, validate the signature,
 * and return the recovered message on success. Signing functions produce the fixed-size raw
 * signature followed by the original message, allowing the signed-message buffer to be processed
 * as a single serialized object.
 *
 * Deterministic signing support is included to enable reproducible signatures for known-answer
 * testing and standards alignment. In deterministic mode, the ephemeral nonce is derived from
 * the private scalar and message digest rather than obtained from an external random source.
 * This behavior is required for compatibility with official RFC 6979 test vectors for the
 * supported curves. Randomized signing is also supported through the standard high-level API
 * when the implementation is configured to use an approved random generator. The exact digest
 * and nonce-generation behavior is curve-dependent and must remain aligned with the active
 * parameter-set implementation.
 *
 * All externally visible byte arrays use big-endian encoding. All buffers passed to the API
 * must be correctly sized for the active curve selection. The caller is responsible for
 * supplying valid output buffers and, where required, a cryptographically secure random
 * generator. Private-key material should be treated as sensitive and cleared from memory by
 * the caller when no longer required. Public-key and signature validation is performed by the
 * relevant decode and verify functions, but callers must still ensure that buffer lengths and
 * calling conventions are consistent with the selected parameter set.
 *
 * This header declares only the public interface and associated size constants. Curve-specific
 * field arithmetic, scalar arithmetic, point operations, deterministic nonce generation, and
 * internal validation routines are implemented in the corresponding ECDSA base modules for the
 * selected parameter set.
 */

#if defined(QSC_ECDSA_S1P256)

	/*!
	 * \def QSC_ECDSA_SIGNATURE_SIZE
	 * \brief The byte size of the signature array (r[32] || s[32]).
	 */
#	define QSC_ECDSA_SIGNATURE_SIZE 64U

	/*!
	 * \def QSC_ECDSA_PRIVATEKEY_SIZE
	 * \brief The byte size of the private key array (seed[32] || Qx[32] || Qy[32]).
	 */
#	define QSC_ECDSA_PRIVATEKEY_SIZE 96U

	/*!
	 * \def QSC_ECDSA_PUBLICKEY_SIZE
	 * \brief The byte size of the public key array (Qx[32] || Qy[32], big-endian).
	 */
#	define QSC_ECDSA_PUBLICKEY_SIZE 64U

	/*!
	 * \def QSC_ECDSA_SEED_SIZE
	 * \brief The byte size of the random seed / private scalar input array.
	 */
#	define QSC_ECDSA_SEED_SIZE 32ULL

	/*!
	 * \def QSC_ECDSA_ALGNAME
	 * \brief The formal algorithm name.
	 */
#	define QSC_ECDSA_ALGNAME "ECDSA-P256"

	/*!
	 * \def QSC_ECDSA_SEC1_PUBLICKEY_SIZE
	 * \brief SEC 1 uncompressed EC point byte length for P-384.
	 */
#	define QSC_ECDSA_SEC1_PUBLICKEY_SIZE 65U

	/*!
	* \def QSC_ECDSA_SPKI_DER_SIZE
	* \brief SubjectPublicKeyInfo DER byte length for id-ecPublicKey + secp384r1.
	*/
#	define QSC_ECDSA_SPKI_DER_SIZE 91U

	/*!
	 * \def QSC_ECDSA_SIGNATURE_DER_MAX_SIZE
	 * \brief Maximum DER-encoded ECDSA signature size for P-384.
	 */
#	define QSC_ECDSA_SIGNATURE_DER_MAX_SIZE 72U

#elif defined(QSC_ECDSA_S3P384)

	/*!
	 * \def QSC_ECDSA_SIGNATURE_SIZE
	 * \brief The byte size of the signature array (r[48] || s[48]).
	 */
#	define QSC_ECDSA_SIGNATURE_SIZE 96U

	/*!
	 * \def QSC_ECDSA_PRIVATEKEY_SIZE
	 * \brief The byte size of the private key array (seed[48] || Qx[48] || Qy[48]).
	 */
#	define QSC_ECDSA_PRIVATEKEY_SIZE 144U

	/*!
	 * \def QSC_ECDSA_PUBLICKEY_SIZE
	 * \brief The byte size of the public key array (Qx[48] || Qy[48], big-endian).
	 */
#	define QSC_ECDSA_PUBLICKEY_SIZE 96U

	/*!
	 * \def QSC_ECDSA_SEED_SIZE
	 * \brief The byte size of the random seed / private scalar input array.
	 */
#	define QSC_ECDSA_SEED_SIZE 48ULL

	/*!
	 * \def QSC_ECDSA_ALGNAME
	 * \brief The formal algorithm name.
	 */
#	define QSC_ECDSA_ALGNAME "ECDSA-P384"

	/*!
	 * \def QSC_ECDSA_SEC1_PUBLICKEY_SIZE
	 * \brief SEC 1 uncompressed EC point byte length for P-384.
	 */
#	define QSC_ECDSA_SEC1_PUBLICKEY_SIZE 97U

	/*!
	 * \def QSC_ECDSA_SPKI_DER_SIZE
	 * \brief SubjectPublicKeyInfo DER byte length for id-ecPublicKey + secp384r1.
	 */
#	define QSC_ECDSA_SPKI_DER_SIZE 120U

	/*!
	 * \def QSC_ECDSA_SIGNATURE_DER_MAX_SIZE
	 * \brief Maximum DER-encoded ECDSA signature size for P-384.
	 */
#	define QSC_ECDSA_SIGNATURE_DER_MAX_SIZE 104U

#elif defined(QSC_ECDSA_S5P521)

	/*!
	 * \def QSC_ECDSA_SIGNATURE_SIZE
	 * \brief The byte size of the signature array (r[66] || s[66]).
	 */
#	define QSC_ECDSA_SIGNATURE_SIZE 132U

	/*!
	 * \def QSC_ECDSA_PRIVATEKEY_SIZE
	 * \brief The byte size of the private key array (seed[66] || Qx[66] || Qy[66]).
	 */
#	define QSC_ECDSA_PRIVATEKEY_SIZE 198U

	/*!
	 * \def QSC_ECDSA_PUBLICKEY_SIZE
	 * \brief The byte size of the public key array (Qx[66] || Qy[66], big-endian).
	 */
#	define QSC_ECDSA_PUBLICKEY_SIZE 132U

	/*!
	 * \def QSC_ECDSA_SEED_SIZE
	 * \brief The byte size of the random seed / private scalar input array.
	 */
#	define QSC_ECDSA_SEED_SIZE 66ULL

	/*!
	 * \def QSC_ECDSA_ALGNAME
	 * \brief The formal algorithm name.
	 */
#	define QSC_ECDSA_ALGNAME "ECDSA-P521"

	/*!
	 * \def QSC_ECDSA_SEC1_PUBLICKEY_SIZE
	 * \brief SEC 1 uncompressed EC point byte length for P-384.
	 */
#	define QSC_ECDSA_SEC1_PUBLICKEY_SIZE 133U

	/*!
	 * \def QSC_ECDSA_SPKI_DER_SIZE
	 * \brief SubjectPublicKeyInfo DER byte length for id-ecPublicKey + secp384r1.
	 */
#	define QSC_ECDSA_SPKI_DER_SIZE 158U

    /*!
     * \def QSC_ECDSA_SIGNATURE_DER_MAX_SIZE
     * \brief Maximum DER-encoded ECDSA signature size for P-384.
     */
#	define QSC_ECDSA_SIGNATURE_DER_MAX_SIZE 139U

#else
#	error "The ECDSA parameter set is invalid! Define QSC_ECDSA_S1EC256 or QSC_ECDSA_S3P384."
#endif

/**
 * \brief Convert a raw public key (Qx || Qy) to SEC 1 uncompressed point form.
 *
 * \param secpub: [uint8_t*] Output buffer of 65 bytes.
 * \param publickey: [const uint8_t*] Input raw public key of 64 bytes.
 */
QSC_EXPORT_API void qsc_ecdsa_publickey_to_sec1(uint8_t* secpub, const uint8_t* publickey);

/**
 * \brief Derive a P-256 public key from a raw private scalar.
 *
 * \details
 * This function derives the affine public point Q = dG from a 32-byte
 * big-endian private scalar and serializes the result as the raw public-key
 * form Qx || Qy.
 *
 * The private scalar must be in the range [1, n - 1], where n is the order
 * of the P-256 base point.
 *
 * \param publickey: [uint8_t*] Output buffer receiving the 64-byte public key.
 * \param privatekey: [const uint8_t*] Input 32-byte private scalar.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
QSC_EXPORT_API int32_t qsc_ecdsa_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Convert a SEC 1 uncompressed point to the library raw public-key form.
 *
 * \param publickey: [uint8_t*] Output raw public key of 64 bytes.
 * \param secpub: [const uint8_t*] Input SEC 1 public key of 65 bytes.
 * 
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_publickey_from_sec1(uint8_t* publickey, const uint8_t* secpub);

/**
 * \brief Generate a P-256 public/private key pair from a 32-byte seed.
 *
 * \details
 * Derives the private scalar d = SHA-256(seed) mod n, computes the public key
 * Q = d*G, and stores both.  This function is deterministic: the same seed
 * always produces the same key pair.
 *
 * \warning Arrays must be sized to QSC_ECDSA_PUBLICKEY_SIZE and QSC_ECDSA_PRIVATEKEY_SIZE respectively.
 *
 * \param publickey: [uint8_t*] Pointer to the output public verification-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private signature-key array.
 * \param seed: [const uint8_t*] Pointer to the random 32-byte seed array.
 * 
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Generate a P-256 public/private key pair using a caller-supplied RNG.
 *
 * \details
 * Fills a 32-byte seed from rng_generate, then calls
 * qsc_ecdsa_generate_seeded_keypair.  The seed is erased from stack
 * memory before returning.
 *
 * \warning Arrays must be sized to QSC_ECDSA_PUBLICKEY_SIZE and QSC_ECDSA_PRIVATEKEY_SIZE respectively.
 *
 * \param publickey: [uint8_t*] Pointer to the public verification-key array.
 * \param privatekey: [uint8_t*] Pointer to the private signature-key array.
 * \param rng_generate: [bool(*)(uint8_t*, size_t)] Pointer to the random generator function.
 * 
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Sign a message with a P-256 private key.
 *
 * \details
 * Computes a deterministic ECDSA signature (RFC 6979, HMAC-SHA256) over the
 * SHA-256 digest of the message, then writes the 64-byte signature followed by
 * the message into signedmsg. On success *smsglen = msglen + 64.
 *
 * \warning signedmsg must be at least msglen + QSC_ECDSA_SIGNATURE_SIZE bytes.
 *
 * \param signedmsg: [uint8_t*] Pointer to the signed-message output array.
 * \param smsglen: [size_t*] Pointer to the signed-message length output.
 * \param message: [const uint8_t*] Pointer to the message to sign.
 * \param msglen: [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] Pointer to the 96-byte private key array.
 * 
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Sign a message with a P-256 private key, used primarily for RFC KAT testing).
 *
 * \details
 * Computes a deterministic ECDSA signature using the private key scalar d, 
 * (RFC KATs) then writes the 64-byte signature followed by
 * the message into signedmsg. On success *smsglen = msglen + 64.
 *
 * \warning signedmsg must be at least msglen + QSC_ECDSA_SIGNATURE_SIZE bytes.
 *
 * \param signedmsg: [uint8_t*] Pointer to the signed-message output array.
 * \param smsglen: [size_t*] Pointer to the signed-message length output.
 * \param message: [const uint8_t*] Pointer to the message to sign.
 * \param msglen: [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] Pointer to the 96-byte private key array.
 * 
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Verify a P-256 ECDSA signature and recover the message.
 *
 * \details
 * Parses the 64-byte signature prepended to signedmsg, validates r and s are
 * in [1, n-1], verifies that the public key lies on the curve, and checks the
 * ECDSA equation.  On success the message bytes are copied into message and
 * *msglen is set.  On failure message is zeroed and *msglen is set to 0.
 *
 * \param message: [uint8_t*] Pointer to the recovered message output array.
 * \param msglen: [size_t*] Pointer to the recovered message length.
 * \param signedmsg: [const uint8_t*] Pointer to the signed-message input array.
 * \param smsglen: [size_t] Total signed-message length (signature + message).
 * \param publickey: [const uint8_t*] Pointer to the 64-byte public verification-key array.
 * 
 * \return [bool] Returns true if the signature is valid, false otherwise.
 */
QSC_EXPORT_API bool qsc_ecdsa_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
