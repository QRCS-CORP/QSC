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

#ifndef QSC_X509_KEY_H
#define QSC_X509_KEY_H

#include "qsccommon.h"
#include "x509types.h"

/*!
 * \file x509key.h
 * \brief X.509 private key decoding, size validation, and certificate-key matching interface.
 *
 * \details
 * This header defines constants and helper functions used to decode private-key
 * objects represented in SEC 1 and PKCS #8 form, including PEM and DER input
 * variants. The interface stores the decoded private key together with its
 * algorithm identifier and an optional embedded public key, allowing the
 * implementation to support both classical and post-quantum key formats.
 *
 * The public interface also provides algorithm-dependent size expectation
 * helpers for strict validation of private and public key lengths, together
 * with a certificate-to-private-key matching helper used to confirm that a
 * certificate SubjectPublicKeyInfo corresponds to a supplied private key object.
 */


/*!
 * \def QSC_X509_EDDSA_SEED_SIZE
 * \brief The EDDSA seed size in bytes.
 */
#define QSC_X509_EDDSA_SEED_SIZE 32U

/*!
 * \def QSC_X509_EDDSA_PUBLIC_KEY_SIZE
 * \brief The EDDSA oublic key size in bytes.
 */
#define QSC_X509_EDDSA_PUBLIC_KEY_SIZE 32U

/*!
 * \def QSC_X509_ML_DSA_44_PRIVATEKEY_SIZE
 * \brief The ML-DSA-44 private key size in bytes.
 */
#define QSC_X509_ML_DSA_44_PRIVATEKEY_SIZE 2560U

/*!
 * \def QSC_X509_ML_DSA_65_PRIVATEKEY_SIZE
 * \brief The ML-DSA-65 private key size in bytes.
 */
#define QSC_X509_ML_DSA_65_PRIVATEKEY_SIZE 4032U

/*!
 * \def QSC_X509_ML_DSA_87_PRIVATEKEY_SIZE
 * \brief The ML-DSA-87 private key size in bytes.
 */
#define QSC_X509_ML_DSA_87_PRIVATEKEY_SIZE 4896U

/*!
 * \def QSC_X509_ML_KEM_512_PRIVATEKEY_SIZE
 * \brief The ML-KEM-512 private key size in bytes.
 */
#define QSC_X509_ML_KEM_512_PRIVATEKEY_SIZE 1632U

/*!
 * \def QSC_X509_ML_KEM_768_PRIVATEKEY_SIZE
 * \brief The ML-KEM-768 private key size in bytes.
 */
#define QSC_X509_ML_KEM_768_PRIVATEKEY_SIZE 2400U

/*!
 * \def QSC_X509_ML_KEM_1024_PRIVATEKEY_SIZE
 * \brief The ML-KEM-1024 private key size in bytes.
 */
#define QSC_X509_ML_KEM_1024_PRIVATEKEY_SIZE 3168U

#ifndef QSC_X509_ML_DSA_44_PUBLICKEY_SIZE
/*!
 * \def QSC_X509_ML_DSA_44_PUBLICKEY_SIZE
 * \brief The ML-DSA-44 public key size in bytes.
 */
#define QSC_X509_ML_DSA_44_PUBLICKEY_SIZE 1312U
#endif

#ifndef QSC_X509_ML_DSA_65_PUBLICKEY_SIZE
/*!
 * \def QSC_X509_ML_DSA_65_PUBLICKEY_SIZE
 * \brief The ML-DSA-65 public key size in bytes.
 */
#define QSC_X509_ML_DSA_65_PUBLICKEY_SIZE 1952U
#endif

#ifndef QSC_X509_ML_DSA_87_PUBLICKEY_SIZE
/*!
 * \def QSC_X509_ML_DSA_87_PUBLICKEY_SIZE
 * \brief The ML-DSA-87 public key size in bytes.
 */
#define QSC_X509_ML_DSA_87_PUBLICKEY_SIZE 2592U
#endif

#ifndef QSC_X509_ML_KEM_512_PUBLICKEY_SIZE
/*!
 * \def QSC_X509_ML_KEM_512_PUBLICKEY_SIZE
 * \brief The ML-KEM-512 public key size in bytes.
 */
#define QSC_X509_ML_KEM_512_PUBLICKEY_SIZE 800U
#endif

#ifndef QSC_X509_ML_KEM_768_PUBLICKEY_SIZE
/*!
 * \def QSC_X509_ML_KEM_768_PUBLICKEY_SIZE
 * \brief The ML-KEM-768 public key size in bytes.
 */
#define QSC_X509_ML_KEM_768_PUBLICKEY_SIZE 1184U
#endif

#ifndef QSC_X509_ML_KEM_1024_PUBLICKEY_SIZE
/*!
 * \def QSC_X509_ML_KEM_1024_PUBLICKEY_SIZE
 * \brief The ML-KEM-1024 public key size in bytes.
 */
#define QSC_X509_ML_KEM_1024_PUBLICKEY_SIZE 1568U
#endif

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \def QSC_X509_PRIVATE_KEY_MAX
 * \brief The maximum supported decoded private key length in bytes.
 *
 * \details
 * This value is set to the largest currently supported private key object size
 * so that the generic private-key container can hold any supported key type.
 */
#define QSC_X509_PRIVATE_KEY_MAX QSC_X509_ML_DSA_87_PRIVATEKEY_SIZE

/*!
 * \def QSC_X509_PRIVATE_KEY_PUBLIC_MAX
 * \brief The maximum supported embedded public key length in bytes.
 *
 * \details
 * This value is aligned to the maximum SubjectPublicKeyInfo storage capacity
 * used by the X.509 type layer.
 */
#define QSC_X509_PRIVATE_KEY_PUBLIC_MAX QSC_X509_SPKI_MAX

/*!
 * \struct qsc_x509_private_key
 * \brief A decoded private key object with optional embedded public key material.
 *
 * \details
 * This structure stores the decoded algorithm identifier, the raw private key
 * octets, an optional associated public key, and the active lengths of both
 * buffers. It is used as a normalized container for SEC 1 and PKCS #8 decode
 * operations.
 */
typedef struct qsc_x509_private_key_t
{
    qsc_x509_algorithm_identifier algorithm;            /*!< The decoded private-key algorithm identifier. */
    uint8_t privatekey[QSC_X509_PRIVATE_KEY_MAX];       /*!< The decoded private key octets. */
    size_t privatekeylen;                               /*!< The number of valid bytes in the privatekey buffer. */
    uint8_t publickey[QSC_X509_PRIVATE_KEY_PUBLIC_MAX]; /*!< The optional decoded public key octets. */
    size_t publickeylen;                                /*!< The number of valid bytes in the publickey buffer. */
    bool publickey_present;                             /*!< Indicates whether the publickey buffer contains a decoded public key. */
} qsc_x509_private_key;

/*!
 * \brief Initialize a private-key container.
 *
 * \details
 * Resets the private-key object to a clean default state before decoding or
 * reuse.
 *
 * \param key: [struct] The private-key container to initialize.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_private_key_initialize(qsc_x509_private_key* key);

/*!
 * \brief Decode a SEC 1 DER private key.
 *
 * \details
 * Parses a DER encoded SEC 1 private key object and populates the destination
 * private-key container.
 *
 * \param data: [const] The DER encoded input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param key: [struct] The destination private-key container.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_decode_sec1_der(const uint8_t* data, size_t datalen, qsc_x509_private_key* key);

/*!
 * \brief Decode a SEC 1 PEM private key.
 *
 * \details
 * Parses a PEM encoded SEC 1 private key object and populates the destination
 * private-key container.
 *
 * \param pem: [const] The NULL-terminated PEM text.
 * \param pemlen: The length of the pem array.
 * \param key: [struct] The destination private-key container.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_decode_sec1_pem(const char* pem, size_t pemlen, qsc_x509_private_key* key);

/*!
 * \brief Decode a PKCS #8 DER private key.
 *
 * \details
 * Parses a DER encoded PKCS #8 private key object and populates the destination
 * private-key container.
 *
 * \param data: [const] The DER encoded input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param key: [struct] The destination private-key container.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_decode_pkcs8_der(const uint8_t* data, size_t datalen, qsc_x509_private_key* key);

/*!
 * \brief Decode a PKCS #8 PEM private key.
 *
 * \details
 * Parses a PEM encoded PKCS #8 private key object and populates the destination
 * private-key container.
 *
 * \param pem: [const] The NULL-terminated PEM text.
 * \param pemlen: The length of the PEM text.
 * \param key: [struct] The destination private-key container.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_decode_pkcs8_pem(const char* pem, size_t pemlen, qsc_x509_private_key* key);

/*!
 * \brief Get the expected private key size for an algorithm identifier.
 *
 * \details
 * Returns the implementation-defined private key length associated with the
 * supplied algorithm identifier. This helper is used for strict parameter-set
 * validation during decode and import operations.
 *
 * \param algorithm: [const][struct] The algorithm identifier to evaluate.
 *
 * \return Returns the expected private key size in bytes, or zero if the algorithm is unsupported.
 */

/*!
 * brief Validate a decoded private-key object.
 *
 * \details
 * Performs strict algorithm, parameter-set, and key-size validation on a
 * normalized private-key object. When an embedded public key is present, the
 * helper also validates its size against the decoded algorithm identifier.
 *
 * \param key: [const][struct] The private-key object to validate.
 *
 * 
eturn [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_validate(const qsc_x509_private_key* key);

QSC_EXPORT_API size_t qsc_x509_private_key_expected_private_size(const qsc_x509_algorithm_identifier* algorithm);

/*!
 * \brief Get the expected public key size for an algorithm identifier.
 *
 * \details
 * Returns the implementation-defined public key length associated with the
 * supplied algorithm identifier. This helper is used for strict parameter-set
 * validation during decode and import operations.
 *
 * \param algorithm: [const][struct] The algorithm identifier to evaluate.
 *
 * \return Returns the expected public key size in bytes, or zero if the algorithm is unsupported.
 */
QSC_EXPORT_API size_t qsc_x509_private_key_expected_public_size(const qsc_x509_algorithm_identifier* algorithm);

/*!
 * \brief Decode a PKCS #8 DER private key into caller-supplied buffers.
 *
 * \details
 * Parses a DER encoded PKCS #8 private key object and writes the decoded
 * algorithm identifier, private key bytes, optional public key bytes, and
 * presence flag into caller-managed storage. On entry, the caller supplies the
 * output buffer capacities. On return, the length outputs are set to the number
 * of bytes written, or reset to zero when decoding fails before a value is
 * produced.
 *
 * \param data: [const] The DER encoded input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param algorithm: [struct] The destination algorithm identifier.
 * \param privatekey: The destination private key buffer.
 * \param privatekeycapacity: The capacity of the private key buffer in bytes.
 * \param privatekeylen: The number of bytes written to the private key buffer.
 * \param publickey: The destination public key buffer.
 * \param publickeycapacity: The capacity of the public key buffer in bytes.
 * \param publickeylen: The number of bytes written to the public key buffer.
 * \param publickeypresent: Indicates whether a public key was present in the decoded object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_decode_pkcs8_der_ex(const uint8_t* data, size_t datalen, qsc_x509_algorithm_identifier* algorithm,
    uint8_t* privatekey, size_t privatekeycapacity, size_t* privatekeylen,
    uint8_t* publickey, size_t publickeycapacity, size_t* publickeylen, bool* publickeypresent);

/*!
 * \brief Decode a PKCS #8 PEM private key into caller-supplied buffers.
 *
 * \details
 * Parses a PEM encoded PKCS #8 private key object and writes the decoded
 * algorithm identifier, private key bytes, optional public key bytes, and
 * presence flag into caller-managed storage. The helper first base64-decodes the
 * PEM object into an internal DER buffer and then applies the same strict PKCS
 * #8 decode rules as the DER interface.
 *
 * \param pem: [const] The NULL-terminated PEM text.
 * \param pemlen: The length of the PEM text.
 * \param algorithm: [struct] The destination algorithm identifier.
 * \param privatekey: The destination private key buffer.
 * \param privatekeycapacity: The capacity of the private key buffer in bytes.
 * \param privatekeylen: The number of bytes written to the private key buffer.
 * \param publickey: The destination public key buffer.
 * \param publickeycapacity: The capacity of the public key buffer in bytes.
 * \param publickeylen: The number of bytes written to the public key buffer.
 * \param publickeypresent: Indicates whether a public key was present in the decoded object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_decode_pkcs8_pem_ex(const char* pem, size_t pemlen, qsc_x509_algorithm_identifier* algorithm,
    uint8_t* privatekey, size_t privatekeycapacity, size_t* privatekeylen,
    uint8_t* publickey, size_t publickeycapacity, size_t* publickeylen, bool* publickeypresent);

/*!
 * \brief Test whether a certificate matches a private key object.
 *
 * \details
 * Compares the subject public key information contained in the certificate with
 * the public key material associated with the supplied private-key object.
 *
 * \param certificate: [const][struct] The certificate to evaluate.
 * \param key: [const][struct] The private-key object to compare.
 *
 * \return Returns true if the certificate corresponds to the supplied private key; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_key_match(const qsc_x509_certificate* certificate, const qsc_x509_private_key* key);

QSC_CPLUSPLUS_ENABLED_END

#endif
