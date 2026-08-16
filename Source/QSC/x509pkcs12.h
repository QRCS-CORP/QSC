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

#ifndef QSC_X509_PKCS12_H
#define QSC_X509_PKCS12_H

#include "qsccommon.h"
#include "x509cert.h"
#include "x509key.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509pkcs12.h
 * \brief PKCS #12 bundle parsing and encrypted private-key decryption interface.
 *
 * \details
 * This header defines constants, container types, and helper functions used to
 * parse PKCS #12 bundles carrying a private key and associated certificate
 * chain material. The interface exposes a compact bundle object that stores an
 * optional decoded private key together with a bounded certificate collection.
 *
 * The public API supports bundle initialization, top-level PKCS #12 parsing,
 * explicit bundle cleanup, and direct decryption of an EncryptedPrivateKeyInfo
 * object using a supplied password. The parser accepts a version 3 PFX container
 * carrying a PKCS #7 data AuthSafe, validates the outer MAC using either RFC 7292
 * classic MacData or RFC 9879 PBMAC1 MacData, decodes the AuthenticatedSafe
 * sequence of ContentInfo values, and supports plaintext data plus password-
 * protected encryptedData safe contents. The password-encryption profile uses
 * PBES2/PBKDF2 with an explicit HMAC-SHA2 PRF and AES-128-CBC or AES-256-CBC.
 * Certificate bags, PKCS #8 key bags, shrouded key bags, and nested safe-contents
 * bags are processed. Recognized bag
 * failures are fail-closed, and an imported private key is cryptographically
 * matched to its associated certificate when certificate material is present.
 */

/*!
 * \def QSC_X509_PKCS12_MAX_CERTIFICATES
 * \brief The maximum number of certificates retained in a parsed PKCS #12 bundle.
 */
#define QSC_X509_PKCS12_MAX_CERTIFICATES 16U

/*!
 * \def QSC_X509_PKCS12_DER_MAX
 * \brief The maximum supported DER size for PKCS #12 processing buffers.
 */
#define QSC_X509_PKCS12_DER_MAX 16384U

#if !defined(QSC_X509_PKCS12_USE_AES) && !defined(QSC_X509_PKCS12_USE_RCS)
/*!
 * \def QSC_X509_PKCS12_USE_AES
 * \brief Select AES as the default PKCS #12 content-encryption backend.
 *
 * \details
 * This macro is defined automatically when no alternative PKCS #12 encryption
 * backend has been selected at compile time.
 */
#   define QSC_X509_PKCS12_USE_AES
#endif

/*!
 * \struct qsc_x509_pkcs12_bundle
 * \brief A parsed PKCS #12 bundle containing an optional private key and certificate set.
 *
 * \details
 * This structure stores the decoded private key when present together with a
 * bounded collection of certificates extracted from the PKCS #12 container.
 */
typedef struct qsc_x509_pkcs12_bundle_t
{
    qsc_x509_private_key privatekey;                                        /*!< The decoded private key extracted from the bundle. */
    bool hasprivatekey;                                                     /*!< Indicates whether the bundle contained a decodable private key. */
    qsc_x509_certificate certificates[QSC_X509_PKCS12_MAX_CERTIFICATES];    /*!< The decoded certificate objects extracted from the bundle. */
    size_t certificatecount;                                                /*!< The number of valid certificate entries stored in the certificates array. */
} qsc_x509_pkcs12_bundle;

/*!
 * \brief Initialize a PKCS #12 bundle container.
 *
 * \details
 * Resets a fresh bundle object to a clean default state before first use. A bundle
 * populated by \ref qsc_x509_pkcs12_parse owns certificate backing storage and
 * must be released with \ref qsc_x509_pkcs12_clear rather than reinitialized.
 *
 * \param bundle: [struct] The PKCS #12 bundle container to initialize.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_pkcs12_initialize(qsc_x509_pkcs12_bundle* bundle);

/*!
 * \brief Clear a PKCS #12 bundle and release certificate backing storage.
 *
 * \details
 * Releases all certificate DER storage owned by a successfully parsed bundle,
 * securely erases the decoded private-key object, and resets the container.
 * Call this function before reusing or discarding a bundle that has been
 * populated by \ref qsc_x509_pkcs12_parse.
 *
 * \param bundle: [struct] The initialized PKCS #12 bundle to clear.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_pkcs12_clear(qsc_x509_pkcs12_bundle* bundle);

/*!
 * \brief Parse a PKCS #12 bundle from DER.
 *
 * \details
 * Decodes a PKCS #12 container, validates the outer MAC, processes the
 * AuthenticatedSafe ContentInfo sequence, applies password-based decryption where
 * required, extracts at most one private key, and loads decoded X.509 certificates
 * into owned backing storage. Recognized SafeBag parse/decryption failures abort
 * the import instead of returning a partial bundle. When both a private key and
 * certificate material are present, the key must cryptographically match a
 * certificate; localKeyId attributes are used as an additional association check
 * when both sides provide them.
 *
 * The destination is initialized before parsing. A previously populated bundle
 * must first be released with \ref qsc_x509_pkcs12_clear before reuse.
 *
 * \param data: [const] The DER encoded PKCS #12 input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param password: [const] The password used to decrypt protected contents.
 * \param bundle: [struct] The destination parsed PKCS #12 bundle object.
 *
 * \return Returns true if parsing completed successfully; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_pkcs12_parse(const uint8_t* data, size_t datalen, const char* password, qsc_x509_pkcs12_bundle* bundle);

/*!
 * \brief Encode a PKCS #12 MacData object over an AuthSafe OCTET STRING value.
 *
 * \details
 * Computes the PKCS #12 whole-file integrity MAC over the supplied AuthSafe
 * contents and encodes the resulting MacData object. When \c usepbmac1 is false,
 * the function emits a classic RFC 7292 MacData object using the PKCS #12
 * Appendix B MAC KDF with HMAC-SHA2-256. When \c usepbmac1 is true, the
 * function emits an RFC 9879 PBMAC1 AlgorithmIdentifier using
 * PBKDF2-HMAC-SHA2-256 and HMAC-SHA2-256.
 *
 * \param output: The destination buffer receiving DER encoded MacData.
 * \param outcap: The capacity of the destination buffer in bytes.
 * \param outlen: The number of bytes written to the destination buffer.
 * \param authsafe: [const] The AuthSafe OCTET STRING contents to authenticate.
 * \param authsafelen: The length of the AuthSafe contents in bytes.
 * \param password: [const] The PKCS #12 password.
 * \param salt: [const] The MAC salt.
 * \param saltlen: The MAC salt length in bytes.
 * \param iterations: The MAC KDF iteration count.
 * \param usepbmac1: When true, encode PBMAC1; otherwise encode classic MacData.
 *
 * \return Returns true if MacData encoding completed successfully; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_pkcs12_encode_mac_data_der(uint8_t* output, size_t outcap, size_t* outlen, const uint8_t* authsafe,
    size_t authsafelen, const char* password, const uint8_t* salt, size_t saltlen, uint64_t iterations, bool usepbmac1);


/*!
 * \brief Verify the outer PKCS #12 MacData without extracting bundle contents.
 *
 * \details
 * Decodes the PFX wrapper, locates the AuthSafe OCTET STRING, and verifies the
 * outer MacData. Both classic RFC 7292 MacData and RFC 9879 PBMAC1 MacData are
 * supported. This function does not decrypt safe contents or extract certificates
 * or private keys; use \c qsc_x509_pkcs12_parse for full bundle import.
 *
 * \param data: [const] The DER encoded PKCS #12 input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param password: [const] The PKCS #12 MAC password.
 *
 * \return Returns true if the outer PKCS #12 MacData verifies; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_pkcs12_verify_mac_data(const uint8_t* data, size_t datalen, const char* password);

/*!
 * \brief Decrypt an EncryptedPrivateKeyInfo object.
 *
 * \details
 * Decrypts a DER encoded EncryptedPrivateKeyInfo structure using the supplied
 * password and writes the recovered PrivateKeyInfo bytes to the caller-supplied
 * output buffer.
 *
 * \param data: [const] The DER encoded EncryptedPrivateKeyInfo input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param password: [const] The password used to decrypt the private key object.
 * \param privatekeyinfo: The destination buffer receiving the decrypted PrivateKeyInfo bytes.
 * \param privatekeyinfocapacity: The capacity of the destination buffer in bytes.
 * \param privatekeyinfolen: The number of bytes written to the destination buffer.
 *
 * \return Returns true if decryption completed successfully; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_pkcs12_decrypt_encrypted_private_key_info(const uint8_t* data, size_t datalen, const char* password,
    uint8_t* privatekeyinfo, size_t privatekeyinfocapacity, size_t* privatekeyinfolen);

QSC_CPLUSPLUS_ENABLED_END

#endif
