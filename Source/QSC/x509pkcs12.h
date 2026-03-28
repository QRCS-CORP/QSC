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
 * and direct decryption of an EncryptedPrivateKeyInfo object using a supplied
 * password. The parser currently accepts a version 3 PFX container carrying a
 * PKCS #7 data AuthSafe, validates the outer MAC using HMAC-SHA-256, and
 * extracts certificate bags, PKCS #8 key bags, and shrouded key bags. Cipher
 * selection for private-key decryption is controlled by the supporting PKCS #12
 * crypto implementation and associated compile-time feature macros.
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
 * Resets the bundle object to a clean default state before parsing or reuse.
 *
 * \param bundle: [struct] The PKCS #12 bundle container to initialize.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_pkcs12_initialize(qsc_x509_pkcs12_bundle* bundle);

/*!
 * \brief Parse a PKCS #12 bundle from DER.
 *
 * \details
 * Decodes a PKCS #12 container, validates the outer MAC, applies password-based
 * decryption where required, extracts the private key when present, and loads
 * any decoded certificates into the destination bundle object. The destination
 * bundle is reinitialized before parsing begins.
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
