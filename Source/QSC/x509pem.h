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

#ifndef QSC_X509_PEM_H
#define QSC_X509_PEM_H

#include "qsccommon.h"
#include "x509cert.h"
#include "x509crl.h"
#include "x509csr.h"
#include "x509key.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509pem.h
 * \brief PEM bundle decoding, object extraction, and PEM encoding utilities for X.509 objects.
 *
 * \details
 * This header defines helper functions used to decode PEM encoded X.509
 * certificates, chains, trust stores, certificate signing requests, certificate
 * revocation lists, and private keys. The interface also provides PEM emission
 * helpers for DER encoded certificates, CRLs, CSRs, and private keys in PKCS #8
 * and SEC 1 form.
 *
 * PEM bundle decoding helpers accept concatenated PEM text and extract the first
 * matching object or populate caller-supplied chain and store containers. All
 * searches are bounded by the supplied \p pemlen window so trailing or adjacent
 * data outside that window is not consulted during label discovery. PEM
 * encoding helpers support the standard
 * two-pass pattern: pass a NULL output pointer or a too-small output buffer to
 * receive the required size in \p pemlen and a
 * QSC_ASN1_STATUS_BUFFER_TOO_SMALL result, then call again with a suitably
 * sized output buffer. Private-key bundle helpers support both generic dispatch
 * and format-specific SEC 1 and PKCS #8 decoding paths.
 */

/*!
 * \def QSC_X509_PEM_DER_MAX
 * \brief The maximum DER object size supported by the PEM conversion helpers.
 */
#define QSC_X509_PEM_DER_MAX 16384U

 /**
  * \def QSC_X509_PEM_BINARY_MAX
  * \brief Maximum binary input size for PEM encoding operations.
  *
  * This macro defines the upper bound, in bytes, of DER-encoded (binary) data
  * that may be supplied to PEM encoding routines. It is derived from
  * QSC_X509_KEY_WRITE_MAX and therefore reflects the maximum size of supported
  * X.509 key material in binary form, including structures such as PKCS#8
  * private keys and SubjectPublicKeyInfo.
  *
  * This value is used as the input capacity for base64 encoding when generating
  * PEM output. It does not represent the size of the resulting PEM text.
  *
  * \note The corresponding PEM text output buffer must be sized using
  *       QSC_X509_PEM_TEXT_MAX, which accounts for base64 expansion and
  *       formatting overhead.
  */
#define QSC_X509_PEM_BINARY_MAX 8192U

  /**
   * \def QSC_X509_PEM_TEXT_MAX
   * \brief Maximum buffer size required for PEM-encoded text output.
   *
   * This macro defines the maximum number of bytes required to store the PEM
   * representation of binary X.509 data. It accounts for:
   * - Base64 expansion (4 output bytes for every 3 input bytes),
   * - Line breaks inserted during PEM formatting,
   * - Header and footer delimiters (e.g. "-----BEGIN ...-----"),
   * - A safety margin to accommodate formatting variations.
   *
   * The base64 expansion is computed as:
   *   ceil(n / 3) * 4
   * where n is the binary input size (QSC_X509_PEM_BINARY_MAX).
   *
   * An additional fixed overhead of 512 bytes is included to ensure sufficient
   * space for PEM headers, footers, line wrapping, and null termination.
   *
   * This macro should be used to size buffers passed to PEM encoding functions
   * such as qsc_x509_certificate_encode_pem(), qsc_x509_csr_encode_pem(), and
   * qsc_x509_private_key_encode_pkcs8_pem().
   *
   * \note This value is format-dependent and independent of the underlying
   *       cryptographic algorithm. Larger key types (e.g. ML-DSA-87) increase
   *       the required size through QSC_X509_PEM_BINARY_MAX.
   */
#define QSC_X509_PEM_TEXT_MAX ((((QSC_X509_PEM_BINARY_MAX + 2U) / 3U) * 4U) + 512U)

/*!
 * \brief Decode a PEM encoded certificate.
 *
 * \details
 * Parses a PEM encoded X.509 certificate and decodes the contained DER
 * Certificate object into the supplied certificate structure.
 *
 * \param pem: [const] The PEM encoded certificate text.
 * \param pemlen: The length of the PEM text in bytes.
 * \param certificate: [struct] The destination certificate object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_decode_pem(const char* pem, size_t pemlen, qsc_x509_certificate* certificate);

/*!
 * \brief Free the resources associated with a decoded certificate chain.
 *
 * \details
 * Releases or resets any internal state held by the supplied chain object after
 * PEM bundle loading or chain construction.
 *
 * \param chain: [struct] The certificate chain object to free.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_chain_free(qsc_x509_chain* chain);

/*!
 * \brief Free the resources associated with a certificate store.
 *
 * \details
 * Releases or resets any internal state held by the supplied trust store object
 * after PEM bundle loading or verification use.
 *
 * \param store: [struct] The certificate store object to free.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_store_free(qsc_x509_store* store);

/*!
 * \brief Decode a PEM certificate bundle into a chain object.
 *
 * \details
 * Parses a concatenated PEM bundle containing one or more certificates and
 * loads the decoded certificates into the caller-supplied chain object using
 * the provided certificate storage array.
 *
 * \param pem: [const] The PEM bundle text.
 * \param pemlen: The length of the PEM bundle in bytes.
 * \param certificates: [struct] The caller-supplied certificate storage array.
 * \param certcount: The number of certificate elements available in \p certificates.
 * \param chain: [struct] The destination certificate chain object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_chain_decode_pem_bundle(const char* pem, size_t pemlen, qsc_x509_certificate* certificates, size_t certcount, qsc_x509_chain* chain);

/*!
 * \brief Load a PEM trust-anchor bundle into a certificate store.
 *
 * \details
 * Parses a concatenated PEM bundle containing one or more trust-anchor
 * certificates and populates the destination store using the provided anchor
 * storage array.
 *
 * \param pem: [const] The PEM bundle text.
 * \param pemlen: The length of the PEM bundle in bytes.
 * \param anchors: [struct] The caller-supplied trust-anchor storage array.
 * \param anchorcount: The number of trust-anchor elements available in \p anchors.
 * \param store: [struct] The destination certificate store object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_store_load_pem_bundle(const char* pem, size_t pemlen, qsc_x509_trust_anchor* anchors, size_t anchorcount, qsc_x509_store* store);

/*!
 * \brief Decode a CSR from a PEM bundle.
 *
 * \details
 * Searches a PEM bundle for a certificate signing request object and decodes
 * the first matching CSR into the destination structure.
 *
 * \param pem: [const] The PEM bundle text.
 * \param pemlen: The length of the PEM bundle in bytes.
 * \param csr: [struct] The destination CSR object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_decode_pem_from_bundle(const char* pem, size_t pemlen, qsc_x509_csr* csr);

/*!
 * \brief Decode a CRL from a PEM bundle.
 *
 * \details
 * Searches a PEM bundle for a certificate revocation list object and decodes
 * the first matching CRL into the destination structure.
 *
 * \param pem: [const] The PEM bundle text.
 * \param pemlen: The length of the PEM bundle in bytes.
 * \param crl: [struct] The destination CRL object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_decode_pem(const char* pem, size_t pemlen, qsc_x509_crl* crl);

/*!
 * \brief Decode a private key from a PEM bundle.
 *
 * \details
 * Searches a PEM bundle for a supported private-key object and decodes the
 * first matching key into the normalized private-key container.
 *
 * \param pem: [const] The PEM bundle text.
 * \param pemlen: The length of the PEM bundle in bytes.
 * \param key: [struct] The destination private-key object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_decode_pem_from_bundle(const char* pem, size_t pemlen, qsc_x509_private_key* key);

/*!
 * \brief Decode a SEC 1 private key from a PEM bundle.
 *
 * \details
 * Searches a PEM bundle for a PEM encoded SEC 1 private key and decodes the
 * first matching object into the normalized private-key container.
 *
 * \param pem: [const] The PEM bundle text.
 * \param pemlen: The length of the PEM bundle in bytes.
 * \param key: [struct] The destination private-key object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_decode_sec1_pem_from_bundle(const char* pem, size_t pemlen, qsc_x509_private_key* key);

/*!
 * \brief Decode a PKCS #8 private key from a PEM bundle.
 *
 * \details
 * Searches a PEM bundle for a PEM encoded PKCS #8 private key and decodes the
 * first matching object into the normalized private-key container.
 *
 * \param pem: [const] The PEM bundle text.
 * \param pemlen: The length of the PEM bundle in bytes.
 * \param key: [struct] The destination private-key object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_decode_pkcs8_pem_from_bundle(const char* pem, size_t pemlen, qsc_x509_private_key* key);

/*!
 * \brief Decode a PKCS #8 private key from a PEM bundle into caller-supplied buffers.
 *
 * \details
 * Searches a PEM bundle for a PEM encoded PKCS #8 private key and decodes the
 * first matching object into caller-managed algorithm, private-key, and public-
 * key buffers.
 *
 * \param pem: [const] The PEM bundle text.
 * \param pemlen: The length of the PEM bundle in bytes.
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
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_decode_pkcs8_pem_ex_from_bundle(const char* pem, size_t pemlen, qsc_x509_algorithm_identifier* algorithm, 
    uint8_t* privatekey, size_t privatekeycapacity, size_t* privatekeylen, uint8_t* publickey, size_t publickeycapacity, size_t* publickeylen, bool* publickeypresent);

/*!
 * \brief Convert a DER encoded PKCS #8 private key to PEM.
 *
 * \param der: [const] The DER encoded private key.
 * \param derlen: The length of the DER input in bytes.
 * \param pem: The destination PEM buffer.
 * \param pemlen: The input capacity of the PEM buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_pem_encode_private_key_pkcs8(const uint8_t* der, size_t derlen, char* pem, size_t* pemlen);

/*!
 * \brief Convert a DER encoded SEC 1 private key to PEM.
 *
 * \param der: [const] The DER encoded private key.
 * \param derlen: The length of the DER input in bytes.
 * \param pem: The destination PEM buffer.
 * \param pemlen: The input capacity of the PEM buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_pem_encode_private_key_sec1(const uint8_t* der, size_t derlen, char* pem, size_t* pemlen);

/*!
 * \brief Encode a normalized private key object as PKCS #8 PEM.
 *
 * \details
 * Serializes the supplied private-key container as PKCS #8 and converts the
 * resulting DER object to PEM text form.
 *
 * \param key: [const][struct] The source private-key container.
 * \param includepublickey: Includes the optional embedded public key when set to true.
 * \param pem: The destination PEM buffer.
 * \param pemlen: The input capacity of the PEM buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_pem_encode_private_key_pkcs8_from_key(const qsc_x509_private_key* key, bool includepublickey, char* pem, size_t* pemlen);

/*!
 * \brief Encode a normalized private key object as SEC 1 PEM.
 *
 * \details
 * Serializes the supplied private-key container as SEC 1 and converts the
 * resulting DER object to PEM text form.
 *
 * \param key: [const][struct] The source private-key container.
 * \param includeparameters: Includes algorithm parameters when set to true.
 * \param includepublickey: Includes the optional embedded public key when set to true.
 * \param pem: The destination PEM buffer.
 * \param pemlen: The input capacity of the PEM buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_pem_encode_private_key_sec1_from_key(const qsc_x509_private_key* key, bool includeparameters, bool includepublickey, char* pem, size_t* pemlen);

/*!
 * \brief Convert a DER encoded certificate to PEM.
 *
 * \param der: [const] The DER encoded certificate.
 * \param derlen: The length of the DER input in bytes.
 * \param pem: The destination PEM buffer.
 * \param pemlen: The input capacity of the PEM buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_pem_encode_certificate(const uint8_t* der, size_t derlen, char* pem, size_t* pemlen);

/*!
 * \brief Convert a DER encoded CRL to PEM.
 *
 * \param der: [const] The DER encoded CRL.
 * \param derlen: The length of the DER input in bytes.
 * \param pem: The destination PEM buffer.
 * \param pemlen: The input capacity of the PEM buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_pem_encode_crl(const uint8_t* der, size_t derlen, char* pem, size_t* pemlen);

/*!
 * \brief Convert a DER encoded CSR to PEM.
 *
 * \param der: [const] The DER encoded CSR.
 * \param derlen: The length of the DER input in bytes.
 * \param pem: The destination PEM buffer.
 * \param pemlen: The input capacity of the PEM buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_pem_encode_csr(const uint8_t* der, size_t derlen, char* pem, size_t* pemlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
