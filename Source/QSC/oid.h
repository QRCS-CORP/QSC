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

#ifndef QSC_OID_H
#define QSC_OID_H

#include "qsccommon.h"
#include "asn1.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file oid.h
 * \brief Object identifier registry and lookup helpers for the QSC X.509 layer.
 *
 * \details
 * This header defines the internal object identifier registry used by the
 * X.509 support modules. The registry provides stable identifiers, encoded
 * value octets, dotted-decimal names, and descriptive strings for the subset
 * of ASN.1 OBJECT IDENTIFIER values required by certificate parsing,
 * signature verification, public key extraction, distinguished name decoding,
 * and extension handling.
 *
 * The functions in this module operate on qsc_asn1_oid objects decoded by the
 * ASN.1 helper layer. The registry is intentionally compact and focused on the
 * algorithms and fields that are commonly encountered in DER-encoded X.509
 * certificates.
 */

/*!
 * \brief Known object identifier registry entries.
 */
typedef enum qsc_oid_id_t
{
    QSC_OID_ID_NONE = 0,                            /*!< No matching object identifier was found. */

    QSC_OID_ID_RSA_ENCRYPTION,                      /*!< rsaEncryption. */
    QSC_OID_ID_MD5_WITH_RSA_ENCRYPTION,             /*!< md5WithRSAEncryption. */
    QSC_OID_ID_SHA1_WITH_RSA_ENCRYPTION,            /*!< sha1WithRSAEncryption. */
    QSC_OID_ID_SHA256_WITH_RSA_ENCRYPTION,          /*!< sha256WithRSAEncryption. */
    QSC_OID_ID_SHA384_WITH_RSA_ENCRYPTION,          /*!< sha384WithRSAEncryption. */
    QSC_OID_ID_SHA512_WITH_RSA_ENCRYPTION,          /*!< sha512WithRSAEncryption. */

    QSC_OID_ID_EC_PUBLIC_KEY,                       /*!< id-ecPublicKey. */
    QSC_OID_ID_PRIME256V1,                          /*!< prime256v1. */
    QSC_OID_ID_SECP384R1,                           /*!< secp384r1. */
    QSC_OID_ID_SECP521R1,                           /*!< secp521r1. */
    QSC_OID_ID_ECDSA_WITH_SHA1,                     /*!< ecdsa-with-SHA1. */
    QSC_OID_ID_ECDSA_WITH_SHA256,                   /*!< ecdsa-with-SHA256. */
    QSC_OID_ID_ECDSA_WITH_SHA384,                   /*!< ecdsa-with-SHA384. */
    QSC_OID_ID_ECDSA_WITH_SHA512,                   /*!< ecdsa-with-SHA512. */

    QSC_OID_ID_SHA1,                                /*!< id-sha1. */
    QSC_OID_ID_SHA224,                              /*!< id-sha224. */
    QSC_OID_ID_SHA256,                              /*!< id-sha256. */
    QSC_OID_ID_SHA384,                              /*!< id-sha384. */
    QSC_OID_ID_SHA512,                              /*!< id-sha512. */

    QSC_OID_ID_COMMON_NAME,                         /*!< commonName. */
    QSC_OID_ID_SURNAME,                             /*!< surname. */
    QSC_OID_ID_SERIAL_NUMBER,                       /*!< serialNumber. */
    QSC_OID_ID_COUNTRY_NAME,                        /*!< countryName. */
    QSC_OID_ID_LOCALITY_NAME,                       /*!< localityName. */
    QSC_OID_ID_STATE_OR_PROVINCE_NAME,              /*!< stateOrProvinceName. */
    QSC_OID_ID_STREET_ADDRESS,                      /*!< streetAddress. */
    QSC_OID_ID_ORGANIZATION_NAME,                   /*!< organizationName. */
    QSC_OID_ID_ORGANIZATIONAL_UNIT_NAME,            /*!< organizationalUnitName. */
    QSC_OID_ID_TITLE,                               /*!< title. */
    QSC_OID_ID_DESCRIPTION,                         /*!< description. */
    QSC_OID_ID_GIVEN_NAME,                          /*!< givenName. */
    QSC_OID_ID_INITIALS,                            /*!< initials. */
    QSC_OID_ID_GENERATION_QUALIFIER,                /*!< generationQualifier. */
    QSC_OID_ID_DN_QUALIFIER,                        /*!< dnQualifier. */
    QSC_OID_ID_PSEUDONYM,                           /*!< pseudonym. */
    QSC_OID_ID_DOMAIN_COMPONENT,                    /*!< domainComponent. */
    QSC_OID_ID_EMAIL_ADDRESS,                       /*!< emailAddress. */

    QSC_OID_ID_SUBJECT_KEY_IDENTIFIER,              /*!< subjectKeyIdentifier. */
    QSC_OID_ID_KEY_USAGE,                           /*!< keyUsage. */
    QSC_OID_ID_SUBJECT_ALT_NAME,                    /*!< subjectAltName. */
    QSC_OID_ID_ISSUER_ALT_NAME,                     /*!< issuerAltName. */
    QSC_OID_ID_BASIC_CONSTRAINTS,                   /*!< basicConstraints. */
    QSC_OID_ID_NAME_CONSTRAINTS,                    /*!< nameConstraints. */
    QSC_OID_ID_CRL_DISTRIBUTION_POINTS,             /*!< cRLDistributionPoints. */
    QSC_OID_ID_CERTIFICATE_POLICIES,                /*!< certificatePolicies. */
    QSC_OID_ID_AUTHORITY_KEY_IDENTIFIER,            /*!< authorityKeyIdentifier. */
    QSC_OID_ID_EXTENDED_KEY_USAGE,                  /*!< extKeyUsage. */
    QSC_OID_ID_AUTHORITY_INFO_ACCESS,               /*!< authorityInfoAccess. */
    QSC_OID_ID_SUBJECT_INFO_ACCESS,                 /*!< subjectInfoAccess. */

    QSC_OID_ID_ANY_EXTENDED_KEY_USAGE,              /*!< anyExtendedKeyUsage. */
    QSC_OID_ID_SERVER_AUTH,                         /*!< id-kp-serverAuth. */
    QSC_OID_ID_CLIENT_AUTH,                         /*!< id-kp-clientAuth. */
    QSC_OID_ID_CODE_SIGNING,                        /*!< id-kp-codeSigning. */
    QSC_OID_ID_EMAIL_PROTECTION,                    /*!< id-kp-emailProtection. */
    QSC_OID_ID_TIME_STAMPING,                       /*!< id-kp-timeStamping. */
    QSC_OID_ID_OCSP_SIGNING,                        /*!< id-kp-OCSPSigning. */

    QSC_OID_ID_OCSP,                                /*!< id-ad-ocsp. */
    QSC_OID_ID_CA_ISSUERS                           /*!< id-ad-caIssuers. */
} qsc_oid_id;

/*!
 * \brief A registry entry describing a known object identifier.
 */
QSC_EXPORT_API typedef struct qsc_oid_entry_t
{
    qsc_oid_id id;                  /*!< The internal registry identifier. */
    const uint8_t* data;            /*!< The encoded OID value octets. */
    size_t length;                  /*!< The number of encoded OID value octets. */
    const char* dotted;             /*!< The dotted-decimal text form. */
    const char* name;               /*!< The short descriptive registry name. */
} qsc_oid_entry;

/*!
 * \brief Gets the number of entries in the static object identifier registry.
 *
 * \return [size_t] Returns the number of known registry entries.
 */
QSC_EXPORT_API size_t qsc_oid_registry_count(void);

/*!
 * \brief Gets a registry entry by zero-based table index.
 *
 * \param index: [size_t] The registry entry index.
 *
 * \return [const qsc_oid_entry*] Returns a pointer to the registry entry, or NULL on error.
 */
QSC_EXPORT_API const qsc_oid_entry* qsc_oid_registry_at(size_t index);

/*!
 * \brief Gets a registry entry by internal identifier.
 *
 * \param id: [qsc_oid_id] The internal registry identifier.
 *
 * \return [const qsc_oid_entry*] Returns a pointer to the matching registry entry, or NULL if not found.
 */
QSC_EXPORT_API const qsc_oid_entry* qsc_oid_get_entry(qsc_oid_id id);

/*!
 * \brief Identifies a decoded object identifier against the static registry.
 *
 * \param oid: [const qsc_asn1_oid*] The decoded object identifier.
 *
 * \return [qsc_oid_id] Returns the matching registry identifier, or QSC_OID_ID_NONE if not found.
 */
QSC_EXPORT_API qsc_oid_id qsc_oid_identify(const qsc_asn1_oid* oid);

/*!
 * \brief Tests whether a decoded object identifier matches a registry identifier.
 *
 * \param oid: [const qsc_asn1_oid*] The decoded object identifier.
 * \param id: [qsc_oid_id] The registry identifier.
 *
 * \return [bool] Returns true if the decoded object identifier matches the registry entry.
 */
QSC_EXPORT_API bool qsc_oid_equals_id(const qsc_asn1_oid* oid, qsc_oid_id id);

/*!
 * \brief Gets the encoded value octets for a registry identifier.
 *
 * \param id: [qsc_oid_id] The registry identifier.
 * \param data: [const uint8_t**] Receives a pointer to the encoded OID value octets.
 * \param length: [size_t*] Receives the number of encoded OID value octets.
 *
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_oid_get_encoded(qsc_oid_id id, const uint8_t** data, size_t* length);

/*!
 * \brief Copies the encoded value octets of a registry identifier to a decoded ASN.1 OID structure.
 *
 * \param id: [qsc_oid_id] The registry identifier.
 * \param oid: [qsc_asn1_oid*] Receives the decoded OID structure.
 *
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_oid_to_asn1(qsc_oid_id id, qsc_asn1_oid* oid);

/*!
 * \brief Gets the dotted-decimal text form of a registry identifier.
 *
 * \param id: [qsc_oid_id] The registry identifier.
 *
 * \return [const char*] Returns the dotted-decimal text form, or NULL if the identifier is invalid.
 */
QSC_EXPORT_API const char* qsc_oid_get_dotted(qsc_oid_id id);

/*!
 * \brief Gets the descriptive registry name of a registry identifier.
 *
 * \param id: [qsc_oid_id] The registry identifier.
 *
 * \return [const char*] Returns the descriptive name, or NULL if the identifier is invalid.
 */
QSC_EXPORT_API const char* qsc_oid_get_name(qsc_oid_id id);

/*!
 * \brief Gets the descriptive registry name of a decoded object identifier.
 *
 * \param oid: [const qsc_asn1_oid*] The decoded object identifier.
 *
 * \return [const char*] Returns the descriptive name, or NULL if the OID is not recognized.
 */
QSC_EXPORT_API const char* qsc_oid_get_name_from_oid(const qsc_asn1_oid* oid);

QSC_CPLUSPLUS_ENABLED_END

#endif
