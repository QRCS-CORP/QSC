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

#ifndef QSC_X509_TYPES_H
#define QSC_X509_TYPES_H

#include "qsccommon.h"
#include "asn1.h"
#include "oid.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509_types.h
 * \brief Public data types used by the QSC X.509 parsing and validation layer.
 *
 * \details
 * This header defines the normalized in-memory structures used by the X.509
 * certificate modules. The types in this file provide a bridge between the
 * low-level ASN.1 representation exposed by the DER and BER decoding layer and
 * the strongly typed objects required by certificate parsing, signature
 * verification, trust processing, and certificate path validation.
 *
 * The structures in this module are intentionally compact. They are designed to
 * support a practical certificate implementation centered on DER-encoded X.509
 * certificates, common public key algorithms, distinguished name processing,
 * validity interval evaluation, and the subset of certificate extensions that
 * are normally required for certificate verification.
 *
 * The types declared here do not perform parsing by themselves. They are used
 * by the x509_name, x509_time, x509_spki, x509_ext, x509_cert, x509_store, and
 * x509_verify modules to store decoded certificate state in a stable internal
 * format.
 */

/*!
 * \def QSC_X509_NAME_ATTRIBUTE_STRING_MAX
 * \brief The maximum number of octets stored for a decoded distinguished name attribute string, excluding the terminator.
 */
#define QSC_X509_NAME_ATTRIBUTE_STRING_MAX 256U

/*!
 * \def QSC_X509_NAME_ATTRIBUTES_MAX
 * \brief The maximum number of decoded attributes stored in a distinguished name.
 */
#define QSC_X509_NAME_ATTRIBUTES_MAX 32U

/*!
 * \def QSC_X509_EXTENSIONS_MAX
 * \brief The maximum number of decoded certificate extensions stored in a certificate object.
 */
#define QSC_X509_EXTENSIONS_MAX 32U

/*!
 * \def QSC_X509_SAN_ENTRIES_MAX
 * \brief The maximum number of decoded subject alternative name entries stored in a certificate object.
 */
#define QSC_X509_SAN_ENTRIES_MAX 16U

/*!
 * \def QSC_X509_KEY_IDENTIFIER_MAX
 * \brief The maximum number of octets stored for a subject or authority key identifier.
 */
#define QSC_X509_KEY_IDENTIFIER_MAX 32U

/*!
 * \def QSC_X509_SERIAL_NUMBER_MAX
 * \brief The maximum number of octets stored for a certificate serial number.
 */
#define QSC_X509_SERIAL_NUMBER_MAX 20U

/*!
 * \def QSC_X509_ML_DSA_44_PUBLICKEY_SIZE
 * \brief The size in octets of an ML-DSA-44 public key.
 */
#define QSC_X509_ML_DSA_44_PUBLICKEY_SIZE 1312U

/*!
 * \def QSC_X509_ML_DSA_65_PUBLICKEY_SIZE
 * \brief The size in octets of an ML-DSA-65 public key.
 */
#define QSC_X509_ML_DSA_65_PUBLICKEY_SIZE 1952U

/*!
 * \def QSC_X509_ML_DSA_87_PUBLICKEY_SIZE
 * \brief The size in octets of an ML-DSA-87 public key.
 */
#define QSC_X509_ML_DSA_87_PUBLICKEY_SIZE 2592U

/*!
 * \def QSC_X509_ML_DSA_44_SIGNATURE_SIZE
 * \brief The size in octets of an ML-DSA-44 signature.
 */
#define QSC_X509_ML_DSA_44_SIGNATURE_SIZE 2420U

/*!
 * \def QSC_X509_ML_DSA_65_SIGNATURE_SIZE
 * \brief The size in octets of an ML-DSA-65 signature.
 */
#define QSC_X509_ML_DSA_65_SIGNATURE_SIZE 3309U

/*!
 * \def QSC_X509_ML_DSA_87_SIGNATURE_SIZE
 * \brief The size in octets of an ML-DSA-87 signature.
 */
#define QSC_X509_ML_DSA_87_SIGNATURE_SIZE 4627U

/*!
 * \def QSC_X509_ML_KEM_512_PUBLICKEY_SIZE
 * \brief The size in octets of an ML-KEM-512 encapsulation key carried in subjectPublicKey.
 */
#define QSC_X509_ML_KEM_512_PUBLICKEY_SIZE 800U

/*!
 * \def QSC_X509_ML_KEM_768_PUBLICKEY_SIZE
 * \brief The size in octets of an ML-KEM-768 encapsulation key carried in subjectPublicKey.
 */
#define QSC_X509_ML_KEM_768_PUBLICKEY_SIZE 1184U

/*!
 * \def QSC_X509_ML_KEM_1024_PUBLICKEY_SIZE
 * \brief The size in octets of an ML-KEM-1024 encapsulation key carried in subjectPublicKey.
 */
#define QSC_X509_ML_KEM_1024_PUBLICKEY_SIZE 1568U

/*!
 * \def QSC_X509_SIGNATURE_MAX
 * \brief The maximum number of octets stored for a certificate signature value.
 */
#define QSC_X509_SIGNATURE_MAX 4627U

/*!
 * \def QSC_X509_SPKI_MAX
 * \brief The maximum number of octets stored for a subjectPublicKey BIT STRING payload.
 */
#define QSC_X509_SPKI_MAX 2624U

/*!
 * \brief X.509 public key algorithm identifiers.
 */
typedef enum qsc_x509_public_key_algorithm_t
{
    QSC_X509_PUBLIC_KEY_ALGORITHM_NONE = 0,                     /*!< No recognized public key algorithm was decoded. */
    QSC_X509_PUBLIC_KEY_ALGORITHM_RSA,                          /*!< The subject public key algorithm is RSA. */
    QSC_X509_PUBLIC_KEY_ALGORITHM_EC,                           /*!< The subject public key algorithm is elliptic curve public key. */
    QSC_X509_PUBLIC_KEY_ALGORITHM_ED25519,                      /*!< The subject public key algorithm is edwards elliptic curve public key. */
    QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA,                       /*!< The subject public key algorithm is ML-DSA. */
    QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM                        /*!< The subject public key algorithm is ML-KEM. */
} qsc_x509_public_key_algorithm;


/*!
 * \brief Post-quantum algorithm class identifiers.
 *
 * \details
 * These identifiers classify a recognized PQC parameter set by role. ML-DSA
 * is a signing algorithm family, and ML-KEM is a key-establishment algorithm
 * family. The separation is used by construction and validation code to reject
 * misuse of encapsulation keys in certificate-signing paths.
 */
typedef enum qsc_x509_pqc_algorithm_class_t
{
    QSC_X509_PQC_ALGORITHM_CLASS_NONE = 0,                      /*!< No PQC algorithm class is associated with the object. */
    QSC_X509_PQC_ALGORITHM_CLASS_SIGNATURE,                     /*!< The object carries a PQ signature algorithm or signing key. */
    QSC_X509_PQC_ALGORITHM_CLASS_KEM                            /*!< The object carries a PQ key-encapsulation algorithm or encapsulation key. */
} qsc_x509_pqc_algorithm_class;

/*!
 * \brief X.509 signature algorithm identifiers.
 */
typedef enum qsc_x509_signature_algorithm_t
{
    QSC_X509_SIGNATURE_ALGORITHM_NONE = 0,                      /*!< No recognized signature algorithm was decoded. */
    QSC_X509_SIGNATURE_ALGORITHM_RSA_MD5,                       /*!< The signature algorithm is md5WithRSAEncryption. */
    QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA1,                      /*!< The signature algorithm is sha1WithRSAEncryption. */
    QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA256,                    /*!< The signature algorithm is sha256WithRSAEncryption. */
    QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA384,                    /*!< The signature algorithm is sha384WithRSAEncryption. */
    QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA512,                    /*!< The signature algorithm is sha512WithRSAEncryption. */
    QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA1,                    /*!< The signature algorithm is ecdsa-with-SHA1. */
    QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256,                  /*!< The signature algorithm is ecdsa-with-SHA256. */
    QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384,                  /*!< The signature algorithm is ecdsa-with-SHA384. */
    QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512,                  /*!< The signature algorithm is ecdsa-with-SHA512. */
    QSC_X509_SIGNATURE_ALGORITHM_ED25519,                       /*!< The signature algorithm is eddsa. */
    QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44,                     /*!< The signature algorithm is pure ML-DSA-44. */
    QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65,                     /*!< The signature algorithm is pure ML-DSA-65. */
    QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87                      /*!< The signature algorithm is pure ML-DSA-87. */
} qsc_x509_signature_algorithm;

/*!
 * \brief Post-quantum parameter set identifiers used by ML-DSA and ML-KEM.
 */
typedef enum qsc_x509_pqc_parameter_set_t
{
    QSC_X509_PQC_PARAMETER_SET_NONE = 0,                        /*!< No recognized PQC parameter set was decoded. */
    QSC_X509_PQC_PARAMETER_SET_ML_DSA_44,                       /*!< The parameter set is ML-DSA-44. */
    QSC_X509_PQC_PARAMETER_SET_ML_DSA_65,                       /*!< The parameter set is ML-DSA-65. */
    QSC_X509_PQC_PARAMETER_SET_ML_DSA_87,                       /*!< The parameter set is ML-DSA-87. */
    QSC_X509_PQC_PARAMETER_SET_ML_KEM_512,                      /*!< The parameter set is ML-KEM-512. */
    QSC_X509_PQC_PARAMETER_SET_ML_KEM_768,                      /*!< The parameter set is ML-KEM-768. */
    QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024,                     /*!< The parameter set is ML-KEM-1024. */
} qsc_x509_pqc_parameter_set;

/*!
 * \brief X.509 digest algorithm identifiers.
 */
typedef enum qsc_x509_hash_algorithm_t
{
    QSC_X509_HASH_ALGORITHM_NONE = 0,                           /*!< No recognized digest algorithm was decoded. */
    QSC_X509_HASH_ALGORITHM_MD5,                                /*!< The digest algorithm is MD5. */
    QSC_X509_HASH_ALGORITHM_SHA1,                               /*!< The digest algorithm is SHA-1. */
    QSC_X509_HASH_ALGORITHM_SHA224,                             /*!< The digest algorithm is SHA-224. */
    QSC_X509_HASH_ALGORITHM_SHA256,                             /*!< The digest algorithm is SHA-256. */
    QSC_X509_HASH_ALGORITHM_SHA384,                             /*!< The digest algorithm is SHA-384. */
    QSC_X509_HASH_ALGORITHM_SHA512                              /*!< The digest algorithm is SHA-512. */
} qsc_x509_hash_algorithm;

/*!
 * \brief X.509 named elliptic curve identifiers.
 */
typedef enum qsc_x509_named_curve_t
{
    QSC_X509_NAMED_CURVE_NONE = 0,                              /*!< No recognized named curve was decoded. */
    QSC_X509_NAMED_CURVE_PRIME256V1,                            /*!< The named curve is prime256v1. */
    QSC_X509_NAMED_CURVE_SECP384R1,                             /*!< The named curve is secp384r1. */
    QSC_X509_NAMED_CURVE_SECP521R1                              /*!< The named curve is secp521r1. */
} qsc_x509_named_curve;

/*!
 * \brief Distinguished name attribute identifiers.
 */
typedef enum qsc_x509_name_attribute_type_t
{
    QSC_X509_NAME_ATTRIBUTE_NONE = 0,                           /*!< No recognized attribute type was decoded. */
    QSC_X509_NAME_ATTRIBUTE_COMMON_NAME,                        /*!< commonName. */
    QSC_X509_NAME_ATTRIBUTE_SURNAME,                            /*!< surname. */
    QSC_X509_NAME_ATTRIBUTE_SERIAL_NUMBER,                      /*!< serialNumber. */
    QSC_X509_NAME_ATTRIBUTE_COUNTRY_NAME,                       /*!< countryName. */
    QSC_X509_NAME_ATTRIBUTE_LOCALITY_NAME,                      /*!< localityName. */
    QSC_X509_NAME_ATTRIBUTE_STATE_OR_PROVINCE,                  /*!< stateOrProvinceName. */
    QSC_X509_NAME_ATTRIBUTE_STREET_ADDRESS,                     /*!< streetAddress. */
    QSC_X509_NAME_ATTRIBUTE_ORGANIZATION_NAME,                  /*!< organizationName. */
    QSC_X509_NAME_ATTRIBUTE_ORGANIZATIONAL_UNIT,                /*!< organizationalUnitName. */
    QSC_X509_NAME_ATTRIBUTE_TITLE,                              /*!< title. */
    QSC_X509_NAME_ATTRIBUTE_DESCRIPTION,                        /*!< description. */
    QSC_X509_NAME_ATTRIBUTE_GIVEN_NAME,                         /*!< givenName. */
    QSC_X509_NAME_ATTRIBUTE_INITIALS,                           /*!< initials. */
    QSC_X509_NAME_ATTRIBUTE_GENERATION_QUALIFIER,               /*!< generationQualifier. */
    QSC_X509_NAME_ATTRIBUTE_DN_QUALIFIER,                       /*!< dnQualifier. */
    QSC_X509_NAME_ATTRIBUTE_PSEUDONYM,                          /*!< pseudonym. */
    QSC_X509_NAME_ATTRIBUTE_DOMAIN_COMPONENT,                   /*!< domainComponent. */
    QSC_X509_NAME_ATTRIBUTE_EMAIL_ADDRESS,                      /*!< emailAddress. */
    QSC_X509_NAME_ATTRIBUTE_UNKNOWN                             /*!< The attribute type is present but not recognized by the registry. */
} qsc_x509_name_attribute_type;

/*!
 * \brief General name identifiers used by subjectAltName and issuerAltName.
 */
typedef enum qsc_x509_general_name_type_t
{
    QSC_X509_GENERAL_NAME_NONE = 0,                             /*!< No valid general name was decoded. */
    QSC_X509_GENERAL_NAME_OTHER_NAME,                           /*!< otherName [0]. */
    QSC_X509_GENERAL_NAME_RFC822_NAME,                          /*!< rfc822Name [1]. */
    QSC_X509_GENERAL_NAME_DNS_NAME,                             /*!< dNSName [2]. */
    QSC_X509_GENERAL_NAME_X400_ADDRESS,                         /*!< x400Address [3]. */
    QSC_X509_GENERAL_NAME_DIRECTORY_NAME,                       /*!< directoryName [4]. */
    QSC_X509_GENERAL_NAME_EDI_PARTY_NAME,                       /*!< ediPartyName [5]. */
    QSC_X509_GENERAL_NAME_UNIFORM_RESOURCE_IDENTIFIER,          /*!< uniformResourceIdentifier [6]. */
    QSC_X509_GENERAL_NAME_IP_ADDRESS,                           /*!< iPAddress [7]. */
    QSC_X509_GENERAL_NAME_REGISTERED_ID                         /*!< registeredID [8]. */
} qsc_x509_general_name_type;

/*!
 * \brief X.509 extension identifiers.
 */
/*!
 * \brief Encoded storage ownership model used by decoded X.509 objects.
 */
typedef enum qsc_x509_storage_class_t
{
    QSC_X509_STORAGE_CLASS_NONE = 0,                            /*!< No storage model has been assigned. */
    QSC_X509_STORAGE_CLASS_BORROWED,                            /*!< The bytes are borrowed from an external backing buffer. */
    QSC_X509_STORAGE_CLASS_OWNED                                /*!< The bytes are owned by the object and must be released by the owner. */
} qsc_x509_storage_class;

/*!
 * \brief A raw encoded byte region associated with a decoded object.
 */
QSC_EXPORT_API typedef struct qsc_x509_encoded_region_t
{
    const uint8_t* data;                                        /*!< Pointer to the original encoded bytes when available. */
    size_t length;                                              /*!< The number of octets in the encoded region. */
    qsc_x509_storage_class storage;                             /*!< The ownership model for the encoded region. */
} qsc_x509_encoded_region;

/*!
 * \brief A preserved signed DER region associated with a decoded signed object.
 *
 * \details
 * This is a semantic alias of qsc_x509_encoded_region used for the exact
 * DER bytes that were covered by a signature at the time the object was
 * encoded on the wire. The alias distinguishes verification-time truth from
 * general encoded storage used for convenience or inspection.
 */
typedef qsc_x509_encoded_region qsc_x509_signed_region;

typedef enum qsc_x509_extension_type_t
{
    QSC_X509_EXTENSION_NONE = 0,                                /*!< No recognized extension type was decoded. */
    QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER,                  /*!< subjectKeyIdentifier. */
    QSC_X509_EXTENSION_KEY_USAGE,                               /*!< keyUsage. */
    QSC_X509_EXTENSION_SUBJECT_ALT_NAME,                        /*!< subjectAltName. */
    QSC_X509_EXTENSION_ISSUER_ALT_NAME,                         /*!< issuerAltName. */
    QSC_X509_EXTENSION_BASIC_CONSTRAINTS,                       /*!< basicConstraints. */
    QSC_X509_EXTENSION_NAME_CONSTRAINTS,                        /*!< nameConstraints. */
    QSC_X509_EXTENSION_CRL_DISTRIBUTION_POINTS,                 /*!< cRLDistributionPoints. */
    QSC_X509_EXTENSION_CERTIFICATE_POLICIES,                    /*!< certificatePolicies. */
    QSC_X509_EXTENSION_CRL_NUMBER,                              /*!< cRLNumber. */
    QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER,                /*!< authorityKeyIdentifier. */
    QSC_X509_EXTENSION_EXTENDED_KEY_USAGE,                      /*!< extKeyUsage. */
    QSC_X509_EXTENSION_AUTHORITY_INFO_ACCESS,                   /*!< authorityInfoAccess. */
    QSC_X509_EXTENSION_SUBJECT_INFO_ACCESS,                     /*!< subjectInfoAccess. */
    QSC_X509_EXTENSION_UNKNOWN                                  /*!< The extension OID is present but not recognized by the registry. */
} qsc_x509_extension_type;

/*!
 * \brief Certificate key usage bit flags.
 */
typedef enum qsc_x509_key_usage_bits_t
{
    QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE = 0x0001U,             /*!< digitalSignature bit. */
    QSC_X509_KEY_USAGE_NON_REPUDIATION = 0x0002U,               /*!< nonRepudiation or contentCommitment bit. */
    QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT = 0x0004U,              /*!< keyEncipherment bit. */
    QSC_X509_KEY_USAGE_DATA_ENCIPHERMENT = 0x0008U,             /*!< dataEncipherment bit. */
    QSC_X509_KEY_USAGE_KEY_AGREEMENT = 0x0010U,                 /*!< keyAgreement bit. */
    QSC_X509_KEY_USAGE_KEY_CERT_SIGN = 0x0020U,                 /*!< keyCertSign bit. */
    QSC_X509_KEY_USAGE_CRL_SIGN = 0x0040U,                      /*!< cRLSign bit. */
    QSC_X509_KEY_USAGE_ENCIPHER_ONLY = 0x0080U,                 /*!< encipherOnly bit. */
    QSC_X509_KEY_USAGE_DECIPHER_ONLY = 0x0100U                  /*!< decipherOnly bit. */
} qsc_x509_key_usage_bits;

/*!
 * \brief Extended key usage bit flags for commonly used purposes.
 */
typedef enum qsc_x509_extended_key_usage_bits_t
{
    QSC_X509_EXTENDED_KEY_USAGE_NONE = 0x0000U,                 /*!< No recognized extended key usage bits are set. */
    QSC_X509_EXTENDED_KEY_USAGE_ANY = 0x0001U,                  /*!< anyExtendedKeyUsage. */
    QSC_X509_EXTENDED_KEY_USAGE_SERVER_AUTH = 0x0002U,          /*!< id-kp-serverAuth. */
    QSC_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH = 0x0004U,          /*!< id-kp-clientAuth. */
    QSC_X509_EXTENDED_KEY_USAGE_CODE_SIGNING = 0x0008U,         /*!< id-kp-codeSigning. */
    QSC_X509_EXTENDED_KEY_USAGE_EMAIL_PROTECTION = 0x0010U,     /*!< id-kp-emailProtection. */
    QSC_X509_EXTENDED_KEY_USAGE_TIME_STAMPING = 0x0020U,        /*!< id-kp-timeStamping. */
    QSC_X509_EXTENDED_KEY_USAGE_OCSP_SIGNING = 0x0040U          /*!< id-kp-OCSPSigning. */
} qsc_x509_extended_key_usage_bits;

/*!
 * \brief Parsed algorithm identifier data.
 */
QSC_EXPORT_API typedef struct qsc_x509_algorithm_identifier_t
{
    qsc_oid_id oid;                                             /*!< The raw registry identifier of the algorithm OID. */
    qsc_x509_public_key_algorithm publickey;                    /*!< The mapped public key algorithm, if applicable. */
    qsc_x509_signature_algorithm signature;                     /*!< The mapped signature algorithm, if applicable. */
    qsc_x509_hash_algorithm hash;                               /*!< The mapped digest algorithm, if applicable. */
    qsc_x509_named_curve curve;                                 /*!< The mapped named curve, if applicable. */
    qsc_x509_pqc_parameter_set pqcparameter;                    /*!< The mapped PQC parameter set, if applicable. */
    qsc_asn1_oid algorithm_oid;                                 /*!< The decoded algorithm object identifier. */
    qsc_asn1_oid parameter_oid;                                 /*!< The decoded parameter object identifier, if the parameter is an OID. */
    bool parameters_present;                                    /*!< true if the AlgorithmIdentifier included a parameters field. */
    bool parameters_null;                                       /*!< true if the parameters field was present and encoded as NULL. */
    bool parameters_oid;                                        /*!< true if the parameters field was present and encoded as an object identifier. */
} qsc_x509_algorithm_identifier;

/*!
 * \brief A decoded distinguished name attribute.
 */
QSC_EXPORT_API typedef struct qsc_x509_name_attribute_t
{
    qsc_x509_name_attribute_type type;                          /*!< The normalized attribute type. */
    qsc_oid_id oid;                                             /*!< The raw registry identifier of the attribute OID. */
    qsc_asn1_oid attribute_oid;                                 /*!< The decoded attribute object identifier. */
    uint8_t string_tag;                                         /*!< The ASN.1 string tag used to encode the attribute value. */
    uint16_t rdn_index;                                         /*!< The zero-based relative distinguished name index. */
    size_t length;                                              /*!< The number of octets in the decoded attribute string. */
    char value[QSC_X509_NAME_ATTRIBUTE_STRING_MAX + 1U];        /*!< The decoded attribute string in a normalized zero-terminated form. */
} qsc_x509_name_attribute;

/*!
 * \brief A decoded distinguished name.
 */
QSC_EXPORT_API typedef struct qsc_x509_name_t
{
    qsc_x509_name_attribute attributes[QSC_X509_NAME_ATTRIBUTES_MAX];   /*!< The decoded attribute list. */
    size_t count;                                               /*!< The number of valid attributes in the array. */
} qsc_x509_name;

/*!
 * \brief A decoded X.509 validity interval.
 */
QSC_EXPORT_API typedef struct qsc_x509_validity_t
{
    qsc_asn1_time notbefore;                                    /*!< The notBefore time. */
    qsc_asn1_time notafter;                                     /*!< The notAfter time. */
} qsc_x509_validity;

/*!
 * \brief A decoded general name entry.
 */
QSC_EXPORT_API typedef struct qsc_x509_general_name_t
{
    qsc_x509_general_name_type type;                            /*!< The normalized general name type. */
    qsc_oid_id oid;                                             /*!< The registry identifier when the entry is a registered object identifier. */
    qsc_asn1_oid registeredid;                                  /*!< The decoded registered object identifier when the type is registeredID. */
    size_t length;                                              /*!< The number of valid octets in the data buffer. */
    uint8_t data[QSC_X509_NAME_ATTRIBUTE_STRING_MAX + 1U];      /*!< The raw or normalized general name payload. */
} qsc_x509_general_name;

/*!
 * \brief A decoded subject public key information structure.
 */
QSC_EXPORT_API typedef struct qsc_x509_subject_public_key_info_t
{
    qsc_x509_algorithm_identifier algorithm;                    /*!< The subject public key algorithm identifier. */
    uint8_t publickey[QSC_X509_SPKI_MAX];                       /*!< The BIT STRING payload octets of the subject public key. */
    size_t publickeylen;                                        /*!< The number of valid octets in the publickey array. */
    uint8_t unusedbits;                                         /*!< The number of unused bits in the final public key octet. */
} qsc_x509_subject_public_key_info;

/*!
 * \brief Parsed basic constraints extension data.
 */
QSC_EXPORT_API typedef struct qsc_x509_basic_constraints_t
{
    bool present;                                               /*!< true if the extension was decoded. */
    bool critical;                                              /*!< true if the extension critical flag was set. */
    bool ca;                                                    /*!< true if cA is asserted. */
    bool pathlen_present;                                       /*!< true if pathLenConstraint is present. */
    uint32_t pathlen;                                           /*!< The pathLenConstraint value if present. */
} qsc_x509_basic_constraints;

/*!
 * \brief Parsed key usage extension data.
 */
QSC_EXPORT_API typedef struct qsc_x509_key_usage_t
{
    bool present;                                               /*!< true if the extension was decoded. */
    bool critical;                                              /*!< true if the extension critical flag was set. */
    uint16_t bits;                                              /*!< The normalized key usage bit mask. */
} qsc_x509_key_usage;

/*!
 * \brief Parsed extended key usage extension data.
 */
QSC_EXPORT_API typedef struct qsc_x509_extended_key_usage_t
{
    bool present;                                               /*!< true if the extension was decoded. */
    bool critical;                                              /*!< true if the extension critical flag was set. */
    uint32_t bits;                                              /*!< The normalized extended key usage bit mask. */
} qsc_x509_extended_key_usage;

/*!
 * \brief Parsed subject key identifier extension data.
 */
QSC_EXPORT_API typedef struct qsc_x509_subject_key_identifier_t
{
    bool present;                                               /*!< true if the extension was decoded. */
    bool critical;                                              /*!< true if the extension critical flag was set. */
    uint8_t identifier[QSC_X509_KEY_IDENTIFIER_MAX];            /*!< The subject key identifier octets. */
    size_t identifierlen;                                       /*!< The number of valid octets in the identifier array. */
} qsc_x509_subject_key_identifier;

/*!
 * \brief Parsed authority key identifier extension data.
 */
QSC_EXPORT_API typedef struct qsc_x509_authority_key_identifier_t
{
    bool present;                                               /*!< true if the extension was decoded. */
    bool critical;                                              /*!< true if the extension critical flag was set. */
    uint8_t keyidentifier[QSC_X509_KEY_IDENTIFIER_MAX];         /*!< The authority key identifier octets. */
    size_t keyidentifierlen;                                    /*!< The number of valid octets in the keyidentifier array. */
    bool issuer_present;                                        /*!< true if the authorityCertIssuer field was present. */
    bool issuername_present;                                    /*!< true if a directoryName form was decoded from authorityCertIssuer. */
    qsc_x509_name issuername;                                   /*!< The decoded authorityCertIssuer directoryName when present. */
    bool serial_present;                                        /*!< true if the authorityCertSerialNumber field was present. */
    uint8_t serial[QSC_X509_SERIAL_NUMBER_MAX];                 /*!< The authority certificate serial number octets. */
    size_t seriallen;                                           /*!< The number of valid octets in the serial array. */
} qsc_x509_authority_key_identifier;

/*!
 * \brief Parsed CRL number extension data.
 */
QSC_EXPORT_API typedef struct qsc_x509_crl_number_t
{
    bool present;                                               /*!< true if the extension was decoded or assigned. */
    bool critical;                                              /*!< true if the extension critical flag was set. */
    uint8_t value[QSC_X509_SERIAL_NUMBER_MAX];                  /*!< The CRL number INTEGER octets in normalized unsigned form. */
    size_t valuelen;                                            /*!< The number of valid octets in the value array. */
} qsc_x509_crl_number;

/*!
 * \brief Parsed subject alternative name extension data.
 */
QSC_EXPORT_API typedef struct qsc_x509_subject_alt_name_t
{
    bool present;                                               /*!< true if the extension was decoded. */
    bool critical;                                              /*!< true if the extension critical flag was set. */
    qsc_x509_general_name entries[QSC_X509_SAN_ENTRIES_MAX];    /*!< The decoded subject alternative name entries. */
    size_t count;                                               /*!< The number of valid entries in the array. */
} qsc_x509_subject_alt_name;

/*!
 * \brief Parsed issuer alternative name extension data.
 */
QSC_EXPORT_API typedef struct qsc_x509_issuer_alt_name_t
{
    bool present;                                               /*!< true if the extension was decoded. */
    bool critical;                                              /*!< true if the extension critical flag was set. */
    qsc_x509_general_name entries[QSC_X509_SAN_ENTRIES_MAX];    /*!< The decoded issuer alternative name entries. */
    size_t count;                                               /*!< The number of valid entries in the array. */
} qsc_x509_issuer_alt_name;

/*!
 * \brief A decoded certificate extension entry.
 */
QSC_EXPORT_API typedef struct qsc_x509_extension_t
{
    qsc_x509_extension_type type;                               /*!< The normalized extension type. */
    qsc_oid_id oid;                                             /*!< The raw registry identifier of the extension OID. */
    qsc_asn1_oid extension_oid;                                 /*!< The decoded extension object identifier. */
    bool critical;                                              /*!< true if the extension critical flag is set. */
    uint8_t value[QSC_X509_SPKI_MAX];                           /*!< The DER payload octets stored from the extnValue OCTET STRING contents. */
    size_t valuelen;                                            /*!< The number of valid octets in the value array. */
    qsc_x509_encoded_region rawextnvalue;                       /*!< Borrowed or owned reference to the original extnValue OCTET STRING contents. */
    bool decoded;                                               /*!< true if the extension was successfully decoded and initialized. */
} qsc_x509_extension;

/*!
 * \brief Parsed extension set data.
 */
QSC_EXPORT_API typedef struct qsc_x509_extensions_t
{
    qsc_x509_extension entries[QSC_X509_EXTENSIONS_MAX];        /*!< The raw decoded extension entries. */
    size_t count;                                               /*!< The number of valid extension entries. */
    bool decoded;                                               /*!< true if the extensions container was successfully decoded. */
    bool duplicatesrejected;                                    /*!< true if duplicate extension OIDs were actively checked and rejected. */
    qsc_x509_basic_constraints basicconstraints;                /*!< The parsed basic constraints extension, if present. */
    qsc_x509_key_usage keyusage;                                /*!< The parsed key usage extension, if present. */
    qsc_x509_extended_key_usage extendedkeyusage;               /*!< The parsed extended key usage extension, if present. */
    qsc_x509_subject_key_identifier subjectkeyidentifier;       /*!< The parsed subject key identifier extension, if present. */
    qsc_x509_crl_number crlnumber;                              /*!< The parsed or assigned CRL number extension, if present. */
    qsc_x509_authority_key_identifier authoritykeyidentifier;   /*!< The parsed authority key identifier extension, if present. */
    qsc_x509_subject_alt_name subjectaltname;                   /*!< The parsed subject alternative name extension, if present. */
    qsc_x509_issuer_alt_name issueraltname;                     /*!< The parsed issuer alternative name extension, if present. */
} qsc_x509_extensions;

/*!
 * \brief A parsed X.509 certificate object.
 */
QSC_EXPORT_API typedef struct qsc_x509_certificate_t
{
    uint32_t version;                                           /*!< The certificate version number in the range 1 to 3. */
    uint8_t serialnumber[QSC_X509_SERIAL_NUMBER_MAX];           /*!< The certificate serial number octets. */
    size_t serialnumberlen;                                     /*!< The number of valid octets in the serialnumber array. */
    qsc_x509_algorithm_identifier tbsignature;                  /*!< The TBSCertificate signature algorithm identifier. */
    qsc_x509_name issuer;                                       /*!< The certificate issuer distinguished name. */
    qsc_x509_validity validity;                                 /*!< The certificate validity interval. */
    qsc_x509_name subject;                                      /*!< The certificate subject distinguished name. */
    qsc_x509_subject_public_key_info subjectpublickeyinfo;      /*!< The subject public key information. */
    bool issueruniqueid_present;                                /*!< true if issuerUniqueID is present. */
    bool subjectuniqueid_present;                               /*!< true if subjectUniqueID is present. */
    qsc_x509_extensions extensions;                             /*!< The decoded certificate extensions. */
    qsc_x509_algorithm_identifier signaturealgorithm;           /*!< The outer certificate signature algorithm identifier. */
    uint8_t signature[QSC_X509_SIGNATURE_MAX];                  /*!< The certificate signature BIT STRING payload octets. */
    size_t signaturelen;                                        /*!< The number of valid octets in the signature array. */
    uint8_t signatureunusedbits;                                /*!< The number of unused bits in the final signature octet. */
    const uint8_t* tbsdata;                                     /*!< Pointer to the original TBSCertificate DER bytes within the source buffer. */
    size_t tbsdatalen;                                          /*!< The number of octets in the TBSCertificate DER encoding. */
    const uint8_t* der;                                         /*!< Pointer to the original certificate DER buffer. */
    size_t derlen;                                              /*!< The number of octets in the original certificate DER buffer. */
    bool derowned;                                              /*!< true if the certificate object owns and must release the DER buffer. */
} qsc_x509_certificate;

/*!
 * \brief A trust anchor entry.
 */
QSC_EXPORT_API typedef struct qsc_x509_trust_anchor_t
{
    qsc_x509_certificate certificate;                           /*!< The trusted certificate object. */
    bool selfsigned;                                            /*!< true if the trust anchor is self-signed. */
} qsc_x509_trust_anchor;

/*!
 * \brief A certificate chain container.
 */
QSC_EXPORT_API typedef struct qsc_x509_chain_t
{
    qsc_x509_certificate* certificates;                         /*!< Pointer to a caller-managed array of certificate objects. */
    size_t count;                                               /*!< The number of certificates in the chain. */
} qsc_x509_chain;

/*!
 * \brief A trust store container.
 */
QSC_EXPORT_API typedef struct qsc_x509_store_t
{
    qsc_x509_trust_anchor* anchors;                             /*!< Pointer to a caller-managed array of trust anchors. */
    size_t count;                                               /*!< The number of trust anchors in the store. */
    size_t capacity;                                            /*!< The of trust anchor store capacity. */
} qsc_x509_store;

/*!
 * \def QSC_X509_CERTIFICATE_WRITE_MAX
 * \brief The maximum number of octets used by the certificate writer scratch buffers.
 */
#define QSC_X509_CERTIFICATE_WRITE_MAX 8192U

/*!
 * \brief Certificate signing callback used by the X.509 writer layer.
 *
 * \param signaturealgorithm: [qsc_x509_signature_algorithm] The signature algorithm selected for the certificate.
 * \param tbsdata: [const uint8_t*] Pointer to the complete DER encoded TBSCertificate.
 * \param tbsdatalen: [size_t] The number of octets in the TBSCertificate encoding.
 * \param signature: [uint8_t*] Receives the encoded signature payload.
 * \param signaturelen: [size_t*] On input, the available signature buffer size. On success, the encoded signature size.
 * \param context: [void*] An opaque caller supplied context pointer.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
typedef qsc_asn1_status (*qsc_x509_certificate_sign_callback)(qsc_x509_signature_algorithm signaturealgorithm,
    const uint8_t* tbsdata, size_t tbsdatalen, uint8_t* signature, size_t* signaturelen, void* context);

/*!
 * \brief A mutable certificate builder used to construct an X.509 v3 certificate.
 */
QSC_EXPORT_API typedef struct qsc_x509_certificate_builder_t
{
    uint32_t version;                                           /*!< The certificate version number. Version 3 is encoded as value 2 in DER. */
    uint8_t serialnumber[QSC_X509_SERIAL_NUMBER_MAX];           /*!< The certificate serial number octets. */
    size_t serialnumberlen;                                     /*!< The number of valid octets in the serialnumber array. */
    qsc_x509_name issuer;                                       /*!< The issuer distinguished name. */
    qsc_x509_validity validity;                                 /*!< The certificate validity interval. */
    qsc_x509_name subject;                                      /*!< The subject distinguished name. */
    qsc_x509_subject_public_key_info spki;                      /*!< The subject public key information structure. */
    qsc_x509_algorithm_identifier signaturealgorithm;           /*!< The TBSCertificate signature AlgorithmIdentifier. */
    qsc_x509_extensions extensions;                             /*!< The certificate extension set. */
} qsc_x509_certificate_builder;

QSC_CPLUSPLUS_ENABLED_END

#endif
