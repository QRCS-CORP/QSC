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

#ifndef QSC_X509_CSR_H
#define QSC_X509_CSR_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509csr.h
 * \brief PKCS#10 certificate signing request encoding, decoding, mutation, and verification interface.
 *
 * \details
 * This header defines the public interface used to construct, decode, inspect,
 * sign, verify, and PEM-convert PKCS#10 certificate signing requests. The CSR
 * object stores the request subject name, subject public key information,
 * signature algorithm identifier, requested X.509 extensions, optional generic
 * CSR attributes, signature bytes, and references to the original DER-encoded
 * CertificationRequestInfo and full CertificationRequest buffers.
 *
 * The interface supports direct field mutation for request construction,
 * extensionRequest normalization through the qsc_x509_extensions container,
 * generic non-extension attribute storage, callback-driven signing, default and
 * custom verification paths, and convenience helpers for Subject Alternative
 * Name, Extended Key Usage, Subject Key Identifier, ML-DSA, and ML-KEM request
 * population. Decoded CSRs preserve an owned copy of the original DER request
 * buffer together with the exact CertificationRequestInfo signed region so that
 * verification can prefer the original wire encoding.
 */

/*!
 * \def QSC_X509_CSR_ATTRIBUTES_MAX
 * \brief The maximum number of generic non-extension CSR attributes stored in a CSR object.
 */
#define QSC_X509_CSR_ATTRIBUTES_MAX 8U

/*!
 * \def QSC_X509_CSR_ATTRIBUTE_VALUE_MAX
 * \brief The maximum number of DER octets stored for a generic CSR attribute value.
 */
#define QSC_X509_CSR_ATTRIBUTE_VALUE_MAX 1024U

/*!
 * \def QSC_X509_CSR_WRITE_MAX
 * \brief The maximum number of octets used by CSR writer scratch buffers.
 */
#define QSC_X509_CSR_WRITE_MAX 16384U

/*!
 * \brief A decoded or mutable PKCS#10 CSR attribute.
 *
 * \details
 * The value buffer stores the DER encoding of the first value element contained
 * in the Attribute values SET. The PKCS#9 extensionRequest attribute is not
 * represented through this generic container; it is normalized into the
 * qsc_x509_extensions structure stored in the parent CSR object.
 */
QSC_EXPORT_API typedef struct qsc_x509_csr_attribute_t
{
    qsc_asn1_oid oid;                                               /*!< The attribute object identifier. */
    uint8_t value[QSC_X509_CSR_ATTRIBUTE_VALUE_MAX];                /*!< The DER encoding of the first attribute value. */
    size_t valuelen;                                                /*!< The number of valid octets in the value buffer. */
} qsc_x509_csr_attribute;

/*!
 * \brief A decoded or mutable PKCS#10 certificate signing request.
 */
QSC_EXPORT_API typedef struct qsc_x509_csr_t
{
    uint32_t version;                                               /*!< The CertificationRequestInfo version. This is encoded as zero for PKCS#10 v1. */
    qsc_x509_name subject;                                          /*!< The request subject distinguished name. */
    qsc_x509_subject_public_key_info spki;                          /*!< The subject public key information. */
    qsc_x509_algorithm_identifier signaturealgorithm;               /*!< The outer signature AlgorithmIdentifier. */
    qsc_x509_extensions extensions;                                 /*!< The optional normalized extensionRequest payload extensions. */
    qsc_x509_csr_attribute attributes[QSC_X509_CSR_ATTRIBUTES_MAX]; /*!< The generic non-extension CSR attributes. */
    size_t attributecount;                                          /*!< The number of valid generic CSR attributes. */
    uint8_t signature[QSC_X509_SIGNATURE_MAX];                      /*!< The CSR signature BIT STRING payload octets. */
    size_t signaturelen;                                            /*!< The number of valid octets in the signature array. */
    uint8_t signatureunusedbits;                                    /*!< The number of unused bits in the final signature octet. */
    const uint8_t* infodata;                                        /*!< Pointer to the preserved CertificationRequestInfo DER bytes. */
    size_t infodatalen;                                             /*!< The number of octets in the preserved CertificationRequestInfo DER encoding. */
    const uint8_t* der;                                             /*!< Pointer to the preserved CSR DER buffer. */
    size_t derlen;                                                  /*!< The number of octets in the preserved CSR DER buffer. */
    bool derowned;                                                  /*!< true if der points to heap storage owned by the CSR object. */
} qsc_x509_csr;

/*!
 * \typedef qsc_x509_csr_signature_verify_callback
 * \brief Caller-supplied CSR signature verification callback type.
 *
 * \details
 * This callback is used by qsc_x509_csr_verify_ex to delegate cryptographic
 * signature verification to the surrounding verification layer.
 *
 * \param csr: [const][struct] The CSR to verify.
 * \param state: Caller-defined opaque verification context.
 *
 * \return Returns true if the CSR signature is valid; otherwise returns false.
 */
typedef bool (*qsc_x509_csr_signature_verify_callback)(const qsc_x509_csr* csr, void* state);

/*!
 * \brief Verify a CSR signature against a caller-supplied signer SPKI.
 *
 * \details
 * This function verifies the CSR signature using the supplied subject public
 * key information structure rather than the SPKI carried inside the CSR. It is
 * intended for cases where signature verification is performed against an
 * external or previously normalized public key representation.
 *
 * \param csr: [const][struct] The CSR to verify.
 * \param signerspki: [const][struct] The signer subject public key information used for verification.
 *
 * \return Returns true if the CSR signature is valid; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_csr_verify_with_spki(const qsc_x509_csr* csr, const qsc_x509_subject_public_key_info* signerspki);

/*!
 * \brief Initialize a CSR object.
 *
 * \details
 * Initializes a CSR object to a clean default state suitable for first use.
 * For an object that may already hold decoded or owned DER state, call
 * qsc_x509_csr_clear() instead.
 *
 * \param csr: [struct] The CSR object to initialize.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_csr_initialize(qsc_x509_csr* csr);

/*!
 * \brief Clear a CSR object.
 *
 * \details
 * Clears all mutable and decoded state held in the CSR object.
 *
 * \param csr: [struct] The CSR object to clear.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_csr_clear(qsc_x509_csr* csr);

/*!
 * \brief Set the CSR subject distinguished name.
 *
 * \param csr: [struct] The CSR object to update.
 * \param subject: [const][struct] The subject distinguished name.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_set_subject(qsc_x509_csr* csr, const qsc_x509_name* subject);

/*!
 * \brief Set the CSR subject public key information.
 *
 * \param csr: [struct] The CSR object to update.
 * \param spki: [const][struct] The subject public key information.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_set_spki(qsc_x509_csr* csr, const qsc_x509_subject_public_key_info* spki);

/*!
 * \brief Set the CSR signature algorithm identifier.
 *
 * \param csr: [struct] The CSR object to update.
 * \param signaturealgorithm: [const][struct] The signature algorithm identifier.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_set_signature_algorithm(qsc_x509_csr* csr, const qsc_x509_algorithm_identifier* signaturealgorithm);

/*!
 * \brief Set the normalized extensionRequest payload.
 *
 * \details
 * Replaces the CSR extensionRequest contents with the supplied X.509 extension
 * set.
 *
 * \param csr: [struct] The CSR object to update.
 * \param extensions: [const][struct] The requested extension set.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_set_extension_request(qsc_x509_csr* csr, const qsc_x509_extensions* extensions);

/*!
 * \brief Get the normalized extensionRequest payload.
 *
 * \param csr: [const][struct] The CSR object to inspect.
 *
 * \return Returns a pointer to the requested extension set.
 */
QSC_EXPORT_API const qsc_x509_extensions* qsc_x509_csr_get_extension_request(const qsc_x509_csr* csr);

/*!
 * \brief Copy the normalized extensionRequest payload.
 *
 * \param csr: [const][struct] The CSR object to inspect.
 * \param extensions: [struct] The destination extension set.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_copy_extension_request(const qsc_x509_csr* csr, qsc_x509_extensions* extensions);

/*!
 * \brief Encode the CertificationRequestInfo structure as DER.
 *
 * \details
 * Serializes only the unsigned CertificationRequestInfo portion of the CSR.
 *
 * \param csr: [const][struct] The CSR object to encode.
 * \param output: The destination buffer receiving the DER output.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_encode_info_der(const qsc_x509_csr* csr, uint8_t* output, size_t* outputlen);

/*!
 * \brief Encode and sign a complete CSR as DER.
 *
 * \details
 * Encodes the CertificationRequestInfo structure, invokes the supplied signing
 * callback, and emits the complete DER encoded CertificationRequest object.
 *
 * \param csr: [const][struct] The CSR object to encode.
 * \param signcallback: The CSR signing callback.
 * \param context: Caller-defined opaque signing context.
 * \param output: The destination buffer receiving the DER CSR.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_encode_der(const qsc_x509_csr* csr, qsc_x509_certificate_sign_callback signcallback, void* context, uint8_t* output, size_t* outputlen);

/*!
 * \brief Sign and encode a CSR as DER.
 *
 * \details
 * This function performs CSR signing and final DER emission. It provides a
 * semantically explicit signing entry point alongside qsc_x509_csr_encode_der.
 *
 * \param csr: [const][struct] The CSR object to sign.
 * \param signcallback: The CSR signing callback.
 * \param context: Caller-defined opaque signing context.
 * \param output: The destination buffer receiving the DER CSR.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_sign(const qsc_x509_csr* csr, qsc_x509_certificate_sign_callback signcallback, void* context, uint8_t* output, size_t* outputlen);

/*!
 * \brief Decode a DER encoded CSR.
 *
 * \param csr: [struct] The destination CSR object.
 * \param input: [const] The DER encoded CSR input buffer.
 * \param inputlen: The length of the input buffer in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_decode_der(qsc_x509_csr* csr, const uint8_t* input, size_t inputlen);

/*!
 * \brief Decode a PEM encoded CSR.
 *
 * \param csr: [struct] The destination CSR object.
 * \param input: [const] The PEM encoded CSR input buffer.
 * \param inputlen: The length of the input buffer in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_decode_pem(qsc_x509_csr* csr, const char* input, size_t inputlen);

/*!
 * \brief Find a requested extension by type.
 *
 * \param csr: [const][struct] The CSR object to inspect.
 * \param type: [enum] The extension type to locate.
 *
 * \return Returns a pointer to the matching extension, or NULL if no match is present.
 */
QSC_EXPORT_API const qsc_x509_extension* qsc_x509_csr_find_extension(const qsc_x509_csr* csr, qsc_x509_extension_type type);

/*!
 * \brief Verify a CSR using its contained subject public key information.
 *
 * \param csr: [const][struct] The CSR to verify.
 *
 * \return Returns true if the CSR signature is valid; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_csr_verify(const qsc_x509_csr* csr);

/*!
 * \brief Verify a CSR using a caller-supplied verification callback.
 *
 * \param csr: [const][struct] The CSR to verify.
 * \param verifycallback: The verification callback.
 * \param state: Caller-defined opaque verification context.
 *
 * \return Returns true if the CSR signature is valid; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_csr_verify_ex(const qsc_x509_csr* csr, qsc_x509_csr_signature_verify_callback verifycallback, void* state);

/*!
 * \brief Encode a DER CSR as PEM.
 *
 * \param der: [const] The DER encoded CSR input.
 * \param derlen: The length of the DER input in bytes.
 * \param output: The destination character buffer receiving the PEM text.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_encode_pem(const uint8_t* der, size_t derlen, char* output, size_t* outputlen);

/*!
 * \brief Add a generic non-extension CSR attribute.
 *
 * \details
 * Adds a generic CSR attribute identified by the supplied OID and storing the
 * DER encoding of the first attribute value.
 *
 * \param csr: [struct] The CSR object to update.
 * \param oid: [const][struct] The attribute object identifier.
 * \param value: [const] The DER encoded first attribute value.
 * \param valuelen: The length of the value in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_add_attribute(qsc_x509_csr* csr, const qsc_asn1_oid* oid, const uint8_t* value, size_t valuelen);

/*!
 * \brief Get a generic CSR attribute by OID.
 *
 * \param csr: [const][struct] The CSR object to inspect.
 * \param oid: [const][struct] The attribute object identifier to locate.
 *
 * \return Returns a pointer to the matching attribute, or NULL if no match is present.
 */
QSC_EXPORT_API const qsc_x509_csr_attribute* qsc_x509_csr_get_attribute(const qsc_x509_csr* csr, const qsc_asn1_oid* oid);

/*!
 * \brief Set the requested Subject Alternative Name extension.
 *
 * \param csr: [struct] The CSR object to update.
 * \param subjectaltname: [const][struct] The Subject Alternative Name value.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_set_subject_alt_name(qsc_x509_csr* csr, const qsc_x509_subject_alt_name* subjectaltname);

/*!
 * \brief Add a DNS name to the requested Subject Alternative Name extension.
 *
 * \param csr: [struct] The CSR object to update.
 * \param dnsname: [const] The DNS name string.
 * \param dnsnamelen: The length of the DNS name string in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_add_san_dns(qsc_x509_csr* csr, const char* dnsname, size_t dnsnamelen);

/*!
 * \brief Add an IP address to the requested Subject Alternative Name extension.
 *
 * \param csr: [struct] The CSR object to update.
 * \param address: [const] The binary IP address.
 * \param addresslen: The length of the binary IP address in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_add_san_ip(qsc_x509_csr* csr, const uint8_t* address, size_t addresslen);

/*!
 * \brief Set the requested Extended Key Usage extension.
 *
 * \param csr: [struct] The CSR object to update.
 * \param extendedkeyusage: [const][struct] The Extended Key Usage value.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_set_extended_key_usage(qsc_x509_csr* csr, const qsc_x509_extended_key_usage* extendedkeyusage);

/*!
 * \brief Set the requested Subject Key Identifier extension.
 *
 * \param csr: [struct] The CSR object to update.
 * \param subjectkeyidentifier: [const][struct] The Subject Key Identifier value.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_set_subject_key_identifier(qsc_x509_csr* csr, const qsc_x509_subject_key_identifier* subjectkeyidentifier);

/*!
 * \brief Set the CSR signature algorithm to an ML-DSA variant.
 *
 * \details
 * Selects the ML-DSA parameter set corresponding to the supplied level and
 * updates the CSR signature algorithm identifier accordingly.
 *
 * \param csr: [struct] The CSR object to update.
 * \param level: The ML-DSA parameter-set level selector.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_set_ml_dsa_signature_algorithm(qsc_x509_csr* csr, uint32_t level);

/*!
 * \brief Set the CSR subject public key information to an ML-DSA key.
 *
 * \details
 * Populates the CSR SPKI field using an ML-DSA public key and the supplied
 * ML-DSA parameter-set level.
 *
 * \param csr: [struct] The CSR object to update.
 * \param level: The ML-DSA parameter-set level selector.
 * \param publickey: [const] The ML-DSA public key bytes.
 * \param publickeylen: The length of the public key in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_set_ml_dsa_spki(qsc_x509_csr* csr, uint32_t level, const uint8_t* publickey, size_t publickeylen);

/*!
 * \brief Set the CSR subject public key information to an ML-KEM key.
 *
 * \details
 * Populates the CSR SPKI field using an ML-KEM public key and the supplied
 * ML-KEM parameter-set level.
 *
 * \param csr: [struct] The CSR object to update.
 * \param level: The ML-KEM parameter-set level selector.
 * \param publickey: [const] The ML-KEM public key bytes.
 * \param publickeylen: The length of the public key in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_csr_set_ml_kem_spki(qsc_x509_csr* csr, uint32_t level, const uint8_t* publickey, size_t publickeylen);

QSC_CPLUSPLUS_ENABLED_END

#endif
