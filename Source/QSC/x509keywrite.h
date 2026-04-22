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

#ifndef QSC_X509_KEYWRITE_H
#define QSC_X509_KEYWRITE_H

#include "qsccommon.h"
#include "x509key.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509keywrite.h
 * \brief X.509 private key encoding and PEM conversion interface.
 *
 * \details
 * This header defines the public interface used to encode normalized private
 * key objects into SEC 1 and PKCS #8 representations in both DER and PEM
 * forms. The interface supports generic encoding from a
 * qsc_x509_private_key container, caller-supplied raw key material and
 * algorithm identifiers, and convenience wrappers for ML-DSA and ML-KEM
 * parameter-set specific PKCS #8 emission. For EC keys, the PKCS #8 encoder
 * normalizes the AlgorithmIdentifier parameters to a namedCurve OID when the
 * caller supplies only the curve selector.
 *
 * The PKCS #8 helpers support optional inclusion of the embedded public key
 * when the underlying format and algorithm permit its representation. The SEC 1
 * helpers additionally provide control over whether algorithm parameters and
 * public key fields are emitted.
 */

/*!
 * \def QSC_X509_KEY_WRITE_MAX
 * \brief The maximum number of octets used by key writer scratch and output buffers.
 */
#define QSC_X509_KEY_WRITE_MAX 16384U

/*!
 * \brief Encode a normalized private key object as SEC 1 DER.
 *
 * \details
 * Serializes the supplied private-key container to DER encoded SEC 1 format.
 * The caller may request inclusion of algorithm parameters and an embedded
 * public key when supported by the underlying key representation.
 *
 * \param key: [const][struct] The source private-key container.
 * \param includeparameters: Includes algorithm parameters when set to true.
 * \param includepublickey: Includes the optional embedded public key when set to true.
 * \param output: The destination buffer receiving the DER encoding.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_encode_sec1_der(const qsc_x509_private_key* key, bool includeparameters, bool includepublickey, uint8_t* output, size_t* outputlen);

/*!
 * \brief Encode a normalized private key object as SEC 1 PEM.
 *
 * \details
 * Serializes the supplied private-key container to SEC 1 DER and converts the
 * result to PEM text form.
 *
 * \param key: [const][struct] The source private-key container.
 * \param includeparameters: Includes algorithm parameters when set to true.
 * \param includepublickey: Includes the optional embedded public key when set to true.
 * \param output: The destination character buffer receiving the PEM text.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_encode_sec1_pem(const qsc_x509_private_key* key, bool includeparameters, bool includepublickey, char* output, size_t* outputlen);

/*!
 * \brief Encode a normalized private key object as PKCS #8 DER.
 *
 * \details
 * Serializes the supplied private-key container to DER encoded PKCS #8 format.
 * The caller may request inclusion of the optional embedded public key.
 *
 * \param key: [const][struct] The source private-key container.
 * \param includepublickey: Includes the optional embedded public key when set to true.
 * \param output: The destination buffer receiving the DER encoding.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_encode_pkcs8_der(const qsc_x509_private_key* key, bool includepublickey, uint8_t* output, size_t* outputlen);

/*!
 * \brief Encode a normalized private key object as PKCS #8 PEM.
 *
 * \details
 * Serializes the supplied private-key container to PKCS #8 DER and converts
 * the result to PEM text form.
 *
 * \param key: [const][struct] The source private-key container.
 * \param includepublickey: Includes the optional embedded public key when set to true.
 * \param output: The destination character buffer receiving the PEM text.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_encode_pkcs8_pem(const qsc_x509_private_key* key, bool includepublickey, char* output, size_t* outputlen);

/*!
 * \brief Encode raw private key material as PKCS #8 DER.
 *
 * \details
 * Serializes caller-supplied private key bytes, algorithm identifier, and
 * optional public key bytes to DER encoded PKCS #8 format without requiring a
 * qsc_x509_private_key container.
 *
 * \param algorithm: [const][struct] The algorithm identifier to encode.
 * \param privatekey: [const] The raw private key bytes.
 * \param privatekeylen: The length of the private key in bytes.
 * \param publickey: [const] The optional raw public key bytes.
 * \param publickeylen: The length of the public key in bytes.
 * \param publickeypresent: Indicates whether the public key input is present.
 * \param output: The destination buffer receiving the DER encoding.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_encode_pkcs8_der_ex(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* privatekey, 
    size_t privatekeylen, const uint8_t* publickey, size_t publickeylen, bool publickeypresent, uint8_t* output, size_t* outputlen);

/*!
 * \brief Encode raw private key material as PKCS #8 PEM.
 *
 * \details
 * Serializes caller-supplied private key bytes, algorithm identifier, and
 * optional public key bytes to PKCS #8 DER and converts the result to PEM text
 * form.
 *
 * \param algorithm: [const][struct] The algorithm identifier to encode.
 * \param privatekey: [const] The raw private key bytes.
 * \param privatekeylen: The length of the private key in bytes.
 * \param publickey: [const] The optional raw public key bytes.
 * \param publickeylen: The length of the public key in bytes.
 * \param publickeypresent: Indicates whether the public key input is present.
 * \param output: The destination character buffer receiving the PEM text.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_encode_pkcs8_pem_ex(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* privatekey, 
    size_t privatekeylen, const uint8_t* publickey, size_t publickeylen, bool publickeypresent, char* output, size_t* outputlen);

/*!
 * \brief Encode an ML-DSA private key as PKCS #8 DER.
 *
 * \details
 * Serializes caller-supplied ML-DSA private key material using the selected
 * ML-DSA parameter set and emits DER encoded PKCS #8 output.
 *
 * \param parameter: [enum] The ML-DSA parameter set identifier.
 * \param privatekey: [const] The raw ML-DSA private key bytes.
 * \param privatekeylen: The length of the private key in bytes.
 * \param publickey: [const] The optional raw ML-DSA public key bytes.
 * \param publickeylen: The length of the public key in bytes.
 * \param publickeypresent: Indicates whether the public key input is present.
 * \param output: The destination buffer receiving the DER encoding.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_encode_pkcs8_ml_dsa_der(qsc_x509_pqc_parameter_set parameter, const uint8_t* privatekey, 
    size_t privatekeylen, const uint8_t* publickey, size_t publickeylen, bool publickeypresent, uint8_t* output, size_t* outputlen);

/*!
 * \brief Encode an ML-DSA private key as PKCS #8 PEM.
 *
 * \details
 * Serializes caller-supplied ML-DSA private key material using the selected
 * ML-DSA parameter set and converts the resulting PKCS #8 object to PEM text.
 *
 * \param parameter: [enum] The ML-DSA parameter set identifier.
 * \param privatekey: [const] The raw ML-DSA private key bytes.
 * \param privatekeylen: The length of the private key in bytes.
 * \param publickey: [const] The optional raw ML-DSA public key bytes.
 * \param publickeylen: The length of the public key in bytes.
 * \param publickeypresent: Indicates whether the public key input is present.
 * \param output: The destination character buffer receiving the PEM text.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_encode_pkcs8_ml_dsa_pem(qsc_x509_pqc_parameter_set parameter, const uint8_t* privatekey, 
    size_t privatekeylen, const uint8_t* publickey, size_t publickeylen, bool publickeypresent, char* output, size_t* outputlen);

/*!
 * \brief Encode an ML-KEM private key as PKCS #8 DER.
 *
 * \details
 * Serializes caller-supplied ML-KEM private key material using the selected
 * ML-KEM parameter set and emits DER encoded PKCS #8 output.
 *
 * \param parameter: [enum] The ML-KEM parameter set identifier.
 * \param privatekey: [const] The raw ML-KEM private key bytes.
 * \param privatekeylen: The length of the private key in bytes.
 * \param publickey: [const] The optional raw ML-KEM public key bytes.
 * \param publickeylen: The length of the public key in bytes.
 * \param publickeypresent: Indicates whether the public key input is present.
 * \param output: The destination buffer receiving the DER encoding.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_encode_pkcs8_ml_kem_der(qsc_x509_pqc_parameter_set parameter, const uint8_t* privatekey, 
    size_t privatekeylen, const uint8_t* publickey, size_t publickeylen, bool publickeypresent, uint8_t* output, size_t* outputlen);

/*!
 * \brief Encode an ML-KEM private key as PKCS #8 PEM.
 *
 * \details
 * Serializes caller-supplied ML-KEM private key material using the selected
 * ML-KEM parameter set and converts the resulting PKCS #8 object to PEM text.
 *
 * \param parameter: [enum] The ML-KEM parameter set identifier.
 * \param privatekey: [const] The raw ML-KEM private key bytes.
 * \param privatekeylen: The length of the private key in bytes.
 * \param publickey: [const] The optional raw ML-KEM public key bytes.
 * \param publickeylen: The length of the public key in bytes.
 * \param publickeypresent: Indicates whether the public key input is present.
 * \param output: The destination character buffer receiving the PEM text.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_private_key_encode_pkcs8_ml_kem_pem(qsc_x509_pqc_parameter_set parameter, const uint8_t* privatekey, 
    size_t privatekeylen, const uint8_t* publickey, size_t publickeylen, bool publickeypresent, char* output, size_t* outputlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
