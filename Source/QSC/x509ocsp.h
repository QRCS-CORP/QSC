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

#ifndef QSC_X509_OCSP_H
#define QSC_X509_OCSP_H

#include "qsccommon.h"
#include "x509cert.h"
#include "x509store.h"
#include "x509verify.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509ocsp.h
 * \brief X.509 OCSP response parsing and online certificate status validation interface.
 *
 * \details
 * This header defines the public interface used to parse a simplified OCSP
 * response result and to perform OCSP-based certificate status validation
 * through a caller-supplied fetch callback. The interface models the resulting
 * certificate status, optional revocation time, and optional nonce returned by
 * the responder.
 *
 * The OCSP transport operation is intentionally abstracted. Network retrieval
 * is delegated to the application through a callback that accepts the
 * responder URL and a serialized OCSP request buffer and returns the responder
 * output bytes for local validation and parsing.
 */

/*!
 * \def QSC_X509_OCSP_NONCE_MAX
 * \brief The maximum supported OCSP nonce length in bytes.
 */
#define QSC_X509_OCSP_NONCE_MAX 32U

/*!
 * \enum qsc_x509_ocsp_cert_status
 * \brief OCSP certificate status codes.
 */
typedef enum qsc_x509_ocsp_cert_status_t
{
    QSC_X509_OCSP_STATUS_GOOD = 0,          /*!< The responder reported that the certificate status is good. */
    QSC_X509_OCSP_STATUS_REVOKED = 1,       /*!< The responder reported that the certificate has been revoked. */
    QSC_X509_OCSP_STATUS_UNKNOWN = 2        /*!< The responder could not determine the certificate status. */
} qsc_x509_ocsp_cert_status;

/*!
 * \struct qsc_x509_ocsp_response
 * \brief A parsed OCSP response status summary.
 *
 * \details
 * This structure stores the normalized certificate status extracted from an
 * OCSP response, together with an optional revocation time and optional nonce
 * value when present.
 */
typedef struct qsc_x509_ocsp_response_t
{
    qsc_x509_ocsp_cert_status status;       /*!< The normalized OCSP certificate status result. */
    qsc_asn1_time revocationtime;           /*!< The revocation time when the responder reports a revoked status. */
    bool hasnonce;                          /*!< Indicates whether the response included a nonce value. */
    uint8_t nonce[QSC_X509_OCSP_NONCE_MAX]; /*!< The responder nonce bytes when present. */
    size_t noncelen;                        /*!< The number of valid bytes in the nonce buffer. */
} qsc_x509_ocsp_response;

/*!
 * \typedef qsc_x509_ocsp_fetch_callback
 * \brief Caller-supplied OCSP transport callback.
 *
 * \details
 * This callback performs the responder fetch operation for OCSP validation.
 * The caller receives the responder URL and serialized request bytes and is
 * responsible for transmitting the request and returning the raw OCSP response
 * bytes.
 *
 * \param url: [const] The OCSP responder URL.
 * \param request: [const] The serialized OCSP request buffer.
 * \param requestlen: The length of the request buffer in bytes.
 * \param response: The destination buffer receiving the responder output bytes.
 * \param responselen: The input capacity of the response buffer and, on success, the number of bytes written.
 * \param context: Caller-defined opaque transport context.
 *
 * \return Returns true on successful fetch and response delivery; otherwise returns false.
 */
typedef bool (*qsc_x509_ocsp_fetch_callback)(const char* url, const uint8_t* request, size_t requestlen, uint8_t* response, size_t* responselen, void* context);

/*!
 * \brief Parse an OCSP response from DER.
 *
 * \details
 * Decodes a DER encoded OCSP response using strict DER parsing and extracts the normalized certificate
 * status, optional revocation time, and optional nonce fields into the
 * supplied response object.
 *
 * \param der: [const] The DER encoded OCSP response buffer.
 * \param derlen: The length of the DER buffer in bytes.
 * \param response: [struct] The destination parsed OCSP response object.
 *
 * \return Returns true if the OCSP response was successfully parsed; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_ocsp_parse_response(const uint8_t* der, size_t derlen, qsc_x509_ocsp_response* response);

/*!
 * \brief Validate a certificate using OCSP.
 *
 * \details
 * Builds an OCSP request for the supplied certificate and issuer certificate,
 * retrieves the responder output through the caller-supplied fetch callback,
 * validates and parses the result, verifies the BasicOCSPResponse using the preserved signed bytes, and stores the normalized OCSP status in
 * the destination response object.
 *
 * \param certificate: [const][struct] The certificate whose revocation status is being queried.
 * \param issuer: [const][struct] The issuer certificate for the queried certificate.
 * \param url: [const] The OCSP responder URL.
 * \param fetch: The caller-supplied OCSP transport callback.
 * \param context: Caller-defined opaque transport context.
 * \param now: [const][struct] The caller-supplied validation time used for responder and response freshness checks.
 * \param response: [struct] The destination parsed OCSP response object.
 *
 * \return Returns true if OCSP validation completed successfully; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_ocsp_validate(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer,
    const char* url, qsc_x509_ocsp_fetch_callback fetch, void* context, const qsc_asn1_time* now, qsc_x509_ocsp_response* response);

/*!
 * \brief Verify an OCSP responder certificate.
 *
 * \details
 * Validates that the supplied responder certificate is acceptable for signing
 * OCSP BasicOCSPResponse objects for the supplied issuer. The function checks
 * the responder validity interval, enforces the OCSP signing extended key
 * usage for delegated responders, optionally accepts an explicitly trusted
 * responder present in the supplied trust store, and otherwise verifies the
 * responder certificate against the issuer certificate using the library's
 * signature verification path.
 *
 * When the responder certificate is the issuer certificate itself, the OCSP
 * signing extended key usage is not required. An explicitly trusted responder
 * present in the supplied trust store is accepted under the caller's local
 * trust policy. Otherwise, a delegated responder must include the explicit
 * id-kp-OCSPSigning extended key usage. If the KeyUsage extension is present,
 * the digitalSignature bit must be set.
 *
 * \param responder: [const][struct] The responder certificate extracted from the OCSP response.
 * \param issuer: [const][struct] The issuer certificate for the certificate whose status is being checked.
 * \param store: [const][struct] Optional trust store containing explicitly trusted responder certificates.
 * \param now: [const][struct] The caller-supplied validation time.
 *
 * \return Returns true if the responder certificate is acceptable for OCSP response signing; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_ocsp_verify_responder(const qsc_x509_certificate* responder, const qsc_x509_certificate* issuer, const qsc_x509_store* store, const qsc_asn1_time* now);

QSC_CPLUSPLUS_ENABLED_END

#endif
