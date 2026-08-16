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

#ifndef QSC_X509_REV_EXT_H
#define QSC_X509_REV_EXT_H

#include "x509crl.h"
#include "x509cert.h"
#include <stdbool.h>

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509revext.h
 * \brief Extended X.509 revocation helpers for delta-CRL application and stapled OCSP verification.
 *
 * \details
 * This header defines supplemental revocation-processing helpers that extend the
 * base CRL and certificate validation interfaces. The functions declared here
 * support two specialized operations: applying a delta CRL to a base CRL to
 * produce a merged revocation view, and verifying a stapled OCSP response
 * against a certificate and its issuer.
 *
 * The delta-CRL helper is intended for environments that maintain an existing
 * base CRL and wish to incorporate incremental revocation updates while still
 * enforcing issuer, time, and signature validation. The stapled OCSP helper is
 * intended for network protocols that carry an OCSP response alongside the
 * certificate presentation.
 */

/*!
 * \brief Check whether a CRL can be used to determine the status of a certificate.
 *
 * \details
 * Validates the supported issuingDistributionPoint scope restrictions for the
 * supplied CRL and target certificate. CRLs using scope forms that are not
 * implemented by QSC, including named distribution points, reason-partitioned
 * CRLs, indirect CRLs, and attribute-certificate-only CRLs, are rejected
 * fail-closed rather than being treated as complete status information.
 *
 * \param crl: [const][struct] The CRL whose scope is being evaluated.
 * \param certificate: [const][struct] The certificate whose status is being checked.
 * \param issuer: [const][struct] The issuer certificate for the target certificate.
 *
 * \return [enum] Returns QSC_X509_CRL_VERIFY_STATUS_SUCCESS only when the CRL
 * can safely determine status for the supplied certificate.
 */
QSC_EXPORT_API qsc_x509_crl_verify_status qsc_x509_crl_check_certificate_scope(const qsc_x509_crl* crl, const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer);

/*!
 * \brief Apply a delta CRL to a base CRL and produce a merged CRL view.
 *
 * \details
 * Validates the supplied base CRL and delta CRL against the issuer certificate
 * and evaluation time, then applies the delta revocation updates to the base
 * CRL and writes the resulting merged revocation state to the destination CRL
 * object.
 *
 * The caller supplies the CRL signature verification callback so that
 * cryptographic signature checking remains aligned with the surrounding X.509
 * verification layer and supported algorithm set.
 *
 * \param mergedcrl: [struct] The destination CRL object receiving the merged result.
 * \param basecrl: [const][struct] The base CRL to update.
 * \param deltacrl: [const][struct] The delta CRL containing incremental revocation changes.
 * \param issuer: [const][struct] The issuer certificate expected to have signed the CRLs.
 * \param now: [const][struct] The evaluation time used for CRL validity checks.
 * \param callback: The caller-supplied CRL signature verification callback.
 * \param state: Caller-defined opaque context passed to the verification callback.
 *
 * \return [enum] Returns a qsc_x509_crl_verify_status code indicating success or the reason the merge failed.
 */
QSC_EXPORT_API qsc_x509_crl_verify_status qsc_x509_apply_delta_crl(qsc_x509_crl* mergedcrl, const qsc_x509_crl* basecrl, const qsc_x509_crl* deltacrl,
    const qsc_x509_certificate* issuer, const qsc_asn1_time* now, qsc_x509_crl_signature_verify_callback callback, void* state);

/*!
 * \brief Verify a stapled OCSP response for a certificate.
 *
 * \details
 * Parses and validates a stapled OCSP response associated with the supplied
 * certificate and issuer certificate. This helper is intended for use in
 * protocols that carry an OCSP response out-of-band from direct responder
 * retrieval, such as TLS certificate status stapling.
 *
 * \param stapled: [const] The stapled OCSP response bytes.
 * \param stapledlen: The length of the stapled OCSP response in bytes.
 * \param certificate: [const][struct] The certificate whose status is being verified.
 * \param issuer: [const][struct] The issuer certificate for the target certificate.
 *
 * \return Returns true if the stapled OCSP response is accepted for the certificate; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_ocsp_stapled_verify(const uint8_t* stapled, size_t stapledlen, const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer);

QSC_CPLUSPLUS_ENABLED_END

#endif
