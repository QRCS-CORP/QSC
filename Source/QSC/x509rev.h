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

#ifndef QSC_X509_REV_H
#define QSC_X509_REV_H

#include "qsccommon.h"
#include "x509crl.h"
#include "x509time.h"
#include "x509types.h"
#include "x509revext.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509rev.h
 * \brief X.509 revocation policy and CRL-based certificate status checking interface.
 *
 * \details
 * This header defines the revocation policy modes, revocation status results,
 * callback types, option container, and helper functions used to perform
 * certificate revocation checks through certificate revocation lists. The
 * interface supports direct CRL evaluation as well as resolver-driven CRL
 * acquisition under caller-defined policy.
 */

/*!
 * \enum qsc_x509_revocation_mode
 * \brief Revocation checking policy modes.
 */
typedef enum qsc_x509_revocation_mode_t
{
    QSC_X509_REVOCATION_MODE_NONE = 0,              /*!< Disable revocation checking. */
    QSC_X509_REVOCATION_MODE_BEST_EFFORT = 1,       /*!< Attempt revocation checking but do not hard-fail when a CRL cannot be obtained or validated. */
    QSC_X509_REVOCATION_MODE_REQUIRE_VALID_CRL = 2  /*!< Require a valid CRL-based revocation result for successful validation. */
} qsc_x509_revocation_mode;

/*!
 * \enum qsc_x509_revocation_status
 * \brief Certificate revocation checking result codes.
 */
typedef enum qsc_x509_revocation_status_t
{
    QSC_X509_REVOCATION_STATUS_GOOD = 0,                    /*!< The certificate was checked and is not listed as revoked. */
    QSC_X509_REVOCATION_STATUS_REVOKED = 1,                 /*!< The certificate serial number was found in the CRL and is revoked. */
    QSC_X509_REVOCATION_STATUS_UNCHECKED = 2,               /*!< Revocation status was not checked under the active policy or available inputs. */
    QSC_X509_REVOCATION_STATUS_CRL_NOT_FOUND = 3,           /*!< No CRL could be obtained for the certificate and issuer pair. */
    QSC_X509_REVOCATION_STATUS_CRL_INVALID = 4,             /*!< A CRL was obtained but failed structural or signature validation. */
    QSC_X509_REVOCATION_STATUS_CRL_EXPIRED = 5,             /*!< The CRL validity interval did not cover the supplied validation time. */
    QSC_X509_REVOCATION_STATUS_ISSUER_MISMATCH = 6,         /*!< The CRL issuer did not match the supplied issuer certificate. */
    QSC_X509_REVOCATION_STATUS_ERROR = 7                    /*!< A non-specific error occurred during revocation processing. */
} qsc_x509_revocation_status;

/*!
 * \typedef qsc_x509_crl_resolver_callback
 * \brief Caller-supplied CRL acquisition callback.
 *
 * \details
 * This callback is used to obtain a CRL applicable to the supplied certificate
 * and issuer. The callback populates the destination CRL object and returns an
 * ASN.1 status code indicating whether resolution was successful.
 *
 * \param certificate: [const][struct] The certificate whose revocation status is being checked.
 * \param issuer: [const][struct] The issuer certificate for the target certificate.
 * \param crl: [struct] The destination CRL object to populate.
 * \param context: Caller-defined opaque resolver context.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
typedef qsc_asn1_status (*qsc_x509_crl_resolver_callback)(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, qsc_x509_crl* crl, void* context);

typedef qsc_asn1_status (*qsc_x509_delta_crl_resolver_callback)(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, qsc_x509_crl* basecrl, qsc_x509_crl* deltacrl, bool* deltaavailable, void* context);

/*!
 * \struct qsc_x509_revocation_options
 * \brief Revocation checking configuration options.
 *
 * \details
 * This structure stores the active revocation policy mode together with the
 * callbacks and opaque contexts required for CRL resolution and CRL signature
 * verification.
 */
typedef struct qsc_x509_revocation_options_t
{
    qsc_x509_revocation_mode mode;                              /*!< The active revocation checking policy. */
    qsc_x509_crl_resolver_callback resolver;                    /*!< The callback used to acquire a base CRL for the certificate under evaluation. */
    qsc_x509_delta_crl_resolver_callback deltaresolver;         /*!< Optional callback used to acquire a base CRL and a delta CRL for the certificate under evaluation. */
    qsc_x509_crl_signature_verify_callback verifycallback;      /*!< The callback used to verify the signature on a resolved CRL. */
    void* resolvercontext;                                      /*!< Caller-defined opaque context passed to the CRL resolver callback. */
    void* deltaresolvercontext;                                 /*!< Caller-defined opaque context passed to the delta CRL resolver callback. */
    void* verifycontext;                                        /*!< Caller-defined opaque context passed to the CRL signature verification callback. */
} qsc_x509_revocation_options;

/*!
 * \brief Initialize a revocation options structure.
 *
 * \details
 * Resets the revocation options object to a clean default state suitable for
 * later policy and callback configuration.
 *
 * \param options: [struct] The revocation options structure to initialize.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_revocation_options_initialize(qsc_x509_revocation_options* options);

/*!
 * \brief Check certificate revocation status using a supplied CRL.
 *
 * \details
 * Evaluates the target certificate against the supplied CRL, verifies the CRL
 * against the issuer certificate using the caller-supplied verification
 * callback, and returns a normalized revocation status result.
 *
 * \param certificate: [const][struct] The certificate whose revocation status is being checked.
 * \param issuer: [const][struct] The issuer certificate for the target certificate.
 * \param crl: [const][struct] The CRL to use for revocation checking.
 * \param verifycallback: The callback used to verify the CRL signature.
 * \param verifycontext: Caller-defined opaque context passed to the verification callback.
 * \param validationtime: [const][struct] The time used to evaluate CRL validity.
 *
 * \return [enum] Returns a qsc_x509_revocation_status code.
 */
QSC_EXPORT_API qsc_x509_revocation_status qsc_x509_certificate_check_revocation_with_crl(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, 
    const qsc_x509_crl* crl, qsc_x509_crl_signature_verify_callback verifycallback, void* verifycontext, const qsc_x509_time* validationtime);

/*!
 * \brief Check certificate revocation status using resolver-driven CRL acquisition.
 *
 * \details
 * Resolves a CRL for the target certificate using the configured resolver
 * callback and applies revocation processing according to the supplied
 * revocation policy options.
 *
 * \param certificate: [const][struct] The certificate whose revocation status is being checked.
 * \param issuer: [const][struct] The issuer certificate for the target certificate.
 * \param options: [const][struct] The revocation policy and callback options.
 * \param validationtime: [const][struct] The time used to evaluate CRL validity.
 *
 * \return [enum] Returns a qsc_x509_revocation_status code.
 */
QSC_EXPORT_API qsc_x509_revocation_status qsc_x509_certificate_check_revocation(const qsc_x509_certificate* certificate,
    const qsc_x509_certificate* issuer, const qsc_x509_revocation_options* options, const qsc_x509_time* validationtime);

QSC_CPLUSPLUS_ENABLED_END

#endif
