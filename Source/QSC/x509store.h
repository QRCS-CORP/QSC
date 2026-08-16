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

#ifndef QSC_X509_STORE_H
#define QSC_X509_STORE_H

#include "qsccommon.h"
#include "x509types.h"
#include "x509verify.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509store.h
 * \brief X.509 trust-anchor store and certificate chain construction interface.
 *
 * \details
 * This header defines helper functions used to initialize and query a trust
 * store composed of X.509 trust anchors, to add anchors derived from
 * certificates, to locate anchors and issuers by subject and key identifier,
 * and to build a candidate certification path from a leaf certificate through
 * intermediates to a trusted anchor.
 *
 * The store interface operates on caller-supplied trust-anchor storage and does
 * not allocate memory internally. Chain construction similarly writes the
 * resulting certificate path into caller-managed output storage and a chain
 * descriptor object.
 */

 /*!
  * \brief Initialize a certificate store.
  *
  * \details
  * Initializes a certificate store with a caller-provided buffer.
  * The store starts empty. Anchors must be added using
  * qsc_x509_store_add_anchor().
  *
  * \param store: [struct] Store instance.
  * \param anchors: [array] Caller-allocated array of anchor pointers.
  * \param capacity: [size_t] Number of entries the array can hold.
  */
QSC_EXPORT_API void qsc_x509_store_initialize(qsc_x509_store* store, qsc_x509_trust_anchor* anchors, size_t capacity);

/*!
 * \brief Add a trust anchor to a store from a certificate.
 *
 * \details
 * Converts the supplied certificate into a trust-anchor representation and adds
 * it to the store, subject to the specified anchor storage capacity. The
 * caller indicates whether the certificate should be treated as self-signed for
 * anchor construction purposes.
 *
 * \param store: [struct] The destination trust store.
 * \param certificate: [const][struct] The certificate to add as a trust anchor.
 * \param selfsigned: Indicates whether the certificate is self-signed.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_store_add_anchor(qsc_x509_store* store, const qsc_x509_certificate* certificate, bool selfsigned);

/*!
 * \brief Find a trust anchor applicable to a certificate.
 *
 * \details
 * Searches the store for a trust anchor whose subject matches the certificate
 * issuer. AuthorityKeyIdentifier selectors are used as a preference when they
 * can be evaluated; issuer-name matching remains the fallback so that AKI/SKI
 * metadata is not promoted into an independent path-validation requirement.
 *
 * \param store: [const][struct] The trust store to search.
 * \param certificate: [const][struct] The certificate for which a matching anchor is sought.
 *
 * \return Returns a pointer to the matching trust anchor, or NULL if no suitable anchor is found.
 */
QSC_EXPORT_API const qsc_x509_trust_anchor* qsc_x509_store_find_anchor_for_certificate(const qsc_x509_store* store, const qsc_x509_certificate* certificate);

/*!
 * \brief Find a trust anchor by subject name.
 *
 * \details
 * Searches the store for a trust anchor whose subject distinguished name
 * matches the supplied X.509 name object.
 *
 * \param store: [const][struct] The trust store to search.
 * \param subject: [const][struct] The subject distinguished name to match.
 *
 * \return Returns a pointer to the matching trust anchor, or NULL if no match is found.
 */
QSC_EXPORT_API const qsc_x509_trust_anchor* qsc_x509_store_find_anchor_by_subject(const qsc_x509_store* store, const qsc_x509_name* subject);

/*!
 * \brief Find a trust anchor by Subject Key Identifier.
 *
 * \details
 * Searches the store for a trust anchor whose Subject Key Identifier matches
 * the supplied key identifier byte string.
 *
 * \param store: [const][struct] The trust store to search.
 * \param keyidentifier: [const] The Subject Key Identifier bytes to match.
 * \param keyidentifierlen: The length of the key identifier in bytes.
 *
 * \return Returns a pointer to the matching trust anchor, or NULL if no match is found.
 */
QSC_EXPORT_API const qsc_x509_trust_anchor* qsc_x509_store_find_anchor_by_subject_key_identifier(const qsc_x509_store* store, const uint8_t* keyidentifier, size_t keyidentifierlen);

/*!
 * \brief Test whether a store contains a certificate as a trust anchor.
 *
 * \details
 * Compares the supplied certificate against the anchors present in the store
 * and reports whether an equivalent anchor is already available.
 *
 * \param store: [const][struct] The trust store to inspect.
 * \param certificate: [const][struct] The certificate to test.
 *
 * \return Returns true if the store contains a matching trust anchor; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_store_contains_anchor(const qsc_x509_store* store, const qsc_x509_certificate* certificate);

/*!
 * \brief Find an issuer certificate in the trust store.
 *
 * \details
 * Searches the trust store for a certificate that can act as the issuer of the
 * supplied certificate, typically by subject and authority key identifier
 * matching.
 *
 * \param store: [const][struct] The trust store to search.
 * \param certificate: [const][struct] The certificate whose issuer is sought.
 *
 * \return Returns a pointer to the matching issuer certificate, or NULL if no issuer is found.
 */
QSC_EXPORT_API const qsc_x509_certificate* qsc_x509_store_find_issuer(const qsc_x509_store* store, const qsc_x509_certificate* certificate);

/*!
 * \brief Build a certification chain from a leaf certificate to a trust anchor.
 *
 * \details
 * Attempts to construct a certificate path beginning at the supplied leaf
 * certificate, proceeding through the provided intermediate certificates, and
 * terminating at a trusted anchor in the store. The resulting ordered path is
 * written to the caller-supplied output certificate array and summarized in the
 * destination chain object.
 *
 * \param leaf: [const][struct] The leaf certificate from which path construction begins.
 * \param intermediates: [const][struct] The intermediate certificate array available for path building.
 * \param intermediatecount: The number of certificates in \p intermediates.
 * \param store: [const][struct] The trust store containing candidate trust anchors.
 * \param output: [struct] The destination certificate array receiving the constructed path.
 * \param outputcount: The number of certificate elements available in \p output.
 * \param chain: [struct] The destination chain descriptor object.
 *
 * \return [enum] Returns a qsc_x509_verify_status code describing the chain build result.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_chain_build(const qsc_x509_certificate* leaf, const qsc_x509_certificate* intermediates, 
	size_t intermediatecount, const qsc_x509_store* store, qsc_x509_certificate* output, size_t outputcount, qsc_x509_chain* chain);

QSC_CPLUSPLUS_ENABLED_END

#endif
