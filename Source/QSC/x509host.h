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

#ifndef QSC_X509_HOST_H
#define QSC_X509_HOST_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509host.h
 * \brief X.509 certificate hostname and endpoint matching utilities.
 *
 * \details
 * This header defines helper functions used to evaluate whether a hostname or
 * network address matches the identity information contained in an X.509
 * certificate. Matching is performed against Subject Alternative Name entries
 * when present, and may fall back to the subject distinguished name common
 * name when no DNS SAN is present.
 *
 * DNS matching follows a restrained wildcard model compatible with common
 * X.509 hostname validation practice. Wildcards are accepted only in the
 * left-most label, the wildcard pattern must cover at least two additional
 * labels, and wildcard matching is not applied to IDNA A-label inputs.
 */

/*!
 * \brief Match a DNS hostname against a certificate DNS pattern.
 *
 * \details
 * Compares a hostname against a DNS identifier using ASCII case-insensitive
 * comparison. A wildcard is permitted only as the complete left-most label,
 * in the form "*.example.com", and matches exactly one hostname label.
 * Partial-label wildcards and multiple wildcards are rejected.
 *
 * Both inputs to this function are NUL-terminated strings. Certificate
 * identifiers stored as length-delimited X.509 values are validated through
 * qsc_x509_certificate_match_dns_name().
 *
 * \param pattern: [const] The NUL-terminated DNS pattern.
 * \param hostname: [const] The NUL-terminated hostname to evaluate.
 *
 * \return Returns true if the hostname matches the DNS pattern; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_dns_name_match(const char* pattern, const char* hostname);

/*!
 * \brief Match a hostname against certificate DNS identifiers.
 *
 * \details
 * Evaluates the supplied hostname against dNSName identifiers contained in the
 * certificate Subject Alternative Name extension. Certificate DNS identifiers
 * are processed using their explicit X.509 lengths and are not interpreted as
 * NUL-terminated strings.
 *
 * Matching is ASCII case-insensitive. A wildcard is permitted only as the
 * complete left-most label and matches exactly one hostname label.
 *
 * Subject commonName values are not used as a fallback when no matching
 * dNSName Subject Alternative Name is present.
 *
 * \param certificate: [const][struct] The certificate to evaluate.
 * \param hostname: [const] The NUL-terminated hostname to match.
 *
 * \return Returns true if the hostname matches a dNSName Subject Alternative Name; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_match_dns_name(const qsc_x509_certificate* certificate, const char* hostname);

/*!
 * \brief Match an IP address against certificate IP identifiers.
 *
 * \details
 * Compares a binary IPv4 or IPv6 address against the iPAddress entries
 * contained in the certificate Subject Alternative Name extension.
 *
 * \param certificate: [const][struct] The certificate to evaluate.
 * \param address: [const] The binary IP address.
 * \param addresslen: The address length in bytes. Supported values are 4 and 16.
 *
 * \return Returns true if the address matches a certificate IP identifier; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_match_ip_address(const qsc_x509_certificate* certificate, const uint8_t* address, size_t addresslen);

/*!
 * \brief Match a hostname against a certificate.
 *
 * \details
 * Performs DNS service-identity validation against the dNSName entries in the
 * certificate Subject Alternative Name extension. The subject commonName is
 * not used for hostname validation.
 *
 * Certificate DNS identifiers are evaluated using their explicit X.509 lengths
 * and the DNS matching rules implemented by
 * qsc_x509_certificate_match_dns_name().
 *
 * \param certificate: [const][struct] The certificate to evaluate.
 * \param hostname: [const] The NUL-terminated hostname to match.
 *
 * \return Returns true if the hostname matches a dNSName Subject Alternative Name; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_match_hostname(const qsc_x509_certificate* certificate, const char* hostname);

/*!
 * \brief Match a network endpoint against a certificate.
 *
 * \details
 * Evaluates both hostname and IP address inputs against the certificate. The
 * function first attempts DNS name matching when a hostname is supplied, then
 * attempts IP address matching when a binary address is supplied. Either input
 * may be NULL, but at least one identity input should be provided by the
 * caller.
 *
 * \param certificate: [const][struct] The certificate to evaluate.
 * \param hostname: [const] The hostname to match, or NULL.
 * \param address: [const] The binary IP address, or NULL.
 * \param addresslen: The length of the IP address in bytes.
 *
 * \return Returns true if the endpoint matches the certificate identity; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_match_endpoint(const qsc_x509_certificate* certificate, const char* hostname, const uint8_t* address, size_t addresslen);

QSC_CPLUSPLUS_ENABLED_END

#endif
