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

#ifndef QSC_X509_CRL_H
#define QSC_X509_CRL_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509crl.h
 * \brief X.509 certificate revocation list parsing, encoding, lookup, and verification interface.
 *
 * \details
 * This header declares the public types and functions used to decode, encode,
 * inspect, and verify DER encoded X.509 Certificate Revocation Lists (CRLs).
 * The interface provides a compact CertificateList representation containing
 * the parsed issuer name, update times, revoked serial number entries,
 * signature metadata, and references to the raw TBSCertList and source DER
 * buffers. Helper functions are provided for revocation queries, CRL validity
 * window checks, algorithm consistency checks, and callback-driven signature
 * verification against an issuer certificate.
 *
 * The design is algorithm-neutral. Signature verification is delegated through
 * a caller supplied callback so the surrounding X.509 verification layer can
 * apply its supported signature algorithms, including future post-quantum
 * algorithms, without changing the CRL parser interface.
 */

 /**
  * \def QSC_X509_CRL_ENTRY_MAX
  * \brief Maximum encoded size, in bytes, of a single CRL revoked-certificate entry.
  */
#define QSC_X509_CRL_ENTRY_MAX 512U

/*!
 * \def QSC_X509_CRL_REVOKED_MAX
 * \brief The maximum number of revoked certificate entries retained in a decoded CRL.
 *
 * \details
 * This macro defines the fixed upper bound on the number of revoked certificate
 * entries stored in the \ref qsc_x509_crl.revoked array. CRLs containing more
 * entries than this limit cannot be fully represented by this compact object
 * model without additional application handling.
 */
#define QSC_X509_CRL_REVOKED_MAX 1024U

/*!
 * \struct qsc_x509_crl_entry
 * \brief A decoded revoked-certificate entry from a CRL.
 *
 * \details
 * This structure stores the serial number of a revoked certificate together
 * with the revocation date associated with that entry. Only the core entry
 * data required for revocation status evaluation is retained.
 */
typedef struct qsc_x509_crl_entry_t
{
    uint8_t serialnumber[QSC_X509_SERIAL_NUMBER_MAX];       /*! The revoked certificate serial number. */
    size_t serialnumberlen;                                 /*! The length of the serial number in bytes. */
    qsc_asn1_time revocationdate;                           /*! The revocation date decoded from the CRL entry. */
    uint8_t rawextensions[QSC_X509_CRL_ENTRY_MAX];          /*! The raw extension entries. */
    size_t rawextensionslen;                                /*! The length of raw extension entries. */
} qsc_x509_crl_entry;

/*!
 * \struct qsc_x509_crl
 * \brief A decoded X.509 CertificateList object.
 *
 * \details
 * This structure stores the essential components of a parsed DER encoded CRL,
 * including the TBSCertList signature identifier, issuer name, update times,
 * revoked entry collection, outer signature algorithm, signature bit string,
 * and references to the raw TBSCertList and original DER buffer. The decoded object retains an owned DER copy so the preserved TBSCertList bytes remain valid for signature verification for the lifetime of the CRL object.
 */
typedef struct qsc_x509_crl_t
{
    uint32_t version;                                       /*! The CRL version number. */
    qsc_x509_algorithm_identifier tbsignature;              /*! The signature algorithm identifier from the TBSCertList. */
    qsc_x509_name issuer;                                   /*! The issuer distinguished name of the CRL. */
    qsc_asn1_time thisupdate;                               /*! The CRL thisUpdate time. */
    bool nextupdate_present;                                /*! Indicates whether nextUpdate is present. */
    qsc_asn1_time nextupdate;                               /*! The CRL nextUpdate time when present. */
    qsc_x509_crl_entry revoked[QSC_X509_CRL_REVOKED_MAX];   /*! The fixed-capacity array of decoded revoked entries. */
    size_t revokedcount;                                    /*! The number of valid entries in the revoked array. */
    qsc_x509_extensions extensions;                         /*! The X.509 extensions structure */
    qsc_x509_algorithm_identifier signaturealgorithm;       /*! The outer CertificateList signature algorithm identifier. */
    uint8_t signature[QSC_X509_SIGNATURE_MAX];              /*! The raw signature bit-string content. */
    size_t signaturelen;                                    /*! The signature length in bytes. */
    uint8_t signatureunusedbits;                            /*! The number of unused bits in the signature BIT STRING. */
    const uint8_t* tbsdata;                                 /*! Pointer to the raw TBSCertList DER payload inside the source buffer. */
    size_t tbsdatalen;                                      /*! The length in bytes of the TBSCertList DER payload. */
    const uint8_t* der;                                     /*! Pointer to the original source DER buffer. */
    size_t derlen;                                          /*! The length in bytes of the original source DER buffer. */
} qsc_x509_crl;

/*!
 * \enum qsc_x509_crl_verify_status
 * \brief CRL verification result codes.
 *
 * \details
 * These status codes describe the outcome of CRL verification and related
 * validation checks performed by \ref qsc_x509_crl_verify and supporting
 * helper routines.
 */
typedef enum qsc_x509_crl_verify_status_t
{

    QSC_X509_CRL_VERIFY_STATUS_SUCCESS = 0,                 /*! Verification completed successfully. */
    QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT = 1,           /*! One or more input arguments were invalid. */
    QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL = 2,             /*! The CRL structure was malformed or internally inconsistent. */
    QSC_X509_CRL_VERIFY_STATUS_ALGORITHM_MISMATCH = 3,      /*! The inner and outer signature algorithm identifiers did not match. */
    QSC_X509_CRL_VERIFY_STATUS_ISSUER_MISMATCH = 4,         /*! The CRL issuer did not match the supplied issuer certificate. */
    QSC_X509_CRL_VERIFY_STATUS_EXPIRED = 5,                 /*! The CRL was expired relative to the supplied evaluation time. */
    QSC_X509_CRL_VERIFY_STATUS_NOT_YET_VALID = 6,           /*! The CRL was not yet valid relative to the supplied evaluation time. */
    QSC_X509_CRL_VERIFY_STATUS_KEY_USAGE_REJECTED = 7,      /*! The issuer certificate key-usage policy rejected CRL signing. */
    QSC_X509_CRL_VERIFY_STATUS_SIGNATURE_REJECTED = 8,      /*! The CRL signature was rejected by the verification callback. */
    QSC_X509_CRL_VERIFY_STATUS_CALLBACK_FAILURE = 9,        /*! The caller supplied verification callback failed to execute successfully. */
    QSC_X509_CRL_VERIFY_STATUS_UNSUPPORTED = 10             /*! A required feature or algorithm was not supported. */
} qsc_x509_crl_verify_status;

/*!
 * \typedef qsc_x509_crl_signature_verify_callback
 * \brief Caller supplied CRL signature verification callback.
 *
 * \details
 * The CRL module delegates cryptographic signature verification to this
 * callback. The callback receives the decoded CRL, the candidate issuer
 * certificate, and an opaque caller-defined state pointer, and returns
 * \c true only when the CRL signature is accepted.
 *
 * \param crl: [const][struct] The decoded CRL to verify.
 * \param issuer: [const][struct] The issuer certificate used to verify the CRL signature.
 * \param state: Caller-defined opaque state passed through from the verification call.
 *
 * \return Returns \c true on successful signature verification; otherwise returns \c false.
 */
typedef bool (*qsc_x509_crl_signature_verify_callback)(const qsc_x509_crl* crl, const qsc_x509_certificate* issuer, void* state);

/*!
 * \brief Clear a decoded CRL object.
 *
 * \details
 * Resets all fields of the CRL object to their default state and clears any
 * decoded content retained from a prior parse operation.
 *
 * \param crl: [struct] The CRL object to clear.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_crl_clear(qsc_x509_crl* crl);

/*!
 * \brief Decode a DER encoded X.509 CRL.
 *
 * \details
 * Parses a DER encoded CertificateList structure and populates the destination
 * \ref qsc_x509_crl object with the decoded version, issuer, update times,
 * revoked serial entries, signature metadata, and raw DER slice references.
 *
 * \param der: [const] The input DER encoded CRL buffer.
 * \param derlen: The length of the input DER buffer in bytes.
 * \param crl: [struct] The destination decoded CRL object.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating decode success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_decode_der(const uint8_t* der, size_t derlen, qsc_x509_crl* crl);

/*!
 * \brief Encode a decoded CRL object as DER.
 *
 * \details
 * Serializes the supplied CRL object into DER encoded CertificateList form.
 * This routine is intended for CRL emission and round-trip testing when the
 * CRL object model contains sufficient information to reconstruct the output.
 *
 * \param crl: [const][struct] The source CRL object.
 * \param output: The destination buffer receiving the DER encoded CRL.
 * \param outputlen: The input capacity of \p output and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating encode success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_encode_der(const qsc_x509_crl* crl, uint8_t* output, size_t* outputlen);

/*!
 * \brief Test whether a CRL is current at a supplied evaluation time.
 *
 * \details
 * Compares the supplied time against the CRL thisUpdate and optional nextUpdate
 * bounds and returns whether the CRL is valid for use at that time.
 *
 * \param crl: [const][struct] The decoded CRL.
 * \param now: [const][struct] The evaluation time.
 *
 * \return Returns \c true if the CRL is current at the supplied time; otherwise returns \c false.
 */
QSC_EXPORT_API bool qsc_x509_crl_is_current(const qsc_x509_crl* crl, const qsc_asn1_time* now);

/*!
 * \brief Check CRL signature algorithm consistency.
 *
 * \details
 * Verifies that the TBSCertList signature algorithm identifier and the outer
 * CertificateList signature algorithm identifier are mutually consistent.
 *
 * \param crl: [const][struct] The decoded CRL to inspect.
 *
 * \return [enum] Returns a \ref qsc_x509_crl_verify_status result code.
 */
QSC_EXPORT_API qsc_x509_crl_verify_status qsc_x509_crl_check_algorithms(const qsc_x509_crl* crl);

/*!
 * \brief Find a revoked entry by certificate serial number.
 *
 * \details
 * Searches the decoded revoked entry set for a serial number match and returns
 * a pointer to the matching entry when found.
 *
 * \param crl: [const][struct] The decoded CRL to search.
 * \param serial: [const] The certificate serial number to locate.
 * \param seriallen: The length of the serial number in bytes.
 *
 * \return Returns a pointer to the matching revoked entry, or \c NULL if no match is found.
 */
QSC_EXPORT_API const qsc_x509_crl_entry* qsc_x509_crl_find_serial(const qsc_x509_crl* crl, const uint8_t* serial, size_t seriallen);

/*!
 * \brief Test whether a certificate is revoked by a CRL.
 *
 * \details
 * Compares the serial number of the supplied certificate against the revoked
 * entries contained in the CRL and returns whether the certificate appears
 * in the CRL revocation list.
 *
 * \param certificate: [const][struct] The certificate to test.
 * \param crl: [const][struct] The CRL to query.
 *
 * \return Returns \c true if the certificate serial number is present in the CRL; otherwise returns \c false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_is_revoked_by_crl(const qsc_x509_certificate* certificate, const qsc_x509_crl* crl);

/*!
 * \brief Test whether a certificate is revoked by a CRL.
 *
 * \details
 * This function provides the inverse argument ordering of
 * \ref qsc_x509_certificate_is_revoked_by_crl while performing the same
 * serial number membership test.
 *
 * \param crl: [const][struct] The CRL to query.
 * \param certificate: [const][struct] The certificate to test.
 *
 * \return Returns \c true if the certificate serial number is present in the CRL; otherwise returns \c false.
 */
QSC_EXPORT_API bool qsc_x509_crl_is_revoked(const qsc_x509_crl* crl, const qsc_x509_certificate* certificate);

/*!
 * \brief Verify a decoded CRL against an issuer certificate.
 *
 * \details
 * Performs CRL validation checks including input validation, algorithm
 * consistency, issuer matching, current-time validity checks, issuer policy
 * checks, and callback-driven cryptographic signature verification.
 *
 * \param crl: [const][struct] The decoded CRL to verify.
 * \param issuer: [const][struct] The issuer certificate expected to have signed the CRL.
 * \param now: [const][struct] The evaluation time used for thisUpdate and nextUpdate checks.
 * \param callback: The caller supplied CRL signature verification callback.
 * \param state: Caller-defined opaque state passed through to \p callback.
 *
 * \return [enum] Returns a \ref qsc_x509_crl_verify_status result code.
 */
QSC_EXPORT_API qsc_x509_crl_verify_status qsc_x509_crl_verify(const qsc_x509_crl* crl, const qsc_x509_certificate* issuer, const qsc_asn1_time* now, qsc_x509_crl_signature_verify_callback callback, void* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
