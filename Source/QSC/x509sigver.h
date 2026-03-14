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

#ifndef QSC_X509_QSC_VERIFY_H
#define QSC_X509_QSC_VERIFY_H

#include "qsccommon.h"
#include "x509verify.h"
#include "x509sig.h"
#include "x509spki.h"
#include "ecdsa.h"
#include "sha2.h"
#include "sha3.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509_qsc_verify.h
 * \brief QSC cryptographic verification adapter for the X.509 layer.
 *
 * \details
 * This header defines the callback adapter that binds the generic X.509
 * verification layer to the concrete QSC asymmetric and hash implementations
 * supplied by the library. The first implementation pass is intentionally
 * strict and supports only the X.509 signature profile that can be bound
 * directly and unambiguously to the current QSC NIST P-256 ECDSA API.
 *
 * Supported certificate signature profile in this pass:
 *
 * - ecdsa-with-SHA256
 * - issuer public key algorithm id-ecPublicKey
 * - named curve prime256v1
 *
 * The current QSC P-256 verification API accepts a 64-byte raw signature
 * formatted as r[32] || s[32] prepended to the original message and verifies
 * the signature using an internal SHA2-256 digest computation. The adapter
 * therefore decodes the DER ECDSA signature value from the X.509 certificate,
 * converts it to raw fixed-width form, extracts the issuer public key
 * coordinates from SubjectPublicKeyInfo, builds the verification input buffer,
 * and calls qsc_ecnistp256_verify.
 */

/*!
 * \brief The QSC X.509 crypto binding context.
 *
 * \details
 * The adapter uses caller supplied temporary storage to avoid dynamic
 * allocation. The signaturemessage buffer must be large enough to hold:
 *
 * QSC_ECNISTP256_SIGNATURE_SIZE + certificate->tbsdatalen
 *
 * for the largest certificate expected by the caller.
 */
typedef struct qsc_x509_verify_state_t
{
	uint8_t* signaturemessage;    /*!< The caller supplied verification input buffer. */
	size_t signaturemessage_size; /*!< The size of the verification input buffer in bytes. */
} qsc_x509_verify_state;

/*!
 * \brief Initializes a QSC X.509 verification state structure.
 *
 * \param state: [qsc_x509_verify_state*] The verification state structure.
 * \param buffer: [uint8_t*] The caller supplied verification input buffer.
 * \param buflen: [size_t] The size of the verification input buffer in bytes.
 */
QSC_EXPORT_API void qsc_x509_qsc_verify_state_initialize(qsc_x509_verify_state* state, uint8_t* buffer, size_t buflen);

/*!
 * \brief Verifies a certificate signature using the current QSC cryptographic bindings.
 *
 * \details
 * This function is intended to be passed as the callback argument to the
 * generic X.509 verification routines. The state argument must point to an
 * initialized qsc_x509_verify_state structure.
 *
 * \param certificate: [const qsc_x509_certificate*] The certificate being verified.
 * \param issuer: [const qsc_x509_certificate*] The issuer certificate.
 * \param state: [void*] A pointer to a qsc_x509_verify_state structure.
 *
 * \return [bool] Returns true if the certificate signature is valid.
 */
QSC_EXPORT_API bool qsc_x509_qsc_signature_verify(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, void* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
