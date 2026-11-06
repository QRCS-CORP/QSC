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

#ifndef QSC_HWTPMQUOTE_H
#define QSC_HWTPMQUOTE_H

#include "hwprovider.h"

QSC_CPLUSPLUS_ENABLED_START

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_TPM_ENABLED)

/** \file hwtpmquote.h
 * \brief Bounded TPM2 ECDSA P-256 SHA-256 quote verification.
 * \details Verification is independent of TPM2-TSS and vendor libraries. The caller
 * supplies a separately trusted attestation public key, verified TPM Name, expected
 * PCR selection and expected PCR-composite digest. This function does not verify
 * endorsement certificates or establish a device trust anchor on its own.
 */

/** \def QSC_HW_TPM_QUOTE_MAX_SIZE
 * \brief Maximum serialized TPMS_ATTEST quote length accepted, in bytes.
 */
#define QSC_HW_TPM_QUOTE_MAX_SIZE 1024U

/** \def QSC_HW_TPM_PCR_DIGEST_SIZE
 * \brief SHA-256 PCR-composite digest length in bytes.
 */
#define QSC_HW_TPM_PCR_DIGEST_SIZE 32U

/** \struct qsc_hw_tpm_quote_policy
 * \brief Caller-provided, immutable attestation verification policy.
 * \note Every pointer is borrowed for the call only. Trust in the AK and reference
 * PCR digest must be established independently of the untrusted quote.
 */
typedef struct qsc_hw_tpm_quote_policy
{
	const uint8_t* nonce;		/**< Fresh verifier challenge of 16..64 bytes. */
	size_t noncelen;			/**< Exact challenge length, in bytes. */
	const uint8_t* akname;		/**< Independently trusted TPMT_HA-style AK Name. */
	size_t aknamelen;			/**< Exact AK Name length, currently 34 for SHA-256. */
	const uint8_t* akpublic;	/**< Trusted P-256 AK Qx||Qy, 64 big-endian bytes. */
	const uint8_t* pcrdigest;	/**< Independently expected 32-byte PCR composite digest. */
	uint8_t pcrselect[3U];		/**< Required SHA-256 bank PCR selection, 24 bit positions. */
	bool require_safe_clock;	/**< Reject quotes without TPM clockInfo.safe == 1. */
} qsc_hw_tpm_quote_policy;

/** \brief Verify a bounded TPM2 Quote with a trusted AK and expected PCR policy.
 * \param quote Raw serialized TPMS_ATTEST bytes (without outer TPM2B size word).
 * \param quotelen Number of quote bytes, 1..QSC_HW_TPM_QUOTE_MAX_SIZE.
 * \param signature Serialized TPMT_SIGNATURE ECDSA/SHA-256 (big-endian TPM wire format).
 * \param signaturelen Exact signature byte count, maximum 76 for ECDSA P-256.
 * \param policy Required expected nonce, AK Name, AK public key, PCR selection/digest.
 * \return success only for valid signed content and matching policy; unsupported for
 * non-P256/SHA-256 signature/selection; invalid_parameter for malformed wire input;
 * policy for mismatched verified claims or failed cryptographic signature.
 * \note Does not consult the TPM, validate AK certificate chains, verify PCR event logs,
 * or provide cross-quote replay tracking. Caller must enforce fresh one-use challenges.
 * Thread-safe for independent immutable arguments; all buffers remain caller-owned.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_tpm_quote_verify(const uint8_t* quote, size_t quotelen, const uint8_t* signature, size_t signaturelen, const qsc_hw_tpm_quote_policy* policy);

/** \brief Decode the QSC TPM2-TSS quote envelope and verify its signed claims.
 * \param envelope Caller-owned bytes containing big-endian u16 quote size, quote,
 * big-endian u16 TPMT_SIGNATURE size and signature bytes.
 * \param envelopelen Exact encoded envelope size; trailing bytes are rejected.
 * \param policy Trusted verifier policy for signature, nonce, AK and PCR measurements.
 * \return success only for canonical envelope and verified quote; typed error otherwise.
 * \note This is a convenience parser; it does not supply a hardware trust anchor.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_tpm_quote_envelope_verify(const uint8_t* envelope, size_t envelopelen, const qsc_hw_tpm_quote_policy* policy);

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
