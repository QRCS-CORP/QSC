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

#ifndef QSC_TLS_STATE_H
#define QSC_TLS_STATE_H

#include "tlstypes.h"
#include "tlscert.h"
#include "sha2.h"
#include "tlslimits.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsstate.h
 * \brief TLS internal state container type definitions shared across the record and handshake layers.
 */

/**
 * \struct qsc_tls_transcript_state
 * \brief Stores the active transcript hash context and its selected hash algorithm.
 */
typedef struct qsc_tls_transcript_state
{
	qsc_tls_hash_algorithm hash; /*!< Active transcript hash algorithm. */
	bool initialized; /*!< True when the transcript hash context has been initialized. */
	union
	{
		qsc_sha256_state sha256; /*!< SHA-256 transcript hash state. */
		qsc_sha384_state sha384; /*!< SHA-384 transcript hash state. */
		qsc_sha512_state sha512; /*!< SHA-512 transcript hash state. */
	} ctx; /*!< Storage for the active transcript hash state. */
} qsc_tls_transcript_state;

/**
 * \struct qsc_tls_record_state
 * \brief Stores the active TLS traffic keying material and sequence number for one record direction.
 */
typedef struct qsc_tls_record_state
{
	qsc_tls_cipher_suite suite;	/*!< Current record protection cipher suite. */
	uint8_t key[32U];		/*!< Current record protection key bytes. */
	size_t keylen;			/*!< Current record protection key length in bytes. */
	uint8_t iv[12U];		/*!< Current static record IV bytes. */
	uint64_t sequence;		/*!< Current record sequence number. */
	bool initialized;		/*!< True when the record protection state is initialized. */
} qsc_tls_record_state;

/**
 * \struct qsc_tls_alpn_protocols
 * \brief Stores a bounded ordered ALPN protocol list and its negotiation policy.
 */
typedef struct qsc_tls_alpn_protocols
{
	uint8_t protocols[QSC_TLS_MAX_ALPN_PROTOCOLS][QSC_TLS_MAX_ALPN_SIZE];	/*!< Ordered ALPN protocol identifiers without terminating NULL bytes. */
	size_t protocollens[QSC_TLS_MAX_ALPN_PROTOCOLS];						/*!< Length, in bytes, of each ALPN protocol identifier. */
	size_t protocolcount;											/*!< Number of valid protocol identifiers. */
	bool required;											/*!< Require a mutually supported protocol when true. */
	bool configured;											/*!< Indicates that ALPN policy has been configured. */
} qsc_tls_alpn_protocols;

/**
 * \struct qsc_tls_peer_capabilities
 * \brief Stores the peer-advertised supported groups and signature-scheme capabilities.
 */
typedef struct qsc_tls_peer_capabilities
{
	qsc_tls_named_group groups[QSC_TLS_MAX_GROUPS];							/*!< Peer supported named groups. */
	size_t groupcount;														/*!< Number of valid entries in the groups array. */
	qsc_tls_signature_scheme sigschemes[QSC_TLS_MAX_SIGNATURE_SCHEMES];		/*!< Peer supported handshake signature schemes. */
	size_t sigschemecount;													/*!< Number of valid entries in the sigschemes array. */
	qsc_tls_signature_scheme certsigschemes[QSC_TLS_MAX_SIGNATURE_SCHEMES];	/*!< Peer supported certificate signature schemes. */
	size_t certsigschemecount;												/*!< Number of valid entries in the certsigschemes array. */
} qsc_tls_peer_capabilities;

/**
 * \struct qsc_tls_local_certificate_config
 * \brief Stores the configured local certificate chain and CertificateVerify signing configuration.
 */

typedef struct qsc_tls_local_certificate_config
{
	qsc_tls_certificate_view chain[QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES];	/*!< Local certificate chain entries presented to the peer. */
	size_t chainlength;														/*!< Number of valid certificates in the local chain. */
	qsc_tls_signature_scheme verifyscheme;									/*!< Signature scheme used for CertificateVerify. */
	uint8_t verifysignature[QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE];	/*!< Reserved, no longer written by the public API. */
	size_t verifysignaturelen;												/*!< Reserved. */
	/* C6 fix: stored private key for the internal signing trampoline installed by
	 * qsc_tls_handshake_set_local_certificate().  Zeroed by set_local_certificate
	 * if a user-supplied callback is configured instead. */
	uint8_t signprivatekey[QSC_TLS_MAX_SIGNING_PRIVATE_KEY_SIZE];			/*!< Private key bytes stored for the internal signer. */
	size_t signprivatekeylen;												/*!< Length of the stored private key in bytes; zero if not used. */
	qsc_tls_certificate_sign_callback signcallback;							/*!< Callback used to generate the CertificateVerify signature. */
	void* signstate;														/*!< Caller-supplied state passed to the signing callback. */
	bool configured;														/*!< True when a local certificate chain and signing mode are configured. */
	bool staticsignature;													/*!< Reserved, always false in the current implementation. */
} qsc_tls_local_certificate_config;

/**
 * \struct qsc_tls_psk_state
 * \brief Stores cached TLS 1.3 resumption ticket state and the derived PSK binder for the active connection.
 */
typedef struct qsc_tls_psk_state
{
	//qsc_tls_session_ticket ticket;					/*!< Cached TLS 1.3 resumption ticket. */
	uint8_t binder[QSC_TLS_PSK_BINDER_MAX_SIZE];	/*!< Computed PSK binder bytes. */
	size_t binderlen;								/*!< Length of the PSK binder in bytes. */
	bool enabled;									/*!< True when PSK resumption is enabled for the connection. */
	bool resumed;									/*!< True when the current handshake used the configured PSK ticket. */
} qsc_tls_psk_state;

QSC_CPLUSPLUS_ENABLED_END

#endif
