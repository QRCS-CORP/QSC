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

#ifndef QSC_TLS_DEFS_H
#define QSC_TLS_DEFS_H

#include "tlstypes.h"

/*! 
 * \file tlsdefs.h
 * \brief Defines fixed TLS protocol constants and HKDF label constants.
 */

/*! 
 * \def QSC_TLS_PROTOCOL_VERSION_12
 * \brief Defines the TLS 1.2 legacy protocol version field value.
 */
#define QSC_TLS_PROTOCOL_VERSION_12 0x0303U

/*! 
 * \def QSC_TLS_PROTOCOL_VERSION_13
 * \brief Defines the TLS 1.3 protocol version field value.
 */
#define QSC_TLS_PROTOCOL_VERSION_13 0x0304U

/*! 
 * \def QSC_TLS_RECORD_HEADER_SIZE
 * \brief Defines the size of a TLS record header in bytes.
 */
#define QSC_TLS_RECORD_HEADER_SIZE 5U

/*! 
 * \def QSC_TLS_ALERT_SIZE
 * \brief Defines the size of a TLS alert payload in bytes.
 */
#define QSC_TLS_ALERT_SIZE 2U

/*! 
 * \def QSC_TLS_INNER_CONTENT_TYPE_SIZE
 * \brief Defines the size of the TLSInnerPlaintext content type trailer in bytes.
 */
#define QSC_TLS_INNER_CONTENT_TYPE_SIZE 1U

/*! 
 * \def QSC_TLS_GCM_TAG_SIZE
 * \brief Defines the AEAD authentication tag size in bytes.
 */
#define QSC_TLS_GCM_TAG_SIZE 16U

/*! 
 * \def QSC_TLS_GCM_NONCE_SIZE
 * \brief Defines the AEAD nonce size in bytes.
 */
#define QSC_TLS_GCM_NONCE_SIZE 12U

/*! 
 * \def QSC_TLS_AES128_KEY_SIZE
 * \brief Defines the AES-128 key size in bytes.
 */
#define QSC_TLS_AES128_KEY_SIZE 16U

/*! 
 * \def QSC_TLS_AES256_KEY_SIZE
 * \brief Defines the AES-256 key size in bytes.
 */
#define QSC_TLS_AES256_KEY_SIZE 32U

/*! 
 * \def QSC_TLS_HASH_MAX_SIZE
 * \brief Defines the maximum supported transcript hash size in bytes.
 */
#define QSC_TLS_HASH_MAX_SIZE 64U

/*! 
 * \def QSC_TLS_LABEL_MAX_SIZE
 * \brief Defines the maximum supported TLS HKDF label size in bytes.
 */
#define QSC_TLS_LABEL_MAX_SIZE 64U

/*! 
 * \def QSC_TLS_CONTEXT_MAX_SIZE
 * \brief Defines the maximum supported TLS HKDF context size in bytes.
 */
#define QSC_TLS_CONTEXT_MAX_SIZE 64U

/*! 
 * \def QSC_TLS_HKDF_LABEL_PREFIX
 * \brief Defines the TLS 1.3 HKDF label prefix string.
 */
#define QSC_TLS_HKDF_LABEL_PREFIX "tls13 "

/*! 
 * \def QSC_TLS_HKDF_LABEL_PREFIX_SIZE
 * \brief Defines the length of the TLS 1.3 HKDF label prefix string.
 */
#define QSC_TLS_HKDF_LABEL_PREFIX_SIZE 6U

/*! 
 * \def QSC_TLS_FINISHED_LABEL
 * \brief Defines the HKDF label used to derive Finished keys.
 */
#define QSC_TLS_FINISHED_LABEL "finished"

/*! 
 * \def QSC_TLS_FINISHED_LABEL_SIZE
 * \brief Defines the length of the Finished label string.
 */
#define QSC_TLS_FINISHED_LABEL_SIZE 8U

/*! 
 * \def QSC_TLS_DERIVED_LABEL
 * \brief Defines the HKDF label used for derived-secret transitions.
 */
#define QSC_TLS_DERIVED_LABEL "derived"

/*! 
 * \def QSC_TLS_DERIVED_LABEL_SIZE
 * \brief Defines the length of the derived label string.
 */
#define QSC_TLS_DERIVED_LABEL_SIZE 7U

/*! 
 * \def QSC_TLS_CLIENT_HANDSHAKE_TRAFFIC_LABEL
 * \brief Defines the HKDF label used to derive client handshake traffic secrets.
 */
#define QSC_TLS_CLIENT_HANDSHAKE_TRAFFIC_LABEL "c hs traffic"

/*! 
 * \def QSC_TLS_CLIENT_HANDSHAKE_TRAFFIC_LABEL_SIZE
 * \brief Defines the length of the client handshake traffic label string.
 */
#define QSC_TLS_CLIENT_HANDSHAKE_TRAFFIC_LABEL_SIZE 12U

/*! 
 * \def QSC_TLS_SERVER_HANDSHAKE_TRAFFIC_LABEL
 * \brief Defines the HKDF label used to derive server handshake traffic secrets.
 */
#define QSC_TLS_SERVER_HANDSHAKE_TRAFFIC_LABEL "s hs traffic"

/*! 
 * \def QSC_TLS_SERVER_HANDSHAKE_TRAFFIC_LABEL_SIZE
 * \brief Defines the length of the server handshake traffic label string.
 */
#define QSC_TLS_SERVER_HANDSHAKE_TRAFFIC_LABEL_SIZE 12U

/*! 
 * \def QSC_TLS_CLIENT_APPLICATION_TRAFFIC_LABEL
 * \brief Defines the HKDF label used to derive client application traffic secrets.
 */
#define QSC_TLS_CLIENT_APPLICATION_TRAFFIC_LABEL "c ap traffic"

/*! 
 * \def QSC_TLS_CLIENT_APPLICATION_TRAFFIC_LABEL_SIZE
 * \brief Defines the length of the client application traffic label string.
 */
#define QSC_TLS_CLIENT_APPLICATION_TRAFFIC_LABEL_SIZE 12U

/*! 
 * \def QSC_TLS_SERVER_APPLICATION_TRAFFIC_LABEL
 * \brief Defines the HKDF label used to derive server application traffic secrets.
 */
#define QSC_TLS_SERVER_APPLICATION_TRAFFIC_LABEL "s ap traffic"

/*! 
 * \def QSC_TLS_SERVER_APPLICATION_TRAFFIC_LABEL_SIZE
 * \brief Defines the length of the server application traffic label string.
 */
#define QSC_TLS_SERVER_APPLICATION_TRAFFIC_LABEL_SIZE 12U

/*! 
 * \def QSC_TLS_EXT_BINDER_LABEL
 * \brief Defines the HKDF label used for external PSK binders.
 */
#define QSC_TLS_EXT_BINDER_LABEL "ext binder"

/*! 
 * \def QSC_TLS_EXT_BINDER_LABEL_SIZE
 * \brief Defines the length of the external binder label string.
 */
#define QSC_TLS_EXT_BINDER_LABEL_SIZE 10U

/*! 
 * \def QSC_TLS_RES_BINDER_LABEL
 * \brief Defines the HKDF label used for resumption PSK binders.
 */
#define QSC_TLS_RES_BINDER_LABEL "res binder"

/*! 
 * \def QSC_TLS_RES_BINDER_LABEL_SIZE
 * \brief Defines the length of the resumption binder label string.
 */
#define QSC_TLS_RES_BINDER_LABEL_SIZE 10U

/*! 
 * \def QSC_TLS_EXPORTER_MASTER_LABEL
 * \brief Defines the HKDF label used to derive the exporter master secret.
 */
#define QSC_TLS_EXPORTER_MASTER_LABEL "exp master"

/*! 
 * \def QSC_TLS_EXPORTER_MASTER_LABEL_SIZE
 * \brief Defines the length of the exporter master label string.
 */
#define QSC_TLS_EXPORTER_MASTER_LABEL_SIZE 10U

/*! 
 * \def QSC_TLS_RESUMPTION_LABEL
 * \brief Defines the HKDF label used to derive the resumption secret.
 */
#define QSC_TLS_RESUMPTION_LABEL "resumption"

/*! 
 * \def QSC_TLS_RESUMPTION_LABEL_SIZE
 * \brief Defines the length of the resumption label string.
 */
#define QSC_TLS_RESUMPTION_LABEL_SIZE 10U

/*! 
 * \def QSC_TLS_KEY_LABEL
 * \brief Defines the HKDF label used to derive record protection keys.
 */
#define QSC_TLS_KEY_LABEL "key"

/*! 
 * \def QSC_TLS_KEY_LABEL_SIZE
 * \brief Defines the length of the record key label string.
 */
#define QSC_TLS_KEY_LABEL_SIZE 3U

/*! 
 * \def QSC_TLS_IV_LABEL
 * \brief Defines the HKDF label used to derive record protection IVs.
 */
#define QSC_TLS_IV_LABEL "iv"

/*! 
 * \def QSC_TLS_IV_LABEL_SIZE
 * \brief Defines the length of the record IV label string.
 */
#define QSC_TLS_IV_LABEL_SIZE 2U

/*! 
 * \def QSC_TLS_KEY_UPDATE_LABEL
 * \brief Defines the HKDF label used to update application traffic secrets.
 */
#define QSC_TLS_KEY_UPDATE_LABEL "traffic upd"

/*! 
 * \def QSC_TLS_KEY_UPDATE_LABEL_SIZE
 * \brief Defines the length of the traffic update label string.
 */
#define QSC_TLS_KEY_UPDATE_LABEL_SIZE 11U

/*! 
 * \def QSC_TLS_EXTENSION_HEADER_SIZE
 * \brief Defines the size of a TLS extension header in bytes.
 */
#define QSC_TLS_EXTENSION_HEADER_SIZE 4U

/*! 
 * \def QSC_TLS_VECTOR16_HEADER_SIZE
 * \brief Defines the size of a 16-bit vector length field in bytes.
 */
#define QSC_TLS_VECTOR16_HEADER_SIZE 2U

/*! 
 * \def QSC_TLS_KEYSHARE_ENTRY_HEADER_SIZE
 * \brief Defines the size of a TLS key_share entry header in bytes.
 */
#define QSC_TLS_KEYSHARE_ENTRY_HEADER_SIZE 4U

#endif
