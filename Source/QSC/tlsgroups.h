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

#ifndef QSC_TLS_GROUPS_H
#define QSC_TLS_GROUPS_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"
#include "tlslimits.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsgroups.h
 * \brief TLS named-group descriptors and key-share helper routines.
 *
 * \details
 * This header maps supported TLS named groups onto the underlying QSC key-exchange
 * primitives. A group may be classical, KEM-based, or hybrid. The descriptor table
 * records the canonical wire sizes used by the ClientHello and ServerHello key-share
 * extensions so callers can validate key-share spans before invoking the primitive.
 */

/**
 * \struct qsc_tls_group_descriptor
 * \brief Describes one supported TLS named group and its wire-format sizes.
 */
typedef struct qsc_tls_group_descriptor
{
    qsc_tls_named_group group;            /*!< The TLS named-group identifier. */
    const char* name;                     /*!< Human-readable group name. */
    size_t privatekeysize;                /*!< Private or decapsulation key storage size in bytes. */
    size_t clientpublicsize;              /*!< Expected client key-share length on the wire in bytes. */
    size_t serverpublicsize;              /*!< Expected server response key-share length on the wire in bytes. */
    size_t sharedsecretsize;              /*!< Derived shared-secret length in bytes. */
    bool isclassical;                     /*!< True if the group contains a classical Diffie-Hellman component. */
    bool iskem;                           /*!< True if the group contains a KEM component. */
    bool ishybrid;                        /*!< True if the group combines classical and KEM components. */
    bool supported;                       /*!< True if the group is compiled into the current build. */
} qsc_tls_group_descriptor;

/**
 * \struct qsc_tls_key_exchange_state
 * \brief Stores ephemeral client-side state for a TLS key exchange.
 */
typedef struct qsc_tls_key_exchange_state
{
    qsc_tls_named_group group;                                        /*!< The active named group for the ephemeral key exchange. */
    uint8_t publicshare[QSC_TLS_MAX_HYBRID_CLIENT_KEYSHARE_SIZE];     /*!< Encoded client key share emitted on the wire. */
    size_t publicsharelen;                                            /*!< Length of the publicshare buffer in bytes. */
    uint8_t privatekey[QSC_TLS_MAX_PRIVATE_KEY_SIZE];                 /*!< Stored private or decapsulation key material. */
    size_t privatekeylen;                                             /*!< Length of the private key material in bytes. */
    bool initialized;                                                 /*!< True when the state contains a valid generated key pair. */
} qsc_tls_key_exchange_state;

/**
 * \brief Get the descriptor for a named group.
 *
 * \param group: [enum] The TLS named group.
 *
 * \return [const qsc_tls_group_descriptor*] Returns a pointer to the descriptor, or NULL if the group is unknown.
 */
QSC_EXPORT_API const qsc_tls_group_descriptor* qsc_tls_groups_descriptor_get(qsc_tls_named_group group);

/**
 * \brief Determine whether a named group is supported in the current build.
 *
 * \param group: [enum] The TLS named group.
 *
 * \return [bool] Returns true if the named group is available.
 */
QSC_EXPORT_API bool qsc_tls_groups_is_supported(qsc_tls_named_group group);

/**
 * \brief Generate a client ephemeral key pair for a named group.
 *
 * \details
 * Clears the state structure, generates the ephemeral private key material, emits the
 * corresponding client key share into the publicshare buffer, and records the selected
 * group and lengths for later shared-secret derivation.
 *
 * \param state: [struct*] The key-exchange state to initialize.
 * \param group: [enum] The named group to generate.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_groups_generate_client_keypair(qsc_tls_key_exchange_state* state, qsc_tls_named_group group);

/**
 * \brief Derive the client-side shared secret from the peer server key share.
 *
 * \details
 * Validates the server key-share length against the descriptor for the active named group
 * and derives the shared secret or hybrid secret concatenation into the caller-supplied
 * output buffer.
 *
 * \param state: [struct*] The initialized client key-exchange state.
 * \param serverkeyshare: [const uint8_t*] The peer server key-share bytes.
 * \param serverkeysharelen: [size_t] The server key-share length in bytes.
 * \param sharedsecret: [uint8_t*] The destination buffer for the derived shared secret.
 * \param sharedsecretlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of bytes written to sharedsecret.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_groups_client_derive_shared_secret(qsc_tls_key_exchange_state* state,
    const uint8_t* serverkeyshare, size_t serverkeysharelen, uint8_t* sharedsecret, size_t sharedsecretlen, size_t* written);

/**
 * \brief Generate the server response key share and shared secret for an offered client key share.
 *
 * \details
 * Implements the server-side half of the named-group primitive. Depending on the selected
 * group, the function may perform Diffie-Hellman key generation, KEM encapsulation, or a
 * hybrid composition that concatenates multiple component outputs.
 *
 * \param group: [enum] The negotiated named group.
 * \param clientkeyshare: [const uint8_t*] The client key-share bytes.
 * \param clientkeysharelen: [size_t] The client key-share length in bytes.
 * \param serverkeyshare: [uint8_t*] The destination buffer for the encoded server response key share.
 * \param serverkeysharelen: [size_t] The destination buffer length in bytes.
 * \param serverkeysharewritten: [size_t*] Receives the number of bytes written to serverkeyshare.
 * \param sharedsecret: [uint8_t*] The destination buffer for the derived shared secret.
 * \param sharedsecretlen: [size_t] The destination buffer length in bytes.
 * \param sharedsecretwritten: [size_t*] Receives the number of bytes written to sharedsecret.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_groups_server_respond(qsc_tls_named_group group, const uint8_t* clientkeyshare, size_t clientkeysharelen, 
    uint8_t* serverkeyshare, size_t serverkeysharelen, size_t* serverkeysharewritten, uint8_t* sharedsecret, size_t sharedsecretlen, size_t* sharedsecretwritten);

/**
 * \brief Dispose of a key-exchange state and zeroize retained key material.
 *
 * \param state: [struct*] The key-exchange state to clear.
 */
QSC_EXPORT_API void qsc_tls_groups_key_exchange_state_dispose(qsc_tls_key_exchange_state* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
