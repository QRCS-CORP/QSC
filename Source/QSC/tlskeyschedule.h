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

 /**
  * \file tlskeyschedule.h
  * \brief TLS 1.3 key schedule, HKDF label derivation, traffic-secret expansion,
  *        Finished verification, CertificateVerify input construction, and PSK
  *        binder derivation.
  *
  * \details
  * This header defines the QSC TLS 1.3 key schedule interface. The functions in
  * this module implement the staged secret derivation chain used by the TLS 1.3
  * handshake, including the early secret, handshake secret, master secret,
  * handshake traffic secrets, application traffic secrets, exporter master
  * secret, resumption master secret, resumption PSK, 0-RTT early traffic secret,
  * and PSK binder key.
  *
  * The key schedule is parameterized by the negotiated TLS hash algorithm. It
  * provides HKDF-Extract, HKDF-Expand, and HKDF-Expand-Label helpers for protocol
  * code that must derive secrets using the TLS 1.3 label format. The module also
  * provides utility functions for deriving record protection keys and IVs,
  * advancing application traffic secrets during KeyUpdate, computing and
  * verifying Finished MAC values, and constructing the context-bound input used
  * by CertificateVerify signatures.
  *
  * All secret material stored in qsc_tls_key_schedule_state is fixed-size and
  * bounded by QSC_TLS_HASH_MAX_SIZE. Callers shall initialize a state object with
  * qsc_tls_keyschedule_state_initialize() before use and dispose it with
  * qsc_tls_keyschedule_state_dispose() when the handshake or connection state is
  * no longer required.
  *
  * \section tlskeyschedule_usage Usage
  * Typical full handshake use follows this sequence:
  *
  * \code
  * qsc_tls_key_schedule_state ks;
  * qsc_tls_keyschedule_state_initialize(&ks, qsc_tls_hash_algorithm_sha256);
  * qsc_tls_keyschedule_extract_early_secret(&ks, NULL, 0U);
  * qsc_tls_keyschedule_extract_handshake_secret(&ks, shared_secret, shared_secret_len);
  * qsc_tls_keyschedule_derive_handshake_traffic_secrets(&ks, ch_sh_hash, hash_len);
  * qsc_tls_keyschedule_extract_master_secret(&ks);
  * qsc_tls_keyschedule_derive_application_traffic_secrets(&ks, sf_hash, hash_len);
  * qsc_tls_keyschedule_derive_exporter_master_secret(&ks, sf_hash, hash_len);
  * qsc_tls_keyschedule_derive_resumption_master_secret(&ks, cf_hash, hash_len);
  * qsc_tls_keyschedule_state_dispose(&ks);
  * \endcode
  *
  * \remarks
  * The module performs key schedule derivation only. It does not own transcript
  * hash state, perform record encryption, or negotiate cipher suites. Transcript
  * hashes must be supplied by the caller at the exact protocol boundary required
  * by TLS 1.3.
  */

#ifndef QSC_TLS_KEYSCHEDULE_H
#define QSC_TLS_KEYSCHEDULE_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"
#include "tlsstate.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \struct qsc_tls_key_schedule_state
 * \brief TLS 1.3 key schedule state and derived secret container.
 *
 * \details
 * This structure stores the staged TLS 1.3 secrets derived during handshake and
 * post-handshake processing. The selected hash algorithm determines the valid
 * number of bytes in each fixed-size secret buffer. The boolean state flags
 * record which derivation stages have completed, allowing the implementation to
 * reject operations that are attempted out of sequence.
 *
 * The structure contains sensitive keying material and shall be cleared with
 * qsc_tls_keyschedule_state_dispose() before it is released, reused, or allowed
 * to leave scope.
 */
    typedef struct qsc_tls_key_schedule_state
{
    uint8_t binderkey[QSC_TLS_HASH_MAX_SIZE];                           /*!< PSK binder key, external or resumption, derived from early_secret. */
    uint8_t clientapplicationtrafficsecret[QSC_TLS_HASH_MAX_SIZE];      /*!< Client application traffic secret, generation 0. */
    uint8_t clientearlytrafficsecret[QSC_TLS_HASH_MAX_SIZE];            /*!< Client early traffic secret used for 0-RTT data. */
    uint8_t clienthandshaketrafficsecret[QSC_TLS_HASH_MAX_SIZE];        /*!< Client handshake traffic secret. */
    uint8_t earlyexportermastersecret[QSC_TLS_HASH_MAX_SIZE];           /*!< Early exporter master secret. */
    uint8_t exportermastersecret[QSC_TLS_HASH_MAX_SIZE];                /*!< Exporter master secret. */
    uint8_t earlysecret[QSC_TLS_HASH_MAX_SIZE];                         /*!< TLS early_secret value. */
    uint8_t handshakesecret[QSC_TLS_HASH_MAX_SIZE];                     /*!< TLS handshake_secret value. */
    uint8_t mastersecret[QSC_TLS_HASH_MAX_SIZE];                        /*!< TLS master_secret value. */
    uint8_t resumptionmastersecret[QSC_TLS_HASH_MAX_SIZE];              /*!< Resumption master secret. */
    uint8_t serverhandshaketrafficsecret[QSC_TLS_HASH_MAX_SIZE];        /*!< Server handshake traffic secret. */
    uint8_t serverapplicationtrafficsecret[QSC_TLS_HASH_MAX_SIZE];      /*!< Server application traffic secret, generation 0. */
    size_t digestsize;                                                  /*!< Digest size, in bytes, for the selected hash algorithm. */
    qsc_tls_hash_algorithm hash;                                        /*!< Hash algorithm associated with the negotiated suite. */
    bool binderderived;                                                 /*!< True after binder_key derivation has completed. */
    bool earlydone;                                                     /*!< True after early_secret derivation has completed. */
    bool earlytrafficderived;                                           /*!< True after client_early_traffic_secret derivation has completed. */
    bool handshakedone;                                                 /*!< True after handshake_secret derivation has completed. */
    bool initialized;                                                   /*!< True when the key schedule state has been initialized. */
    bool masterdone;                                                    /*!< True after master_secret derivation has completed. */
} qsc_tls_key_schedule_state;

/**
 * \brief Initialize a TLS key schedule state.
 *
 * \details
 * Clears the supplied state object, records the negotiated hash algorithm, 
 * and resolves the digest size used by all subsequent key schedule operations.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to the key schedule state to initialize.
 * \param hash: [qsc_tls_hash_algorithm] Negotiated TLS hash algorithm.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_state_initialize(qsc_tls_key_schedule_state* state, qsc_tls_hash_algorithm hash);

/**
 * \brief Dispose of a TLS key schedule state.
 *
 * \details
 * Zeroizes all stored secrets, clears state flags, and returns the state object to an inert value. 
 * This function should be called for every initialized key schedule state before the associated connection is released.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to the key schedule state to dispose.
 */
QSC_EXPORT_API void qsc_tls_keyschedule_state_dispose(qsc_tls_key_schedule_state* state);

/**
 * \brief Perform HKDF-Extract for the selected TLS hash algorithm.
 *
 * \details
 * Computes an HKDF pseudorandom key from the supplied salt and input keying material. 
 * The output length must match the digest size of the selected hash
 * algorithm.
 *
 * \param hash: [qsc_tls_hash_algorithm] Hash algorithm selector.
 * \param salt: [const uint8_t*] Pointer to the salt buffer, or NULL when \c saltlen is zero.
 * \param saltlen: [size_t] Length, in bytes, of the salt buffer.
 * \param ikm: [const uint8_t*] Pointer to the input keying material.
 * \param ikmlen: [size_t] Length, in bytes, of the input keying material.
 * \param output: [uint8_t*] Pointer to the destination pseudorandom key buffer.
 * \param outlen: [size_t] Length, in bytes, of the destination buffer.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_hkdf_extract(qsc_tls_hash_algorithm hash, const uint8_t* salt, size_t saltlen, const uint8_t* ikm,
    size_t ikmlen, uint8_t* output, size_t outlen);

/**
 * \brief Perform HKDF-Expand for the selected TLS hash algorithm.
 *
 * \details
 * Expands a pseudorandom key into output keying material using the supplied HKDF info value. 
 * This is the generic HKDF-Expand primitive used internally by the TLS 1.3 label expansion functions.
 *
 * \param hash: [qsc_tls_hash_algorithm] Hash algorithm selector.
 * \param prk: [const uint8_t*] Pointer to the pseudorandom key.
 * \param prklen: [size_t] Length, in bytes, of the pseudorandom key.
 * \param info: [const uint8_t*] Pointer to the HKDF info field, or NULL when \c infolen is zero.
 * \param infolen: [size_t] Length, in bytes, of the HKDF info field.
 * \param output: [uint8_t*] Pointer to the destination output keying material.
 * \param outlen: [size_t] Number of bytes to derive.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_hkdf_expand(qsc_tls_hash_algorithm hash, const uint8_t* prk, size_t prklen, const uint8_t* info,
    size_t infolen, uint8_t* output, size_t outlen);

/**
 * \brief Perform TLS 1.3 HKDF-Expand-Label.
 *
 * \details
 * Encodes the TLS 1.3 HkdfLabel structure as: uint16 length, opaque label vector containing the literal prefix "tls13 " followed by \c label, 
 * and an opaque context vector. The encoded label is then supplied to HKDF-Expand.
 *
 * \param hash: [qsc_tls_hash_algorithm] Hash algorithm selector.
 * \param secret: [const uint8_t*] Pointer to the input secret.
 * \param secretlen: [size_t] Length, in bytes, of the input secret.
 * \param label: [const char*] Pointer to the TLS label string without the "tls13 " prefix.
 * \param labellen: [size_t] Length, in bytes, of \c label.
 * \param context: [const uint8_t*] Pointer to the context value, or NULL when \c contextlen is zero.
 * \param contextlen: [size_t] Length, in bytes, of the context value.
 * \param output: [uint8_t*] Pointer to the destination output buffer.
 * \param outlen: [size_t] Number of bytes to derive.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_hkdf_expand_label(qsc_tls_hash_algorithm hash, const uint8_t* secret, size_t secretlen,
    const char* label, size_t labellen, const uint8_t* context, size_t contextlen, uint8_t* output, size_t outlen);

/**
 * \brief Derive a TLS 1.3 secret using a supplied transcript hash.
 *
 * \details
 * Implements Derive-Secret(secret, label, transcript_hash) by invoking HKDF-Expand-Label, 
 * with the supplied transcript hash as the context and an output length equal to the selected hash digest size unless otherwise constrained by \c outlen.
 *
 * \param hash: [qsc_tls_hash_algorithm] Hash algorithm selector.
 * \param secret: [const uint8_t*] Pointer to the base secret.
 * \param secretlen: [size_t] Length, in bytes, of the base secret.
 * \param label: [const char*] Pointer to the derivation label.
 * \param labellen: [size_t] Length, in bytes, of \c label.
 * \param transcripthash: [const uint8_t*] Pointer to the transcript hash.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 * \param output: [uint8_t*] Pointer to the destination secret buffer.
 * \param outlen: [size_t] Length, in bytes, of the destination buffer.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_secret_with_hash(qsc_tls_hash_algorithm hash, const uint8_t* secret, size_t secretlen,
    const char* label, size_t labellen, const uint8_t* transcripthash, size_t transcripthashlen, uint8_t* output, size_t outlen);

/**
 * \brief Derive a TLS 1.3 secret using the hash of the empty string.
 *
 * \details
 * Computes Derive-Secret(secret, label, "") by using the digest of the empty transcript as the HKDF-Expand-Label context. 
 * This operation is used for the TLS 1.3 derived-secret boundary between extraction stages.
 *
 * \param hash: [qsc_tls_hash_algorithm] Hash algorithm selector.
 * \param secret: [const uint8_t*] Pointer to the base secret.
 * \param secretlen: [size_t] Length, in bytes, of the base secret.
 * \param label: [const char*] Pointer to the derivation label.
 * \param labellen: [size_t] Length, in bytes, of \c label.
 * \param output: [uint8_t*] Pointer to the destination secret buffer.
 * \param outlen: [size_t] Length, in bytes, of the destination buffer.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_secret_empty(qsc_tls_hash_algorithm hash, const uint8_t* secret, size_t secretlen,
    const char* label, size_t labellen, uint8_t* output, size_t outlen);

/**
 * \brief Extract the TLS 1.3 early secret.
 *
 * \details
 * Computes early_secret = HKDF-Extract(0, PSK). When no PSK is used, the caller
 * supplies NULL with a zero length and the implementation performs the no-PSK TLS 1.3 flow.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state.
 * \param psk: [const uint8_t*] Pointer to the optional PSK, or NULL when \c psklen is zero.
 * \param psklen: [size_t] Length, in bytes, of the PSK.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_extract_early_secret(qsc_tls_key_schedule_state* state, const uint8_t* psk, size_t psklen);

/**
 * \brief Extract the TLS 1.3 handshake secret.
 *
 * \details
 * Computes the handshake secret from the derived early-secret boundary value and the supplied DHE or hybrid shared secret. 
 * The early secret must already have been extracted.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state with early_secret derived.
 * \param dhe: [const uint8_t*] Pointer to the DHE, KEM, or hybrid shared secret.
 * \param dhelen: [size_t] Length, in bytes, of the shared secret.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_extract_handshake_secret(qsc_tls_key_schedule_state* state, const uint8_t* dhe, size_t dhelen);

/**
 * \brief Extract the TLS 1.3 master secret.
 *
 * \details
 * Computes the master secret from the derived handshake-secret boundary value and an all-zero input keying material value. 
 * The handshake secret must already have been extracted.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state with handshake_secret derived.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_extract_master_secret(qsc_tls_key_schedule_state* state);

/**
 * \brief Derive the client and server handshake traffic secrets.
 *
 * \details
 * Derives c hs traffic and s hs traffic from handshake_secret using the ClientHello through ServerHello transcript hash. 
 * These secrets are used to derive the handshake record protection keys.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state with handshake_secret derived.
 * \param transcripthash: [const uint8_t*] Pointer to the ClientHello through ServerHello transcript hash.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_handshake_traffic_secrets(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen);

/**
 * \brief Derive the client and server application traffic secrets.
 *
 * \details
 * Derives c ap traffic 0 and s ap traffic 0 from master_secret using the transcript hash that includes the server Finished message. 
 * These secrets are used to derive application-data record protection keys.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state with master_secret derived.
 * \param transcripthash: [const uint8_t*] Pointer to the application traffic transcript hash.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_application_traffic_secrets(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen);

/**
 * \brief Derive the exporter master secret.
 *
 * \details
 * Derives the exporter master secret from master_secret and the supplied transcript hash. 
 * The resulting secret may be used by exporter interfaces that bind external application keys to the TLS session.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state with master_secret derived.
 * \param transcripthash: [const uint8_t*] Pointer to the exporter transcript hash.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_exporter_master_secret(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen);

/**
 * \brief Derive the resumption master secret.
 *
 * \details
 * Derives the resumption master secret from master_secret and the supplied transcript hash. 
 * The resulting secret is used with per-ticket nonces to derive session resumption PSKs.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state with master_secret derived.
 * \param transcripthash: [const uint8_t*] Pointer to the resumption transcript hash.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_resumption_master_secret(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen);

/**
 * \brief Derive record protection key and IV material from a traffic secret.
 *
 * \details
 * Expands a traffic secret into the AEAD record protection key and base IV using the TLS 1.3 "key" and "iv" labels. 
 * The caller supplies the key and IV lengths associated with the negotiated cipher suite.
 *
 * \param hash: [qsc_tls_hash_algorithm] Hash algorithm selector.
 * \param trafficsecret: [const uint8_t*] Pointer to the traffic secret.
 * \param trafficsecretlen: [size_t] Length, in bytes, of the traffic secret.
 * \param keylen: [size_t] Required record protection key length, in bytes.
 * \param ivlen: [size_t] Required record protection IV length, in bytes.
 * \param keyoutput: [uint8_t*] Pointer to the destination key buffer.
 * \param ivoutput: [uint8_t*] Pointer to the destination IV buffer.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_traffic_keys(qsc_tls_hash_algorithm hash,
    const uint8_t* trafficsecret, size_t trafficsecretlen, size_t keylen, size_t ivlen, uint8_t* keyoutput, uint8_t* ivoutput);

/**
 * \brief Advance an application traffic secret for TLS KeyUpdate.
 *
 * \details
 * Computes the next traffic secret from the current traffic secret using the TLS 1.3 "traffic upd" label. 
 * The caller is responsible for replacing the active read or write traffic secret and deriving new record protection keys.
 *
 * \param hash: [qsc_tls_hash_algorithm] Hash algorithm selector.
 * \param currenttrafficsecret: [const uint8_t*] Pointer to the current traffic secret.
 * \param trafficsecretlen: [size_t] Length, in bytes, of the current traffic
 *        secret.
 * \param nexttrafficsecret: [uint8_t*] Pointer to the destination buffer for the next traffic secret.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_advance_traffic_secret(qsc_tls_hash_algorithm hash, const uint8_t* currenttrafficsecret, 
    size_t trafficsecretlen, uint8_t* nexttrafficsecret);

/**
 * \brief Compute a TLS 1.3 Finished verify_data value.
 *
 * \details
 * Derives finished_key from \c basekey using HKDF-Expand-Label with the "finished" label and computes verify_data as
 * HMAC(finished_key, transcript_hash). The output length is the selected hash digest size.
 *
 * \param hash: [qsc_tls_hash_algorithm] Hash algorithm selector.
 * \param basekey: [const uint8_t*] Pointer to the base traffic secret used to derive finished_key.
 * \param basekeylen: [size_t] Length, in bytes, of the base key.
 * \param transcripthash: [const uint8_t*] Pointer to the transcript hash.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 * \param output: [uint8_t*] Pointer to the verify_data output buffer.
 * \param outlen: [size_t] Length, in bytes, of the output buffer.
 * \param written: [size_t*] Pointer receiving the number of bytes written.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_compute_finished(qsc_tls_hash_algorithm hash, const uint8_t* basekey, size_t basekeylen, 
    const uint8_t* transcripthash, size_t transcripthashlen, uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Verify a TLS 1.3 Finished verify_data value.
 *
 * \details
 * Recomputes the expected Finished MAC and compares it to the supplied candidate using constant-time comparison. 
 * The candidate length must match the selected hash digest size.
 *
 * \param hash: [qsc_tls_hash_algorithm] Hash algorithm selector.
 * \param basekey: [const uint8_t*] Pointer to the base traffic secret used to derive finished_key.
 * \param basekeylen: [size_t] Length, in bytes, of the base key.
 * \param transcripthash: [const uint8_t*] Pointer to the transcript hash.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 * \param candidate: [const uint8_t*] Pointer to the received verify_data value.
 * \param candidatelen: [size_t] Length, in bytes, of the candidate value.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_verify_finished(qsc_tls_hash_algorithm hash, const uint8_t* basekey, size_t basekeylen, 
    const uint8_t* transcripthash, size_t transcripthashlen, const uint8_t* candidate, size_t candidatelen);

/**
 * \brief Build the TLS 1.3 CertificateVerify signature input.
 *
 * \details
 * Constructs the exact CertificateVerify input defined by TLS 1.3: 64 space characters, 
 * followed by the role-specific context string, followed by a single zero byte separator, followed by the transcript hash. 
 * The resulting buffer is the message that is signed or verified by the certificate authentication layer.
 *
 * \param contextstring: [const char*] Pointer to the role-specific context string, for example "TLS 1.3, server CertificateVerify".
 * \param transcripthash: [const uint8_t*] Pointer to the transcript hash at the CertificateVerify boundary.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 * \param output: [uint8_t*] Pointer to the destination buffer.
 * \param outlen: [size_t] Length, in bytes, of the destination buffer.
 * \param written: [size_t*] Pointer receiving the number of bytes written.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_build_certificate_verify_input(const char* contextstring, const uint8_t* transcripthash, 
    size_t transcripthashlen, uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Resolve record protection key and IV lengths for a TLS cipher suite.
 *
 * \details
 * Maps the negotiated cipher suite to the AEAD key length and base IV length required by TLS record protection.
 *
 * \param suite: [qsc_tls_cipher_suite] TLS cipher suite selector.
 * \param keylen: [size_t*] Pointer receiving the record protection key length.
 * \param ivlen: [size_t*] Pointer receiving the record protection IV length.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_suite_record_sizes(qsc_tls_cipher_suite suite, size_t* keylen, size_t* ivlen);

/**
 * \brief Resolve the hash algorithm associated with a TLS cipher suite.
 *
 * \details
 * Returns the transcript and HKDF hash algorithm used by the specified cipher suite. 
 * Unsupported suites return the implementation-defined invalid or none hash selector.
 *
 * \param suite: [qsc_tls_cipher_suite] TLS cipher suite selector.
 *
 * \return [qsc_tls_hash_algorithm] Returns the hash algorithm associated with the cipher suite.
 */
QSC_EXPORT_API qsc_tls_hash_algorithm qsc_tls_keyschedule_suite_hash(qsc_tls_cipher_suite suite);

/**
 * \brief Derive a resumption PSK from the resumption master secret.
 *
 * \details
 * Computes PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length). 
 * The caller must derive the resumption master secret before invoking this function.
 *
 * \param state: [const qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state with resumption_master_secret derived.
 * \param nonce: [const uint8_t*] Pointer to the per-ticket nonce from the NewSessionTicket message.
 * \param noncelen: [size_t] Length, in bytes, of the ticket nonce.
 * \param output: [uint8_t*] Pointer to the destination PSK buffer.
 * \param outlen: [size_t] Number of PSK bytes to derive, typically Hash.length.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_resumption_psk(const qsc_tls_key_schedule_state* state, const uint8_t* nonce, 
    size_t noncelen, uint8_t* output, size_t outlen);

/**
 * \brief Derive the TLS 1.3 PSK binder key.
 *
 * \details
 * Derives the binder key from early_secret for PSK binder computation. 
 * The external flag selects the TLS 1.3 "ext binder" label for externally provisioned PSKs or the "res binder" label for resumption PSKs. 
 * The early secret must already have been extracted.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state with early_secret derived.
 * \param external: [bool] Set to true for external PSKs; set to false for resumption PSKs.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on invalid state or derivation failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_binder_key(qsc_tls_key_schedule_state* state, bool external);

/**
 * \brief Derive the client early traffic secret for 0-RTT data.
 *
 * \details
 * Derives client_early_traffic_secret from early_secret using the ClientHello transcript hash up to, but not including, the PSK binder values. 
 * The early secret must already have been extracted.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state with early_secret derived.
 * \param transcripthash: [const uint8_t*] Pointer to the partial ClientHello transcript hash.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_client_early_traffic_secret(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen);

/**
 * \brief Derive the early exporter master secret.
 *
 * \details
 * Derives early_exporter_master_secret from early_secret using the supplied ClientHello transcript hash. 
 * This secret is used by exporter interfaces that are valid during early-data processing.
 *
 * \param state: [qsc_tls_key_schedule_state*] Pointer to an initialized key schedule state with early_secret derived.
 * \param transcripthash: [const uint8_t*] Pointer to the relevant ClientHello transcript hash.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_derive_early_exporter_secret(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen);

/**
 * \brief Compute a TLS 1.3 PSK binder MAC.
 *
 * \details
 * Computes the PSK binder as HMAC(finished_key, transcript_hash_up_to_binders), 
 * where finished_key is derived from the binder key by HKDF-Expand-Label using the "finished" label. 
 * The transcript hash must cover the ClientHello through the PSK identities vector and must exclude the binder values themselves.
 *
 * \param hash: [qsc_tls_hash_algorithm] Hash algorithm selector.
 * \param binderkey: [const uint8_t*] Pointer to the derived binder key.
 * \param binderkeylen: [size_t] Length, in bytes, of the binder key.
 * \param partialtranshash: [const uint8_t*] Pointer to the ClientHello transcript hash up to the binders.
 * \param transcripthashlen: [size_t] Length, in bytes, of the transcript hash.
 * \param output: [uint8_t*] Pointer to the binder output buffer.
 * \param outlen: [size_t] Length, in bytes, of the output buffer.
 * \param written: [size_t*] Pointer receiving the number of binder bytes written.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_keyschedule_compute_psk_binder(qsc_tls_hash_algorithm hash, const uint8_t* binderkey, size_t binderkeylen,
    const uint8_t* partialtranshash, size_t transcripthashlen, uint8_t* output, size_t outlen, size_t* written);

QSC_CPLUSPLUS_ENABLED_END

#endif
