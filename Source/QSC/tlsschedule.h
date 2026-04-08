#ifndef QSC_TLS_SCHEDULE_H
#define QSC_TLS_SCHEDULE_H

#include "tlstranscript.h"
#include "tlscodec.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsschedule.h
 * \brief TLS 1.3 HKDF schedule helpers.
 */

/**
 * \brief Perform HKDF-Extract for the selected TLS transcript hash.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the extracted secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param key: [const uint8_t*] The input keying material buffer, or NULL when keylen is zero.
 * \param keylen: [size_t] The length of the input keying material in bytes.
 * \param salt: [const uint8_t*] The salt buffer, or NULL when saltlen is zero.
 * \param saltlen: [size_t] The length of the salt buffer in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_extract(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen);

/**
 * \brief Expand a TLS 1.3 HKDF label using HKDF-Expand.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the expanded bytes.
 * \param outlen: [size_t] The requested output length in bytes.
 * \param secret: [const uint8_t*] The input secret buffer.
 * \param secretlen: [size_t] The length of the input secret in bytes.
 * \param label: [const char*] The TLS 1.3 label string without the "tls13 " prefix.
 * \param context: [const uint8_t*] The optional label context buffer, or NULL when contextlen is zero.
 * \param contextlen: [size_t] The length of the context buffer in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_expand_label(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* secret, size_t secretlen, const char* label, const uint8_t* context, size_t contextlen);

/**
 * \brief Derive a TLS 1.3 secret from the running transcript hash.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the derived secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param secret: [const uint8_t*] The input secret buffer.
 * \param secretlen: [size_t] The length of the input secret in bytes.
 * \param label: [const char*] The TLS 1.3 derivation label without the "tls13 " prefix.
 * \param transcript: [const struct] The active transcript state.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_derive_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* secret, size_t secretlen, const char* label, const qsc_tls_transcript_state* transcript);

/**
 * \brief Derive a TLS 1.3 secret from an explicit transcript hash.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the derived secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param secret: [const uint8_t*] The input secret buffer.
 * \param secretlen: [size_t] The length of the input secret in bytes.
 * \param label: [const char*] The TLS 1.3 derivation label without the "tls13 " prefix.
 * \param transcript_hash: [const uint8_t*] The transcript hash buffer, or NULL when transcript_hashlen is zero.
 * \param transcript_hashlen: [size_t] The length of the transcript hash buffer in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_derive_secret_from_hash(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* secret, size_t secretlen, const char* label, const uint8_t* transcript_hash, size_t transcript_hashlen);

/**
 * \brief Derive the TLS 1.3 handshake secret from the negotiated shared secret and optional PSK.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the handshake secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param sharedsecret: [const uint8_t*] The negotiated (EC)DHE or KEM shared secret.
 * \param sharedsecretlen: [size_t] The length of the negotiated shared secret in bytes.
 * \param psk: [const uint8_t*] The optional PSK buffer, or NULL when psklen is zero.
 * \param psklen: [size_t] The length of the PSK buffer in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_derive_handshake_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* sharedsecret, size_t sharedsecretlen, const uint8_t* psk, size_t psklen);

/**
 * \brief Derive the TLS 1.3 master secret from the handshake secret.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the master secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param handshakesecret: [const uint8_t*] The handshake secret buffer.
 * \param handshakesecretlen: [size_t] The length of the handshake secret in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_derive_master_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* handshakesecret, size_t handshakesecretlen);

/**
 * \brief Derive the client handshake traffic secret from an explicit transcript hash.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the client handshake traffic secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param handshakesecret: [const uint8_t*] The handshake secret buffer.
 * \param handshakesecretlen: [size_t] The length of the handshake secret in bytes.
 * \param transcript_hash: [const uint8_t*] The transcript hash buffer.
 * \param transcript_hashlen: [size_t] The length of the transcript hash buffer in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_derive_client_handshake_traffic_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* handshakesecret, size_t handshakesecretlen, const uint8_t* transcript_hash, size_t transcript_hashlen);

/**
 * \brief Derive the server handshake traffic secret from an explicit transcript hash.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the server handshake traffic secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param handshakesecret: [const uint8_t*] The handshake secret buffer.
 * \param handshakesecretlen: [size_t] The length of the handshake secret in bytes.
 * \param transcript_hash: [const uint8_t*] The transcript hash buffer.
 * \param transcript_hashlen: [size_t] The length of the transcript hash buffer in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_derive_server_handshake_traffic_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* handshakesecret, size_t handshakesecretlen, const uint8_t* transcript_hash, size_t transcript_hashlen);

/**
 * \brief Derive the client application traffic secret from an explicit transcript hash.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the client application traffic secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param mastersecret: [const uint8_t*] The master secret buffer.
 * \param mastersecretlen: [size_t] The length of the master secret in bytes.
 * \param transcript_hash: [const uint8_t*] The transcript hash buffer.
 * \param transcript_hashlen: [size_t] The length of the transcript hash buffer in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_derive_client_application_traffic_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* mastersecret, size_t mastersecretlen, const uint8_t* transcript_hash, size_t transcript_hashlen);

/**
 * \brief Derive the server application traffic secret from an explicit transcript hash.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the server application traffic secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param mastersecret: [const uint8_t*] The master secret buffer.
 * \param mastersecretlen: [size_t] The length of the master secret in bytes.
 * \param transcript_hash: [const uint8_t*] The transcript hash buffer.
 * \param transcript_hashlen: [size_t] The length of the transcript hash buffer in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_derive_server_application_traffic_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* mastersecret, size_t mastersecretlen, const uint8_t* transcript_hash, size_t transcript_hashlen);

/**
 * \brief Derive a TLS record-protection key from a traffic secret.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the record key.
 * \param outlen: [size_t] The requested key length in bytes.
 * \param trafficsecret: [const uint8_t*] The traffic secret buffer.
 * \param trafficsecretlen: [size_t] The length of the traffic secret in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_derive_record_key(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* trafficsecret, size_t trafficsecretlen);

/**
 * \brief Derive a TLS record-protection IV from a traffic secret.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the static record IV.
 * \param outlen: [size_t] The requested IV length in bytes.
 * \param trafficsecret: [const uint8_t*] The traffic secret buffer.
 * \param trafficsecretlen: [size_t] The length of the traffic secret in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_derive_record_iv(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* trafficsecret, size_t trafficsecretlen);

/**
 * \brief Update an application traffic secret using the TLS 1.3 traffic update label.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the updated traffic secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param trafficsecret: [const uint8_t*] The current application traffic secret buffer.
 * \param trafficsecretlen: [size_t] The length of the current traffic secret in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_update_application_traffic_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* trafficsecret, size_t trafficsecretlen);

/**
 * \brief Derive the TLS Finished key from a base traffic secret.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the Finished key.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param basekey: [const uint8_t*] The input base secret buffer.
 * \param keylen: [size_t] The length of the input base secret in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_finished_key(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* basekey, size_t keylen);

/**
 * \brief Compute the empty-message hash for the selected TLS transcript hash.
 *
 * \param hash: [enum] The TLS transcript hash algorithm.
 * \param output: [uint8_t*] The output buffer that receives the empty-message hash.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 *
 * \return Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_schedule_empty_hash(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
