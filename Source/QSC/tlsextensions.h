#ifndef QSC_TLS_EXTENSIONS_H
#define QSC_TLS_EXTENSIONS_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsextensions.h
 * \brief TLS 1.3 extension encoding and decoding helpers.
 *
 * \details This module encodes and decodes individual TLS extensions as standalone
 * extension blocks, including the 2-byte extension type and 2-byte extension-data
 * length fields. The functions in this interface are structural helpers only. They do
 * not own handshake sequencing, policy selection, or transcript mutation.
 */

/**
 * \brief Encode a supported_groups extension.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param groups: [const qsc_tls_named_group*] The ordered group list to encode.
 * \param groupcount: [size_t] The number of groups in the list.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_supported_groups(uint8_t* output, size_t outlen, size_t* extlen, const qsc_tls_named_group* groups, size_t groupcount);

/**
 * \brief Decode a supported_groups extension.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param groups: [qsc_tls_named_group*] Receives the decoded group list.
 * \param maxgroups: [size_t] The capacity of the groups array.
 * \param groupcount: [size_t*] Receives the decoded group count.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_supported_groups(const uint8_t* input, size_t inlen, qsc_tls_named_group* groups, size_t maxgroups, size_t* groupcount);

/**
 * \brief Encode a signature_algorithms extension.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param sigschemes: [const qsc_tls_signature_scheme*] The ordered signature scheme list to encode.
 * \param sigcount: [size_t] The number of signature schemes in the list.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_signature_algorithms(uint8_t* output, size_t outlen, size_t* extlen, const qsc_tls_signature_scheme* sigschemes, size_t sigcount);

/**
 * \brief Decode a signature_algorithms extension.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param sigschemes: [qsc_tls_signature_scheme*] Receives the decoded signature scheme list.
 * \param maxschemes: [size_t] The capacity of the sigschemes array.
 * \param sigcount: [size_t*] Receives the decoded signature scheme count.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_signature_algorithms(const uint8_t* input, size_t inlen, qsc_tls_signature_scheme* sigschemes, size_t maxschemes, size_t* sigcount);

/**
 * \brief Encode a signature_algorithms_cert extension.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param sigschemes: [const qsc_tls_signature_scheme*] The ordered certificate signature scheme list to encode.
 * \param sigcount: [size_t] The number of signature schemes in the list.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_signature_algorithms_cert(uint8_t* output, size_t outlen, size_t* extlen, const qsc_tls_signature_scheme* sigschemes, size_t sigcount);

/**
 * \brief Decode a signature_algorithms_cert extension.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param sigschemes: [qsc_tls_signature_scheme*] Receives the decoded certificate signature scheme list.
 * \param maxschemes: [size_t] The capacity of the sigschemes array.
 * \param sigcount: [size_t*] Receives the decoded signature scheme count.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_signature_algorithms_cert(const uint8_t* input, size_t inlen, qsc_tls_signature_scheme* sigschemes, size_t maxschemes, size_t* sigcount);

/**
 * \brief Encode a single-entry key_share extension.
 *
 * \details This form is used for ClientHello and for ServerHello when a single key share
 * is present. The function encodes the extension header, the vector length, the selected
 * group, the share length, and the share bytes.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param group: [qsc_tls_named_group] The key share group identifier.
 * \param keyshare: [const uint8_t*] The encoded key share bytes.
 * \param keysharelen: [size_t] The key share length in bytes.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_key_share_single(uint8_t* output, size_t outlen, size_t* extlen, qsc_tls_named_group group, const uint8_t* keyshare, size_t keysharelen);

/**
 * \brief Decode a single-entry key_share extension.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param group: [qsc_tls_named_group*] Receives the decoded group.
 * \param keyshare: [const uint8_t**] Receives a span pointer to the share bytes.
 * \param keysharelen: [size_t*] Receives the share length in bytes.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_key_share_single(const uint8_t* input, size_t inlen, qsc_tls_named_group* group, const uint8_t** keyshare, size_t* keysharelen);

/**
 * \brief Encode a HelloRetryRequest key_share extension.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param group: [qsc_tls_named_group] The selected group requested by the server.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_key_share_hello_retry_request(uint8_t* output, size_t outlen, size_t* extlen, qsc_tls_named_group group);

/**
 * \brief Decode a HelloRetryRequest key_share extension.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param group: [qsc_tls_named_group*] Receives the decoded selected group.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_key_share_hello_retry_request(const uint8_t* input, size_t inlen, qsc_tls_named_group* group);

/**
 * \brief Encode a psk_key_exchange_modes extension.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param permitpskdhe: [bool] When true, encode support for psk_dhe_ke; otherwise only psk_ke is permitted.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_psk_key_exchange_modes(uint8_t* output, size_t outlen, size_t* extlen, bool permitpskdhe);

/**
 * \brief Decode a psk_key_exchange_modes extension.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param permitpskdhe: [bool*] Receives true when psk_dhe_ke is permitted.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_psk_key_exchange_modes(const uint8_t* input, size_t inlen, bool* permitpskdhe);

/**
 * \brief Encode a single-identity client pre_shared_key extension.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param identity: [const uint8_t*] The PSK identity bytes.
 * \param identitylen: [size_t] The PSK identity length in bytes.
 * \param obfuscatedage: [uint32_t] The obfuscated ticket age value.
 * \param binderlen: [size_t] The binder length in bytes.
 * \param binderoffset: [size_t*] Receives the binder offset relative to the output buffer.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_pre_shared_key_client(uint8_t* output, size_t outlen, size_t* extlen, const uint8_t* identity, size_t identitylen, uint32_t obfuscatedage, size_t binderlen, size_t* binderoffset);

/**
 * \brief Decode a single-identity client pre_shared_key extension.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param identity: [const uint8_t**] Receives a span pointer to the PSK identity.
 * \param identitylen: [size_t*] Receives the PSK identity length in bytes.
 * \param obfuscatedage: [uint32_t*] Receives the obfuscated ticket age value.
 * \param binder: [const uint8_t**] Receives a span pointer to the binder bytes.
 * \param binderlen: [size_t*] Receives the binder length in bytes.
 * \param binderoffset: [size_t*] Receives the binder offset relative to the input buffer.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_pre_shared_key_client(const uint8_t* input, size_t inlen, const uint8_t** identity, size_t* identitylen, uint32_t* obfuscatedage, const uint8_t** binder, size_t* binderlen, size_t* binderoffset);

/**
 * \brief Encode a server pre_shared_key extension.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param selectedidentity: [uint16_t] The selected PSK identity index.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_pre_shared_key_server(uint8_t* output, size_t outlen, size_t* extlen, uint16_t selectedidentity);

/**
 * \brief Decode a server pre_shared_key extension.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param selectedidentity: [uint16_t*] Receives the selected PSK identity index.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_pre_shared_key_server(const uint8_t* input, size_t inlen, uint16_t* selectedidentity);

/**
 * \brief Encode a client server_name extension containing a single host_name entry.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param hostname: [const uint8_t*] The host name bytes.
 * \param hostnamelen: [size_t] The host name length in bytes.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_server_name_client(uint8_t* output, size_t outlen, size_t* extlen, const uint8_t* hostname, size_t hostnamelen);

/**
 * \brief Decode a client server_name extension containing a single host_name entry.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param hostname: [const uint8_t**] Receives a span pointer to the host name bytes.
 * \param hostnamelen: [size_t*] Receives the host name length in bytes.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_server_name_client(const uint8_t* input, size_t inlen, const uint8_t** hostname, size_t* hostnamelen);

/**
 * \brief Encode an empty server_name acknowledgement extension.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_server_name_ack(uint8_t* output, size_t outlen, size_t* extlen);

/**
 * \brief Decode an empty server_name acknowledgement extension.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_server_name_ack(const uint8_t* input, size_t inlen);

/**
 * \brief Encode a client ALPN extension with a single protocol identifier.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param protocol: [const uint8_t*] The ALPN protocol identifier bytes.
 * \param protocollen: [size_t] The ALPN protocol identifier length in bytes.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_alpn_client(uint8_t* output, size_t outlen, size_t* extlen, const uint8_t* protocol, size_t protocollen);

/**
 * \brief Decode a client ALPN extension with a single protocol identifier.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param protocol: [const uint8_t**] Receives a span pointer to the ALPN protocol identifier.
 * \param protocollen: [size_t*] Receives the ALPN protocol identifier length in bytes.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_alpn_client(const uint8_t* input, size_t inlen, const uint8_t** protocol, size_t* protocollen);

/**
 * \brief Encode a server ALPN extension with a single protocol identifier.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param extlen: [size_t*] Receives the encoded extension length in bytes.
 * \param protocol: [const uint8_t*] The ALPN protocol identifier bytes.
 * \param protocollen: [size_t] The ALPN protocol identifier length in bytes.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_alpn_server(uint8_t* output, size_t outlen, size_t* extlen, const uint8_t* protocol, size_t protocollen);

/**
 * \brief Decode a server ALPN extension with a single protocol identifier.
 *
 * \param input: [const uint8_t*] The encoded extension.
 * \param inlen: [size_t] The encoded extension length in bytes.
 * \param protocol: [const uint8_t**] Receives a span pointer to the ALPN protocol identifier.
 * \param protocollen: [size_t*] Receives the ALPN protocol identifier length in bytes.
 *
 * \return qsc_tls_status_success on success or a negative TLS status code on failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_alpn_server(const uint8_t* input, size_t inlen, const uint8_t** protocol, size_t* protocollen);

QSC_CPLUSPLUS_ENABLED_END

#endif
