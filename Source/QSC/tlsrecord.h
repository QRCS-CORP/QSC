#ifndef QSC_TLS_RECORD_H
#define QSC_TLS_RECORD_H

#include "tlserrors.h"
#include "tlstypes.h"
#include "tlsstate.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsrecord.h
 * \brief TLS record formatting and protection helpers.
 */

/**
 * \brief Initialize a TLS record protection state.
 *
 * \param state: [struct] The record state to initialize.
 * \param key: [const uint8_t*] The traffic key buffer.
 * \param keylen: [size_t] The traffic key length in bytes.
 * \param iv: [const uint8_t*] The static traffic IV buffer.
 * \param ivlen: [size_t] The static traffic IV length in bytes.
 */
QSC_EXPORT_API void qsc_tls_record_state_initialize(qsc_tls_record_state* state, const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen);

/**
 * \brief Dispose of a TLS record protection state.
 *
 * \param state: [struct] The record state to clear.
 */
QSC_EXPORT_API void qsc_tls_record_state_dispose(qsc_tls_record_state* state);

/**
 * \brief Encode a plaintext TLS record.
 *
 * \param output: [uint8_t*] The destination record buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of bytes written.
 * \param type: [enum] The outer record content type.
 * \param input: [const uint8_t*] The plaintext payload buffer.
 * \param inlen: [size_t] The plaintext payload length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_encode_plaintext(uint8_t* output, size_t outlen, size_t* written, qsc_tls_record_content_type type, const uint8_t* input, size_t inlen);

/**
 * \brief Decode a plaintext TLS record.
 *
 * \param input: [const uint8_t*] The source record buffer.
 * \param inlen: [size_t] The source buffer length in bytes.
 * \param type: [enum] Receives the decoded outer record content type.
 * \param payload: [const uint8_t**] Receives a pointer to the decoded payload span.
 * \param payloadlen: [size_t*] Receives the decoded payload length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_decode_plaintext(const uint8_t* input, size_t inlen, qsc_tls_record_content_type* type, const uint8_t** payload, size_t* payloadlen);

/**
 * \brief Determine the full span length of a TLS record.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length in bytes.
 * \param recordlen: [size_t*] Receives the full record span length in bytes.
 * \param complete: [bool*] Receives true if the full record is present in the source buffer.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_try_get_span_length(const uint8_t* input, size_t inlen, size_t* recordlen, bool* complete);

/**
 * \brief Protect a TLSInnerPlaintext payload as a TLSCiphertext record.
 *
 * \param state: [struct] The active write-side record protection state.
 * \param output: [uint8_t*] The destination record buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of bytes written.
 * \param inner_type: [enum] The inner content type trailer.
 * \param input: [const uint8_t*] The plaintext payload buffer.
 * \param inlen: [size_t] The plaintext payload length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_encrypt(qsc_tls_record_state* state, uint8_t* output, size_t outlen, size_t* written, 
	qsc_tls_record_content_type inner_type, const uint8_t* input, size_t inlen);

/**
 * \brief Decrypt a protected TLSCiphertext record.
 *
 * \param state: [struct] The active read-side record protection state.
 * \param output: [uint8_t*] The destination plaintext buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of plaintext bytes written.
 * \param inner_type: [enum] Receives the decoded inner content type.
 * \param input: [const uint8_t*] The protected record buffer.
 * \param inlen: [size_t] The protected record length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_decrypt(qsc_tls_record_state* state, uint8_t* output, size_t outlen, size_t* written, 
	qsc_tls_record_content_type* inner_type, const uint8_t* input, size_t inlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
