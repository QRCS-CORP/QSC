#ifndef QSC_TLS_TRANSCRIPT_H
#define QSC_TLS_TRANSCRIPT_H

#include "qsccommon.h"
#include "tlsstate.h"
#include "tlserrors.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlstranscript.h
 * \brief TLS 1.3 transcript-hash state management helpers.
 */

/**
 * \brief Clear and dispose of a transcript state structure.
 *
 * \param state: [struct] The transcript state to clear.
 */
QSC_EXPORT_API void qsc_tls_transcript_dispose(qsc_tls_transcript_state* state);

/**
 * \brief Initialize a transcript state for the selected hash algorithm.
 *
 * \param state: [struct] The transcript state to initialize.
 * \param hash: [enum] The transcript hash algorithm.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_transcript_initialize(qsc_tls_transcript_state* state, qsc_tls_hash_algorithm hash);

/**
 * \brief Reset a transcript state to the initialized empty-hash state.
 *
 * \param state: [struct] The transcript state to reset.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_transcript_reset(qsc_tls_transcript_state* state);

/**
 * \brief Append transcript bytes to the running handshake hash.
 *
 * \param state: [struct] The transcript state.
 * \param message: [const uint8_t*] The bytes to append.
 * \param msglen: [size_t] The length of the message in bytes.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_transcript_append(qsc_tls_transcript_state* state, const uint8_t* message, size_t msglen);

/**
 * \brief Finalize a copy of the running transcript and return the current digest.
 *
 * \param state: [const struct] The transcript state.
 * \param output: [uint8_t*] The destination buffer for the transcript hash.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param hashlen: [size_t*] Receives the digest length in bytes.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_transcript_snapshot(const qsc_tls_transcript_state* state, uint8_t* output, size_t outlen, size_t* hashlen);

/**
 * \brief Clone a transcript state, preserving the exact running hash context.
 *
 * \param output: [struct] Receives the cloned transcript state.
 * \param input: [const struct] The source transcript state.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_transcript_clone(qsc_tls_transcript_state* output, const qsc_tls_transcript_state* input);

/**
 * \brief Get the digest size of a transcript hash algorithm.
 *
 * \param hash: [enum] The transcript hash algorithm.
 *
 * \return Returns the hash size in bytes, or zero for an unsupported algorithm.
 */
QSC_EXPORT_API size_t qsc_tls_transcript_hash_size(qsc_tls_hash_algorithm hash);

QSC_CPLUSPLUS_ENABLED_END

#endif
