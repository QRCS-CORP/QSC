#ifndef QSC_TLS_RESUMPTION_H
#define QSC_TLS_RESUMPTION_H

#include "qsccommon.h"
#include "tlsdefs.h"
#include "tlserrors.h"
#include "tlslimits.h"
#include "tlstypes.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsresumption.h
 * \brief TLS 1.3 session-ticket, resumption, and PSK binder helpers.
 */

typedef struct qsc_tls_connection_state qsc_tls_connection_state;

/**
 * \brief The TLS 1.3 session ticket container.
 */
typedef struct qsc_tls_session_ticket
{
	qsc_tls_hash_algorithm hash;
	qsc_tls_cipher_suite ciphersuite;
	uint32_t ageadd;
	uint32_t lifetime;
	uint32_t maxearlydata;
	uint8_t ticket[QSC_TLS_TICKET_MAX_SIZE];
	size_t ticketlen;
	uint8_t nonce[QSC_TLS_TICKET_NONCE_MAX_SIZE];
	size_t noncelen;
	uint8_t resumptionsecret[QSC_TLS_HASH_MAX_SIZE];
	size_t resumptionsecretlen;
	bool valid;
} qsc_tls_session_ticket;

/**
 * \brief Initialize a session-ticket container.
 *
 * \param ticket: [struct] The ticket structure to initialize.
 */
QSC_EXPORT_API void qsc_tls_session_ticket_initialize(qsc_tls_session_ticket* ticket);

/**
 * \brief Clear and dispose a session-ticket container.
 *
 * \param ticket: [struct] The ticket structure to clear.
 */
QSC_EXPORT_API void qsc_tls_session_ticket_dispose(qsc_tls_session_ticket* ticket);

/**
 * \brief Determine whether a session-ticket container is structurally valid.
 *
 * \param ticket: [const struct] The ticket structure to test.
 *
 * \return True if the ticket contents are valid.
 */
QSC_EXPORT_API bool qsc_tls_session_ticket_is_valid(const qsc_tls_session_ticket* ticket);

/**
 * \brief Encode a session-ticket container to an internal serialized form.
 *
 * \param ticket: [const struct] The ticket structure to encode.
 * \param output: [uint8_t*] The output buffer receiving the serialized ticket.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param msglen: [size_t*] Receives the encoded length in bytes.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_session_ticket_encode(const qsc_tls_session_ticket* ticket, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Decode an internal serialized session-ticket container.
 *
 * \param input: [const uint8_t*] The encoded ticket bytes.
 * \param inlen: [size_t] The length of the encoded ticket in bytes.
 * \param ticket: [struct] The destination ticket structure.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_session_ticket_decode(const uint8_t* input, size_t inlen, qsc_tls_session_ticket* ticket);

/**
 * \brief Derive a PSK binder base key.
 *
 * \param hash: [enum] The negotiated transcript hash algorithm.
 * \param psk: [const uint8_t*] The PSK bytes.
 * \param psklen: [size_t] The PSK length in bytes.
 * \param externalpsk: [bool] True for an external PSK label; false for a resumption PSK label.
 * \param output: [uint8_t*] Receives the derived binder key.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_resumption_binder_key(qsc_tls_hash_algorithm hash, const uint8_t* psk, size_t psklen, bool externalpsk, uint8_t* output, size_t outlen);

/**
 * \brief Compute PSK binder verify data for a transcript prefix.
 *
 * \param hash: [enum] The negotiated transcript hash algorithm.
 * \param binderkey: [const uint8_t*] The binder base key.
 * \param binderkeylen: [size_t] The binder-key length in bytes.
 * \param transcript: [const uint8_t*] The transcript prefix bytes.
 * \param transcriptlen: [size_t] The transcript prefix length in bytes.
 * \param output: [uint8_t*] Receives the binder verify-data bytes.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_resumption_binder_verify_data(qsc_tls_hash_algorithm hash, const uint8_t* binderkey, size_t binderkeylen, const uint8_t* transcript, size_t transcriptlen, uint8_t* output, size_t outlen);

/**
 * \brief Compute the PSK binder associated with a cached resumption ticket.
 *
 * \param ticket: [const struct] The cached resumption ticket.
 * \param transcript: [const uint8_t*] The transcript prefix bytes.
 * \param transcriptlen: [size_t] The transcript prefix length in bytes.
 * \param output: [uint8_t*] Receives the computed binder bytes.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_resumption_compute_psk_binder(const qsc_tls_session_ticket* ticket, const uint8_t* transcript, size_t transcriptlen, uint8_t* output, size_t outlen);

/**
 * \brief Encode a TLS 1.3 NewSessionTicket handshake body.
 *
 * \param ticket: [const struct] The session ticket to encode.
 * \param output: [uint8_t*] Receives the encoded handshake body.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param msglen: [size_t*] Receives the encoded body length in bytes.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_resumption_encode_new_session_ticket(const qsc_tls_session_ticket* ticket, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Decode a TLS 1.3 NewSessionTicket handshake body.
 *
 * \param state: [const struct] The connection state providing the active suite and hash.
 * \param input: [const uint8_t*] The encoded handshake body bytes.
 * \param inlen: [size_t] The length of the handshake body in bytes.
 * \param ticket: [struct] The destination ticket structure.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_resumption_decode_new_session_ticket(const qsc_tls_connection_state* state, const uint8_t* input, size_t inlen, qsc_tls_session_ticket* ticket);

/**
 * \brief Generate a new locally owned resumption ticket from connection state.
 *
 * \param state: [const struct] The connection state providing the active master secret and suite.
 * \param lifetime: [uint32_t] The ticket lifetime in seconds.
 * \param ticket: [struct] The destination ticket structure.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_connection_state_generate_resumption_ticket(const qsc_tls_connection_state* state, uint32_t lifetime, qsc_tls_session_ticket* ticket);

/**
 * \brief Enable resumption on a connection state from a cached ticket.
 *
 * \param state: [struct] The connection state to update.
 * \param ticket: [const struct] The ticket to install.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_connection_state_enable_resumption(qsc_tls_connection_state* state, const qsc_tls_session_ticket* ticket);

/**
 * \brief Determine whether a connection state has resumption enabled.
 *
 * \param state: [const struct] The connection state to query.
 *
 * \return True if resumption is enabled.
 */
QSC_EXPORT_API bool qsc_tls_connection_state_is_resumption_enabled(const qsc_tls_connection_state* state);

/**
 * \brief Build a resumption ticket from NewSessionTicket fields and connection state.
 *
 * \param state: [const struct] The connection state providing the active master secret and suite.
 * \param newticket: [const uint8_t*] The opaque ticket bytes from the peer.
 * \param newticketlen: [size_t] The opaque ticket length in bytes.
 * \param nonce: [const uint8_t*] The ticket nonce bytes.
 * \param noncelen: [size_t] The nonce length in bytes.
 * \param lifetime: [uint32_t] The ticket lifetime in seconds.
 * \param ageadd: [uint32_t] The ticket age-add value.
 * \param ticket: [struct] The destination ticket structure.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_connection_state_build_resumption_ticket(const qsc_tls_connection_state* state, const uint8_t* newticket, size_t newticketlen, const uint8_t* nonce, size_t noncelen, uint32_t lifetime, uint32_t ageadd, qsc_tls_session_ticket* ticket);

/**
 * \brief Compute the active PSK binder for a connection state.
 *
 * \param state: [const struct] The connection state supplying the cached ticket.
 * \param transcript: [const uint8_t*] The transcript prefix bytes.
 * \param transcriptlen: [size_t] The transcript prefix length in bytes.
 * \param output: [uint8_t*] Receives the binder bytes.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_connection_state_get_psk_binder(const qsc_tls_connection_state* state, const uint8_t* transcript, size_t transcriptlen, uint8_t* output, size_t outlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
