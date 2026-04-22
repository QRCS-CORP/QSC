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
	uint8_t verifysignature[QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE];	/*!< Reserved — no longer written by the public API. */
	size_t verifysignaturelen;												/*!< Reserved. */
	/* C6 fix: stored private key for the internal signing trampoline installed by
	 * qsc_tls_handshake_set_local_certificate().  Zeroed by set_local_certificate
	 * if a user-supplied callback is configured instead. */
	uint8_t signprivatekey[QSC_TLS_MAX_SIGNING_PRIVATE_KEY_SIZE];			/*!< Private key bytes stored for the internal signer. */
	size_t signprivatekeylen;												/*!< Length of the stored private key in bytes; zero if not used. */
	qsc_tls_certificate_sign_callback signcallback;							/*!< Callback used to generate the CertificateVerify signature. */
	void* signstate;														/*!< Caller-supplied state passed to the signing callback. */
	bool configured;														/*!< True when a local certificate chain and signing mode are configured. */
	bool staticsignature;													/*!< Reserved — always false in the current implementation. */
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
