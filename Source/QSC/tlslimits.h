#ifndef QSC_TLS_LIMITS_H
#define QSC_TLS_LIMITS_H

#include "qsccommon.h"
#include "tlsdefs.h"
#include "kyber.h"
#include "dilithium.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlslimits.h
 * \brief Fixed upper bounds used by the TLS implementation.
 */

/* Record and stream limits */
/*! 
 * \def QSC_TLS_MAX_RECORD_SIZE
 * \brief Maximum accepted TLS record size in bytes.
 */
#define QSC_TLS_MAX_RECORD_SIZE 18432U

/*! 
 * \def QSC_TLS_STREAM_BUFFER_MAX_SIZE
 * \brief Maximum buffered inbound TLS stream size in bytes.
 */
#define QSC_TLS_STREAM_BUFFER_MAX_SIZE (QSC_TLS_MAX_RECORD_SIZE * 4U)

/*! 
 * \def QSC_TLS_MAX_PLAINTEXT_SIZE
 * \brief Maximum TLS plaintext fragment size in bytes.
 */
#define QSC_TLS_MAX_PLAINTEXT_SIZE 16384U

/*! 
 * \def QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE
 * \brief Alias for the TLS plaintext maximum.
 */
#define QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE QSC_TLS_MAX_PLAINTEXT_SIZE

/*! 
 * \def QSC_TLS_RECORD_MAX_INNER_SIZE
 * \brief Maximum TLSInnerPlaintext size including the content-type trailer.
 */
#define QSC_TLS_RECORD_MAX_INNER_SIZE (QSC_TLS_MAX_PLAINTEXT_SIZE + QSC_TLS_INNER_CONTENT_TYPE_SIZE)

/* Registry and identifier limits */
/*! 
 * \def QSC_TLS_MAX_GROUPS
 * \brief Maximum number of supported groups tracked per peer.
 */
#define QSC_TLS_MAX_GROUPS 16U

/*! 
 * \def QSC_TLS_MAX_SIGNATURE_SCHEMES
 * \brief Maximum number of signature schemes tracked per peer.
 */
#define QSC_TLS_MAX_SIGNATURE_SCHEMES 16U

/*! 
 * \def QSC_TLS_MAX_CIPHER_SUITES
 * \brief Maximum number of cipher suites tracked or advertised by the TLS layer.
 */
#define QSC_TLS_MAX_CIPHER_SUITES 16U

/*! 
 * \def QSC_TLS_MAX_HOSTNAME_SIZE
 * \brief Maximum hostname length accepted by the TLS layer.
 */
#define QSC_TLS_MAX_HOSTNAME_SIZE 255U

/*! 
 * \def QSC_TLS_MAX_ALPN_SIZE
 * \brief Maximum ALPN identifier length in bytes.
 */
#define QSC_TLS_MAX_ALPN_SIZE 255U

/* Certificate and handshake message limits */
/*! 
 * \def QSC_TLS_CERTIFICATE_REQUEST_CONTEXT_MAX_SIZE
 * \brief Maximum certificate request-context size.
 */
#define QSC_TLS_CERTIFICATE_REQUEST_CONTEXT_MAX_SIZE 255U

/*! 
 * \def QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES
 * \brief Maximum number of certificates tracked in a chain.
 */
#define QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES 8U

/*! 
 * \def QSC_TLS_CERTIFICATE_MAX_SIZE
 * \brief Maximum size of a single encoded certificate.
 */
#define QSC_TLS_CERTIFICATE_MAX_SIZE 65535U

/*! 
 * \def QSC_TLS_HANDSHAKE_FINISHED_MAX_SIZE
 * \brief Maximum size of a Finished verify-data field.
 */
#define QSC_TLS_HANDSHAKE_FINISHED_MAX_SIZE 64U

/*! 
 * \def QSC_TLS_MAX_PSK_IDENTITIES
 * \brief Maximum number of PSK identities processed in a ClientHello.
 */
#define QSC_TLS_MAX_PSK_IDENTITIES 4U

/*! 
 * \def QSC_TLS_TICKET_MAX_SIZE
 * \brief Maximum size of a serialized session ticket.
 */
#define QSC_TLS_TICKET_MAX_SIZE 1024U

/*! 
 * \def QSC_TLS_TICKET_NONCE_MAX_SIZE
 * \brief Maximum ticket nonce size in bytes.
 */
#define QSC_TLS_TICKET_NONCE_MAX_SIZE 255U

/*! 
 * \def QSC_TLS_PSK_BINDER_MAX_SIZE
 * \brief Maximum size of a PSK binder in bytes.
 */
#define QSC_TLS_PSK_BINDER_MAX_SIZE QSC_TLS_HASH_MAX_SIZE

/* Key material and algorithm-size limits */
/*! 
 * \def QSC_TLS_MAX_CLASSICAL_PUBLIC_KEY_SIZE
 * \brief Maximum classical named-group public-key size exposed by the TLS registry.
 */
#define QSC_TLS_MAX_CLASSICAL_PUBLIC_KEY_SIZE 97U

/*! 
 * \def QSC_TLS_MAX_CLASSICAL_PRIVATE_KEY_SIZE
 * \brief Maximum classical named-group private-key state size exposed by the TLS registry.
 */
#define QSC_TLS_MAX_CLASSICAL_PRIVATE_KEY_SIZE 96U

/*! 
 * \def QSC_TLS_MAX_KEM_PUBLIC_KEY_SIZE
 * \brief Maximum KEM public-key size exposed by the TLS registry.
 */
#define QSC_TLS_MAX_KEM_PUBLIC_KEY_SIZE QSC_KYBER_PUBLICKEY_SIZE

/*! 
 * \def QSC_TLS_MAX_KEM_PRIVATE_KEY_SIZE
 * \brief Maximum KEM private-key size exposed by the TLS registry.
 */
#define QSC_TLS_MAX_KEM_PRIVATE_KEY_SIZE QSC_KYBER_PRIVATEKEY_SIZE

/*! 
 * \def QSC_TLS_MAX_KEM_CIPHERTEXT_SIZE
 * \brief Maximum KEM ciphertext size exposed by the TLS registry.
 */
#define QSC_TLS_MAX_KEM_CIPHERTEXT_SIZE QSC_KYBER_CIPHERTEXT_SIZE

/*! 
 * \def QSC_TLS_MAX_KEM_SHARED_SECRET_SIZE
 * \brief Maximum KEM shared-secret size exposed by the TLS registry.
 */
#define QSC_TLS_MAX_KEM_SHARED_SECRET_SIZE QSC_KYBER_SHAREDSECRET_SIZE

/*! 
 * \def QSC_TLS_MAX_HYBRID_CLIENT_KEYSHARE_SIZE
 * \brief Maximum hybrid client key-share size in bytes.
 */
#define QSC_TLS_MAX_HYBRID_CLIENT_KEYSHARE_SIZE (QSC_TLS_MAX_CLASSICAL_PUBLIC_KEY_SIZE + QSC_TLS_MAX_KEM_PUBLIC_KEY_SIZE)

/*! 
 * \def QSC_TLS_MAX_HYBRID_SERVER_KEYSHARE_SIZE
 * \brief Maximum hybrid server key-share size in bytes.
 */
#define QSC_TLS_MAX_HYBRID_SERVER_KEYSHARE_SIZE (QSC_TLS_MAX_CLASSICAL_PUBLIC_KEY_SIZE + QSC_TLS_MAX_KEM_CIPHERTEXT_SIZE)

/*! 
 * \def QSC_TLS_MAX_PRIVATE_KEY_SIZE
 * \brief Maximum stored private-key state across the current named groups.
 */
#define QSC_TLS_MAX_PRIVATE_KEY_SIZE (QSC_TLS_MAX_CLASSICAL_PRIVATE_KEY_SIZE + QSC_TLS_MAX_KEM_PRIVATE_KEY_SIZE)

/*! 
 * \def QSC_TLS_MAX_SHARED_SECRET_SIZE
 * \brief Maximum combined shared-secret size across the current classical and hybrid groups.
 */
#define QSC_TLS_MAX_SHARED_SECRET_SIZE (48U + QSC_TLS_MAX_KEM_SHARED_SECRET_SIZE)

/*! 
 * \def QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE
 * \brief Maximum CertificateVerify signature size in bytes across the registered signature schemes.
 */
#define QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE QSC_DILITHIUM_SIGNATURE_SIZE

/*! 
 * \def QSC_TLS_MAX_KEYSHARE_SIZE
 * \brief Maximum encoded client key-share size in bytes.
 */
#define QSC_TLS_MAX_KEYSHARE_SIZE QSC_TLS_MAX_HYBRID_CLIENT_KEYSHARE_SIZE

/*! 
 * \def QSC_TLS_KEY_SHARE_MAX_SIZE
 * \brief Alias for the maximum key-share size.
 */
#define QSC_TLS_KEY_SHARE_MAX_SIZE QSC_TLS_MAX_KEYSHARE_SIZE

/* Extension and hello size limits */
/*! 
 * \def QSC_TLS_MAX_EXTENSION_SIZE
 * \brief Maximum size of an encoded extension block in bytes for the current ClientHello scaffolding.
 */
#define QSC_TLS_MAX_EXTENSION_SIZE (64U + QSC_TLS_MAX_HYBRID_CLIENT_KEYSHARE_SIZE + (QSC_TLS_MAX_GROUPS * sizeof(uint16_t)) + (QSC_TLS_MAX_SIGNATURE_SCHEMES * sizeof(uint16_t)))

/*! 
 * \def QSC_TLS_SUPPORTED_VERSIONS_CLIENT_EXTENSION_SIZE
 * \brief Encoded supported_versions extension size in bytes for the current ClientHello.
 */
#define QSC_TLS_SUPPORTED_VERSIONS_CLIENT_EXTENSION_SIZE 7U

/*! 
 * \def QSC_TLS_SUPPORTED_VERSIONS_SERVER_EXTENSION_SIZE
 * \brief Encoded supported_versions extension size in bytes for the current ServerHello.
 */
#define QSC_TLS_SUPPORTED_VERSIONS_SERVER_EXTENSION_SIZE 6U

/*! 
 * \def QSC_TLS_SUPPORTED_GROUPS_EXTENSION_MAX_SIZE
 * \brief Maximum encoded supported_groups extension size in bytes.
 */
#define QSC_TLS_SUPPORTED_GROUPS_EXTENSION_MAX_SIZE (6U + (QSC_TLS_MAX_GROUPS * sizeof(uint16_t)))

/*! 
 * \def QSC_TLS_SIGNATURE_ALGORITHMS_EXTENSION_MAX_SIZE
 * \brief Maximum encoded signature_algorithms extension size in bytes.
 */
#define QSC_TLS_SIGNATURE_ALGORITHMS_EXTENSION_MAX_SIZE (6U + (QSC_TLS_MAX_SIGNATURE_SCHEMES * sizeof(uint16_t)))

/*! 
 * \def QSC_TLS_KEY_SHARE_CLIENT_EXTENSION_MAX_SIZE
 * \brief Maximum encoded key_share extension size in bytes for ClientHello.
 */
#define QSC_TLS_KEY_SHARE_CLIENT_EXTENSION_MAX_SIZE (8U + QSC_TLS_MAX_KEYSHARE_SIZE)

/*! 
 * \def QSC_TLS_KEY_SHARE_SERVER_EXTENSION_MAX_SIZE
 * \brief Maximum encoded key_share extension size in bytes for ServerHello.
 */
#define QSC_TLS_KEY_SHARE_SERVER_EXTENSION_MAX_SIZE (8U + QSC_TLS_MAX_HYBRID_SERVER_KEYSHARE_SIZE)

/*! 
 * \def QSC_TLS_CLIENT_HELLO_EXTENSIONS_MAX_SIZE
 * \brief Maximum encoded ClientHello extension block size excluding the outer vector16 header.
 */
#define QSC_TLS_CLIENT_HELLO_EXTENSIONS_MAX_SIZE (QSC_TLS_SUPPORTED_VERSIONS_CLIENT_EXTENSION_SIZE + QSC_TLS_SUPPORTED_GROUPS_EXTENSION_MAX_SIZE + QSC_TLS_SIGNATURE_ALGORITHMS_EXTENSION_MAX_SIZE + QSC_TLS_KEY_SHARE_CLIENT_EXTENSION_MAX_SIZE)

/*! 
 * \def QSC_TLS_CLIENT_HELLO_BODY_MAX_SIZE
 * \brief Maximum encoded ClientHello body size for the current TLS scaffolding.
 */
#define QSC_TLS_CLIENT_HELLO_BODY_MAX_SIZE (43U + QSC_TLS_CLIENT_HELLO_EXTENSIONS_MAX_SIZE)

/*! 
 * \def QSC_TLS_SERVER_HELLO_EXTENSIONS_MAX_SIZE
 * \brief Maximum encoded ServerHello extension block size excluding the outer vector16 header.
 */
#define QSC_TLS_SERVER_HELLO_EXTENSIONS_MAX_SIZE (QSC_TLS_SUPPORTED_VERSIONS_SERVER_EXTENSION_SIZE + QSC_TLS_KEY_SHARE_SERVER_EXTENSION_MAX_SIZE)

/*! 
 * \def QSC_TLS_SERVER_HELLO_BODY_MAX_SIZE
 * \brief Maximum encoded ServerHello body size for the current TLS scaffolding.
 */
#define QSC_TLS_SERVER_HELLO_BODY_MAX_SIZE (42U + QSC_TLS_SERVER_HELLO_EXTENSIONS_MAX_SIZE)

/* HKDF label limits */
/*! 
 * \def QSC_TLS_HKDF_LABEL_MAX_WIRE_SIZE
 * \brief Maximum serialized HKDF label size.
 */
#define QSC_TLS_HKDF_LABEL_MAX_WIRE_SIZE (2U + 1U + (QSC_TLS_HKDF_LABEL_PREFIX_SIZE + QSC_TLS_LABEL_MAX_SIZE) + 1U + QSC_TLS_CONTEXT_MAX_SIZE)

typedef char qsc_tls_limit_assert_keyshare[(QSC_TLS_MAX_KEYSHARE_SIZE >= QSC_TLS_MAX_HYBRID_CLIENT_KEYSHARE_SIZE) ? 1 : -1];
typedef char qsc_tls_limit_assert_extension[(QSC_TLS_MAX_EXTENSION_SIZE >= QSC_TLS_CLIENT_HELLO_EXTENSIONS_MAX_SIZE) ? 1 : -1];
typedef char qsc_tls_limit_assert_client_hello[(QSC_TLS_CLIENT_HELLO_BODY_MAX_SIZE >= (43U + QSC_TLS_KEY_SHARE_CLIENT_EXTENSION_MAX_SIZE)) ? 1 : -1];
typedef char qsc_tls_limit_assert_server_hello[(QSC_TLS_SERVER_HELLO_BODY_MAX_SIZE >= (42U + QSC_TLS_KEY_SHARE_SERVER_EXTENSION_MAX_SIZE)) ? 1 : -1];
typedef char qsc_tls_limit_assert_private[(QSC_TLS_MAX_PRIVATE_KEY_SIZE >= (QSC_TLS_MAX_CLASSICAL_PRIVATE_KEY_SIZE + QSC_TLS_MAX_KEM_PRIVATE_KEY_SIZE)) ? 1 : -1];
typedef char qsc_tls_limit_assert_signature[(QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE >= QSC_DILITHIUM_SIGNATURE_SIZE) ? 1 : -1];
typedef char qsc_tls_limit_assert_ciphersuites[(QSC_TLS_MAX_CIPHER_SUITES >= 3U) ? 1 : -1];

QSC_CPLUSPLUS_ENABLED_END

#endif
