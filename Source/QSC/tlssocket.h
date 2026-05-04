/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_TLS_SOCKET_H
#define QSC_TLS_SOCKET_H

#include "qsccommon.h"
#include "async.h"
#include "tlsengine.h"
#include "tlssignerdefault.h"
#include "tlsio.h"
#include "socketbase.h"
#include "socketclient.h"
#include "socketserver.h"
#include "x509wrap.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlssocket.h
 * \brief High-level blocking and concurrent socket integration layer for QSC TLS 1.3 and X.509.
 *
 * \details
 * This header defines the public API for the QSC TLS socket wrapper. The wrapper composes the
 * QSC dual-stack socket layer, the TLS 1.3 engine, the record-framed TLS I/O adapter, and the
 * X.509 wrapper into deployment-oriented client, listener, accepted-connection, and server APIs.
 *
 * The wrapper does not implement an independent TLS or X.509 stack. It owns the application-facing
 * lifecycle around the existing TLS and X.509 components. It provides context-based policy selection,
 * trust-store loading, server identity loading, socket option control, blocking client connections,
 * blocking listener accept, a bounded concurrent server mode, framed application messages, session
 * ticket policy helpers, structured result reporting, and optional structured logging callbacks.
 *
 * The default client and server policies are intended for conservative TLS 1.3 interoperability.
 * The ML-KEM hybrid and experimental PQC profiles are explicit opt-in profiles and require compatible
 * peers. The wrapper stores TLS, socket, and X.509 status values separately in qsc_tls_socket_result
 * so that callers can distinguish transport failures from TLS protocol and certificate validation errors.
 *
 * Ownership model:
 * - qsc_tls_socket_context owns reusable policy, trust-store, X.509 bridge, server identity, and
 *   session ticket policy state.
 * - qsc_tls_socket_connection owns a connected or accepted socket, a TLS engine instance, and a
 *   TLS I/O adapter bound to that engine and socket.
 * - qsc_tls_socket_listener owns the listening socket and references a context supplied by the caller.
 * - qsc_tls_socket_server owns a listener and, in concurrent mode, a fixed pool of connection slots.
 *
 * \code
 * // Minimal client usage.
 * qsc_tls_socket_context ctx;
 * qsc_tls_socket_connection conn;
 * uint8_t buf[4096U];
 * size_t rlen = 0U;
 *
 * qsc_tls_socket_context_initialize(&ctx);
 * qsc_tls_socket_context_set_default_client_policy(&ctx);
 * qsc_tls_socket_context_load_trust_anchor_bundle_file(&ctx, "ca-bundle.pem", true);
 *
 * qsc_tls_socket_connection_initialize(&conn);
 *
 * if (qsc_tls_socket_client_connect_host(&conn, &ctx, "example.com", "443") == qsc_tls_socket_status_success)
 * {
 *     const uint8_t req[] = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
 *     qsc_tls_socket_send(&conn, req, sizeof(req) - 1U, NULL);
 *     qsc_tls_socket_receive(&conn, buf, sizeof(buf), &rlen);
 *     qsc_tls_socket_shutdown(&conn);
 * }
 *
 * qsc_tls_socket_connection_dispose(&conn);
 * qsc_tls_socket_context_dispose(&ctx);
 * \endcode
 *
 * \section tlssocket_links Reference Links:
 * - <a href="https://www.rfc-editor.org/rfc/rfc8446">RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3</a>
 * - <a href="https://www.rfc-editor.org/rfc/rfc5280">RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile</a>
 * - <a href="https://www.rfc-editor.org/rfc/rfc6066">RFC 6066: TLS Extension Definitions</a>
 * - <a href="https://www.rfc-editor.org/rfc/rfc7301">RFC 7301: TLS Application-Layer Protocol Negotiation Extension</a>
 */

/**
 * \def QSC_TLS_SOCKET_CIPHER_SUITE_MAX
 * \brief The maximum number of cipher suites stored in a TLS socket context preference list.
 */
#define QSC_TLS_SOCKET_CIPHER_SUITE_MAX 8U

/**
 * \def QSC_TLS_SOCKET_GROUP_MAX
 * \brief The maximum number of named groups stored in a TLS socket context preference list.
 */
#define QSC_TLS_SOCKET_GROUP_MAX 16U

/**
 * \def QSC_TLS_SOCKET_SIGNATURE_SCHEME_MAX
 * \brief The maximum number of signature schemes stored in a TLS socket context preference list.
 */
#define QSC_TLS_SOCKET_SIGNATURE_SCHEME_MAX 16U

/**
 * \def QSC_TLS_SOCKET_SERVER_BUFFER_SIZE
 * \brief The default per-connection application receive buffer size used by the blocking server loop.
 */
#define QSC_TLS_SOCKET_SERVER_BUFFER_SIZE 16384U

/**
 * \def QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX
 * \brief The maximum number of fixed connection slots available to the concurrent server mode.
 */
#define QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX 64U

/**
 * \def QSC_TLS_SOCKET_FRAME_HEADER_SIZE
 * \brief The size in bytes of the length prefix used by the framed application-message API.
 */
#define QSC_TLS_SOCKET_FRAME_HEADER_SIZE 4U

/**
 * \def QSC_TLS_SOCKET_FRAME_SIZE_MAX
 * \brief The maximum payload size in bytes accepted by the framed application-message API.
 */
#define QSC_TLS_SOCKET_FRAME_SIZE_MAX 16777216U

/**
 * \enum qsc_tls_socket_log_level
 * \brief The TLS socket wrapper structured logging severity levels.
 */
typedef enum qsc_tls_socket_log_level
{
    qsc_tls_socket_log_level_none = 0,    /*!< No logging severity is assigned. */
    qsc_tls_socket_log_level_error = 1,   /*!< An error event occurred. */
    qsc_tls_socket_log_level_warning = 2, /*!< A non-fatal warning event occurred. */
    qsc_tls_socket_log_level_info = 3,    /*!< An informational lifecycle event occurred. */
    qsc_tls_socket_log_level_debug = 4    /*!< A diagnostic event occurred. */
} qsc_tls_socket_log_level;

/**
 * \enum qsc_tls_socket_event
 * \brief The TLS socket wrapper structured logging event identifiers.
 */
typedef enum qsc_tls_socket_event
{
    qsc_tls_socket_event_none = 0,                 /*!< No event is assigned. */
    qsc_tls_socket_event_context_configured = 1,   /*!< The TLS socket context policy or settings were configured. */
    qsc_tls_socket_event_socket_options = 2,       /*!< Socket options or timeout settings were applied. */
    qsc_tls_socket_event_connect = 3,              /*!< A client socket connection attempt was performed. */
    qsc_tls_socket_event_accept = 4,               /*!< A server listener accepted an inbound socket. */
    qsc_tls_socket_event_handshake_start = 5,      /*!< A TLS handshake was started. */
    qsc_tls_socket_event_handshake_complete = 6,   /*!< A TLS handshake completed successfully. */
    qsc_tls_socket_event_send = 7,                 /*!< TLS application data was sent. */
    qsc_tls_socket_event_receive = 8,              /*!< TLS application data was received. */
    qsc_tls_socket_event_frame_send = 9,           /*!< A framed application message was sent. */
    qsc_tls_socket_event_frame_receive = 10,       /*!< A framed application message was received. */
    qsc_tls_socket_event_ticket = 11,              /*!< A TLS session ticket operation was performed. */
    qsc_tls_socket_event_key_update = 12,          /*!< A TLS KeyUpdate operation was performed. */
    qsc_tls_socket_event_shutdown = 13,            /*!< A TLS socket shutdown operation was performed. */
    qsc_tls_socket_event_worker_start = 14,        /*!< A concurrent server worker started. */
    qsc_tls_socket_event_worker_stop = 15,         /*!< A concurrent server worker stopped. */
    qsc_tls_socket_event_error = 16                /*!< A generic TLS socket wrapper error occurred. */
} qsc_tls_socket_event;

/**
 * \struct qsc_tls_socket_options
 * \brief The socket and timeout configuration used by TLS socket contexts, listeners, and connections.
 */
typedef struct qsc_tls_socket_options
{
    uint32_t connect_timeout_ms;   /*!< The socket connect timeout in milliseconds. */
    uint32_t handshake_timeout_ms; /*!< The TLS handshake timeout in milliseconds. */
    uint32_t receive_timeout_ms;   /*!< The socket receive timeout in milliseconds. */
    uint32_t send_timeout_ms;      /*!< The socket send timeout in milliseconds. */
    uint32_t idle_timeout_ms;      /*!< The maximum idle timeout in milliseconds. */
    size_t receive_buffer_size;    /*!< The requested socket receive buffer size in bytes. */
    size_t send_buffer_size;       /*!< The requested socket send buffer size in bytes. */
    bool reuse_address;            /*!< Enable address reuse on listener sockets. */
    bool no_delay;                 /*!< Enable TCP no-delay behavior where supported. */
    bool keep_alive;               /*!< Enable TCP keep-alive behavior where supported. */
    bool dual_stack;               /*!< Enable IPv4/IPv6 dual-stack behavior where supported. */
    bool blocking;                 /*!< Use blocking socket behavior when true. */
} qsc_tls_socket_options;

/**
 * \struct qsc_tls_socket_ticket_policy
 * \brief The session ticket policy used by TLS socket client and server operations.
 */
typedef struct qsc_tls_socket_ticket_policy
{
    bool enabled;                       /*!< Enable session ticket handling when true. */
    bool allow_early_data;              /*!< Permit early data when the lower TLS layer and peer support it. */
    bool auto_send_server_ticket;       /*!< Automatically emit a server ticket after a successful server handshake. */
    uint32_t lifetime_seconds;          /*!< The ticket lifetime hint in seconds. */
    uint32_t renewal_interval_seconds;  /*!< The ticket renewal interval in seconds for long-lived services. */
} qsc_tls_socket_ticket_policy;

/**
 * \enum qsc_tls_socket_status
 * \brief The TLS socket wrapper status codes.
 */
typedef enum qsc_tls_socket_status
{
    qsc_tls_socket_status_success = 0,                      /*!< The operation completed successfully. */
    qsc_tls_socket_status_invalid_input = 1,                /*!< One or more input parameters were invalid. */
    qsc_tls_socket_status_not_initialized = 2,              /*!< The requested object was not initialized. */
    qsc_tls_socket_status_socket_start_failed = 3,          /*!< Socket subsystem initialization failed. */
    qsc_tls_socket_status_socket_connect_failed = 4,        /*!< The socket connect operation failed. */
    qsc_tls_socket_status_socket_bind_failed = 5,           /*!< The socket bind operation failed. */
    qsc_tls_socket_status_socket_listen_failed = 6,         /*!< The socket listen operation failed. */
    qsc_tls_socket_status_socket_accept_failed = 7,         /*!< The socket accept operation failed. */
    qsc_tls_socket_status_tls_initialize_failed = 8,        /*!< TLS engine initialization failed. */
    qsc_tls_socket_status_tls_handshake_failed = 9,         /*!< The TLS handshake failed. */
    qsc_tls_socket_status_certificate_load_failed = 10,     /*!< Certificate, private key, trust anchor, or CRL loading failed. */
    qsc_tls_socket_status_certificate_verify_failed = 11,   /*!< Certificate verification failed. */
    qsc_tls_socket_status_private_key_invalid = 12,         /*!< The configured private key was invalid or incompatible. */
    qsc_tls_socket_status_policy_rejected = 13,             /*!< The configured TLS policy was rejected or unsupported. */
    qsc_tls_socket_status_io_failed = 14,                   /*!< A TLS or socket I/O operation failed. */
    qsc_tls_socket_status_closed = 15,                      /*!< The connection was closed or cancelled. */
    qsc_tls_socket_status_internal_error = 16               /*!< An internal wrapper error occurred. */
} qsc_tls_socket_status;

/**
 * \struct qsc_tls_socket_result
 * \brief A structured result containing wrapper, TLS, socket, X.509, verification, and alert status values.
 */
typedef struct qsc_tls_socket_result
{
    qsc_tls_socket_status status;        /*!< The wrapper-level status. */
    qsc_tls_status tlsstatus;            /*!< The lower TLS status. */
    qsc_socket_exceptions socketstatus;  /*!< The lower socket exception value. */
    qsc_x509w_status x509status;         /*!< The X.509 wrapper status. */
    qsc_x509_verify_status verifystatus; /*!< The X.509 path verification status. */
    qsc_tls_alert_description alert;     /*!< The TLS alert value associated with the failure, when present. */
} qsc_tls_socket_result;

/**
 * \brief The TLS socket structured logging callback prototype.
 *
 * \param level: [enum] The logging severity level.
 * \param event: [enum] The event identifier.
 * \param result: [const struct*] A pointer to the structured result associated with the event.
 * \param message: [const char*] A null-terminated event description string.
 * \param state: [void*] The user-defined callback state pointer.
 */
typedef void (*qsc_tls_socket_log_callback)(qsc_tls_socket_log_level level, qsc_tls_socket_event event, const qsc_tls_socket_result* result, const char* message, void* state);

/**
 * \struct qsc_tls_socket_peer_info
 * \brief The peer identity and negotiated-parameter summary exposed by the TLS socket wrapper.
 *
 * \details
 * The negotiated cipher suite, named group, signature scheme, PSK state, and early-data state are
 * populated from the TLS connection state. The subject, issuer, common-name, and DNS-name fields are
 * reserved for deployments where the lower TLS and X.509 layers retain a parsed peer certificate
 * summary after verification.
 */
typedef struct qsc_tls_socket_peer_info
{
    char subject[QSC_X509_NAME_ATTRIBUTE_STRING_MAX];     /*!< The peer certificate subject string, when available. */
    char issuer[QSC_X509_NAME_ATTRIBUTE_STRING_MAX];      /*!< The peer certificate issuer string, when available. */
    char common_name[QSC_X509_NAME_ATTRIBUTE_STRING_MAX]; /*!< The peer certificate common name, when available. */
    char dns_name[QSC_X509_NAME_ATTRIBUTE_STRING_MAX];    /*!< The matched peer DNS name, when available. */
    qsc_tls_cipher_suite cipher_suite;                    /*!< The negotiated TLS cipher suite. */
    qsc_tls_named_group named_group;                      /*!< The negotiated TLS named group. */
    qsc_tls_signature_scheme signature_scheme;            /*!< The negotiated TLS signature scheme. */
    qsc_x509_verify_status verify_status;                 /*!< The X.509 verification status for the peer certificate. */
    bool authenticated;                                   /*!< Indicates whether the peer was authenticated. */
    bool hostname_matched;                                /*!< Indicates whether hostname verification succeeded. */
    bool chain_valid;                                     /*!< Indicates whether the peer certificate chain validated. */
    bool psk_accepted;                                    /*!< Indicates whether PSK resumption was accepted. */
    bool early_data_accepted;                             /*!< Indicates whether early data was accepted. */
} qsc_tls_socket_peer_info;

/**
 * \struct qsc_tls_socket_context
 * \brief A reusable TLS socket policy, trust, identity, and logging context.
 */
typedef struct qsc_tls_socket_context
{
    qsc_x509w_trust_store truststore;                                           /*!< The X.509 trust store used for peer verification. */
    qsc_x509w_server_identity identity;                                         /*!< The loaded server identity and private key material. */
    qsc_x509w_tls_bridge bridge;                                                /*!< The X.509-to-TLS certificate verification bridge. */
    qsc_x509w_tls_local_certificate localcert;                                  /*!< The TLS-facing local certificate exported from the server identity. */
    qsc_x509w_profile certificateprofile;                                       /*!< The X.509 validation profile. */
    qsc_tls_socket_options socketoptions;                                       /*!< The default socket options for connections derived from this context. */
    qsc_tls_socket_ticket_policy ticketpolicy;                                  /*!< The default session ticket policy. */
    qsc_tls_session_ticket sessionticket;                                       /*!< The configured client session ticket for resumption. */
    qsc_tls_socket_log_callback logcallback;                                    /*!< The context-level structured logging callback. */
    void* logstate;                                                             /*!< The context-level logging callback state. */
    qsc_tls_cipher_suite ciphersuites[QSC_TLS_SOCKET_CIPHER_SUITE_MAX];         /*!< The ordered TLS cipher suite preference list. */
    qsc_tls_named_group groups[QSC_TLS_SOCKET_GROUP_MAX];                       /*!< The ordered TLS named group preference list. */
    qsc_tls_signature_scheme sigschemes[QSC_TLS_SOCKET_SIGNATURE_SCHEME_MAX];   /*!< The ordered TLS signature scheme preference list. */
    size_t ciphersuitecount;                                                    /*!< The number of cipher suites in the preference list. */
    size_t groupcount;                                                          /*!< The number of named groups in the preference list. */
    size_t sigschemecount;                                                      /*!< The number of signature schemes in the preference list. */
    bool hasidentity;                                                           /*!< Indicates that a server identity has been loaded. */
    bool hastruststore;                                                         /*!< Indicates that at least one trust anchor has been loaded. */
    bool requireclientauth;                                                     /*!< Require client certificate authentication in server mode. */
    bool requestclientauth;                                                     /*!< Request client certificate authentication in server mode. */
    bool allowunverified;                                                       /*!< Permit unverified peer certificates in development policy mode. */
    bool hassessionticket;                                                      /*!< Indicates that a client session ticket has been configured. */
    bool initialized;                                                           /*!< Indicates that the context has been initialized. */
} qsc_tls_socket_context;

/**
 * \struct qsc_tls_socket_connection
 * \brief A live TLS socket connection containing the socket, TLS engine, I/O adapter, and connection state.
 */
typedef struct qsc_tls_socket_connection
{
    qsc_socket socket;                              /*!< The connected or accepted socket owned by the connection. */
    qsc_tls_connection engine;                      /*!< The TLS engine instance for this connection. */
    qsc_tls_io_connection io;                       /*!< The TLS I/O adapter bound to the engine and socket. */
    qsc_tls_role role;                              /*!< The TLS role, client or server. */
    qsc_socket_address_families family;             /*!< The socket address family. */
    qsc_tls_socket_result lastresult;               /*!< The last structured result produced by this connection. */
    qsc_tls_socket_options socketoptions;           /*!< The active socket options for this connection. */
    qsc_tls_socket_ticket_policy ticketpolicy;      /*!< The active session ticket policy for this connection. */
    qsc_tls_session_ticket lastticket;              /*!< The last session ticket observed or emitted by this connection. */
    qsc_tls_signer_default_context signcontext;     /*!< The default TLS signing context used by server CertificateVerify. */
    qsc_tls_socket_log_callback logcallback;        /*!< The connection-level structured logging callback. */
    void* logstate;                                 /*!< The connection-level logging callback state. */
    char peername[QSC_SOCKET_ADDRESS_MAX_SIZE];     /*!< The peer hostname or textual address. */
    uint16_t peerport;                              /*!< The peer port number. */
    bool connected;                                 /*!< Indicates that the underlying socket is connected. */
    bool handshaked;                                /*!< Indicates that the TLS handshake completed. */
    bool owns_socket;                               /*!< Indicates that the connection owns and must close the socket. */
    bool haslastticket;                             /*!< Indicates that lastticket contains a valid ticket. */
    bool cancelrequested;                           /*!< Indicates that cancellation has been requested. */
} qsc_tls_socket_connection;

/**
 * \struct qsc_tls_socket_listener
 * \brief A TLS socket listener that owns a listening socket and references a TLS socket context.
 */
typedef struct qsc_tls_socket_listener
{
    qsc_socket socket;                         /*!< The listening socket. */
    const qsc_tls_socket_context* context;     /*!< The context used to initialize accepted TLS server connections. */
    qsc_socket_address_families family;        /*!< The listener address family. */
    uint16_t port;                             /*!< The listener port. */
    int32_t backlog;                           /*!< The listener backlog. */
    qsc_tls_socket_options socketoptions;      /*!< The listener socket options. */
    bool initialized;                          /*!< Indicates that the listener has been initialized. */
    bool listening;                            /*!< Indicates that the listener is bound and accepting. */
} qsc_tls_socket_listener;

struct qsc_tls_socket_server;

/**
 * \struct qsc_tls_socket_server_worker_state
 * \brief The fixed-pool worker state used by the concurrent TLS socket server.
 */
typedef struct qsc_tls_socket_server_worker_state
{
    struct qsc_tls_socket_server* server; /*!< The owning server instance. */
    size_t index;                         /*!< The fixed connection slot index assigned to the worker. */
} qsc_tls_socket_server_worker_state;

/**
 * \brief The TLS socket server connect callback prototype.
 *
 * \param connection: [struct*] A pointer to the established TLS socket connection.
 * \param state: [void*] The user-defined callback state pointer.
 */
typedef void (*qsc_tls_socket_server_connect_callback)(qsc_tls_socket_connection* connection, void* state);

/**
 * \brief The TLS socket server receive callback prototype.
 *
 * \param connection: [struct*] A pointer to the established TLS socket connection.
 * \param message: [const uint8_t*] A pointer to the received application data.
 * \param msglen: [size_t] The length of the received application data in bytes.
 * \param state: [void*] The user-defined callback state pointer.
 */
typedef void (*qsc_tls_socket_server_receive_callback)(qsc_tls_socket_connection* connection, const uint8_t* message, size_t msglen, void* state);

/**
 * \brief The TLS socket server disconnect callback prototype.
 *
 * \param connection: [struct*] A pointer to the TLS socket connection being disconnected.
 * \param state: [void*] The user-defined callback state pointer.
 */
typedef void (*qsc_tls_socket_server_disconnect_callback)(qsc_tls_socket_connection* connection, void* state);

/**
 * \brief The TLS socket server error callback prototype.
 *
 * \param connection: [struct*] A pointer to the TLS socket connection associated with the error, when available.
 * \param status: [enum] The wrapper status value associated with the error.
 * \param state: [void*] The user-defined callback state pointer.
 */
typedef void (*qsc_tls_socket_server_error_callback)(qsc_tls_socket_connection* connection, qsc_tls_socket_status status, void* state);

/**
 * \struct qsc_tls_socket_server
 * \brief A blocking or concurrent TLS socket server using a fixed connection pool.
 */
typedef struct qsc_tls_socket_server
{
    qsc_tls_socket_listener listener;                                                       /*!< The server listener. */
    qsc_tls_socket_server_connect_callback onconnect;                                       /*!< The application connect callback. */
    qsc_tls_socket_server_receive_callback onreceive;                                       /*!< The application receive callback. */
    qsc_tls_socket_server_disconnect_callback ondisconnect;                                 /*!< The application disconnect callback. */
    qsc_tls_socket_server_error_callback onerror;                                           /*!< The application error callback. */
    qsc_tls_socket_log_callback onlog;                                                      /*!< The server-level structured logging callback. */
    void* callbackstate;                                                                    /*!< The application callback state. */
    void* logstate;                                                                         /*!< The server logging callback state. */
    qsc_tls_socket_connection connections[QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX];           /*!< The fixed connection pool. */
    qsc_tls_socket_server_worker_state workerstates[QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX]; /*!< The fixed worker state pool. */
    qsc_thread workerthreads[QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX];                        /*!< The fixed worker thread handle pool. */
    volatile bool active[QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX];                            /*!< The active-state flags for each connection slot. */
    volatile bool started[QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX];                           /*!< The worker-started flags for each connection slot. */
    qsc_mutex poolmutex;                                                                    /*!< The fixed pool mutex. */
    size_t maxclients;                                                                      /*!< The configured maximum number of concurrent clients. */
    volatile bool running;                                                                  /*!< Indicates that the server accept loop is running. */
    bool concurrent;                                                                        /*!< Indicates that concurrent server mode is active. */
    bool initialized;                                                                       /*!< Indicates that the server has been initialized. */
} qsc_tls_socket_server;

/**
 * \brief Clear a TLS socket structured result.
 *
 * \param result: [struct*] A pointer to the result structure to clear.
 */
QSC_EXPORT_API void qsc_tls_socket_result_clear(qsc_tls_socket_result* result);

/**
 * \brief Return a constant string for a TLS socket wrapper status value.
 *
 * \param status: [enum] The TLS socket wrapper status value.
 *
 * \return [const char*] Returns a constant null-terminated status string.
 */
QSC_EXPORT_API const char* qsc_tls_socket_status_string(qsc_tls_socket_status status);

/**
 * \brief Initialize socket options to the wrapper default values.
 *
 * \param options: [struct*] A pointer to the socket options structure to initialize.
 */
QSC_EXPORT_API void qsc_tls_socket_options_initialize_default(qsc_tls_socket_options* options);

/**
 * \brief Initialize a session ticket policy to the wrapper default values.
 *
 * \param policy: [struct*] A pointer to the ticket policy structure to initialize.
 */
QSC_EXPORT_API void qsc_tls_socket_ticket_policy_initialize_default(qsc_tls_socket_ticket_policy* policy);

/**
 * \brief Initialize a reusable TLS socket context.
 *
 * \param context: [struct*] A pointer to the context structure to initialize.
 */
QSC_EXPORT_API void qsc_tls_socket_context_initialize(qsc_tls_socket_context* context);

/**
 * \brief Dispose of a TLS socket context and clear owned sensitive state.
 *
 * \param context: [struct*] A pointer to the context structure to dispose.
 */
QSC_EXPORT_API void qsc_tls_socket_context_dispose(qsc_tls_socket_context* context);

/**
 * \brief Configure the context with the default TLS 1.3 client interoperability policy.
 *
 * \param context: [struct*] A pointer to the initialized context.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_default_client_policy(qsc_tls_socket_context* context);

/**
 * \brief Configure the context with the default TLS 1.3 server interoperability policy.
 *
 * \param context: [struct*] A pointer to the initialized context.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_default_server_policy(qsc_tls_socket_context* context);

/**
 * \brief Configure the context with an explicit ML-KEM hybrid interoperability policy.
 *
 * \details
 * The ML-KEM hybrid policy enables the hybrid ML-KEM named-group preference while retaining
 * conventional TLS 1.3 cipher suites and classical certificate signature schemes for peers that
 * support hybrid key establishment.
 *
 * \param context: [struct*] A pointer to the initialized context.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_mlkem_hybrid_policy(qsc_tls_socket_context* context);

/**
 * \brief Configure the context with the experimental ML-KEM and ML-DSA policy.
 *
 * \details
 * This policy enables experimental post-quantum key-establishment and signature preferences. It
 * requires a peer that supports the same experimental TLS named groups and signature schemes.
 *
 * \param context: [struct*] A pointer to the initialized context.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_experimental_pqc_policy(qsc_tls_socket_context* context);

/**
 * \brief Configure the context with the strict TLS policy.
 *
 * \param context: [struct*] A pointer to the initialized context.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_strict_policy(qsc_tls_socket_context* context);

/**
 * \brief Configure the context with the development TLS policy.
 *
 * \details
 * The development policy is intended for local testing. It may permit unverified peers depending
 * on the lower TLS and X.509 configuration. It must not be used for production deployments.
 *
 * \param context: [struct*] A pointer to the initialized context.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_development_policy(qsc_tls_socket_context* context);

/**
 * \brief Set the ordered cipher suite preference list for the context.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param suites: [const enum*] A pointer to the cipher suite preference array.
 * \param suitecount: [size_t] The number of cipher suites in the array.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_cipher_suites(qsc_tls_socket_context* context, const qsc_tls_cipher_suite* suites, size_t suitecount);

/**
 * \brief Set the ordered named group preference list for the context.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param groups: [const enum*] A pointer to the named group preference array.
 * \param groupcount: [size_t] The number of named groups in the array.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_named_groups(qsc_tls_socket_context* context, const qsc_tls_named_group* groups, size_t groupcount);

/**
 * \brief Set the ordered signature scheme preference list for the context.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param schemes: [const enum*] A pointer to the signature scheme preference array.
 * \param schemecount: [size_t] The number of signature schemes in the array.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_signature_schemes(qsc_tls_socket_context* context, const qsc_tls_signature_scheme* schemes, size_t schemecount);

/**
 * \brief Load a trust anchor certificate file into the context trust store.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param path: [const char*] The null-terminated file path to the trust anchor certificate.
 * \param selfsigned: [bool] Indicates whether the trust anchor is self-signed.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_load_trust_anchor_file(qsc_tls_socket_context* context, const char* path, bool selfsigned);

/**
 * \brief Load a trust anchor bundle file into the context trust store.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param path: [const char*] The null-terminated file path to the trust anchor bundle.
 * \param selfsigned: [bool] Indicates whether the bundle contains self-signed trust anchors.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_load_trust_anchor_bundle_file(qsc_tls_socket_context* context, const char* path, bool selfsigned);

/**
 * \brief Load a certificate revocation list file into the context trust store.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param path: [const char*] The null-terminated file path to the CRL file.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_load_crl_file(qsc_tls_socket_context* context, const char* path);

/**
 * \brief Load a server certificate chain and private key into the context.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param certificatechainpath: [const char*] The null-terminated file path to the server certificate chain.
 * \param privatekeypath: [const char*] The null-terminated file path to the server private key.
 * \param verifyscheme: [enum] The TLS signature scheme used by the server CertificateVerify operation.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_load_server_identity_files(qsc_tls_socket_context* context, const char* certificatechainpath, const char* privatekeypath, qsc_tls_signature_scheme verifyscheme);

/**
 * \brief Configure server-side client certificate authentication policy.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param requestclientauth: [bool] Request a client certificate from peers when true.
 * \param requireclientauth: [bool] Require a verified client certificate when true.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_client_auth(qsc_tls_socket_context* context, bool requestclientauth, bool requireclientauth);

/**
 * \brief Set the default socket options for the context.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param options: [const struct*] A pointer to the socket options to copy into the context.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_socket_options(qsc_tls_socket_context* context, const qsc_tls_socket_options* options);

/**
 * \brief Set the context-level structured logging callback.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param callback: [function] The logging callback pointer, or NULL to disable context logging.
 * \param state: [void*] The user-defined callback state pointer.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_log_callback(qsc_tls_socket_context* context, qsc_tls_socket_log_callback callback, void* state);

/**
 * \brief Set the context-level session ticket policy.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param policy: [const struct*] A pointer to the session ticket policy to copy into the context.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_session_ticket_policy(qsc_tls_socket_context* context, const qsc_tls_socket_ticket_policy* policy);

/**
 * \brief Set the client session ticket used for resumption attempts.
 *
 * \param context: [struct*] A pointer to the initialized context.
 * \param ticket: [const struct*] A pointer to the session ticket to copy into the context.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_context_set_session_ticket(qsc_tls_socket_context* context, const qsc_tls_session_ticket* ticket);

/**
 * \brief Clear the client session ticket stored in the context.
 *
 * \param context: [struct*] A pointer to the initialized context.
 */
QSC_EXPORT_API void qsc_tls_socket_context_clear_session_ticket(qsc_tls_socket_context* context);

/**
 * \brief Initialize a TLS socket connection structure.
 *
 * \param connection: [struct*] A pointer to the connection structure to initialize.
 */
QSC_EXPORT_API void qsc_tls_socket_connection_initialize(qsc_tls_socket_connection* connection);

/**
 * \brief Dispose of a TLS socket connection and clear owned sensitive state.
 *
 * \param connection: [struct*] A pointer to the connection structure to dispose.
 */
QSC_EXPORT_API void qsc_tls_socket_connection_dispose(qsc_tls_socket_connection* connection);

/**
 * \brief Connect to a remote host and complete a TLS client handshake.
 *
 * \param connection: [struct*] A pointer to an initialized connection structure.
 * \param context: [const struct*] A pointer to an initialized client context.
 * \param hostname: [const char*] The null-terminated DNS hostname used for connection and verification.
 * \param service: [const char*] The null-terminated service or port string.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_client_connect_host(qsc_tls_socket_connection* connection, const qsc_tls_socket_context* context, const char* hostname, const char* service);

/**
 * \brief Connect to a remote host with an explicit session ticket and early-data preference.
 *
 * \param connection: [struct*] A pointer to an initialized connection structure.
 * \param context: [const struct*] A pointer to an initialized client context.
 * \param hostname: [const char*] The null-terminated DNS hostname used for connection and verification.
 * \param service: [const char*] The null-terminated service or port string.
 * \param ticket: [const struct*] A pointer to the session ticket to offer, or NULL for a full handshake.
 * \param enableearlydata: [bool] Enable early data if the ticket and peer support it.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_client_connect_host_ex(qsc_tls_socket_connection* connection, const qsc_tls_socket_context* context, const char* hostname, const char* service, const qsc_tls_session_ticket* ticket, bool enableearlydata);

/**
 * \brief Connect to an IPv4 address and complete a TLS client handshake.
 *
 * \param connection: [struct*] A pointer to an initialized connection structure.
 * \param context: [const struct*] A pointer to an initialized client context.
 * \param address: [const struct*] A pointer to the IPv4 address.
 * \param port: [uint16_t] The remote TCP port.
 * \param hostname: [const char*] The verification hostname, or NULL when policy permits.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_client_connect_ipv4(qsc_tls_socket_connection* connection, const qsc_tls_socket_context* context, const qsc_ipinfo_ipv4_address* address, uint16_t port, const char* hostname);

/**
 * \brief Connect to an IPv6 address and complete a TLS client handshake.
 *
 * \param connection: [struct*] A pointer to an initialized connection structure.
 * \param context: [const struct*] A pointer to an initialized client context.
 * \param address: [const struct*] A pointer to the IPv6 address.
 * \param port: [uint16_t] The remote TCP port.
 * \param hostname: [const char*] The verification hostname, or NULL when policy permits.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_client_connect_ipv6(qsc_tls_socket_connection* connection, const qsc_tls_socket_context* context, const qsc_ipinfo_ipv6_address* address, uint16_t port, const char* hostname);

/**
 * \brief Send application data over a completed TLS socket connection.
 *
 * \param connection: [struct*] A pointer to the established TLS socket connection.
 * \param input: [const uint8_t*] A pointer to the plaintext application data to send.
 * \param inlen: [size_t] The input length in bytes.
 * \param written: [size_t*] Receives the number of plaintext bytes accepted for transmission, or NULL.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_send(qsc_tls_socket_connection* connection, const uint8_t* input, size_t inlen, size_t* written);

/**
 * \brief Receive application data from a completed TLS socket connection.
 *
 * \param connection: [struct*] A pointer to the established TLS socket connection.
 * \param output: [uint8_t*] A pointer to the plaintext output buffer.
 * \param outlen: [size_t] The output buffer length in bytes.
 * \param read: [size_t*] Receives the number of plaintext bytes written to output.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_receive(qsc_tls_socket_connection* connection, uint8_t* output, size_t outlen, size_t* read);

/**
 * \brief Send a TLS close_notify alert and close the TLS socket connection.
 *
 * \param connection: [struct*] A pointer to the established TLS socket connection.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_shutdown(qsc_tls_socket_connection* connection);

/**
 * \brief Request a TLS 1.3 KeyUpdate operation on a completed connection.
 *
 * \param connection: [struct*] A pointer to the established TLS socket connection.
 * \param requestpeerupdate: [bool] Request that the peer also update its sending keys when true.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_key_update(qsc_tls_socket_connection* connection, bool requestpeerupdate);

/**
 * \brief Send a TLS server session ticket over a completed server connection.
 *
 * \param connection: [struct*] A pointer to the established server-side TLS socket connection.
 * \param lifetime_seconds: [uint32_t] The ticket lifetime hint in seconds.
 * \param ticketout: [struct*] Receives a copy of the emitted ticket, or NULL.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_server_send_session_ticket(qsc_tls_socket_connection* connection, uint32_t lifetime_seconds, qsc_tls_session_ticket* ticketout);

/**
 * \brief Apply socket options to an initialized or connected TLS socket connection.
 *
 * \param connection: [struct*] A pointer to the TLS socket connection.
 * \param options: [const struct*] A pointer to the socket options to apply.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_connection_set_socket_options(qsc_tls_socket_connection* connection, const qsc_tls_socket_options* options);

/**
 * \brief Set the connection-level structured logging callback.
 *
 * \param connection: [struct*] A pointer to the TLS socket connection.
 * \param callback: [function] The logging callback pointer, or NULL to disable connection logging.
 * \param state: [void*] The user-defined callback state pointer.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_connection_set_log_callback(qsc_tls_socket_connection* connection, qsc_tls_socket_log_callback callback, void* state);

/**
 * \brief Request cancellation of a TLS socket connection.
 *
 * \param connection: [struct*] A pointer to the TLS socket connection.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_connection_cancel(qsc_tls_socket_connection* connection);

/**
 * \brief Retrieve the peer information summary for a TLS socket connection.
 *
 * \param connection: [const struct*] A pointer to the TLS socket connection.
 * \param peerinfo: [struct*] A pointer to the peer information structure to receive the summary.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_get_peer_info(const qsc_tls_socket_connection* connection, qsc_tls_socket_peer_info* peerinfo);

/**
 * \brief Retrieve the most recent session ticket associated with a connection.
 *
 * \param connection: [const struct*] A pointer to the TLS socket connection.
 * \param ticketout: [struct*] A pointer to the ticket structure to receive the ticket copy.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_connection_get_session_ticket(const qsc_tls_socket_connection* connection, qsc_tls_session_ticket* ticketout);

/**
 * \brief Send a length-prefixed framed application message.
 *
 * \details
 * The frame format is a four-byte big-endian unsigned payload length followed by the payload bytes.
 * The payload length must not exceed QSC_TLS_SOCKET_FRAME_SIZE_MAX.
 *
 * \param connection: [struct*] A pointer to the established TLS socket connection.
 * \param input: [const uint8_t*] A pointer to the application payload.
 * \param inlen: [size_t] The payload length in bytes.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_send_frame(qsc_tls_socket_connection* connection, const uint8_t* input, size_t inlen);

/**
 * \brief Receive a length-prefixed framed application message.
 *
 * \details
 * The frame format is a four-byte big-endian unsigned payload length followed by the payload bytes.
 * If the encoded frame length exceeds the output capacity, the call returns an error.
 *
 * \param connection: [struct*] A pointer to the established TLS socket connection.
 * \param output: [uint8_t*] A pointer to the application payload output buffer.
 * \param outlen: [size_t] The output buffer length in bytes.
 * \param read: [size_t*] Receives the number of payload bytes written to output.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_receive_frame(qsc_tls_socket_connection* connection, uint8_t* output, size_t outlen, size_t* read);

/**
 * \brief Test whether a TLS socket connection owns a connected socket.
 *
 * \param connection: [const struct*] A pointer to the TLS socket connection.
 *
 * \return [bool] Returns true when the connection is socket-connected.
 */
QSC_EXPORT_API bool qsc_tls_socket_is_connected(const qsc_tls_socket_connection* connection);

/**
 * \brief Test whether the TLS handshake has completed.
 *
 * \param connection: [const struct*] A pointer to the TLS socket connection.
 *
 * \return [bool] Returns true when the TLS handshake has completed.
 */
QSC_EXPORT_API bool qsc_tls_socket_is_handshake_complete(const qsc_tls_socket_connection* connection);

/**
 * \brief Get the negotiated TLS cipher suite.
 *
 * \param connection: [const struct*] A pointer to the TLS socket connection.
 *
 * \return [qsc_tls_cipher_suite] Returns the negotiated cipher suite, or the lower-layer default value when unavailable.
 */
QSC_EXPORT_API qsc_tls_cipher_suite qsc_tls_socket_negotiated_cipher_suite(const qsc_tls_socket_connection* connection);

/**
 * \brief Get the negotiated TLS named group.
 *
 * \param connection: [const struct*] A pointer to the TLS socket connection.
 *
 * \return [qsc_tls_named_group] Returns the negotiated named group, or the lower-layer default value when unavailable.
 */
QSC_EXPORT_API qsc_tls_named_group qsc_tls_socket_negotiated_group(const qsc_tls_socket_connection* connection);

/**
 * \brief Get the negotiated TLS signature scheme.
 *
 * \param connection: [const struct*] A pointer to the TLS socket connection.
 *
 * \return [qsc_tls_signature_scheme] Returns the negotiated signature scheme, or the lower-layer default value when unavailable.
 */
QSC_EXPORT_API qsc_tls_signature_scheme qsc_tls_socket_negotiated_signature_scheme(const qsc_tls_socket_connection* connection);

/**
 * \brief Initialize a TLS socket listener structure.
 *
 * \param listener: [struct*] A pointer to the listener structure to initialize.
 */
QSC_EXPORT_API void qsc_tls_socket_listener_initialize(qsc_tls_socket_listener* listener);

/**
 * \brief Set basic listener socket options.
 *
 * \param listener: [struct*] A pointer to the initialized listener.
 * \param reuseaddress: [bool] Enable address reuse when true.
 * \param nodelay: [bool] Enable TCP no-delay when true.
 * \param recvtimeoutms: [uint32_t] The receive timeout in milliseconds.
 * \param sendtimeoutms: [uint32_t] The send timeout in milliseconds.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_listener_set_options(qsc_tls_socket_listener* listener, bool reuseaddress, bool nodelay, uint32_t recvtimeoutms, uint32_t sendtimeoutms);

/**
 * \brief Set the full listener socket option structure.
 *
 * \param listener: [struct*] A pointer to the initialized listener.
 * \param options: [const struct*] A pointer to the socket options to copy into the listener.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_listener_set_socket_options(qsc_tls_socket_listener* listener, const qsc_tls_socket_options* options);

/**
 * \brief Bind a TLS listener to a local address and port.
 *
 * \param listener: [struct*] A pointer to the initialized listener.
 * \param context: [const struct*] A pointer to the initialized server context.
 * \param address: [const char*] The null-terminated local address string.
 * \param port: [uint16_t] The local TCP port.
 * \param family: [enum] The socket address family.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_listener_bind(qsc_tls_socket_listener* listener, const qsc_tls_socket_context* context, const char* address, uint16_t port, qsc_socket_address_families family);

/**
 * \brief Accept an inbound socket and complete a TLS server handshake.
 *
 * \param listener: [struct*] A pointer to the bound and listening TLS listener.
 * \param connection: [struct*] A pointer to the connection structure to receive the accepted connection.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_listener_accept(qsc_tls_socket_listener* listener, qsc_tls_socket_connection* connection);

/**
 * \brief Close a TLS socket listener.
 *
 * \param listener: [struct*] A pointer to the listener to close.
 */
QSC_EXPORT_API void qsc_tls_socket_listener_close(qsc_tls_socket_listener* listener);

/**
 * \brief Initialize a TLS socket server structure.
 *
 * \param server: [struct*] A pointer to the server structure to initialize.
 */
QSC_EXPORT_API void qsc_tls_socket_server_initialize(qsc_tls_socket_server* server);

/**
 * \brief Configure a TLS socket server listener and context.
 *
 * \param server: [struct*] A pointer to the initialized server.
 * \param context: [const struct*] A pointer to the initialized server context.
 * \param address: [const char*] The null-terminated local address string.
 * \param port: [uint16_t] The local TCP port.
 * \param family: [enum] The socket address family.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_server_configure(qsc_tls_socket_server* server, const qsc_tls_socket_context* context, const char* address, uint16_t port, qsc_socket_address_families family);

/**
 * \brief Set the application callbacks for a TLS socket server.
 *
 * \param server: [struct*] A pointer to the initialized server.
 * \param onconnect: [function] The callback invoked after a successful TLS handshake, or NULL.
 * \param onreceive: [function] The callback invoked when application data is received, or NULL.
 * \param ondisconnect: [function] The callback invoked when a connection is closed, or NULL.
 * \param onerror: [function] The callback invoked when an error occurs, or NULL.
 * \param state: [void*] The user-defined callback state pointer.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_server_set_callbacks(qsc_tls_socket_server* server, qsc_tls_socket_server_connect_callback onconnect, qsc_tls_socket_server_receive_callback onreceive, qsc_tls_socket_server_disconnect_callback ondisconnect, qsc_tls_socket_server_error_callback onerror, void* state);

/**
 * \brief Set the server-level structured logging callback.
 *
 * \param server: [struct*] A pointer to the initialized server.
 * \param callback: [function] The logging callback pointer, or NULL to disable server logging.
 * \param state: [void*] The user-defined callback state pointer.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_server_set_log_callback(qsc_tls_socket_server* server, qsc_tls_socket_log_callback callback, void* state);

/**
 * \brief Set the maximum number of concurrent client connections accepted by the server.
 *
 * \param server: [struct*] A pointer to the initialized server.
 * \param maxclients: [size_t] The maximum number of clients. The value must not exceed QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on success.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_server_set_max_clients(qsc_tls_socket_server* server, size_t maxclients);

/**
 * \brief Start the server in blocking sequential mode.
 *
 * \details
 * Sequential mode accepts one TLS connection at a time and processes received application data
 * through the configured callbacks until the connection closes or the server is stopped.
 *
 * \param server: [struct*] A pointer to the configured server.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on normal completion.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_server_start(qsc_tls_socket_server* server);

/**
 * \brief Start the server in bounded concurrent mode.
 *
 * \details
 * Concurrent mode accepts inbound TLS connections into a fixed pool of connection slots and dispatches
 * one worker per accepted connection, up to the configured maximum client count.
 *
 * \param server: [struct*] A pointer to the configured server.
 *
 * \return [qsc_tls_socket_status] Returns qsc_tls_socket_status_success on normal completion.
 */
QSC_EXPORT_API qsc_tls_socket_status qsc_tls_socket_server_start_concurrent(qsc_tls_socket_server* server);

/**
 * \brief Stop a running TLS socket server.
 *
 * \details
 * The stop operation clears the running flag, closes the listener, requests cancellation of active
 * connection slots, and allows worker cleanup to complete through the fixed connection pool.
 *
 * \param server: [struct*] A pointer to the running server.
 */
QSC_EXPORT_API void qsc_tls_socket_server_stop(qsc_tls_socket_server* server);

/**
 * \brief Dispose of a TLS socket server and clear owned connection state.
 *
 * \param server: [struct*] A pointer to the server to dispose.
 */
QSC_EXPORT_API void qsc_tls_socket_server_dispose(qsc_tls_socket_server* server);

QSC_CPLUSPLUS_ENABLED_END

#endif
