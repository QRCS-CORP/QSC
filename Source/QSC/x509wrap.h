/**
 * \file x509wrap.h
 * \brief High-level offline X.509 wrapper for certificate loading, validation,
 * deployment configuration, trust-store management, provisioning, and TLS
 * bridge integration.
 *
 * \details
 * This header defines the public wrapper layer over the QSC X.509
 * implementation. The wrapper is intended to simplify the most common
 * operational uses of X.509 while preserving strict control over ownership,
 * validation policy, diagnostics, and TLS integration boundaries.
 *
 * The wrapper is offline-only. Public APIs declared in this header do not
 * perform network I/O, dereference remote URIs, fetch issuer certificates,
 * retrieve CRLs, or issue OCSP requests. Any future network-assisted
 * certificate retrieval is expected to reside in a separate companion layer.
 */
#ifndef QSC_X509_WRAP_H
#define QSC_X509_WRAP_H

#include "qsccommon.h"
#include "x509cert.h"
#include "x509certwrite.h"
#include "x509crl.h"
#include "x509csr.h"
#include "x509key.h"
#include "x509keywrite.h"
#include "x509name.h"
#include "x509pem.h"
#include "x509sigver.h"
#include "x509store.h"
#include "x509time.h"
#include "x509verify.h"
#include "tlscert.h"
#include "tlslimits.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \brief Maximum number of certificates supported by the wrapper chain model.
 */
#define QSC_X509W_CHAIN_MAX 8U

/**
 * \brief Maximum number of trust anchors supported by a wrapper trust store.
 */
#define QSC_X509W_ANCHOR_MAX 16U

/**
 * \brief Maximum number of CRLs stored in a wrapper trust store.
 */
#define QSC_X509W_CRL_MAX 8U

/**
 * \brief Size in bytes of the internal TLS verification work buffer.
 */
#define QSC_X509W_VERIFY_BUFFER_SIZE QSC_X509_CERTIFICATE_WRITE_MAX

/**
 * \brief Maximum length of the fixed diagnostic message buffer in
 * qsc_x509w_result.
 */
#define QSC_X509W_RESULT_MESSAGE_MAX 160U

/**
 * \enum qsc_x509w_status_t
 * \brief Wrapper-level status codes returned by x509wrap operations.
 */
typedef enum qsc_x509w_status_t
{
    QSC_X509W_STATUS_SUCCESS = 0,             /*!< Operation completed successfully. */
    QSC_X509W_STATUS_INVALID_INPUT = 1,       /*!< One or more input parameters were invalid. */
    QSC_X509W_STATUS_IO_ERROR = 2,            /*!< File or local input/output processing failed. */
    QSC_X509W_STATUS_DECODE_ERROR = 3,        /*!< ASN.1, DER, PEM, or wrapper object decoding failed. */
    QSC_X509W_STATUS_CHAIN_BUILD_ERROR = 4,   /*!< Certificate-chain construction failed. */
    QSC_X509W_STATUS_VERIFY_ERROR = 5,        /*!< Certificate or chain verification failed. */
    QSC_X509W_STATUS_HOSTNAME_MISMATCH = 6,   /*!< Hostname validation failed. */
    QSC_X509W_STATUS_KEY_MISMATCH = 7,        /*!< The private key does not match the certificate public key. */
    QSC_X509W_STATUS_PURPOSE_REJECTED = 8,    /*!< The certificate is not suitable for the requested role or purpose. */
    QSC_X509W_STATUS_STORE_FULL = 9,          /*!< The destination trust-store container has no remaining capacity. */
    QSC_X509W_STATUS_BUFFER_TOO_SMALL = 10,   /*!< A caller-supplied output buffer is too small. */
    QSC_X509W_STATUS_NETWORK_ERROR = 11,      /*!< Reserved for companion network-assisted layers. */
    QSC_X509W_STATUS_UNSUPPORTED = 12,        /*!< The requested format, algorithm, or operation is not supported. */
    QSC_X509W_STATUS_NOT_FOUND = 13,          /*!< The requested item or attribute was not found. */
    QSC_X509W_STATUS_ENCODING_ERROR = 14,     /*!< DER, PEM, or wrapper object encoding failed. */
    QSC_X509W_STATUS_PROFILE_ERROR = 15,      /*!< The validation or deployment profile is inconsistent or invalid. */
    QSC_X509W_STATUS_CALLBACK_ERROR = 16      /*!< A caller-supplied callback failed or rejected the operation. */
} qsc_x509w_status;

/**
 * \enum qsc_x509w_stage_t
 * \brief High-level operational stage indicators recorded in wrapper results.
 */
typedef enum qsc_x509w_stage_t
{
    QSC_X509W_STAGE_NONE = 0,             /*!< No stage has been recorded. */
    QSC_X509W_STAGE_LOAD = 1,             /*!< Input loading from file or memory. */
    QSC_X509W_STAGE_PARSE = 2,            /*!< Parse and decode of X.509 material. */
    QSC_X509W_STAGE_CHAIN_BUILD = 3,      /*!< Certificate-chain construction. */
    QSC_X509W_STAGE_TIME = 4,             /*!< Validity time checking. */
    QSC_X509W_STAGE_PURPOSE = 5,          /*!< Certificate-purpose or role evaluation. */
    QSC_X509W_STAGE_HOSTNAME = 6,         /*!< Hostname or DNS name matching. */
    QSC_X509W_STAGE_KEY_MATCH = 7,        /*!< Local certificate/private-key correspondence check. */
    QSC_X509W_STAGE_REVOCATION = 8,       /*!< Revocation evaluation using already loaded material. */
    QSC_X509W_STAGE_TRUST = 9,            /*!< Trust-anchor or chain trust decision. */
    QSC_X509W_STAGE_EXPORT = 10,          /*!< Object export or re-encoding. */
    QSC_X509W_STAGE_CONFIGURATION = 11    /*!< Deployment or wrapper configuration processing. */
} qsc_x509w_stage;

/**
 * \enum qsc_x509w_certificate_role_t
 * \brief Common certificate roles evaluated by wrapper suitability checks.
 */
typedef enum qsc_x509w_certificate_role_t
{
    QSC_X509W_CERTIFICATE_ROLE_NONE = 0,          /*!< No specific certificate role is requested. */
    QSC_X509W_CERTIFICATE_ROLE_TLS_SERVER = 1,    /*!< The certificate is intended for TLS server authentication. */
    QSC_X509W_CERTIFICATE_ROLE_TLS_CLIENT = 2,    /*!< The certificate is intended for TLS client authentication. */
    QSC_X509W_CERTIFICATE_ROLE_CA = 3,            /*!< The certificate is intended to act as a certificate authority. */
    QSC_X509W_CERTIFICATE_ROLE_TRUST_ANCHOR = 4   /*!< The certificate is intended to be loaded as a trust anchor. */
} qsc_x509w_certificate_role;

/**
 * \enum qsc_x509w_profile_preset_t
 * \brief Predefined validation-profile configurations for common workflows.
 */
typedef enum qsc_x509w_profile_preset_t
{
    QSC_X509W_PROFILE_PRESET_TLS_SERVER = 1,          /*!< TLS server certificate validation defaults. */
    QSC_X509W_PROFILE_PRESET_TLS_CLIENT = 2,          /*!< TLS client certificate validation defaults. */
    QSC_X509W_PROFILE_PRESET_CA = 3,                  /*!< CA and trust-material validation defaults. */
    QSC_X509W_PROFILE_PRESET_STRICT_REVOCATION = 4,   /*!< TLS server defaults with mandatory CRL revocation checking. */
    QSC_X509W_PROFILE_PRESET_DEVELOPMENT = 5          /*!< Relaxed development and test defaults. */
} qsc_x509w_profile_preset;

/**
 * \enum qsc_x509w_revocation_mode_t
 * \brief Revocation policy requested by a validation profile.
 */
typedef enum qsc_x509w_revocation_mode_t
{
    QSC_X509W_REVOCATION_MODE_NONE = 0,                    /*!< Revocation is not evaluated. */
    QSC_X509W_REVOCATION_MODE_CRL_IF_PRESENT = 1,          /*!< Use CRLs only when suitable loaded CRLs are present. */
    QSC_X509W_REVOCATION_MODE_CRL_REQUIRED = 2,            /*!< Require CRL-based revocation information. */
    QSC_X509W_REVOCATION_MODE_OCSP_IF_PRESENT = 3,         /*!< Reserved hook for OCSP use when present. */
    QSC_X509W_REVOCATION_MODE_OCSP_REQUIRED = 4,           /*!< Reserved hook requiring OCSP status. */
    QSC_X509W_REVOCATION_MODE_CRL_OR_OCSP_REQUIRED = 5,    /*!< Reserved hook requiring either CRL or OCSP status. */
    QSC_X509W_REVOCATION_MODE_CRL_AND_OCSP_REQUIRED = 6    /*!< Reserved hook requiring both CRL and OCSP status. */
} qsc_x509w_revocation_mode;

/**
 * \enum qsc_x509w_locator_policy_t
 * \brief Policy for future embedded locator handling such as AIA and OCSP URIs.
 */
typedef enum qsc_x509w_locator_policy_t
{
    QSC_X509W_LOCATOR_POLICY_DISABLED = 0,          /*!< Embedded locator information is ignored. */
    QSC_X509W_LOCATOR_POLICY_ALLOW_EMBEDDED = 1,    /*!< Embedded locator information is allowed but not required. */
    QSC_X509W_LOCATOR_POLICY_REQUIRE_EMBEDDED = 2   /*!< Embedded locator information is required by policy. */
} qsc_x509w_locator_policy;

/**
 * \enum qsc_x509w_revocation_source_t
 * \brief Source category used to satisfy a revocation decision.
 */
typedef enum qsc_x509w_revocation_source_t
{
    QSC_X509W_REVOCATION_SOURCE_NONE = 0,   /*!< No revocation source was used. */
    QSC_X509W_REVOCATION_SOURCE_CRL = 1,    /*!< Revocation status was determined from a CRL. */
    QSC_X509W_REVOCATION_SOURCE_OCSP = 2    /*!< Revocation status was determined from OCSP. */
} qsc_x509w_revocation_source;

/**
 * \enum qsc_x509w_availability_t
 * \brief Availability reporting for optional policy-driven materials.
 */
typedef enum qsc_x509w_availability_t
{
    QSC_X509W_AVAILABILITY_UNSPECIFIED = 0,  /*!< Availability was not specified or is not meaningful. */
    QSC_X509W_AVAILABILITY_UNCHECKED = 1,    /*!< Availability was not checked by the offline wrapper. */
    QSC_X509W_AVAILABILITY_AVAILABLE = 2,    /*!< Required material or locator information was available. */
    QSC_X509W_AVAILABILITY_UNAVAILABLE = 3   /*!< Required material or locator information was unavailable. */
} qsc_x509w_availability;

/**
 * \struct qsc_x509w_profile_t
 * \brief Validation profile describing the intended certificate-verification
 * policy.
 */
typedef struct qsc_x509w_profile_t
{
    qsc_x509_verify_purpose purpose;                  /*!< Requested verification purpose applied to the leaf certificate. */
    const qsc_x509_time* validationtime;             /*!< Optional caller-owned validation time override, or NULL for current time handling by the caller. */
    const char* hostname;                            /*!< Optional caller-owned hostname used for DNS validation. */
    bool rejectunsupportedcriticalextensions;        /*!< Reject unsupported critical extensions when true. */
    bool requirehostname;                            /*!< Require hostname validation when true. */
    qsc_x509w_revocation_mode revocationmode;        /*!< Revocation policy requested by the caller. */
    qsc_x509w_locator_policy aiaissuerpolicy;        /*!< Future policy hook for issuer-locator handling. */
    qsc_x509w_locator_policy ocsppolicy;             /*!< Future policy hook for OCSP locator handling. */
} qsc_x509w_profile;

/**
 * \struct qsc_x509w_result_t
 * \brief Structured operational result returned by wrapper validation and
 * configuration routines.
 */
typedef struct qsc_x509w_result_t
{
    qsc_x509w_status status;                         /*!< High-level wrapper status code. */
    qsc_x509w_stage stage;                          /*!< Stage at which the operation completed or failed. */
    qsc_x509_verify_status verifystatus;            /*!< Underlying certificate verification status. */
    qsc_x509_revocation_status revocationstatus;    /*!< Underlying revocation status. */
    qsc_x509w_revocation_source revocationsource;   /*!< Revocation source used by the wrapper. */
    qsc_x509w_availability aiaavailability;         /*!< Availability report for issuer-locator handling. */
    qsc_x509w_availability ocspavailability;        /*!< Availability report for OCSP handling. */
    size_t chainlength;                             /*!< Number of certificates examined or loaded into the effective chain. */
    size_t failuredepth;                            /*!< Chain position at which failure was detected, when known. */
    bool chainbuilt;                                /*!< True if a certificate chain was successfully constructed. */
    bool hostnamechecked;                           /*!< True if hostname validation was attempted. */
    bool hostnamevalid;                             /*!< True if hostname validation succeeded. */
    bool keymatch;                                  /*!< True if the tested private key matched the certificate public key. */
    bool purposevalid;                              /*!< True if purpose or role evaluation succeeded. */
    bool timevalid;                                 /*!< True if time validity checks succeeded. */
    bool aiahintpresent;                            /*!< True if issuer-locator extension hints were present. */
    bool ocsphintpresent;                           /*!< True if OCSP locator hints were present. */
    char message[QSC_X509W_RESULT_MESSAGE_MAX];     /*!< Fixed diagnostic message buffer populated by the wrapper. */
} qsc_x509w_result;

/**
 * \struct qsc_x509w_trust_store_t
 * \brief Wrapper-owned trust-store object containing anchors, CRLs, and the
 * underlying QSC store state.
 */
typedef struct qsc_x509w_trust_store_t
{
    qsc_x509_trust_anchor anchors[QSC_X509W_ANCHOR_MAX];   /*!< Embedded trust-anchor storage. */
    qsc_x509_store store;                                  /*!< Underlying QSC store descriptor initialized to reference the embedded anchors. */
    qsc_x509_crl crls[QSC_X509W_CRL_MAX];                  /*!< Embedded CRL storage. */
    size_t crlcount;                                       /*!< Number of valid CRLs currently stored. */
} qsc_x509w_trust_store;

/**
 * \brief Forward declaration of the QSC TLS client type.
 */
typedef struct qsc_tls_client qsc_tls_client;

/**
 * \brief Forward declaration of the QSC TLS server type.
 */
typedef struct qsc_tls_server qsc_tls_server;

/**
 * \struct qsc_x509w_server_identity_t
 * \brief Wrapper-owned server identity consisting of a leaf certificate,
 * optional intermediates, and the associated private key.
 */
typedef struct qsc_x509w_server_identity_t
{
    qsc_x509_certificate leaf;                                /*!< Leaf certificate used by the server endpoint. */
    qsc_x509_certificate intermediates[QSC_X509W_CHAIN_MAX - 1U]; /*!< Intermediate certificates following the leaf in presented-chain order. */
    size_t intermediatecount;                                 /*!< Number of intermediates currently loaded. */
    qsc_x509_private_key privatekey;                          /*!< Private key associated with the leaf certificate. */
} qsc_x509w_server_identity;

/**
 * \struct qsc_x509w_deployment_config_t
 * \brief File-path and policy configuration used to load server identities and
 * trust material for deployment workflows.
 */
typedef struct qsc_x509w_deployment_config_t
{
    const char* certificatechainpath;                 /*!< Caller-owned path to a PEM or DER certificate-chain input. */
    const char* privatekeypath;                       /*!< Caller-owned path to the associated private-key input. */
    const char* trustanchorpath;                      /*!< Caller-owned path to trust-anchor material. */
    const char* crlpath;                              /*!< Caller-owned path to CRL material. */
    const char* hostname;                             /*!< Caller-owned deployment hostname for certificate-suitability validation. */
    qsc_x509_verify_purpose purpose;                  /*!< Requested certificate purpose for the loaded deployment identity. */
    bool requireclientauth;                           /*!< Indicates that the deployment is expected to enforce client authentication. */
    bool loadtrustanchors;                            /*!< Load trust anchors from trustanchorpath when true. */
    bool loadcrls;                                    /*!< Load CRLs from crlpath when true. */
    bool rejectunsupportedcriticalextensions;         /*!< Reject unsupported critical extensions when validating loaded material. */
    bool requirerevocation;                           /*!< Require revocation information during deployment validation when true. */
} qsc_x509w_deployment_config;

/**
 * \struct qsc_x509w_tls_bridge_t
 * \brief Thin TLS bridge object binding wrapper validation policy and trust
 * material to the QSC TLS certificate interface.
 *
 * \details
 * This object does not implement handshake processing, transcript hashing,
 * key-schedule logic, or CertificateVerify signing. It is limited to
 * certificate-validation binding and interface preparation for the TLS layer.
 */
typedef struct qsc_x509w_tls_bridge_t
{
    qsc_x509w_profile profile;                         /*!< Validation profile copied into the bridge at configuration time. */
    const qsc_x509w_trust_store* truststore;          /*!< Borrowed pointer to a trust store that must outlive the bridge. */
    qsc_tls_qsc_x509_context context;                 /*!< TLS-facing certificate-validation context. */
    qsc_tls_certificate_interface iface;              /*!< Prepared TLS certificate interface. */
    qsc_x509_time currenttime;                        /*!< Embedded current-time storage for TLS verification use. */
    uint8_t verifybuffer[QSC_X509W_VERIFY_BUFFER_SIZE]; /*!< TLS verification work buffer. */
    bool initialized;                                 /*!< True when the bridge has been configured and is ready for attachment. */
} qsc_x509w_tls_bridge;

/**
 * \struct qsc_x509w_tls_local_certificate_t
 * \brief TLS-facing export container for a local certificate chain and optional
 * caller-supplied CertificateVerify signature bytes.
 */
typedef struct qsc_x509w_tls_local_certificate_t
{
    qsc_tls_certificate_view chain[QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES]; /*!< TLS certificate views referencing the embedded DER buffers. */
    uint8_t chainder[QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES][QSC_X509_CERTIFICATE_WRITE_MAX]; /*!< Embedded DER storage for the exported certificate chain. */
    size_t chainlength;                                                   /*!< Number of certificate views currently populated. */
    qsc_tls_signature_scheme verifyscheme;                                /*!< TLS CertificateVerify signature scheme associated with the supplied signature bytes. */
    uint8_t verifysignature[QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE]; /*!< Caller-supplied CertificateVerify signature bytes. */
    size_t verifysignaturelen;                                            /*!< Length in bytes of the caller-supplied CertificateVerify signature. */
} qsc_x509w_tls_local_certificate;

/**
 * \brief Initialize a validation profile to wrapper defaults.
 *
 * \param profile: The profile to initialize.
 */
QSC_EXPORT_API void qsc_x509w_profile_initialize(qsc_x509w_profile* profile);

/**
 * \brief Apply a predefined validation-profile preset.
 *
 * \param profile: The profile to update.
 * \param preset: The preset to apply.
 */
QSC_EXPORT_API void qsc_x509w_profile_apply_preset(qsc_x509w_profile* profile, qsc_x509w_profile_preset preset);

/**
 * \brief Set TLS server validation defaults in a profile.
 *
 * \param profile: The profile to update.
 */
QSC_EXPORT_API void qsc_x509w_profile_set_tls_server_defaults(qsc_x509w_profile* profile);

/**
 * \brief Set TLS client validation defaults in a profile.
 *
 * \param profile: The profile to update.
 */
QSC_EXPORT_API void qsc_x509w_profile_set_tls_client_defaults(qsc_x509w_profile* profile);

/**
 * \brief Set CA-validation defaults in a profile.
 *
 * \param profile: The profile to update.
 */
QSC_EXPORT_API void qsc_x509w_profile_set_ca_defaults(qsc_x509w_profile* profile);

/**
 * \brief Set strict revocation defaults in a profile.
 *
 * \param profile: The profile to update.
 */
QSC_EXPORT_API void qsc_x509w_profile_set_strict_revocation_defaults(qsc_x509w_profile* profile);

/**
 * \brief Set relaxed development defaults in a profile.
 *
 * \param profile: The profile to update.
 */
QSC_EXPORT_API void qsc_x509w_profile_set_development_defaults(qsc_x509w_profile* profile);

/**
 * \brief Initialize a wrapper result object to its default state.
 *
 * \param result: The result object to initialize.
 */
QSC_EXPORT_API void qsc_x509w_result_initialize(qsc_x509w_result* result);

/**
 * \brief Initialize a wrapper trust store.
 *
 * \param store: The trust store to initialize.
 */
QSC_EXPORT_API void qsc_x509w_trust_store_initialize(qsc_x509w_trust_store* store);

/**
 * \brief Clear a wrapper trust store and release its stored material.
 *
 * \param store: The trust store to clear.
 */
QSC_EXPORT_API void qsc_x509w_trust_store_clear(qsc_x509w_trust_store* store);

/**
 * \brief Initialize a server identity object.
 *
 * \param identity: The server identity to initialize.
 */
QSC_EXPORT_API void qsc_x509w_server_identity_initialize(qsc_x509w_server_identity* identity);

/**
 * \brief Clear a server identity and release its stored material.
 *
 * \param identity: The server identity to clear.
 */
QSC_EXPORT_API void qsc_x509w_server_identity_clear(qsc_x509w_server_identity* identity);

/**
 * \brief Initialize a deployment configuration object.
 *
 * \param config: The configuration object to initialize.
 */
QSC_EXPORT_API void qsc_x509w_deployment_config_initialize(qsc_x509w_deployment_config* config);

/**
 * \brief Initialize a TLS bridge object.
 *
 * \param bridge: The bridge object to initialize.
 */
QSC_EXPORT_API void qsc_x509w_tls_bridge_initialize(qsc_x509w_tls_bridge* bridge);

/**
 * \brief Initialize a TLS local-certificate export object.
 *
 * \param localcert: The local certificate container to initialize.
 */
QSC_EXPORT_API void qsc_x509w_tls_local_certificate_initialize(qsc_x509w_tls_local_certificate* localcert);

/**
 * \brief Acquire the current UTC time in X.509 time form.
 *
 * \param currenttime: The destination time object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_current_utc_time(qsc_x509_time* currenttime);

/**
 * \brief Load a certificate from a file.
 *
 * \param path: The input file path.
 * \param certificate: The destination certificate object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_load_file(const char* path, qsc_x509_certificate* certificate);

/**
 * \brief Load a certificate from a memory buffer.
 *
 * \param data: The input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param certificate: The destination certificate object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_load_memory(const uint8_t* data, size_t datalen, qsc_x509_certificate* certificate);

/**
 * \brief Load a certificate chain from a file into caller-supplied certificate
 * storage and a chain descriptor.
 *
 * \param path: The input file path.
 * \param certificates: The caller-supplied certificate storage array.
 * \param certificatecount: The capacity of the certificate storage array.
 * \param chain: The destination chain descriptor.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_chain_load_file(const char* path, qsc_x509_certificate* certificates, size_t certificatecount, qsc_x509_chain* chain);

/**
 * \brief Load a certificate chain from a memory buffer into caller-supplied
 * certificate storage and a chain descriptor.
 *
 * \param data: The input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param certificates: The caller-supplied certificate storage array.
 * \param certificatecount: The capacity of the certificate storage array.
 * \param chain: The destination chain descriptor.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_chain_load_memory(const uint8_t* data, size_t datalen, qsc_x509_certificate* certificates, size_t certificatecount, qsc_x509_chain* chain);

/**
 * \brief Load a private key from a file.
 *
 * \param path: The input file path.
 * \param privatekey: The destination private-key object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_private_key_load_file(const char* path, qsc_x509_private_key* privatekey);

/**
 * \brief Load a private key from a memory buffer.
 *
 * \param data: The input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param privatekey: The destination private-key object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_private_key_load_memory(const uint8_t* data, size_t datalen, qsc_x509_private_key* privatekey);

/**
 * \brief Load a CRL from a file.
 *
 * \param path: The input file path.
 * \param crl: The destination CRL object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_crl_load_file(const char* path, qsc_x509_crl* crl);

/**
 * \brief Load a CRL from a memory buffer.
 *
 * \param data: The input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param crl: The destination CRL object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_crl_load_memory(const uint8_t* data, size_t datalen, qsc_x509_crl* crl);

/**
 * \brief Load a CSR from a file.
 *
 * \param path: The input file path.
 * \param csr: The destination CSR object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_csr_load_file(const char* path, qsc_x509_csr* csr);

/**
 * \brief Load a CSR from a memory buffer.
 *
 * \param data: The input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param csr: The destination CSR object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_csr_load_memory(const uint8_t* data, size_t datalen, qsc_x509_csr* csr);

/**
 * \brief Add a certificate to the trust store as an anchor.
 *
 * \param store: The destination trust store.
 * \param certificate: The certificate to add.
 * \param selfsigned: Set true when the anchor is expected to be self-signed.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_trust_store_add_anchor(qsc_x509w_trust_store* store, const qsc_x509_certificate* certificate, bool selfsigned);

/**
 * \brief Decode and add one or more trust anchors from a memory buffer.
 *
 * \param store: The destination trust store.
 * \param data: The input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param selfsigned: Set true when the loaded anchors are expected to be self-signed.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_trust_store_add_anchor_bundle_memory(qsc_x509w_trust_store* store, const uint8_t* data, size_t datalen, bool selfsigned);

/**
 * \brief Decode and add one or more trust anchors from a file.
 *
 * \param store: The destination trust store.
 * \param path: The input file path.
 * \param selfsigned: Set true when the loaded anchors are expected to be self-signed.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_trust_store_add_anchor_bundle_file(qsc_x509w_trust_store* store, const char* path, bool selfsigned);

/**
 * \brief Load and add a single trust anchor from a file.
 *
 * \param store: The destination trust store.
 * \param path: The input file path.
 * \param selfsigned: Set true when the loaded anchor is expected to be self-signed.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_trust_store_add_anchor_file(qsc_x509w_trust_store* store, const char* path, bool selfsigned);

/**
 * \brief Load and add a single trust anchor from a memory buffer.
 *
 * \param store: The destination trust store.
 * \param data: The input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \param selfsigned: Set true when the loaded anchor is expected to be self-signed.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_trust_store_add_anchor_memory(qsc_x509w_trust_store* store, const uint8_t* data, size_t datalen, bool selfsigned);

/**
 * \brief Add a decoded CRL to the trust store.
 *
 * \param store: The destination trust store.
 * \param crl: The CRL to add.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_trust_store_add_crl(qsc_x509w_trust_store* store, const qsc_x509_crl* crl);

/**
 * \brief Load and add a CRL from a file.
 *
 * \param store: The destination trust store.
 * \param path: The input file path.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_trust_store_add_crl_file(qsc_x509w_trust_store* store, const char* path);

/**
 * \brief Load and add a CRL from a memory buffer.
 *
 * \param store: The destination trust store.
 * \param data: The input buffer.
 * \param datalen: The length of the input buffer in bytes.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_trust_store_add_crl_memory(qsc_x509w_trust_store* store, const uint8_t* data, size_t datalen);

/**
 * \brief Load a server identity from certificate-chain and private-key files.
 *
 * \param identity: The destination server identity.
 * \param certificatechainpath: The path to the certificate chain file.
 * \param privatekeypath: The path to the private-key file.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_server_identity_load_files(qsc_x509w_server_identity* identity, const char* certificatechainpath, const char* privatekeypath);

/**
 * \brief Load a server identity using a deployment configuration.
 *
 * \param identity: The destination server identity.
 * \param config: The deployment configuration.
 * \param result: The optional diagnostic result object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_server_identity_load_configuration(qsc_x509w_server_identity* identity, const qsc_x509w_deployment_config* config, qsc_x509w_result* result);

/**
 * \brief Load trust material using a deployment configuration.
 *
 * \param store: The destination trust store.
 * \param config: The deployment configuration.
 * \param result: The optional diagnostic result object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_trust_store_load_configuration(qsc_x509w_trust_store* store, const qsc_x509w_deployment_config* config, qsc_x509w_result* result);

/**
 * \brief Build a chain descriptor from a loaded server identity.
 *
 * \param identity: The source server identity.
 * \param chain: The destination chain descriptor.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_server_identity_get_chain(const qsc_x509w_server_identity* identity, qsc_x509_chain* chain);

/**
 * \brief Validate a loaded server identity against a wrapper profile.
 *
 * \param identity: The server identity to validate.
 * \param profile: The validation profile.
 * \param result: The destination diagnostic result object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_server_identity_validate(const qsc_x509w_server_identity* identity, const qsc_x509w_profile* profile, qsc_x509w_result* result);

/**
 * \brief Verify a loaded server identity against a trust store and profile.
 *
 * \param identity: The server identity to verify.
 * \param store: The trust store supplying anchors and CRLs.
 * \param profile: The validation profile.
 * \param result: The destination diagnostic result object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_server_identity_verify(const qsc_x509w_server_identity* identity, const qsc_x509w_trust_store* store,
    const qsc_x509w_profile* profile, qsc_x509w_result* result);

/**
 * \brief Evaluate whether a certificate is suitable for a requested role.
 *
 * \param certificate: The certificate to test.
 * \param role: The requested certificate role.
 * \param hostname: An optional hostname used for TLS server role evaluation.
 * \param result: The destination diagnostic result object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_check_role(const qsc_x509_certificate* certificate, qsc_x509w_certificate_role role,
    const char* hostname, qsc_x509w_result* result);

/**
 * \brief Verify a peer certificate chain against a trust store and wrapper
 * profile.
 *
 * \param certificates: The certificate chain array in peer-presented order.
 * \param certificatecount: The number of certificates in the array.
 * \param store: The trust store supplying anchors and CRLs.
 * \param profile: The validation profile.
 * \param result: The destination diagnostic result object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_verify_peer_certificates(const qsc_x509_certificate* certificates, size_t certificatecount,
    const qsc_x509w_trust_store* store, const qsc_x509w_profile* profile, qsc_x509w_result* result);

/**
 * \brief Format a distinguished name into a normalized string.
 *
 * \param name: The name to format.
 * \param output: The destination character buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written excluding the terminator.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_name_string(const qsc_x509_name* name, char* output, size_t outputlen, size_t* written);

/**
 * \brief Extract the first matching attribute value from a distinguished name.
 *
 * \param name: The name to search.
 * \param type: The requested attribute type.
 * \param output: The destination character buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written excluding the terminator.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_name_get_attribute_first(const qsc_x509_name* name, qsc_x509_name_attribute_type type, char* output, size_t outputlen, size_t* written);

/**
 * \brief Format a certificate subject distinguished name into a normalized
 * string.
 *
 * \param certificate: The source certificate.
 * \param output: The destination character buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written excluding the terminator.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_subject_string(const qsc_x509_certificate* certificate, char* output, size_t outputlen, size_t* written);

/**
 * \brief Format a certificate issuer distinguished name into a normalized
 * string.
 *
 * \param certificate: The source certificate.
 * \param output: The destination character buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written excluding the terminator.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_issuer_string(const qsc_x509_certificate* certificate, char* output, size_t outputlen, size_t* written);

/**
 * \brief Extract the first common-name attribute from a certificate subject.
 *
 * \param certificate: The source certificate.
 * \param output: The destination character buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written excluding the terminator.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_subject_common_name(const qsc_x509_certificate* certificate, char* output, size_t outputlen, size_t* written);

/**
 * \brief Get the number of DNS subjectAltName entries in a certificate.
 *
 * \param certificate: The source certificate.
 * \return Returns the number of DNS subjectAltName entries.
 */
QSC_EXPORT_API size_t qsc_x509w_certificate_subject_dns_name_count(const qsc_x509_certificate* certificate);

/**
 * \brief Retrieve a DNS subjectAltName entry by index.
 *
 * \param certificate: The source certificate.
 * \param index: The zero-based DNS name index.
 * \param output: The destination character buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written excluding the terminator.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_subject_dns_name(const qsc_x509_certificate* certificate, size_t index, char* output, size_t outputlen, size_t* written);

/**
 * \brief Convert a revocation mode to a constant display string.
 *
 * \param mode: The revocation mode.
 * \return Returns a constant string describing the mode.
 */
QSC_EXPORT_API const char* qsc_x509w_revocation_mode_string(qsc_x509w_revocation_mode mode);

/**
 * \brief Convert a locator policy to a constant display string.
 *
 * \param policy: The locator policy.
 * \return Returns a constant string describing the policy.
 */
QSC_EXPORT_API const char* qsc_x509w_locator_policy_string(qsc_x509w_locator_policy policy);

/**
 * \brief Convert a revocation source to a constant display string.
 *
 * \param source: The revocation source.
 * \return Returns a constant string describing the source.
 */
QSC_EXPORT_API const char* qsc_x509w_revocation_source_string(qsc_x509w_revocation_source source);

/**
 * \brief Convert an availability indicator to a constant display string.
 *
 * \param availability: The availability indicator.
 * \return Returns a constant string describing the availability state.
 */
QSC_EXPORT_API const char* qsc_x509w_availability_string(qsc_x509w_availability availability);

/**
 * \brief Convert a wrapper status code to a constant display string.
 *
 * \param status: The wrapper status code.
 * \return Returns a constant string describing the status.
 */
QSC_EXPORT_API const char* qsc_x509w_status_string(qsc_x509w_status status);

/**
 * \brief Convert a wrapper stage identifier to a constant display string.
 *
 * \param stage: The wrapper stage identifier.
 * \return Returns a constant string describing the stage.
 */
QSC_EXPORT_API const char* qsc_x509w_stage_string(qsc_x509w_stage stage);

/**
 * \brief Convert an underlying verification status to a constant display
 * string.
 *
 * \param status: The underlying verification status.
 * \return Returns a constant string describing the verification status.
 */
QSC_EXPORT_API const char* qsc_x509w_verify_status_string(qsc_x509_verify_status status);

/**
 * \brief Get the current diagnostic message stored in a wrapper result.
 *
 * \param result: The source result object.
 * \return Returns the fixed diagnostic message buffer.
 */
QSC_EXPORT_API const char* qsc_x509w_result_message(const qsc_x509w_result* result);

/**
 * \brief Export a certificate as DER.
 *
 * \param certificate: The certificate to export.
 * \param output: The destination byte buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_export_der(const qsc_x509_certificate* certificate, uint8_t* output, size_t outputlen, size_t* written);

/**
 * \brief Export a certificate as PEM.
 *
 * \param certificate: The certificate to export.
 * \param output: The destination character buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written excluding the terminator.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_export_pem(const qsc_x509_certificate* certificate, char* output, size_t outputlen, size_t* written);

/**
 * \brief Export a private key as PKCS#8 DER.
 *
 * \param privatekey: The private key to export.
 * \param includepublickey: Set true to include public-key data when supported.
 * \param output: The destination byte buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_private_key_export_pkcs8_der(const qsc_x509_private_key* privatekey, bool includepublickey, uint8_t* output, size_t outputlen, size_t* written);

/**
 * \brief Export a private key as PKCS#8 PEM.
 *
 * \param privatekey: The private key to export.
 * \param includepublickey: Set true to include public-key data when supported.
 * \param output: The destination character buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written excluding the terminator.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_private_key_export_pkcs8_pem(const qsc_x509_private_key* privatekey, bool includepublickey, char* output, size_t outputlen, size_t* written);

/**
 * \brief Export a CSR as DER.
 *
 * \param csr: The CSR to export.
 * \param output: The destination byte buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_csr_export_der(const qsc_x509_csr* csr, uint8_t* output, size_t outputlen, size_t* written);

/**
 * \brief Export a CSR as PEM.
 *
 * \param csr: The CSR to export.
 * \param output: The destination character buffer.
 * \param outputlen: The capacity of the destination buffer in bytes.
 * \param written: The optional number of bytes written excluding the terminator.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_csr_export_pem(const qsc_x509_csr* csr, char* output, size_t outputlen, size_t* written);

/**
 * \brief Initialize a CSR for later signing.
 *
 * \param csr: The CSR object to initialize.
 * \param subject: The CSR subject name.
 * \param spki: The subject public-key information.
 * \param signaturealgorithm: The requested CSR signature algorithm identifier.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_csr_create(qsc_x509_csr* csr, const qsc_x509_name* subject,
    const qsc_x509_subject_public_key_info* spki, const qsc_x509_algorithm_identifier* signaturealgorithm);

/**
 * \brief Add a DNS subjectAltName entry to a CSR.
 *
 * \param csr: The CSR to modify.
 * \param dnsname: The DNS name to add.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_csr_add_dns_name(qsc_x509_csr* csr, const char* dnsname);

/**
 * \brief Sign a CSR and export the result as DER.
 *
 * \param csr: The CSR to sign.
 * \param signcallback: The caller-supplied signing callback.
 * \param context: The opaque callback context.
 * \param output: The destination DER buffer.
 * \param outputlen: On input, the output-buffer capacity; on output, the number of bytes written.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_csr_sign_der(const qsc_x509_csr* csr, qsc_x509_certificate_sign_callback signcallback,
    void* context, uint8_t* output, size_t* outputlen);

/**
 * \brief Sign a CSR and export the result as PEM.
 *
 * \param csr: The CSR to sign.
 * \param signcallback: The caller-supplied signing callback.
 * \param context: The opaque callback context.
 * \param output: The destination PEM buffer.
 * \param outputlen: On input, the output-buffer capacity; on output, the number of bytes written excluding the terminator.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_csr_sign_pem(const qsc_x509_csr* csr, qsc_x509_certificate_sign_callback signcallback,
    void* context, char* output, size_t* outputlen);

/**
 * \brief Verify a CSR signature and structure.
 *
 * \param csr: The CSR to verify.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_csr_verify(const qsc_x509_csr* csr);

/**
 * \brief Issue a certificate from a CSR and export the result as DER.
 *
 * \param csr: The source CSR.
 * \param issuer: The issuer certificate.
 * \param signaturealgorithm: The signature algorithm identifier to encode.
 * \param serialnumber: The certificate serial number buffer.
 * \param serialnumberlen: The length of the serial-number buffer in bytes.
 * \param validity: The certificate validity period.
 * \param profile: The issuer-profile flags passed through to the certificate builder.
 * \param policyflags: Additional issuance policy flags passed through to the certificate builder.
 * \param signcallback: The issuer signing callback.
 * \param context: The opaque callback context.
 * \param output: The destination DER buffer.
 * \param outputlen: On input, the output-buffer capacity; on output, the number of bytes written.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_certificate_issue_from_csr(const qsc_x509_csr* csr, const qsc_x509_certificate* issuer,
    const qsc_x509_algorithm_identifier* signaturealgorithm, const uint8_t* serialnumber, size_t serialnumberlen,
    const qsc_x509_validity* validity, uint32_t profile, uint32_t policyflags,
    qsc_x509_certificate_sign_callback signcallback, void* context, uint8_t* output, size_t* outputlen);

/**
 * \brief Configure a TLS bridge with a trust store and validation profile.
 *
 * \param bridge: The bridge to configure.
 * \param store: The trust store that must outlive the bridge.
 * \param profile: The validation profile to copy into the bridge.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_tls_bridge_configure(qsc_x509w_tls_bridge* bridge, const qsc_x509w_trust_store* store,
    const qsc_x509w_profile* profile);

/**
 * \brief Determine whether a TLS bridge has been configured and is ready for
 * use.
 *
 * \param bridge: The bridge to test.
 * \return Returns true if the bridge is ready.
 */
QSC_EXPORT_API bool qsc_x509w_tls_bridge_is_ready(const qsc_x509w_tls_bridge* bridge);

/**
 * \brief Get the prepared TLS certificate interface from a configured bridge.
 *
 * \param bridge: The configured bridge.
 * \return Returns a pointer to the prepared TLS certificate interface.
 */
QSC_EXPORT_API const qsc_tls_certificate_interface* qsc_x509w_tls_bridge_get_interface(const qsc_x509w_tls_bridge* bridge);

/**
 * \brief Attach wrapper-backed peer validation to a TLS client.
 *
 * \param client: The TLS client to configure.
 * \param bridge: The configured bridge.
 * \param hostname: The caller-owned hostname for TLS validation.
 * \param requirepeercertificate: Set true to require a peer certificate.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_tls_bridge_attach_client_validation(qsc_tls_client* client, const qsc_x509w_tls_bridge* bridge,
    const char* hostname, bool requirepeercertificate);

/**
 * \brief Attach wrapper-backed peer validation to a TLS server.
 *
 * \param server: The TLS server to configure.
 * \param bridge: The configured bridge.
 * \param hostname: The caller-owned hostname for TLS validation.
 * \param requirepeercertificate: Set true to require a peer certificate.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_tls_bridge_attach_server_validation(qsc_tls_server* server, const qsc_x509w_tls_bridge* bridge,
    const char* hostname, bool requirepeercertificate);

/**
 * \brief Determine whether a TLS local-certificate export object is ready for
 * use.
 *
 * \param localcert: The local-certificate export object to test.
 * \return Returns true if the object is ready.
 */
QSC_EXPORT_API bool qsc_x509w_tls_local_certificate_is_ready(const qsc_x509w_tls_local_certificate* localcert);

/**
 * \brief Backward-compatible helper that attaches wrapper-backed peer
 * validation to a TLS client.
 *
 * \param client: The TLS client to configure.
 * \param bridge: The configured bridge.
 * \param hostname: The caller-owned hostname for TLS validation.
 * \param requirepeercertificate: Set true to require a peer certificate.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_tls_bridge_set_client(qsc_tls_client* client, qsc_x509w_tls_bridge* bridge,
    const char* hostname, bool requirepeercertificate);

/**
 * \brief Backward-compatible helper that attaches wrapper-backed peer
 * validation to a TLS server.
 *
 * \param server: The TLS server to configure.
 * \param bridge: The configured bridge.
 * \param hostname: The caller-owned hostname for TLS validation.
 * \param requirepeercertificate: Set true to require a peer certificate.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_tls_bridge_set_server_validation(qsc_tls_server* server, qsc_x509w_tls_bridge* bridge,
    const char* hostname, bool requirepeercertificate);

/**
 * \brief Export a server identity into TLS local-certificate form.
 *
 * \param identity: The source server identity.
 * \param verifyscheme: The TLS CertificateVerify signature scheme identifier.
 * \param verifysignature: The caller-supplied CertificateVerify signature bytes.
 * \param verifysignaturelen: The length of the supplied signature in bytes.
 * \param localcert: The destination TLS local-certificate export object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_tls_local_certificate_from_identity(const qsc_x509w_server_identity* identity,
    qsc_tls_signature_scheme verifyscheme, const uint8_t* verifysignature, size_t verifysignaturelen,
    qsc_x509w_tls_local_certificate* localcert);

/**
 * \brief Install a local certificate chain into a TLS server.
 *
 * \param server: The TLS server to configure.
 * \param localcert: The local-certificate export object.
 * \return Returns the wrapper status code.
 */
QSC_EXPORT_API qsc_x509w_status qsc_x509w_tls_server_set_local_certificate(qsc_tls_server* server,
    const qsc_x509w_tls_local_certificate* localcert);

QSC_CPLUSPLUS_ENABLED_END

#endif
