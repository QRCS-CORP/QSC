#ifndef QSC_TLS_TYPES_H
#define QSC_TLS_TYPES_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlstypes.h
 * \brief Public TLS type definitions.
 */

/**
 * \enum qsc_tls_hash_algorithm
 * \brief Identifies the transcript and HKDF hash algorithm associated with a TLS cipher suite.
 */
typedef enum qsc_tls_hash_algorithm
{
	qsc_tls_hash_none = 0,		/*!< No hash algorithm selected. */
	qsc_tls_hash_sha256 = 1,	/*!< SHA-256 hash algorithm. */
	qsc_tls_hash_sha384 = 2,	/*!< SHA-384 hash algorithm. */
	qsc_tls_hash_sha512 = 3		/*!< SHA-512 hash algorithm. */
} qsc_tls_hash_algorithm;

/**
 * \enum qsc_tls_record_content_type
 * \brief TLS record content-type codes.
 */
typedef enum qsc_tls_record_content_type
{
	qsc_tls_record_content_invalid = 0,				/*!< Invalid or unset content type. */
	qsc_tls_record_content_change_cipher_spec = 20, /*!< ChangeCipherSpec record type. */
	qsc_tls_record_content_alert = 21,				/*!< Alert record type. */
	qsc_tls_record_content_handshake = 22,			/*!< Handshake record type. */
	qsc_tls_record_content_application_data = 23	/*!< ApplicationData record type. */
} qsc_tls_record_content_type;

/**
 * \enum qsc_tls_alert_description
 * \brief TLS alert description codes carried in Alert protocol messages.
 */
typedef enum qsc_tls_alert_description
{
	qsc_tls_alert_close_notify = 0,							/*!< The connection is being closed normally. */
	qsc_tls_alert_unexpected_message = 10,					/*!< An unexpected protocol message was received. */
	qsc_tls_alert_bad_record_mac = 20,						/*!< Record authentication failed. */
	qsc_tls_alert_record_overflow = 22,						/*!< A record exceeded the permitted size. */
	qsc_tls_alert_handshake_failure = 40,					/*!< The handshake could not be completed successfully. */
	qsc_tls_alert_bad_certificate = 42,						/*!< The certificate was corrupt or unacceptable. */
	qsc_tls_alert_unsupported_certificate = 43,				/*!< The certificate type is unsupported. */
	qsc_tls_alert_certificate_revoked = 44,					/*!< The certificate has been revoked. */
	qsc_tls_alert_certificate_expired = 45,					/*!< The certificate has expired. */
	qsc_tls_alert_certificate_unknown = 46,					/*!< The certificate could not be validated for an unspecified reason. */
	qsc_tls_alert_illegal_parameter = 47,					/*!< A field contained an invalid value. */
	qsc_tls_alert_unknown_ca = 48,							/*!< The certificate issuer is not trusted. */
	qsc_tls_alert_access_denied = 49,						/*!< Access was denied after successful authentication. */
	qsc_tls_alert_decode_error = 50,						/*!< A message could not be decoded correctly. */
	qsc_tls_alert_decrypt_error = 51,						/*!< A cryptographic operation failed. */
	qsc_tls_alert_protocol_version = 70,					/*!< The negotiated protocol version is unsupported. */
	qsc_tls_alert_insufficient_security = 71,				/*!< The peer requires stronger security parameters. */
	qsc_tls_alert_internal_error = 80,						/*!< An internal implementation error occurred. */
	qsc_tls_alert_inappropriate_fallback = 86,				/*!< An inappropriate version fallback was detected. */
	qsc_tls_alert_user_canceled = 90,						/*!< The operation was canceled by the peer. */
	qsc_tls_alert_missing_extension = 109,					/*!< A required extension was missing. */
	qsc_tls_alert_unsupported_extension = 110,				/*!< An unsupported extension was received. */
	qsc_tls_alert_unrecognized_name = 112,					/*!< The requested server name was not recognized. */
	qsc_tls_alert_bad_certificate_status_response = 113,	/*!< The certificate status response was invalid. */
	qsc_tls_alert_unknown_psk_identity = 115,				/*!< The offered PSK identity was not recognized. */
	qsc_tls_alert_certificate_required = 116,				/*!< A certificate was required but not provided. */
	qsc_tls_alert_no_application_protocol = 120				/*!< No mutually supported application protocol was found. */
} qsc_tls_alert_description;

/**
 * \enum qsc_tls_cipher_suite
 * \brief TLS 1.3 cipher-suite identifiers.
 */
typedef enum qsc_tls_cipher_suite
{
	qsc_tls_cipher_suite_none = 0,								/*!< No cipher suite selected. */
	qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 = 0x1301,		/*!< TLS_AES_128_GCM_SHA256. */
	qsc_tls_cipher_suite_tls_aes_256_gcm_sha384 = 0x1302,		/*!< TLS_AES_256_GCM_SHA384. */
	qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256 = 0x1303	/*!< TLS_CHACHA20_POLY1305_SHA256. */
} qsc_tls_cipher_suite;

/**
 * \enum qsc_tls_extension_type
 * \brief TLS extension type identifiers.
 */
typedef enum qsc_tls_extension_type
{
	qsc_tls_extension_server_name = 0,								/*!< server_name extension. */
	qsc_tls_extension_pre_shared_key = 41,							/*!< pre_shared_key extension. */
	qsc_tls_extension_early_data = 42,								/*!< early_data extension. */
	qsc_tls_extension_supported_groups = 10,						/*!< supported_groups extension. */
	qsc_tls_extension_signature_algorithms = 13,					/*!< signature_algorithms extension. */
	qsc_tls_extension_application_layer_protocol_negotiation = 16,	/*!< application_layer_protocol_negotiation extension. */
	qsc_tls_extension_supported_versions = 43,						/*!< supported_versions extension. */
	qsc_tls_extension_psk_key_exchange_modes = 45,					/*!< psk_key_exchange_modes extension. */
	qsc_tls_extension_signature_algorithms_cert = 50,				/*!< signature_algorithms_cert extension. */
	qsc_tls_extension_key_share = 51								/*!< key_share extension. */
} qsc_tls_extension_type;

/**
 * \enum qsc_tls_named_group
 * \brief TLS named-group identifiers for classical, ML-KEM, and hybrid key exchange groups.
 */
typedef enum qsc_tls_named_group
{
	qsc_tls_group_none = 0,							/*!< No group selected. */
	qsc_tls_group_secp256r1 = 0x0017,				/*!< secp256r1 named group. */
	qsc_tls_group_secp384r1 = 0x0018,				/*!< secp384r1 named group. */
	qsc_tls_group_secp521r1 = 0x0019,				/*!< secp521r1 named group. */
	qsc_tls_group_x25519 = 0x001D,					/*!< x25519 named group. */
	qsc_tls_group_x448 = 0x001E,					/*!< x448 named group. */
	qsc_tls_group_mlkem512 = 0x0200,				/*!< ML-KEM-512 named group. */
	qsc_tls_group_mlkem768 = 0x0201,				/*!< ML-KEM-768 named group. */
	qsc_tls_group_mlkem1024 = 0x0202,				/*!< ML-KEM-1024 named group. */
	qsc_tls_group_x25519_mlkem512 = 0x11EB,			/*!< Hybrid x25519 plus ML-KEM-512 named group. */
	qsc_tls_group_x25519_mlkem768 = 0x11EC,			/*!< Hybrid x25519 plus ML-KEM-768 named group. */
	qsc_tls_group_secp256r1_mlkem768 = 0x11ED,		/*!< Hybrid secp256r1 plus ML-KEM-768 named group. */
	qsc_tls_group_secp384r1_mlkem1024 = 0x11EE,		/*!< Hybrid secp384r1 plus ML-KEM-1024 named group. */
	qsc_tls_group_x25519_mlkem1024 = 0x11EF,		/*!< Hybrid x25519 plus ML-KEM-1024 named group. */
	qsc_tls_group_secp256r1_mlkem512 = 0x11F0,		/*!< Hybrid secp256r1 plus ML-KEM-512 named group. */
	qsc_tls_group_secp256r1_mlkem1024 = 0x11F1,		/*!< Hybrid secp256r1 plus ML-KEM-1024 named group. */
	qsc_tls_group_secp384r1_mlkem768 = 0x11F2		/*!< Hybrid secp384r1 plus ML-KEM-768 named group. */
} qsc_tls_named_group;

/**
 * \enum qsc_tls_signature_scheme
 * \brief TLS signature-scheme identifiers.
 */
typedef enum qsc_tls_signature_scheme
{
	qsc_tls_sig_none = 0,							/*!< No signature scheme selected. */
	qsc_tls_sig_ecdsa_secp256r1_sha256 = 0x0403,	/*!< ecdsa_secp256r1_sha256 signature scheme. */
	qsc_tls_sig_ecdsa_secp384r1_sha384 = 0x0503,	/*!< ecdsa_secp384r1_sha384 signature scheme. */
	qsc_tls_sig_ed25519 = 0x0807,					/*!< ed25519 signature scheme. */
	qsc_tls_sig_mldsa44 = 0x0904,					/*!< ML-DSA-44 signature scheme. */
	qsc_tls_sig_mldsa65 = 0x0905,					/*!< ML-DSA-65 signature scheme. */
	qsc_tls_sig_mldsa87 = 0x0906					/*!< ML-DSA-87 signature scheme. */
} qsc_tls_signature_scheme;

QSC_CPLUSPLUS_ENABLED_END

#endif
