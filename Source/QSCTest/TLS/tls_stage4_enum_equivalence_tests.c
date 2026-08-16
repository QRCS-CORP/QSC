#include "tls_stage4_enum_equivalence_tests.h"
#include "../testutils.h"
#include "../../QSC/tlstypes.h"
#include "../../QSC/tlsdefs.h"

#define PL_PROTOCOL_VERSION_TLS12 0x0303U
#define PL_PROTOCOL_VERSION_TLS13 0x0304U

#define PL_ALERT_CLOSE_NOTIFY 0U
#define PL_ALERT_UNEXPECTED_MESSAGE 10U
#define PL_ALERT_BAD_RECORD_MAC 20U
#define PL_ALERT_RECORD_OVERFLOW 22U
#define PL_ALERT_HANDSHAKE_FAILURE 40U
#define PL_ALERT_BAD_CERTIFICATE 42U
#define PL_ALERT_UNSUPPORTED_CERTIFICATE 43U
#define PL_ALERT_CERTIFICATE_REVOKED 44U
#define PL_ALERT_CERTIFICATE_EXPIRED 45U
#define PL_ALERT_CERTIFICATE_UNKNOWN 46U
#define PL_ALERT_ILLEGAL_PARAMETER 47U
#define PL_ALERT_UNKNOWN_CA 48U
#define PL_ALERT_ACCESS_DENIED 49U
#define PL_ALERT_DECODE_ERROR 50U
#define PL_ALERT_DECRYPT_ERROR 51U
#define PL_ALERT_PROTOCOL_VERSION 70U
#define PL_ALERT_INSUFFICIENT_SECURITY 71U
#define PL_ALERT_INTERNAL_ERROR 80U
#define PL_ALERT_INAPPROPRIATE_FALLBACK 86U
#define PL_ALERT_USER_CANCELED 90U
#define PL_ALERT_MISSING_EXTENSION 109U
#define PL_ALERT_UNSUPPORTED_EXTENSION 110U
#define PL_ALERT_UNRECOGNIZED_NAME 112U
#define PL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE 113U
#define PL_ALERT_UNKNOWN_PSK_IDENTITY 115U
#define PL_ALERT_CERTIFICATE_REQUIRED 116U
#define PL_ALERT_NO_APPLICATION_PROTOCOL 120U

#define PL_ALERT_LEVEL_WARNING 1U
#define PL_ALERT_LEVEL_FATAL 2U

#define PL_HS_CLIENT_HELLO 1U
#define PL_HS_SERVER_HELLO 2U
#define PL_HS_NEW_SESSION_TICKET 4U
#define PL_HS_END_OF_EARLY_DATA 5U
#define PL_HS_ENCRYPTED_EXTENSIONS 8U
#define PL_HS_CERTIFICATE 11U
#define PL_HS_CERTIFICATE_REQUEST 13U
#define PL_HS_CERTIFICATE_VERIFY 15U
#define PL_HS_FINISHED 20U
#define PL_HS_KEY_UPDATE 24U
#define PL_HS_MESSAGE_HASH 254U

#define PL_CS_AES128_GCM_SHA256 0x1301U
#define PL_CS_AES256_GCM_SHA384 0x1302U
#define PL_CS_CHACHA20_POLY1305_SHA256 0x1303U

#define PL_GROUP_SECP256R1 23U
#define PL_GROUP_SECP384R1 24U
#define PL_GROUP_SECP521R1 25U
#define PL_GROUP_X25519 29U
#define PL_GROUP_X448 30U
#define PL_GROUP_MLKEM512 512U
#define PL_GROUP_MLKEM768 513U
#define PL_GROUP_MLKEM1024 514U

#define PL_SIG_ECDSA_SECP256R1_SHA256 0x0403U
#define PL_SIG_ECDSA_SECP384R1_SHA384 0x0503U
#define PL_SIG_ED25519 0x0807U

#define QSCTEST_TLS_STAGE4_ASSERT_EQ(a, b, tag) typedef char qsctest_tls_stage4_assert_##tag[((a) == (b)) ? 1 : -1]

QSCTEST_TLS_STAGE4_ASSERT_EQ(QSC_TLS_PROTOCOL_VERSION_12, PL_PROTOCOL_VERSION_TLS12, ver12);
QSCTEST_TLS_STAGE4_ASSERT_EQ(QSC_TLS_PROTOCOL_VERSION_13, PL_PROTOCOL_VERSION_TLS13, ver13);

QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_close_notify, PL_ALERT_CLOSE_NOTIFY, a_close_notify);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_unexpected_message, PL_ALERT_UNEXPECTED_MESSAGE, a_unexpected);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_bad_record_mac, PL_ALERT_BAD_RECORD_MAC, a_bad_mac);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_record_overflow, PL_ALERT_RECORD_OVERFLOW, a_overflow);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_handshake_failure, PL_ALERT_HANDSHAKE_FAILURE, a_hsfail);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_bad_certificate, PL_ALERT_BAD_CERTIFICATE, a_badcert);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_unsupported_certificate, PL_ALERT_UNSUPPORTED_CERTIFICATE, a_unscert);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_certificate_revoked, PL_ALERT_CERTIFICATE_REVOKED, a_revoked);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_certificate_expired, PL_ALERT_CERTIFICATE_EXPIRED, a_expired);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_certificate_unknown, PL_ALERT_CERTIFICATE_UNKNOWN, a_unkcert);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_illegal_parameter, PL_ALERT_ILLEGAL_PARAMETER, a_illegal);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_unknown_ca, PL_ALERT_UNKNOWN_CA, a_unknownca);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_access_denied, PL_ALERT_ACCESS_DENIED, a_accessdenied);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_decode_error, PL_ALERT_DECODE_ERROR, a_decode);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_decrypt_error, PL_ALERT_DECRYPT_ERROR, a_decrypt);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_protocol_version, PL_ALERT_PROTOCOL_VERSION, a_proto);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_insufficient_security, PL_ALERT_INSUFFICIENT_SECURITY, a_sec);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_internal_error, PL_ALERT_INTERNAL_ERROR, a_internal);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_inappropriate_fallback, PL_ALERT_INAPPROPRIATE_FALLBACK, a_fallback);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_user_canceled, PL_ALERT_USER_CANCELED, a_usercancel);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_missing_extension, PL_ALERT_MISSING_EXTENSION, a_missing);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_unsupported_extension, PL_ALERT_UNSUPPORTED_EXTENSION, a_unsupported);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_unrecognized_name, PL_ALERT_UNRECOGNIZED_NAME, a_unrecname);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_bad_certificate_status_response, PL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE, a_badstatus);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_unknown_psk_identity, PL_ALERT_UNKNOWN_PSK_IDENTITY, a_unknownpsk);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_certificate_required, PL_ALERT_CERTIFICATE_REQUIRED, a_certreq);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_no_application_protocol, PL_ALERT_NO_APPLICATION_PROTOCOL, a_noalpn);

QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_level_warning, PL_ALERT_LEVEL_WARNING, level_warn);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_alert_level_fatal, PL_ALERT_LEVEL_FATAL, level_fatal);

QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_client_hello, PL_HS_CLIENT_HELLO, hs_ch);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_server_hello, PL_HS_SERVER_HELLO, hs_sh);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_new_session_ticket, PL_HS_NEW_SESSION_TICKET, hs_nst);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_end_of_early_data, PL_HS_END_OF_EARLY_DATA, hs_eoed);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_encrypted_extensions, PL_HS_ENCRYPTED_EXTENSIONS, hs_ee);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_certificate, PL_HS_CERTIFICATE, hs_cert);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_certificate_request, PL_HS_CERTIFICATE_REQUEST, hs_cr);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_certificate_verify, PL_HS_CERTIFICATE_VERIFY, hs_cv);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_finished, PL_HS_FINISHED, hs_fin);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_key_update, PL_HS_KEY_UPDATE, hs_ku);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_handshake_type_message_hash, PL_HS_MESSAGE_HASH, hs_mh);

QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, PL_CS_AES128_GCM_SHA256, cs_128);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_cipher_suite_tls_aes_256_gcm_sha384, PL_CS_AES256_GCM_SHA384, cs_256);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256, PL_CS_CHACHA20_POLY1305_SHA256, cs_chacha);

QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_group_secp256r1, PL_GROUP_SECP256R1, g_p256);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_group_secp384r1, PL_GROUP_SECP384R1, g_p384);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_group_secp521r1, PL_GROUP_SECP521R1, g_p521);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_group_x25519, PL_GROUP_X25519, g_x25519);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_group_x448, PL_GROUP_X448, g_x448);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_group_mlkem512, PL_GROUP_MLKEM512, g_mlkem512);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_group_mlkem768, PL_GROUP_MLKEM768, g_mlkem768);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_group_mlkem1024, PL_GROUP_MLKEM1024, g_mlkem1024);

QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_sig_ecdsa_secp256r1_sha256, PL_SIG_ECDSA_SECP256R1_SHA256, s_p256);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_sig_ecdsa_secp384r1_sha384, PL_SIG_ECDSA_SECP384R1_SHA384, s_p384);
QSCTEST_TLS_STAGE4_ASSERT_EQ(qsc_tls_sig_ed25519, PL_SIG_ED25519, s_ed25519);

bool qsctest_tls_stage4_enum_equivalence(void)
{
	return true;
}

bool qsctest_tls_stage4_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage4_enum_equivalence() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 4 enumeration equivalence test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 4 enumeration equivalence test.");
		res = false;
	}

	return res;
}
