#include "tls_test.h"
#include "testutils.h"
#include "TLS/tls_stage1_codec_extension_tests.h"
#include "TLS/tls_stage2_certificate_tests.h"
#include "TLS/tls_stage3_keyupdate_tests.h"
#include "TLS/tls_stage4_enum_equivalence_tests.h"
#include "TLS/tls_stage5_subsystem_tests.h"
#include "TLS/tls_stage6_session_resumption_tests.h"
#include "TLS/tls_stage7_hrr_tests.h"
#include "TLS/tls_stage8_vector_tests.h"
#include "TLS/tls_stage9_tlscert_x509_tests.h"
#include "TLS/tls_stage10_0rtt_tests.h"
#include "TLS/tls_stage11_ecdsa_der_tests.h"
#include "TLS/tls_stage12_ecdsa_signer_tests.h"
#include "TLS/tls_stage13_secp256r1_tests.h"
#include "TLS/tls_stage14_e2e_tests.h"
#include "TLS/tls_stage15_truststore_tests.h"
#include "TLS/tls_stage16_psk_codec_tests.h"
#include "TLS/tls_stage17_multi_suite_tests.h"
#include "TLS/tls_stage18_0rtt_resumption_tests.h"
#include "TLS/tls_stage19_socket_wrapper_tests.h"
#include "TLS/tls_stage20_alpn_tests.h"
#include "TLS/tls_stage21_sni_tests.h"
#include "TLS/tls_stage22_mtls_authorization_tests.h"
#include "TLS/tls_stage23_peer_info_tests.h"
#include "TLS/tls_stage24_ticket_policy_tests.h"
#include "TLS/tls_stage25_framed_message_tests.h"
#include "TLS/tls_stage26_record_fragmentation_tests.h"
#include "TLS/tls_stage27_socket_options_tests.h"
#include "TLS/tls_stage28_concurrent_shutdown_tests.h"
#include "TLS/tls_stage29_negative_x509_tests.h"
#include "TLS/tls_stage30_post_handshake_dispatch_tests.h"
#include "TLS/tls_stage31_mtls_handshake_tests.h"
#include "TLS/tls_stage32_resumption_profile_tests.h"
#include "TLS/tls_stage33_rfc9846_compliance_tests.h"
#include "TLS/tls_stage34_rfc10024_hybrid_tests.h"
#include "TLS/tls_stage35_handshake_deadline_tests.h"
#include "TLS/tls_stage36_pq_standards_tests.h"

bool qsctest_tls_run(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage1_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage2_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage3_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage4_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage5_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage6_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage7_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage8_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage9_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage10_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage11_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage12_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage13_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage14_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage15_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage16_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage17_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage18_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage19_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage20_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage21_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage22_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage23_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage24_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage25_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage26_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage27_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage28_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage29_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage30_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage31_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage32_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage33_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage34_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage35_tests() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage36_tests() == false)
	{
		res = false;
	}

	return res;
}
