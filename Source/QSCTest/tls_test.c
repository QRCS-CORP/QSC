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

	return res;
}
