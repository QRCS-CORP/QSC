#include "tls_test.h"
#include "testutils.h"
#include "TLS/tls_stage1_codec_extension_tests.h"
#include "TLS/tls_stage2_registry_policy_tests.h"
#include "TLS/tls_stage3_transcript_tests.h"
#include "TLS/tls_stage4_schedule_tests.h"
#include "TLS/tls_stage5_record_tests.h"
#include "TLS/tls_stage6_certificate_message_tests.h"

bool qsctest_tls_stage1_run(void)
{
	return qsctest_tls_stage1_tests();
}

bool qsctest_tls_stage2_run(void)
{
	return qsctest_tls_stage2_tests();
}

bool qsctest_tls_stage3_run(void)
{
	return qsctest_tls_stage3_tests();
}

bool qsctest_tls_stage4_run(void)
{
	return qsctest_tls_stage4_tests();
}

bool qsctest_tls_stage5_run(void)
{
	return qsctest_tls_stage5_tests();
}

bool qsctest_tls_stage6_run(void)
{
	return qsctest_tls_stage6_tests();
}

bool qsctest_tls_run(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage1_run() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage2_run() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage3_run() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage4_run() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage5_run() == false)
	{
		res = false;
	}

	if (qsctest_tls_stage6_run() == false)
	{
		res = false;
	}

	return res;
}
