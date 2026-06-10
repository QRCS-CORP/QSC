#include "qmac_test.h"
#include "qsctestcommon.h"
#include "testutils.h"
#include "intutils.h"
#include "memutils.h"
#include "qmac.h"

bool qsctest_qmac_kat()
{
	uint8_t exp[6][QSC_QMAC_MAC_SIZE] = { 0 };
	uint8_t key[4][QSC_QMAC_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_QMAC_MAC_SIZE] = { 0 };
	uint8_t otp2[QSC_QMAC_MAC_SIZE] = { 0 };
	uint8_t msg0[34];
	uint8_t msg1[30];
	uint8_t msg2[65];
	uint8_t msg3[64];
	uint8_t nonce[QSC_QMAC_NONCE_SIZE];
	uint64_t cla[4U] = { 0U, 1U, 0U, 0U };
	uint64_t clb[4U] = { 0U, 1U, 0U, 0U };
	uint64_t clr[8U] = { 0U };
	uint8_t zmsg0[3] = { 0x61U, 0x62U, 0x63U };
	uint8_t zmsg1[4] = { 0x61U, 0x62U, 0x63U, 0x00U };
	bool status;

	status = true;

	/* Carryless multiplication regression: x^64 * x^64 = x^128. */
	qsc_memutils_clmulepi64_si256(clr, cla, clb);

	if (clr[0U] != 0U || clr[1U] != 0U || clr[2U] != 1U || clr[3U] != 0U ||
		clr[4U] != 0U || clr[5U] != 0U || clr[6U] != 0U || clr[7U] != 0U)
	{
		qsctest_print_safe("Failure! QMAC: Carryless multiplication regression failed -PKM \n");
		status = false;
	}

	qsctest_hex_to_bin("5F762A2B98E0FCB7600080D8CD19AE63560D7852D6779416F7184DCC9A2CBCF4", exp[0], sizeof(exp[0]));
	qsctest_hex_to_bin("2890A15ACE3ACA27B389E746161936241D3CC14EB1411AF7354D5D3286636253", exp[1], sizeof(exp[1]));
	qsctest_hex_to_bin("0B468A6EEF98DC71004C4DB21E8E5D394248F0BF282317E9F339A824704A1AAE", exp[2], sizeof(exp[2]));
	qsctest_hex_to_bin("B533949BE4C71A2CAC2358D6B35C944AA16BB0362C3F2D8DDF89D41361B815C4", exp[3], sizeof(exp[3]));

	qsctest_hex_to_bin("85D6BE7857556D337F4452FE42D506A80103808AFB0DB2FD4ABFF6AF4149F51B", key[0], sizeof(key[0]));
	qsctest_hex_to_bin("746869732069732033322D62797465206B657920666F7220506F6C7931333035", key[1], sizeof(key[1]));
	qsctest_hex_to_bin("1000000000000000000000000000000000000000000000000000000000000000", key[2], sizeof(key[2]));
	qsctest_hex_to_bin("0000000000000000000000000000000036E5F6B5C5E06070F0EFCA96227A863E", key[3], sizeof(key[3]));

	qsctest_hex_to_bin("43727970746F6772617068696320466F72756D2052657365617263682047726F7570", msg0, sizeof(msg0));
	qsctest_hex_to_bin("48656C6C6F20776F726C642148656C6C6F20776F726C642148656C6C6F20", msg1, sizeof(msg1));
	qsctest_hex_to_bin("00000000000000000000000000000000000000000000000000000000000000000000"
		"00000000000000000000000000000000000000000000000000000000000001", msg2, sizeof(msg2));
	qsctest_hex_to_bin("746869732069732033322D62797465206B657920666F7220506F6C7931333035"
		"642062792074686520436F6E7472696275746F7220666F72207075626C69C1A1", msg3, sizeof(msg3));

	qsctest_hex_to_bin("0000000000000000000000000000000000000000000000000000000000000001", nonce, sizeof(nonce));

	/* compact api */

	qsc_qmac_keyparams kp0 = { .key = key[0], .keylen =  QSC_QMAC_KEY_SIZE };
	
	qsc_qmac_compute(otp, &kp0, msg1, sizeof(msg1));

	if (qsc_intutils_are_equal8(otp, exp[0], sizeof(otp)) == false)
	{
		qsctest_print_safe("Failure! QMAC: Output does not match the known answer -PK0 \n");
		status = false;
	}

	qsc_qmac_keyparams kp1 = { .key = key[1], .keylen = QSC_QMAC_KEY_SIZE };

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_qmac_compute(otp, &kp1, msg1, sizeof(msg1));
	
	if (qsc_intutils_are_equal8(otp, exp[1], sizeof(otp)) == false)
	{
		qsctest_print_safe("Failure! QMAC: Output does not match the known answer -PK1 \n");
		status = false;
	}

	qsc_qmac_keyparams kp2 = { .key = key[2], .keylen = QSC_QMAC_KEY_SIZE };

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_qmac_compute(otp, &kp2, msg2, sizeof(msg2));
	
	if (qsc_intutils_are_equal8(otp, exp[2], sizeof(otp)) == false)
	{
		qsctest_print_safe("Failure! QMAC: Output does not match the known answer -PK2 \n");
		status = false;
	}

	/* long-form api */

	qsc_qmac_state ctx = { 0 };

	qsc_intutils_clear8(otp, sizeof(otp));

	qsc_qmac_initialize(&ctx, &kp2);
	qsc_qmac_update(&ctx, msg2, QSC_QMAC_BLOCK_SIZE);
	qsc_qmac_update(&ctx, msg2 + QSC_QMAC_BLOCK_SIZE, QSC_QMAC_BLOCK_SIZE);
	qsc_qmac_update(&ctx, msg2 + (2 * QSC_QMAC_BLOCK_SIZE), sizeof(uint8_t));
	qsc_qmac_finalize(&ctx, otp);
	
	if (qsc_intutils_are_equal8(otp, exp[2], sizeof(otp)) == false)
	{
		qsctest_print_safe("Failure! QMAC: Output does not match the known answer -PK3 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_intutils_clear8(otp2, sizeof(otp2));
	qsc_qmac_compute(otp, &kp2, msg2, sizeof(msg2));
	qsc_qmac_initialize(&ctx, &kp2);
	qsc_qmac_update(&ctx, msg2, sizeof(uint8_t));
	qsc_qmac_update(&ctx, msg2 + sizeof(uint8_t), 7U);
	qsc_qmac_update(&ctx, msg2 + 8U, sizeof(msg2) - 8U);
	qsc_qmac_finalize(&ctx, otp2);

	if (qsc_intutils_are_equal8(otp, otp2, sizeof(otp)) == false)
	{
		qsctest_print_safe("Failure! QMAC: Split updates do not match one-shot processing -PK4 \n");
		status = false;
	}

	qsc_qmac_compute(otp, &kp1, zmsg0, sizeof(zmsg0));
	qsc_qmac_compute(otp2, &kp1, zmsg1, sizeof(zmsg1));

	if (qsc_intutils_are_equal8(otp, otp2, sizeof(otp)) == true)
	{
		qsctest_print_safe("Failure! QMAC: Length-domain separation test failed -PK5 \n");
		status = false;
	}

	qsc_qmac_keyparams kp3 = { .key = key[3], .keylen = QSC_QMAC_KEY_SIZE, .nonce = nonce, .noncelen = sizeof(nonce) };

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_qmac_compute(otp, &kp3, msg3, sizeof(msg3));
	
	if (qsc_intutils_are_equal8(otp, exp[3], sizeof(otp)) == false)
	{
		qsctest_print_safe("Failure! QMAC: Output does not match the known answer -PK6 \n");
		status = false;
	}

	return status;
}

void qsctest_qmac_run()
{
	if (qsctest_qmac_kat() == true)
	{
		qsctest_print_safe("Success! Passed the QMAC KAT tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the QMAC KAT tests. \n");
	}
}
