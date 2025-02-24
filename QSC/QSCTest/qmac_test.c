#include "qmac_test.h"
#include "common.h"
#include "testutils.h"
#include "../QSC/intutils.h"
#include "../QSC/qmac.h"

bool qsctest_qmac_kat()
{
	uint8_t exp[6][QSC_QMAC_MAC_SIZE] = { 0 };
	uint8_t key[4][QSC_QMAC_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_QMAC_MAC_SIZE] = { 0 };
	uint8_t msg0[34];
	uint8_t msg1[30];
	uint8_t msg2[65];
	uint8_t msg3[64];
	uint8_t nonce[QSC_QMAC_NONCE_SIZE];
	bool status;

	status = true;

	qsctest_hex_to_bin("B5C75720CA4C30BC4CB1A7DB0E6A53BF565CF742CB4340FA3399C00C1E8B44CF", exp[0], sizeof(exp[0]));
	qsctest_hex_to_bin("63A590FC8BBD10A07793BACC6B76B289A2527C4B073B76AA1455ACAAD6257C31", exp[1], sizeof(exp[1]));
	qsctest_hex_to_bin("776DE965936ED950CC845BE013F54B83D8042CF58B7B815F94EF5195D8100EB4", exp[2], sizeof(exp[2]));
	qsctest_hex_to_bin("3F530334CBEBD167EFCCEEE8BB659BB0DD1E41F761517810D1C3ACAD3DA92E73", exp[3], sizeof(exp[3]));

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

	qsc_qmac_keyparams kp0 = { key[0], QSC_QMAC_KEY_SIZE, NULL, 0, NULL, 0 };
	
	qsc_qmac_compute(otp, &kp0, msg1, sizeof(msg1));

	if (qsc_intutils_are_equal8(otp, exp[0], sizeof(otp)) == false)
	{
		qsctest_print_safe("Failure! QMAC: Output does not match the known answer -PK0 \n");
		status = false;
	}

	qsc_qmac_keyparams kp1 = { key[1], QSC_QMAC_KEY_SIZE, NULL, 0, NULL, 0 };

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_qmac_compute(otp, &kp1, msg1, sizeof(msg1));

	if (qsc_intutils_are_equal8(otp, exp[1], sizeof(otp)) == false)
	{
		qsctest_print_safe("Failure! QMAC: Output does not match the known answer -PK1 \n");
		status = false;
	}

	qsc_qmac_keyparams kp2 = { key[2], QSC_QMAC_KEY_SIZE, NULL, 0, NULL, 0 };

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

	qsc_qmac_keyparams kp3 = { key[3], QSC_QMAC_KEY_SIZE, nonce, sizeof(nonce), NULL, 0 };

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_qmac_compute(otp, &kp3, msg3, sizeof(msg3));

	if (qsc_intutils_are_equal8(otp, exp[3], sizeof(otp)) == false)
	{
		qsctest_print_safe("Failure! QMAC: Output does not match the known answer -PK4 \n");
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
