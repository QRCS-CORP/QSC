#include "poly1305_test.h"
#include "common.h"
#include "testutils.h"
#include "../QSC/intutils.h"
#include "../QSC/poly1305.h"

bool qsctest_poly1305_kat()
{
	uint8_t exp[4][16] = { 0 };
	uint8_t key[4][32] = { 0 };
	uint8_t out[16] = { 0 };
	uint8_t msg1[34] = { 0 };
	uint8_t msg2[12] = { 0 };
	uint8_t msg3[64] = { 0 };
	uint8_t msg4[64] = { 0 };
	size_t i;
	bool status;

	status = true;

	qsctest_hex_to_bin("A8061DC1305136C6C22B8BAF0C0127A9", exp[0], sizeof(exp[0]));
	qsctest_hex_to_bin("A6F745008F81C916A20DCC74EEF2B2F0", exp[1], sizeof(exp[1]));
	qsctest_hex_to_bin("00000000000000000000000000000000", exp[2], sizeof(exp[2]));
	qsctest_hex_to_bin("36E5F6B5C5E06070F0EFCA96227A863E", exp[3], sizeof(exp[3]));

	qsctest_hex_to_bin("85D6BE7857556D337F4452FE42D506A80103808AFB0DB2FD4ABFF6AF4149F51B", key[0], sizeof(key[0]));
	qsctest_hex_to_bin("746869732069732033322D62797465206B657920666F7220506F6C7931333035", key[1], sizeof(key[1]));
	qsctest_hex_to_bin("0000000000000000000000000000000000000000000000000000000000000000", key[2], sizeof(key[2]));
	qsctest_hex_to_bin("0000000000000000000000000000000036E5F6B5C5E06070F0EFCA96227A863E", key[3], sizeof(key[3]));

	qsctest_hex_to_bin("43727970746F6772617068696320466F72756D2052657365617263682047726F7570", msg1, sizeof(msg1));
	qsctest_hex_to_bin("48656C6C6F20776F726C6421", msg2, sizeof(msg2));
	qsctest_hex_to_bin("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", msg3, sizeof(msg3));
	qsctest_hex_to_bin("416E79207375626D697373696F6E20746F20746865204945544620696E74656E6465642062792074686520436F6E7472696275746F7220666F72207075626C69", msg4, sizeof(msg4));

	/* compact api */

	qsc_intutils_clear8(out, 16);
	qsc_poly1305_compute(out, msg1, 34, key[0]);

	if (qsc_intutils_are_equal8(out, exp[0], 16) == false)
	{
		qsctest_print_safe("Failure! poly1305_kat: MAC output does not match the known answer -PK1 \n");
		status = false;
	}

	qsc_intutils_clear8(out, 16);
	qsc_poly1305_compute(out, msg2, 12, key[1]);

	if (qsc_intutils_are_equal8(out, exp[1], 16) == false)
	{
		qsctest_print_safe("Failure! poly1305_kat: MAC output does not match the known answer -PK2 \n");
		status = false;
	}

	qsc_intutils_clear8(out, 16);
	qsc_poly1305_compute(out, msg3, 34, key[2]);

	if (qsc_intutils_are_equal8(out, exp[2], 16) == false)
	{
		qsctest_print_safe("Failure! poly1305_kat: MAC output does not match the known answer -PK3 \n");
		status = false;
	}

	qsc_intutils_clear8(out, 16);
	qsc_poly1305_compute(out, msg4, 34, key[3]);

	if (qsc_intutils_are_equal8(out, exp[3], 16) == false)
	{
		qsctest_print_safe("Failure! poly1305_kat: MAC output does not match the known answer -PK4 \n");
		status = false;
	}

	/* long-form api */

	qsc_intutils_clear8(out, 16);
	qsc_poly1305_state ctx;

	qsc_poly1305_initialize(&ctx, key[0]);

	for (i = 0; i < 32; i += QSC_POLY1305_BLOCK_SIZE)
	{
		qsc_poly1305_blockupdate(&ctx, msg1 + i);
	}

	qsc_poly1305_update(&ctx, msg1 + i, 2);
	qsc_poly1305_finalize(&ctx, out);

	if (qsc_intutils_are_equal8(out, exp[0], 16) == false)
	{
		qsctest_print_safe("Failure! poly1305_kat: MAC output does not match the known answer -PK5 \n");
		status = false;
	}

	return status;
}

void qsctest_poly1305_run()
{
	if (qsctest_poly1305_kat() == true)
	{
		qsctest_print_safe("Success! Passed the Poly1305 KAT tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Poly1305 KAT tests. \n");
	}
}
