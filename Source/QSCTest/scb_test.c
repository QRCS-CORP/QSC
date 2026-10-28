#include "csx_test.h"
#include "scb.h"
#include "intutils.h"
#include "memutils.h"
#include "csp.h"
#include "testutils.h"

bool qsctest_scb_256_kat()
{
	uint8_t exp[32] = { 0 };
	uint8_t hash[32] = { 0 };
	uint8_t seed[QSC_SCB_256_SEED_SIZE] = { 0 };
	bool status;
	qsc_scb_state ctx = { 0 };

	qsctest_hex_to_bin("8DFD94A8F690DD9F7FA9818088050A256FD6B1DEE9F3AF7CC03993683D541824", exp, sizeof(exp));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", seed, sizeof(seed));

	status = true;

	/* initialize the state */
	qsc_scb_initialize(&ctx, seed, sizeof(seed), NULL, 0, 1, 1);

	/* generate the hash */
	qsc_scb_generate(&ctx, hash, sizeof(hash));

	if (qsc_intutils_are_equal8(hash, exp, sizeof(exp)) == false)
	{
		qsctest_print_safe("Failure! scb_256_kat: output does not match the expected answer -SK1 \n");
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_scb_dispose(&ctx);

	return status;
}

bool qsctest_scb_512_kat()
{
	uint8_t exp[64] = { 0 };
	uint8_t hash[64] = { 0 };
	uint8_t seed[QSC_SCB_512_SEED_SIZE] = { 0 };
	bool status;
	qsc_scb_state ctx = { 0 };

	qsctest_hex_to_bin("E035E46C1BE6C3BC4F91F2B4B983B191486884EB3EF65A501064FA4016E84E7E"
		"B7B5AB4BFF88589933377B43AAA2709F2D8491826FECC4DD79110275EF6863A6", exp, sizeof(exp));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"
		"101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F", seed, sizeof(seed));

	status = true;

	/* initialize the state */
	qsc_scb_initialize(&ctx, seed, sizeof(seed), NULL, 0, 1, 1);

	/* generate the hash */
	qsc_scb_generate(&ctx, hash, sizeof(hash));

	if (qsc_intutils_are_equal8(hash, exp, sizeof(exp)) == false)
	{
		qsctest_print_safe("Failure! scb_512_kat: output does not match the expected answer -SK2 \n");
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_scb_dispose(&ctx);

	return status;
}

void qsctest_scb_run()
{
	if (qsctest_scb_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the SCB-256 known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SCB-256 known answer tests. \n");
	}

	if (qsctest_scb_512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the SCB-512 known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SCB-512 known answer tests. \n");
	}
}
