#include "csx_test.h"
#include "../QSC/scb.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/csp.h"
#include "testutils.h"

bool qsctest_scb_256_kat()
{
	uint8_t exp[32] = { 0 };
	uint8_t hash[32] = { 0 };
	uint8_t seed[QSC_SCB_256_SEED_SIZE] = { 0 };
	bool status;
	qsc_scb_state ctx = { 0 };

	qsctest_hex_to_bin("ED87E9E2D1788399839835CD12B90820A3ED02C9D770ABE1E3D8D38CEEB9E2C5", exp, sizeof(exp));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", seed, sizeof(seed));

	status = true;

	/* initialize the state */
	qsc_scb_initialize(&ctx, seed, sizeof(seed), NULL, 0, 1, 1);

	/* generate the hash */
	qsc_scb_generate(&ctx, hash, sizeof(hash));

	if (qsc_intutils_are_equal8(hash, exp, sizeof(exp)) == false)
	{
		qsctest_print_safe("Failure! scb_512_kat: output does not match the expected answer -SK1 \n");
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

	qsctest_hex_to_bin("273CD4A8634D25FE2F422E12ADEDCDE46FCA4936D46C4970F9EFEA7EE1835269"
		"75586C168E95D29203BD59007CC1DA59DEB168946EF6113EB8D3174BF2AB73CD", exp, sizeof(exp));
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
