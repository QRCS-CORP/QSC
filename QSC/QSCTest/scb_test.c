#include "csx_test.h"
#include "../QSC/scb.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/csp.h"
#include "testutils.h"

bool qsctest_scb_256_kat()
{
	uint8_t exp[QSC_SCB_256_HASH_SIZE] = { 0 };
	uint8_t hash[QSC_SCB_256_HASH_SIZE] = { 0 };
	uint8_t seed[QSC_SCB_256_SEED_SIZE] = { 0 };
	bool status;
	qsc_scb_state ctx = { 0 };

	qsctest_hex_to_bin("C17CECE6A67ACB2C058D5082EF6E64764442D79186AE18032A97A8B3546CE8EF", exp, sizeof(exp));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", seed, sizeof(seed));

	status = true;

	/* initialize the state */
	qsc_scb_initialize(&ctx, seed, sizeof(seed), NULL, 0, 10, 10);

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
	uint8_t exp[QSC_SCB_512_HASH_SIZE] = { 0 };
	uint8_t hash[64] = { 0 };
	uint8_t seed[QSC_SCB_512_HASH_SIZE] = { 0 };
	bool status;
	qsc_scb_state ctx = { 0 };

	qsctest_hex_to_bin("B369BD7A0AAADA4F14077C1269116194D164BB2085FF91919399FA14FE2E1C69"
		"083036973924A96FFA6A1B09294BC4C7BF79EB2C37391908C222FF6C2047F690", exp, sizeof(exp));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"
		"101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F", seed, sizeof(seed));

	status = true;

	/* initialize the state */
	qsc_scb_initialize(&ctx, seed, sizeof(seed), NULL, 0, 10, 10);

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
