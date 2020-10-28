#include "sha2_test.h"
#include "testutils.h"
#include "../QSC/intutils.h"
#include "../QSC/sha2.h"
#include <stdio.h>

bool qsctest_hkdf_256_kat() 
{
	uint8_t exp0[42] = { 0 };
	uint8_t exp1[82] = { 0 };
	uint8_t inf0[10] = { 0 };
	uint8_t inf1[80] = { 0 };
	uint8_t key0[22] = { 0 };
	uint8_t key1[80] = { 0 };
	uint8_t otp0[42] = { 0 };
	uint8_t otp1[82] = { 0 };
	bool status;

	qsctest_hex_to_bin("D03C9AB82C884B1DCFD3F4CFFD0E4AD1501915E5D72DF0E6D846D59F6CF78047"
		"39958B5DF06BDE49DB6D", exp0, sizeof(exp0));
	qsctest_hex_to_bin("24B29E50BD5B2968A8FC1B030B52A07B3B87C45603AAA046D649CD3CAAE06D5C"
		"B029960513275DF28548068821DF861904F0C095D063097A61EF571687217603"
				"E7D7673A7F98AEC538879E81E80864A91BCC", exp1, sizeof(exp1));
	qsctest_hex_to_bin("F0F1F2F3F4F5F6F7F8F9", inf0, sizeof(inf0));
	qsctest_hex_to_bin("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
		"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
				"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", inf1, sizeof(inf1));
	qsctest_hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F", key1, sizeof(key1));

	status = true;

	/* test compact api */

	qsc_hkdf256_expand(otp0, sizeof(otp0), key0, sizeof(key0), inf0, sizeof(inf0));

	if (qsc_intutils_are_equal8(otp0, exp0, sizeof(otp0)) != true)
	{
		qsctest_print_safe("Failure! hkdf_256_kat: output does not match the known answer -HK1 \n");
		status = false;
	}

	qsc_hkdf256_expand(otp1, sizeof(otp1), key1, sizeof(key1), inf1, sizeof(inf1));

	if (qsc_intutils_are_equal8(otp1, exp1, sizeof(otp1)) != true)
	{
		qsctest_print_safe("Failure! hkdf_256_kat: output does not match the known answer -HK2 \n");
		status = false;
	}

	return status;
}

bool qsctest_hkdf_512_kat()
{
	uint8_t exp0[42] = { 0 };
	uint8_t exp1[82] = { 0 };
	uint8_t inf0[10] = { 0 };
	uint8_t inf1[80] = { 0 };
	uint8_t key0[22] = { 0 };
	uint8_t key1[80] = { 0 };
	uint8_t otp0[42] = { 0 };
	uint8_t otp1[82] = { 0 };
	bool status;

	qsctest_hex_to_bin("7CE212EEB2A92270C4460A4728944B9B0EE9E060DE13C197853D37A20CE7184F"
		"94390EAEA4C18CEF989D", exp0, sizeof(exp0));
	qsctest_hex_to_bin("C66BAAA5CFB588D3B99CCC193005CD39C7CBAB0E6682F95E4E7D8B5A92EE3031"
		"6D59BC93F6E2BAC696A05BF448E2C088632691CC9CD3B238042FE564439B9074"
		"5DD4E27DC0E6D779129657F3CF424CA207F3", exp1, sizeof(exp1));
	qsctest_hex_to_bin("F0F1F2F3F4F5F6F7F8F9", inf0, sizeof(inf0));
	qsctest_hex_to_bin("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
		"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", inf1, sizeof(inf1));
	qsctest_hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F", key1, sizeof(key1));

	status = true;

	/* test compact api */

	qsc_hkdf512_expand(otp0, sizeof(otp0), key0, sizeof(key0), inf0, sizeof(inf0));

	if (qsc_intutils_are_equal8(otp0, exp0, sizeof(otp0)) != true)
	{
		qsctest_print_safe("Failure! hkdf_512_kat: output does not match the known answer -HK1 \n");
		status = false;
	}

	qsc_hkdf512_expand(otp1, sizeof(otp1), key1, sizeof(key1), inf1, sizeof(inf1));

	if (qsc_intutils_are_equal8(otp1, exp1, sizeof(otp1)) != true)
	{
		qsctest_print_safe("Failure! hkdf_512_kat: output does not match the known answer -HK2 \n");
		status = false;
	}

	return status;
}

bool qsctest_hmac_256_kat()
{
	uint8_t exp0[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp1[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp2[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp3[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp4[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t key0[20] = { 0 };
	uint8_t key1[20] = { 0 };
	uint8_t key2[25] = { 0 };
	uint8_t key3[131] = { 0 };
	uint8_t key4[131] = { 0 };
	uint8_t msg0[8] = { 0 };
	uint8_t msg1[50] = { 0 };
	uint8_t msg2[50] = { 0 };
	uint8_t msg3[54] = { 0 };
	uint8_t msg4[152] = { 0 };
	uint8_t otp[QSC_HMAC_256_MAC_SIZE] = { 0 };
	qsc_hmac256_state state;
	bool status;

	qsctest_hex_to_bin("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7", exp0, sizeof(exp0));
	qsctest_hex_to_bin("773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE", exp1, sizeof(exp1));
	qsctest_hex_to_bin("82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B", exp2, sizeof(exp2));
	qsctest_hex_to_bin("60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54", exp3, sizeof(exp3));
	qsctest_hex_to_bin("9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713938A7F51535C3A35E2", exp4, sizeof(exp4));

	qsctest_hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	qsctest_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key1, sizeof(key1));
	qsctest_hex_to_bin("0102030405060708090A0B0C0D0E0F10111213141516171819", key2, sizeof(key2));
	qsctest_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAA", key3, sizeof(key3));
	qsctest_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAA", key4, sizeof(key4));

	qsctest_hex_to_bin("4869205468657265", msg0, sizeof(msg0));
	qsctest_hex_to_bin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", msg1, sizeof(msg1));
	qsctest_hex_to_bin("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD", msg2, sizeof(msg2));
	qsctest_hex_to_bin("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374", msg3, sizeof(msg3));
	qsctest_hex_to_bin("5468697320697320612074657374207573696E672061206C6172676572207468616E20626C6F636B2D73697A65206B657920616E642061206C61726765722074"
				"68616E20626C6F636B2D73697A6520646174612E20546865206B6579206E6565647320746F20626520686173686564206265666F7265206265696E6720757365"
				"642062792074686520484D414320616C676F726974686D2E", msg4, sizeof(msg4));

	status = true;

	/* test compact api */

	qsc_hmac256_compute(otp, msg0, sizeof(msg0), key0, sizeof(key0));

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsctest_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK1 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_compute(otp, msg1, sizeof(msg1), key1, sizeof(key1));

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsctest_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK2 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_compute(otp, msg2, sizeof(msg2), key2, sizeof(key2));

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsctest_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK3 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_compute(otp, msg3, sizeof(msg3), key3, sizeof(key3));

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsctest_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK4 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_compute(otp, msg4, sizeof(msg4), key4, sizeof(key4));

	if (qsc_intutils_are_equal8(otp, exp4, sizeof(exp4)) != true)
	{
		qsctest_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK5 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_initialize(&state, key0, sizeof(key0));
	qsc_hmac256_update(&state, msg0, sizeof(msg0));
	qsc_hmac256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsctest_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK6 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_initialize(&state, key1, sizeof(key1));
	qsc_hmac256_update(&state, msg1, sizeof(msg1));
	qsc_hmac256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsctest_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK7 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_initialize(&state, key2, sizeof(key2));
	qsc_hmac256_update(&state, msg2, sizeof(msg2));
	qsc_hmac256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsctest_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK8 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_initialize(&state, key3, sizeof(key3));
	qsc_hmac256_update(&state, msg3, sizeof(msg3));
	qsc_hmac256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsctest_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK9 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_initialize(&state, key4, sizeof(key4));
	qsc_hmac256_update(&state, msg4, sizeof(msg4));
	qsc_hmac256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp4, sizeof(exp4)) != true)
	{
		qsctest_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK10 \n");
		status = false;
	}

	return status;
}

bool qsctest_hmac_512_kat()
{
	uint8_t exp0[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp1[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp2[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp3[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp4[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t key0[20] = { 0 };
	uint8_t key1[20] = { 0 };
	uint8_t key2[25] = { 0 };
	uint8_t key3[131] = { 0 };
	uint8_t key4[131] = { 0 };
	uint8_t msg0[8] = { 0 };
	uint8_t msg1[50] = { 0 };
	uint8_t msg2[50] = { 0 };
	uint8_t msg3[54] = { 0 };
	uint8_t msg4[152] = { 0 };
	uint8_t otp[QSC_HMAC_512_MAC_SIZE] = { 0 };
	qsc_hmac512_state state;
	bool status;

	qsctest_hex_to_bin("87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854", exp0, sizeof(exp0));
	qsctest_hex_to_bin("FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B2279D39BF3E848279A722C806B485A47E67C807B946A337BEE8942674278859E13292FB", exp1, sizeof(exp1));
	qsctest_hex_to_bin("B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DBA91CA5C11AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB10A298DD", exp2, sizeof(exp2));
	qsctest_hex_to_bin("80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F3526B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598", exp3, sizeof(exp3));
	qsctest_hex_to_bin("E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289865DF5A32D20CDC944B6022CAC3C4982B10D5EEB55C3E4DE15134676FB6DE0446065C97440FA8C6A58", exp4, sizeof(exp4));

	qsctest_hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	qsctest_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key1, sizeof(key1));
	qsctest_hex_to_bin("0102030405060708090A0B0C0D0E0F10111213141516171819", key2, sizeof(key2));
	qsctest_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key3, sizeof(key3));
	qsctest_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key4, sizeof(key4));

	qsctest_hex_to_bin("4869205468657265", msg0, sizeof(msg0));
	qsctest_hex_to_bin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", msg1, sizeof(msg1));
	qsctest_hex_to_bin("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD", msg2, sizeof(msg2));
	qsctest_hex_to_bin("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374", msg3, sizeof(msg3));
	qsctest_hex_to_bin("5468697320697320612074657374207573696E672061206C6172676572207468616E20626C6F636B2D73697A65206B657920616E642061206C61726765722074"
		"68616E20626C6F636B2D73697A6520646174612E20546865206B6579206E6565647320746F20626520686173686564206265666F7265206265696E6720757365"
		"642062792074686520484D414320616C676F726974686D2E", msg4, sizeof(msg4));

	status = true;

	/* test compact api */

	qsc_hmac512_compute(otp, msg0, sizeof(msg0), key0, sizeof(key0));

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsctest_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK1 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_compute(otp, msg1, sizeof(msg1), key1, sizeof(key1));

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsctest_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK2 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_compute(otp, msg2, sizeof(msg2), key2, sizeof(key2));

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsctest_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK3 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_compute(otp, msg3, sizeof(msg3), key3, sizeof(key3));

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsctest_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK4 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_compute(otp, msg4, sizeof(msg4), key4, sizeof(key4));

	if (qsc_intutils_are_equal8(otp, exp4, sizeof(exp4)) != true)
	{
		qsctest_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK5 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_initialize(&state, key0, sizeof(key0));
	qsc_hmac512_update(&state, msg0, sizeof(msg0));
	qsc_hmac512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsctest_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK6 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_initialize(&state, key1, sizeof(key1));
	qsc_hmac512_update(&state, msg1, sizeof(msg1));
	qsc_hmac512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsctest_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK7 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_initialize(&state, key2, sizeof(key2));
	qsc_hmac512_update(&state, msg2, sizeof(msg2));
	qsc_hmac512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsctest_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK8 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_initialize(&state, key3, sizeof(key3));
	qsc_hmac512_update(&state, msg3, sizeof(msg3));
	qsc_hmac512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsctest_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK9 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_initialize(&state, key4, sizeof(key4));
	qsc_hmac512_update(&state, msg4, sizeof(msg4));
	qsc_hmac512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp4, sizeof(exp4)) != true)
	{
		qsctest_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK10 \n");
		status = false;
	}

	return status;
}

bool qsctest_sha2_256_kat()
{
	uint8_t exp0[QSC_SHA2_256_HASH_SIZE] = { 0 };
	uint8_t exp1[QSC_SHA2_256_HASH_SIZE] = { 0 };
	uint8_t exp2[QSC_SHA2_256_HASH_SIZE] = { 0 };
	uint8_t exp3[QSC_SHA2_256_HASH_SIZE] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1[3] = { 0 };
	uint8_t msg2[56] = { 0 };
	uint8_t msg3[112] = { 0 };
	uint8_t otp[QSC_SHA2_256_HASH_SIZE] = { 0 };
	qsc_sha256_state state;
	bool status;

	qsctest_hex_to_bin("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", exp0, sizeof(exp0));
	qsctest_hex_to_bin("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", exp1, sizeof(exp1));
	qsctest_hex_to_bin("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1", exp2, sizeof(exp2));
	qsctest_hex_to_bin("CF5B16A778AF8380036CE59E7B0492370B249B11E8F07A51AFAC45037AFEE9D1", exp3, sizeof(exp3));

	qsctest_hex_to_bin("00", msg0, sizeof(msg0));
	qsctest_hex_to_bin("616263", msg1, sizeof(msg1));
	qsctest_hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg2, sizeof(msg2));
	qsctest_hex_to_bin("61626364656667686263646566676869636465666768696A6465666768696A6B"
		"65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
		"696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
		"6D6E6F70717273746E6F707172737475", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	qsc_sha256_compute(otp, msg0, 0);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsctest_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK1 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_compute(otp, msg1, sizeof(msg1));

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsctest_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK2 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_compute(otp, msg2, sizeof(msg2));

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsctest_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK3 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_compute(otp, msg3, sizeof(msg3));

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsctest_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK4 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(otp, sizeof(otp));

	qsc_sha256_initialize(&state);
	qsc_sha256_update(&state, msg0, 0);
	qsc_sha256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsctest_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK5 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_initialize(&state);
	qsc_sha256_update(&state, msg1, sizeof(msg1));
	qsc_sha256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsctest_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK6 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_initialize(&state);
	qsc_sha256_update(&state, msg2, sizeof(msg2));
	qsc_sha256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsctest_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK7 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_initialize(&state);

	/* absorb a the message */
	qsc_sha256_update(&state, msg3, sizeof(msg3));

	/* finalize the hash */
	qsc_sha256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp3, QSC_SHA2_256_HASH_SIZE) != true)
	{
		qsctest_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK8 \n");
		status = false;
	}

	return status;
}

bool qsctest_sha2_512_kat()
{
	uint8_t exp0[QSC_SHA2_512_HASH_SIZE] = { 0 };
	uint8_t exp1[QSC_SHA2_512_HASH_SIZE] = { 0 };
	uint8_t exp2[QSC_SHA2_512_HASH_SIZE] = { 0 };
	uint8_t exp3[QSC_SHA2_512_HASH_SIZE] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1[3] = { 0 };
	uint8_t msg2[56] = { 0 };
	uint8_t msg3[112] = { 0 };
	uint8_t otp[QSC_SHA2_512_HASH_SIZE] = { 0 };
	qsc_sha512_state state;
	bool status;

	qsctest_hex_to_bin("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE"
		"47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E", exp0, sizeof(exp0));
	qsctest_hex_to_bin("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A"
		"2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F", exp1, sizeof(exp1));
	qsctest_hex_to_bin("204A8FC6DDA82F0A0CED7BEB8E08A41657C16EF468B228A8279BE331A703C335"
		"96FD15C13B1B07F9AA1D3BEA57789CA031AD85C7A71DD70354EC631238CA3445", exp2, sizeof(exp2));
	qsctest_hex_to_bin("8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018"
		"501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909", exp3, sizeof(exp3));

	qsctest_hex_to_bin("00", msg0, sizeof(msg0));
	qsctest_hex_to_bin("616263", msg1, sizeof(msg1));
	qsctest_hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg2, sizeof(msg2));
	qsctest_hex_to_bin("61626364656667686263646566676869636465666768696A6465666768696A6B"
		"65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
		"696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
		"6D6E6F70717273746E6F707172737475", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	qsc_sha512_compute(otp, msg0, 0);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsctest_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK1 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_compute(otp, msg1, sizeof(msg1));

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsctest_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK2 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_compute(otp, msg2, sizeof(msg2));

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsctest_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK3 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_compute(otp, msg3, sizeof(msg3));

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsctest_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK4 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_initialize(&state);
	qsc_sha512_update(&state, msg0, 0);
	qsc_sha512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsctest_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK5 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_initialize(&state); 
	qsc_sha512_update(&state, msg1, sizeof(msg1));
	qsc_sha512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsctest_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK6 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_initialize(&state);
	qsc_sha512_update(&state, msg2, sizeof(msg2));
	qsc_sha512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsctest_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK7 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_initialize(&state);
	qsc_sha512_update(&state, msg3, sizeof(msg3));
	qsc_sha512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsctest_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK8 \n");
		status = false;
	}

	return status;
}

void qsctest_sha2_run()
{
	if (qsctest_sha2_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the SHA2-256 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHA2-256 KAT test. \n");
	}

	if (qsctest_sha2_512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the SHA2-512 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHA2-512 KAT test. \n");
	}

	if (qsctest_hkdf_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the HKDF-Expand(HMAC(SHA2-256)) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the HKDF-Expand(HMAC(SHA2-256)) KAT test. \n");
	}

	if (qsctest_hkdf_512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the HKDF-Expand(HMAC(SHA2-512)) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the HKDF-Expand(HMAC(SHA2-512)) test. \n");
	}

	if (qsctest_hmac_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the HMAC(SHA2-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the HMAC(SHA2-256) KAT test. \n");
	}

	if (qsctest_hmac_512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the HMAC(SHA2-512) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the HMAC(SHA2-512) KAT test. \n");
	}
}