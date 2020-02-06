/**
* \file sha3_test.c
* \brief <b>SHA3 test functions</b> \n
* Contains the SHA3 implementation wellness test functions.
*
* \author John Underhill
* \date January 06, 2018
*/

#include "sha3_kat.h"
#include <stdio.h>
#include <stdint.h>

/**
* \brief Get a char from console input.
* \return Returns one user input char
*/
char get_response()
{
	return getchar();
}


/* shake, cshake, kmac, and sha3 tests */

void test_cshake_kat()
{
	if (cshake_256_kat_test() == true)
	{
		printf_s("Success! Passed the cSHAKE-256 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the cSHAKE-256 KAT test. \n");
	}

	if (cshake_512_kat_test() == true)
	{
		printf_s("Success! Passed the cSHAKE-512 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the cSHAKE-512 KAT test. \n");
	}
}

void test_kmac_kat()
{
	if (kmac_128_kat_test() == true)
	{
		printf_s("Success! Passed the KMAC-128 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the KMAC-128 KAT test. \n");
	}

	if (kmac_256_kat_test() == true)
	{
		printf_s("Success! Passed the KMAC-256 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the KMAC-256 KAT test. \n");
	}

	if (kmac_512_kat_test() == true)
	{
		printf_s("Success! Passed the KMAC-512 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the KMAC-512 KAT test. \n");
	}
}

void test_sha3_kat()
{
	if (sha3_256_kat_test() == true)
	{
		printf_s("Success! Passed the SHA3-256 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the SHA3-256 KAT test. \n");
	}

	if (sha3_512_kat_test() == true)
	{
		printf_s("Success! Passed the SHA3-512 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the SHA3-512 KAT test. \n");
	}
}

void test_shake_kat()
{
	if (shake_256_kat_test() == true)
	{
		printf_s("Success! Passed the SHAKE-256 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the SHAKE-256 KAT test. \n");
	}

	if (shake_512_kat_test() == true)
	{
		printf_s("Success! Passed the SHAKE-512 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the SHAKE-512 KAT test. \n");
	}
}

int main()
{
	printf_s("*** Test SHAKE, cSHAKE, KMAC, and SHA3 implementations using the official KAT vetors. *** \n");
	test_shake_kat();
	test_cshake_kat();
	test_kmac_kat();
	test_sha3_kat();
	printf_s("\n");

	printf("\n");
	printf("Completed! Press any key to close..");
	get_response();

    return 0;
}

