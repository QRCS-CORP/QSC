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

/**
* \brief Run the SHA3, SHAKE, and simple cSHAKE KAT tests
*/
void sha3_test_run()
{
	if (sha3_256_kat_test() == SHA3_STATUS_SUCCESS)
	{
		printf("Success! passed sha3-256 known answer tests \n");
	}
	else
	{
		printf("Failure! failed sha3-256 known answer tests \n");
	}

	if (sha3_512_kat_test() == SHA3_STATUS_SUCCESS)
	{
		printf("Success! passed sha3-512 known answer tests \n");
	}
	else
	{
		printf("Failure! failed sha3-512 known answer tests \n");
	}

	if (shake_128_kat_test() == SHA3_STATUS_SUCCESS)
	{
		printf("Success! passed shake-128 known answer tests \n");
	}
	else
	{
		printf("Failure! failed shake-128 known answer tests \n");
	}

	if (shake_256_kat_test() == SHA3_STATUS_SUCCESS)
	{
		printf("Success! passed shake-256 known answer tests \n");
	}
	else
	{
		printf("Failure! failed shake-256 known answer tests \n");
	}

	if (cshake_simple_128_kat_test() == SHA3_STATUS_SUCCESS)
	{
		printf("Success! passed simple cshake-128 known answer tests \n");
	}
	else
	{
		printf("Failure! failed simple cshake-128 known answer tests \n");
	}

	if (cshake_simple_256_kat_test() == SHA3_STATUS_SUCCESS)
	{
		printf("Success! passed simple cshake-256 simple known answer tests \n");
	}
	else
	{
		printf("Failure! failed simple cshake-256 simple known answer tests \n");
	}
}

int main()
{
	printf("*** Testing SHA3 digests, SHAKE, and cSHAKE implementations *** \n");
	sha3_test_run();

	printf("\n");
	printf("Completed! Press any key to close..");
	get_response();

    return 0;
}

