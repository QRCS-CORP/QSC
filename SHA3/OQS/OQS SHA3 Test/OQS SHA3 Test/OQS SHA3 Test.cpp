/**
* \file sha3_test.c
* \brief <b>SHA3 test functions</b> \n
* Contains the SHA3 implementation wellness test functions.
*
* \author John Underhill
* \date January 10, 2018
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

int main()
{
	printf("*** Testing SHA3 digests, SHAKE, and cSHAKE implementations *** \n");
	sha3_test_run();

	printf("\n");
	printf("Completed! Press any key to close..");
	get_response();

	return 0;
}
