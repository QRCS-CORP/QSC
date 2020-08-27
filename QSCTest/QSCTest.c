#include "test_common.h"
#include "sha2_kat.h"

/**
* \brief Get a char from console input.
* \return Returns one user input char
*/
static void get_response()
{
	/*lint -e586 */
	wint_t rsp;

	rsp = getwchar();
}

/**
* \brief Run the Kyber implementation stress and correctness tests tests
*/
void sha2_test_run()
{
	if (sha2_256_kat_test() == true)
	{
		printf_s("Success! Passed SHA2-256 known answer test. \n");
	}
	else
	{
		printf_s("Failure! Failed SHA2-256 known answer test. \n \n");
	}

	if (sha2_384_kat_test() == true)
	{
		printf_s("Success! Passed SHA2-384 known answer test. \n");
	}
	else
	{
		printf_s("Failure! Failed SHA2-256 known answer test. \n \n");
	}

	if (sha2_512_kat_test() == true)
	{
		printf_s("Success! Passed SHA2-512 known answer test. \n");
	}
	else
	{
		printf_s("Failure! Failed SHA2-512 known answer test. \n \n");
	}
}

int main()
{
	printf_s("*** The SHA2 implementations stress and validity tests *** \n");
	printf_s("\n");
	sha2_test_run();
	printf_s("\n");

	printf_s("\n");
	printf_s("Completed! Press any key to close..");
	get_response();

	return 0;
}