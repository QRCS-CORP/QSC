#include "common.h"
#include "sphincstest.h"
#include "testutils.h"

int main()
{
	sphincs_test();

	printf_s("Completed! Press any key to close..");
	/* ignored return value alright for this call */
	/*lint -e534 */ 
	get_response();
	/*lint -restore */

	return 0;
}