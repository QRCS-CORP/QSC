#include "test_utils.h"
/* jgu -suppressing misra sdio header warning in example only */
/*lint -e829 */
#include <stdio.h>

void print_hex(const uint8_t* input, size_t inputlen, size_t linelen)
{
	size_t i;

	while (inputlen >= linelen)
	{
		for (i = 0; i < linelen; ++i)
		{
			printf("%02X", input[i]);
		}

		input += linelen;
		inputlen -= linelen;
		printf("\n");
	}

	if (inputlen != 0)
	{
		for (i = 0; i < inputlen; ++i)
		{
			printf("%02X", input[i]);
		}
	}
}
