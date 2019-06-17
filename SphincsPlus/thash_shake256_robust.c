#include "thash.h"
#include "address.h"
#include "params.h"
#include "sha3.h"
#include <string.h>
#include <stdlib.h>

void thash(uint8_t* out, const uint8_t* in, size_t inblocks, const uint8_t* pub_seed, uint32_t addr[8])
{
	uint8_t* buf = (uint8_t*)malloc((size_t)SPX_N + SPX_ADDR_BYTES + (inblocks * SPX_N));
	uint8_t* bitmask = (uint8_t*)malloc((size_t)inblocks * SPX_N);
	size_t i;

	assert(buf != NULL && bitmask != NULL);

	if (buf != NULL && bitmask != NULL)
	{
		memcpy(buf, pub_seed, SPX_N);
		addr_to_bytes(buf + SPX_N, addr);

		shake256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_ADDR_BYTES);

		for (i = 0; i < (inblocks * SPX_N); ++i)
		{
			buf[SPX_N + SPX_ADDR_BYTES + i] = (in[i] ^ bitmask[i]);
		}

		shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);

		free(buf);
		free(bitmask);
	}
}
