#include "hash.h"
#include "address.h"
#include "utils.h"
#include "params.h"
#include "sha3.h"
#include <stdlib.h>
#include <string.h>

#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

void initialize_hash_function(const uint8_t* pub_seed, const uint8_t* sk_seed)
{
	(void)pub_seed; /* Suppress an 'unused parameter' warning. */
	(void)sk_seed;	/* Suppress an 'unused parameter' warning. */
}

void prf_addr(uint8_t* out, const uint8_t* key, const uint32_t addr[8])
{
	uint8_t buf[SPX_N + SPX_ADDR_BYTES];

	memcpy(buf, key, SPX_N);
	addr_to_bytes(buf + SPX_N, addr);

	shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES);
}


void gen_message_random(uint8_t* R, const uint8_t* sk_prf, const uint8_t* optrand, const uint8_t* m, size_t mlen)
{
	uint8_t* tmp = (uint8_t*)malloc((SPX_N * 2) + mlen);

	assert(tmp != NULL);

	if (tmp != NULL)
	{
		memcpy(tmp, sk_prf, SPX_N);
		memcpy(tmp + SPX_N, optrand, SPX_N);
		memcpy(tmp + (2 * SPX_N), m, mlen);
		shake256(R, SPX_N, tmp, SPX_N * 2 + mlen);
		free(tmp);
	}
}


void hash_message(uint8_t* digest, uint64_t* tree, uint32_t* leaf_idx, const uint8_t* R, const uint8_t* pk, const uint8_t* m, size_t mlen)
{
	uint8_t buf[SPX_DGST_BYTES];
	uint8_t* bufp = buf;
	uint8_t* tmp = (uint8_t*)malloc(SPX_N + SPX_PK_BYTES + mlen);

	assert(tmp != NULL);

	if (tmp != NULL)
	{
		memcpy(tmp, R, SPX_N);
		memcpy(tmp + SPX_N, pk, SPX_PK_BYTES);
		memcpy(tmp + SPX_N + SPX_PK_BYTES, m, mlen);
		shake256(buf, SPX_DGST_BYTES, tmp, SPX_N + SPX_PK_BYTES + mlen);
		free(tmp);

		memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
		bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
#error For given height and depth, 64 bits cannot represent all subtrees
#endif

		*tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
		*tree &= (~0ULL >> (64 - SPX_TREE_BITS));

		bufp += SPX_TREE_BYTES;
		*leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
		*leaf_idx &= (~0UL >> (32 - SPX_LEAF_BITS));
	}
}
