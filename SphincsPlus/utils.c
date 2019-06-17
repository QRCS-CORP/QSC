#include <string.h>
#include <stdlib.h>
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "thash.h"
#include "address.h"

void ull_to_bytes(uint8_t* out, size_t outlen, uint64_t in)
{
	do
	{
		--outlen;
		out[outlen] = in & 0xFF;
		in = in >> 8;
	} 
	while (outlen != 0);
}

uint64_t bytes_to_ull(const uint8_t* in, size_t inlen)
{
	uint64_t ret;
	size_t i;

	ret = 0;

	for (i = 0; i < inlen; ++i)
	{
		ret |= ((uint64_t)in[i]) << (8 * (inlen - 1 - i));
	}

	return ret;
}

void compute_root(uint8_t* root, const uint8_t* leaf, uint32_t leaf_idx, uint32_t idx_offset,
	const uint8_t* auth_path, uint32_t tree_height, const uint8_t* pub_seed, uint32_t addr[8])
{
	uint32_t i;
	uint8_t buffer[2 * SPX_N];

	/* If leaf_idx is odd (last bit = 1), current path element is a right child
	   and auth_path has to go left. Otherwise it is the other way around. */
	if (leaf_idx & 1)
	{
		memcpy(buffer + SPX_N, leaf, SPX_N);
		memcpy(buffer, auth_path, SPX_N);
	}
	else
	{
		memcpy(buffer, leaf, SPX_N);
		memcpy(buffer + SPX_N, auth_path, SPX_N);
	}

	auth_path += SPX_N;

	for (i = 0; i < tree_height - 1; ++i)
	{
		leaf_idx >>= 1;
		idx_offset >>= 1;
		/* Set the address of the node we're creating. */
		set_tree_height(addr, i + 1);
		set_tree_index(addr, leaf_idx + idx_offset);

		/* Pick the right or left neighbor, depending on parity of the node. */
		if (leaf_idx & 1)
		{
			thash(buffer + SPX_N, buffer, 2, pub_seed, addr);
			memcpy(buffer, auth_path, SPX_N);
		}
		else
		{
			thash(buffer, buffer, 2, pub_seed, addr);
			memcpy(buffer + SPX_N, auth_path, SPX_N);
		}

		auth_path += SPX_N;
	}

	/* The last iteration is exceptional; we do not copy an auth_path node. */
	leaf_idx >>= 1;
	idx_offset >>= 1;
	set_tree_height(addr, tree_height);
	set_tree_index(addr, leaf_idx + idx_offset);
	thash(root, buffer, 2, pub_seed, addr);
}

void treehash(uint8_t* root, uint8_t* auth_path, const uint8_t* sk_seed, const uint8_t* pub_seed, uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
	void (*gen_leaf)(
		uint8_t*,
		const uint8_t*,
		const uint8_t*,
		uint32_t,
		const uint32_t[8]),
	uint32_t tree_addr[8])
{
	uint8_t* stack = (uint8_t*)malloc(((size_t)tree_height + 1) * SPX_N);
	uint8_t* heights = (uint8_t*)malloc((size_t)tree_height + 1);
	size_t offset;
	uint32_t idx;
	uint32_t tree_idx;

	assert(stack != NULL && heights != NULL);

	offset = 0;

	if (stack != NULL && heights != NULL)
	{
		for (idx = 0; idx < (1UL << tree_height); ++idx)
		{
			/* Add the next leaf node to the stack. */
			gen_leaf(stack + (offset * SPX_N), sk_seed, pub_seed, idx + idx_offset, tree_addr);
			++offset;
			heights[offset - 1] = 0;

			/* If this is a node we need for the auth path.. */
			if ((leaf_idx ^ 0x01) == idx)
			{
				memcpy(auth_path, stack + (offset - 1) * SPX_N, SPX_N);
			}

			/* While the top-most nodes are of equal height.. */
			while (offset >= 2 && heights[offset - 1] == heights[offset - 2])
			{
				/* Compute index of the new node, in the next layer. */
				tree_idx = (idx >> (heights[offset - 1] + 1));

				/* Set the address of the node we're creating. */
				set_tree_height(tree_addr, heights[offset - 1] + 1);
				set_tree_index(tree_addr, tree_idx + (idx_offset >> (heights[offset - 1] + 1)));
				/* Hash the top-most nodes from the stack together. */
				thash(stack + (offset - 2) * SPX_N, stack + (offset - 2) * SPX_N, 2, pub_seed, tree_addr);
				--offset;
				/* Note that the top-most node is now one layer higher. */
				++heights[offset - 1];

				/* If this is a node we need for the auth path.. */
				if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx)
				{
					memcpy(auth_path + ((size_t)heights[offset - 1] * SPX_N), stack + (offset - 1) * SPX_N, SPX_N);
				}
			}
		}

		memcpy(root, stack, SPX_N);
		free(stack);
		free(heights);
	}
}
