#include "common.h"
#include "hash.h"
#include "haddress.h"
#include "params.h"
#include "utils.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(uint8_t* output, uint32_t outlen, uint64_t input)
{
    int32_t i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = outlen - 1; i >= 0; i--) 
	{
		output[i] = input & 0xFF;
		input = input >> 8;
    }
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
uint64_t bytes_to_ull(const uint8_t* in, uint32_t len)
{
    size_t i;
    uint64_t val;

	val = 0;

    for (i = 0; i < len; i++) 
	{
		val |= ((uint64_t)in[i]) << (8 * (len - 1 - i));
    }

    return val;
}

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
void compute_root(uint8_t* root, const uint8_t* leaf, uint32_t leafidx, uint32_t idxoffset, const uint8_t* authpath, uint32_t treeheight, const uint8_t* pkseed, uint32_t addr[8])
{
    uint8_t buf1[2 * SPX_N];
	uint8_t buf2[SPX_N + SPX_ADDR_BYTES + 2 * SPX_N];
	uint8_t mask[2 * SPX_N];
    size_t i;

    /* If leafidx is odd (last bit = 1), current path element is a right child
       and authpath has to go left. Otherwise it is the other way around. */
    if (leafidx & 1) 
	{
        memcpy(buf1 + SPX_N, leaf, SPX_N);
        memcpy(buf1, authpath, SPX_N);
    }
    else 
	{
        memcpy(buf1, leaf, SPX_N);
        memcpy(buf1 + SPX_N, authpath, SPX_N);
    }

    authpath += SPX_N;

    for (i = 0; i < treeheight - 1; i++) 
	{
        leafidx >>= 1;
        idxoffset >>= 1;
        /* Set the address of the node we're creating. */
        set_tree_height(addr, i + 1);
        set_tree_index(addr, leafidx + idxoffset);

        /* Pick the right or left neighbor, depending on parity of the node. */

        if (leafidx & 1) 
		{
			thash(buf1 + SPX_N, buf1, 2, pkseed, addr, buf2, mask);
            memcpy(buf1, authpath, SPX_N);
        }
        else 
		{
			thash(buf1, buf1, 2, pkseed, addr, buf2, mask);
            memcpy(buf1 + SPX_N, authpath, SPX_N);
        }

        authpath += SPX_N;
    }

    /* The last iteration is exceptional; we do not copy an authpath node. */
    leafidx >>= 1;
    idxoffset >>= 1;
    set_tree_height(addr, treeheight);
    set_tree_index(addr, leafidx + idxoffset);
	thash(root, buf1, 2, pkseed, addr, buf2, mask);
}

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
void treehash(uint8_t* root, uint8_t* authpath, const uint8_t* skseed, const uint8_t* pkseed, uint32_t leafidx, uint32_t idxoffset, uint32_t treeheight,
	void(*gen_leaf)(uint8_t*, const uint8_t*, const uint8_t*, uint32_t, const uint32_t[8]),
	uint32_t treeaddr[8], uint8_t* stack, uint32_t* heights)
{
	uint8_t buf[SPX_N + SPX_ADDR_BYTES + 2 * SPX_N];
	uint8_t mask[2 * SPX_N];
	uint32_t offset;
	uint32_t idx;
	uint32_t tree_idx;

	offset = 0;

	for (idx = 0; idx < (uint32_t)(1 << treeheight); idx++)
	{
		/* Add the next leaf node to the stack. */
		gen_leaf(stack + (offset * SPX_N), skseed, pkseed, idx + idxoffset, treeaddr);
		offset++;
		heights[offset - 1] = 0;

		/* If this is a node we need for the auth path.. */
		if ((leafidx ^ 0x1) == idx)
		{
			memcpy(authpath, stack + ((offset - 1) * SPX_N), SPX_N);
		}

		/* While the top-most nodes are of equal height.. */
		while (offset >= 2 && heights[offset - 1] == heights[offset - 2])
		{
			/* Compute index of the new node, in the next layer. */
			tree_idx = (idx >> (heights[offset - 1] + 1));

			/* Set the address of the node we're creating. */
			set_tree_height(treeaddr, heights[offset - 1] + 1);
			set_tree_index(treeaddr, tree_idx + (idxoffset >> (heights[offset - 1] + 1)));
			/* Hash the top-most nodes from the stack together. */
			thash(stack + ((offset - 2) * SPX_N), stack + ((offset - 2) * SPX_N), 2, pkseed, treeaddr, buf, mask);
			offset--;
			/* Note that the top-most node is now one layer higher. */
			heights[offset - 1]++;

			/* If this is a node we need for the auth path.. */
			if (((leafidx >> heights[offset - 1]) ^ 0x1) == tree_idx)
			{
				memcpy(authpath + (heights[offset - 1] * SPX_N), stack + ((offset - 1) * SPX_N), SPX_N);
			}
		}
	}

	memcpy(root, stack, SPX_N);
}