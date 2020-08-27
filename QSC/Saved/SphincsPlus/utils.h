#ifndef QCX_SPX_UTILS_H
#define QCX_SPX_UTILS_H

#include "common.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(uint8_t* out, size_t outlen, uint64_t in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
uint64_t bytes_to_ull(const uint8_t* in, size_t inlen);

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
void compute_root(uint8_t* root, const uint8_t* leaf, uint32_t leaf_idx, uint32_t idx_offset, const uint8_t* auth_path, 
	uint32_t tree_height, const uint8_t* pub_seed, uint32_t addr[8]);

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
void treehash(uint8_t* root, uint8_t* auth_path, const uint8_t* sk_seed, const uint8_t* pub_seed, uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
	void (*gen_leaf)(
		uint8_t*,			/* leaf */
		const uint8_t*,		/* sk_seed */
		const uint8_t*,		/* pub_seed */
		uint32_t, 			/* addr_idx */
		const uint32_t[8]),	/* tree_addr */
	uint32_t tree_addr[8]);

#endif
