#include "fors.h"
#include "address.h"
#include "hash.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>

static void fors_gen_sk(uint8_t* sk, const uint8_t* sk_seed, uint32_t fors_leaf_addr[8])
{
	prf_addr(sk, sk_seed, fors_leaf_addr);
}

static void fors_sk_to_leaf(uint8_t* leaf, const uint8_t* sk, const uint8_t* pub_seed, uint32_t fors_leaf_addr[8])
{
	thash(leaf, sk, 1, pub_seed, fors_leaf_addr);
}

static void fors_gen_leaf(uint8_t* leaf, const uint8_t* sk_seed, const uint8_t* pub_seed, uint32_t addr_idx, const uint32_t fors_tree_addr[8])
{
	uint32_t fors_leaf_addr[8] = { 0 };

	/* Only copy the parts that must be kept in fors_leaf_addr. */
	copy_keypair_addr(fors_leaf_addr, fors_tree_addr);
	set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
	set_tree_index(fors_leaf_addr, addr_idx);

	fors_gen_sk(leaf, sk_seed, fors_leaf_addr);
	fors_sk_to_leaf(leaf, leaf, pub_seed, fors_leaf_addr);
}

static void message_to_indices(uint32_t* indices, const uint8_t* m)
{
	/* Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
	 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
	 * Assumes indices has space for SPX_FORS_TREES integers. */

	size_t i;
	size_t j;
	uint32_t offset;

	offset = 0;

	for (i = 0; i < SPX_FORS_TREES; ++i)
	{
		indices[i] = 0;

		for (j = 0; j < SPX_FORS_HEIGHT; ++j)
		{
			indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 0x01) << j;
			offset++;
		}
	}
}

void fors_sign(uint8_t* sig, uint8_t* pk, const uint8_t* m, const uint8_t* sk_seed, const uint8_t* pub_seed, const uint32_t fors_addr[8])
{
	uint32_t fors_tree_addr[8] = { 0 };
	uint32_t fors_pk_addr[8] = { 0 };
	uint32_t indices[SPX_FORS_TREES];
	uint8_t roots[SPX_FORS_TREES * SPX_N];
	uint32_t idx_offset;
	size_t i;

	copy_keypair_addr(fors_tree_addr, fors_addr);
	copy_keypair_addr(fors_pk_addr, fors_addr);

	set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
	set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

	message_to_indices(indices, m);

	for (i = 0; i < SPX_FORS_TREES; ++i)
	{
		idx_offset = (uint32_t)i * (1 << SPX_FORS_HEIGHT);

		set_tree_height(fors_tree_addr, 0);
		set_tree_index(fors_tree_addr, indices[i] + idx_offset);

		/* Include the secret key part that produces the selected leaf node. */
		fors_gen_sk(sig, sk_seed, fors_tree_addr);
		sig += SPX_N;

		/* Compute the authentication path for this leaf node. */
		treehash(roots + (i * SPX_N), sig, sk_seed, pub_seed, indices[i], idx_offset, SPX_FORS_HEIGHT, fors_gen_leaf, fors_tree_addr);
		sig += SPX_N * SPX_FORS_HEIGHT;
	}

	/* Hash horizontally across all tree roots to derive the public key. */
	thash(pk, roots, SPX_FORS_TREES, pub_seed, fors_pk_addr);
}

void fors_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* m, const uint8_t* pub_seed, const uint32_t fors_addr[8])
{
	uint32_t indices[SPX_FORS_TREES];
	uint8_t roots[SPX_FORS_TREES * SPX_N];
	uint8_t leaf[SPX_N];
	uint32_t fors_tree_addr[8] = { 0 };
	uint32_t fors_pk_addr[8] = { 0 };
	uint32_t idx_offset;
	size_t i;

	copy_keypair_addr(fors_tree_addr, fors_addr);
	copy_keypair_addr(fors_pk_addr, fors_addr);

	set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
	set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

	message_to_indices(indices, m);

	for (i = 0; i < SPX_FORS_TREES; ++i)
	{
		idx_offset = (uint32_t)i * (1 << SPX_FORS_HEIGHT);

		set_tree_height(fors_tree_addr, 0);
		set_tree_index(fors_tree_addr, indices[i] + idx_offset);

		/* Derive the leaf from the included secret key part. */
		fors_sk_to_leaf(leaf, sig, pub_seed, fors_tree_addr);
		sig += SPX_N;

		/* Derive the corresponding root node of this tree. */
		compute_root(roots + (i * SPX_N), leaf, indices[i], idx_offset, sig, SPX_FORS_HEIGHT, pub_seed, fors_tree_addr);
		sig += SPX_N * SPX_FORS_HEIGHT;
	}

	/* Hash horizontally across all tree roots to derive the public key. */
	thash(pk, roots, SPX_FORS_TREES, pub_seed, fors_pk_addr);
}
