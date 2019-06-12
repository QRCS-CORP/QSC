#include "common.h"
#include "fors.h"
#include "hash.h"
#include "haddress.h"
#include "utils.h"

static void fors_gen_sk(uint8_t* secretkey, const uint8_t* secretseed, uint32_t* forsaddress)
{
    prf_addr(secretkey, secretseed, forsaddress);
}

static void fors_sk_to_leaf(uint8_t* leaf, const uint8_t* secretkey, const uint8_t* publicseed, uint32_t* leafaddress)
{
	uint8_t buf[SPX_N + SPX_ADDR_BYTES + 1 * SPX_N];
	uint8_t mask[1 * SPX_N];

	thash(leaf, secretkey, 1, publicseed, leafaddress, buf, mask);
}

static void fors_gen_leaf(uint8_t* leaf, const uint8_t* secretseed, const uint8_t* publicseed, uint32_t addressidx, const uint32_t* treeaddress)
{
    uint32_t leafaddress[8] = {0};

    /* Only copy the parts that must be kept in fors_leaf_addr. */
    copy_keypair_addr(leafaddress, treeaddress);
    set_type(leafaddress, SPX_ADDR_TYPE_FORSTREE);
    set_tree_index(leafaddress, addressidx);
    fors_gen_sk(leaf, secretseed, leafaddress);
    fors_sk_to_leaf(leaf, leaf, publicseed, leafaddress);
}

/**
 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 * Assumes indices has space for SPX_FORS_TREES integers.
 */
static void message_to_indices(uint32_t* indices, const uint8_t* messages)
{
    uint32_t offset;
	size_t i;
	size_t j;

	offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++)
	{
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) 
		{
            indices[i] <<= 1;
            indices[i] ^= (messages[offset >> 3] >> (offset & 0x7)) & 0x1;
            offset++;
        }
    }
}

void fors_sign(uint8_t* signature, uint8_t* publickey, const uint8_t* message, const uint8_t* skseed, const uint8_t* pkseed, const uint32_t* forsaddress)
{
    uint32_t forstreeaddr[8] = {0};
    uint32_t forspkaddr[8] = {0};
	uint32_t heights[SPX_FORS_HEIGHT + 1];
    uint32_t indices[SPX_FORS_TREES];
    uint8_t roots[SPX_FORS_TREES * SPX_N];
	uint8_t stack[(SPX_FORS_HEIGHT + 1) * SPX_N];
    uint32_t idxoffset;
    uint32_t i;

    copy_keypair_addr(forstreeaddr, forsaddress);
    copy_keypair_addr(forspkaddr, forsaddress);
    set_type(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
    set_type(forspkaddr, SPX_ADDR_TYPE_FORSPK);
    message_to_indices(indices, message);

    for (i = 0; i < SPX_FORS_TREES; i++) 
	{
		idxoffset = i * (1 << SPX_FORS_HEIGHT);
        set_tree_height(forstreeaddr, 0);
        set_tree_index(forstreeaddr, indices[i] + idxoffset);
        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk(signature, skseed, forstreeaddr);
		signature += SPX_N;
        /* Compute the authentication path for this leaf node. */
		treehash(roots + (i * SPX_N), signature, skseed, pkseed, indices[i], idxoffset, SPX_FORS_HEIGHT, fors_gen_leaf, forstreeaddr, stack, heights);
		signature += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
	uint8_t buf[SPX_N + SPX_ADDR_BYTES + SPX_FORS_TREES * SPX_N];
	uint8_t mask[SPX_FORS_TREES * SPX_N];
	thash(publickey, roots, SPX_FORS_TREES, pkseed, forspkaddr, buf, mask);
}

void fors_pk_from_sig(uint8_t* publickey, const uint8_t* signature, const uint8_t* m, const uint8_t* pub_seed, const uint32_t* forsaddress)
{
    uint32_t forstreeaddr[8] = {0};
    uint32_t forspkaddr[8] = {0};
    uint32_t indices[SPX_FORS_TREES];
    uint8_t leaf[SPX_N];
    uint8_t roots[SPX_FORS_TREES * SPX_N];
    uint32_t idxoffset;
    uint32_t i;

    copy_keypair_addr(forstreeaddr, forsaddress);
    copy_keypair_addr(forspkaddr, forsaddress);
    set_type(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
    set_type(forspkaddr, SPX_ADDR_TYPE_FORSPK);
    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) 
	{
		idxoffset = i * (1 << SPX_FORS_HEIGHT);
        set_tree_height(forstreeaddr, 0);
        set_tree_index(forstreeaddr, indices[i] + idxoffset);
        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf(leaf, signature, pub_seed, forstreeaddr);
		signature += SPX_N;
        /* Derive the corresponding root node of this tree. */
        compute_root(roots + (i * SPX_N), leaf, indices[i], idxoffset, signature, SPX_FORS_HEIGHT, pub_seed, forstreeaddr);
		signature += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
	uint8_t buf[SPX_N + SPX_ADDR_BYTES + SPX_FORS_TREES * SPX_N];
	uint8_t mask[SPX_FORS_TREES * SPX_N];
	thash(publickey, roots, SPX_FORS_TREES, pub_seed, forspkaddr, buf, mask);
}
