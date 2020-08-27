#include "sign.h"
#include "address.h"
#include "common.h"
#include "fors.h"
#include "hash.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"
#include <stddef.h>
#include <string.h>

static void wots_gen_leaf(uint8_t* leaf, const uint8_t* sk_seed, const uint8_t* pub_seed, uint32_t addr_idx, const uint32_t tree_addr[8])
{
	/* Computes the leaf at a given address. First generates the WOTS key pair, then computes leaf by hashing horizontally. */

	uint8_t pk[SPX_WOTS_BYTES];
	uint32_t wots_addr[8] = { 0 };
	uint32_t wots_pk_addr[8] = { 0 };

	set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
	set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

	copy_subtree_addr(wots_addr, tree_addr);
	set_keypair_addr(wots_addr, addr_idx);
	wots_gen_pk(pk, sk_seed, pub_seed, wots_addr);

	copy_keypair_addr(wots_pk_addr, wots_addr);
	thash(leaf, pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);
}

static void sphincsplus_sign_seed_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed)
{
	 /* We do not need the auth path in key generation, but it simplifies the
		code to have just one treehash routine that computes both root and path in one function. */
	uint8_t auth_path[SPX_TREE_HEIGHT * SPX_N];
	uint32_t top_tree_addr[8] = { 0 };

	set_layer_addr(top_tree_addr, SPX_D - 1);
	set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE);

	/* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
	memcpy(sk, seed, SPHINCSPLUS_SEED_SIZE);
	memcpy(pk, sk + (2 * SPX_N), SPX_N);

	/* This hook allows the hash function instantiation to do whatever
	   preparation or computation it needs, based on the public seed. */
	initialize_hash_function(pk, sk);

	/* Compute root node of the top-most subtree. */
	treehash(sk + (3 * SPX_N), auth_path, sk, sk + (2 * SPX_N), 0, 0, SPX_TREE_HEIGHT, wots_gen_leaf, top_tree_addr);
	memcpy(pk + SPX_N, sk + (3 * SPX_N), SPX_N);
}

static void sphincsplus_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk, void (*rng_generate)(uint8_t*, size_t))
{
	/* Returns an array containing a detached signature. */

	const uint8_t* sk_seed = sk;
	const uint8_t* sk_prf = sk + SPX_N;
	const uint8_t* pk = sk + 2 * SPX_N;
	const uint8_t* pub_seed = pk;

	uint8_t optrand[SPX_N];
	uint8_t mhash[SPX_FORS_MSG_BYTES];
	uint8_t root[SPX_N];
	size_t i;
	uint64_t tree;
	uint32_t idx_leaf;
	uint32_t wots_addr[8] = { 0 };
	uint32_t tree_addr[8] = { 0 };

	/* This hook allows the hash function instantiation to do whatever
	   preparation or computation it needs, based on the public seed. */
	initialize_hash_function(pub_seed, sk_seed);

	set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
	set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

	/* Optionally, signing can be made non-deterministic using optrand.
	   This can help counter side-channel attacks that would benefit from
	   getting a large number of traces when the signer uses the same nodes. */
	rng_generate(optrand, SPX_N);

	/* Compute the digest randomization value. */
	gen_message_random(sig, sk_prf, optrand, m, mlen);

	/* Derive the message digest and leaf index from R, PK and M. */
	hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen);
	sig += SPX_N;

	set_tree_addr(wots_addr, tree);
	set_keypair_addr(wots_addr, idx_leaf);

	/* Sign the message hash using FORS. */
	fors_sign(sig, root, mhash, sk_seed, pub_seed, wots_addr);
	sig += SPX_FORS_BYTES;

	for (i = 0; i < SPX_D; i++)
	{
		set_layer_addr(tree_addr, (uint32_t)i);
		set_tree_addr(tree_addr, tree);

		copy_subtree_addr(wots_addr, tree_addr);
		set_keypair_addr(wots_addr, idx_leaf);

		/* Compute a WOTS signature. */
		wots_sign(sig, root, sk_seed, pub_seed, wots_addr);
		sig += SPX_WOTS_BYTES;

		/* Compute the authentication path for the used WOTS leaf. */
		treehash(root, sig, sk_seed, pub_seed, idx_leaf, 0, SPX_TREE_HEIGHT, wots_gen_leaf, tree_addr);
		sig += SPX_TREE_HEIGHT * SPX_N;

		/* Update the indices for the next layer. */
		idx_leaf = (tree & ((1ULL << SPX_TREE_HEIGHT) - 1));
		tree = tree >> SPX_TREE_HEIGHT;
	}

	*siglen = SPX_BYTES;
}

static int32_t sphincsplus_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk)
{
	/* Verifies a detached signature and message under a given public key. */

	const uint8_t* pub_seed = pk;
	const uint8_t* pub_root = pk + SPX_N;
	uint8_t mhash[SPX_FORS_MSG_BYTES];
	uint8_t wots_pk[SPX_WOTS_BYTES];
	uint8_t root[SPX_N];
	uint8_t leaf[SPX_N];
	uint32_t i;
	uint64_t tree;
	uint32_t idx_leaf;
	uint32_t wots_addr[8] = { 0 };
	uint32_t tree_addr[8] = { 0 };
	uint32_t wots_pk_addr[8] = { 0 };
	int32_t ret;

	ret = 0;

	if (siglen == SPX_BYTES)
	{
		/* This hook allows the hash function instantiation to do whatever
		   preparation or computation it needs, based on the public seed. */
		initialize_hash_function(pub_seed, NULL);

		set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
		set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
		set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

		/* Derive the message digest and leaf index from R || PK || M. */
		/* The additional SPX_N is a result of the hash domain separator. */
		hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen);
		sig += SPX_N;

		/* Layer correctly defaults to 0, so no need to set_layer_addr */
		set_tree_addr(wots_addr, tree);
		set_keypair_addr(wots_addr, idx_leaf);

		fors_pk_from_sig(root, sig, mhash, pub_seed, wots_addr);
		sig += SPX_FORS_BYTES;

		/* For each subtree.. */
		for (i = 0; i < SPX_D; i++)
		{
			set_layer_addr(tree_addr, i);
			set_tree_addr(tree_addr, tree);
			copy_subtree_addr(wots_addr, tree_addr);
			set_keypair_addr(wots_addr, idx_leaf);
			copy_keypair_addr(wots_pk_addr, wots_addr);

			/* The WOTS public key is only correct if the signature was correct. */
			/* Initially, root is the FORS pk, but on subsequent iterations it is
			   the root of the subtree below the currently processed subtree. */
			wots_pk_from_sig(wots_pk, sig, root, pub_seed, wots_addr);
			sig += SPX_WOTS_BYTES;

			/* Compute the leaf node using the WOTS public key. */
			thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);

			/* Compute the root node of this subtree. */
			compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT, pub_seed, tree_addr);
			sig += SPX_TREE_HEIGHT * SPX_N;

			/* Update the indices for the next layer. */
			idx_leaf = (tree & ((1ULL << SPX_TREE_HEIGHT) - 1));
			tree = tree >> SPX_TREE_HEIGHT;
		}

		/* Check if the root node equals the root node in the public key. */
		if (memcmp(root, pub_root, SPX_N))
		{
			ret = -1;
		}
	}
	else
	{
		ret = -1;
	}

	return ret;
}

void sphincsplus_generate(uint8_t* pk, uint8_t* sk, void (*rng_generate)(uint8_t*, size_t))
{
	/* Generates an SPX key pair. */

	uint8_t seed[SPHINCSPLUS_SEED_SIZE];

	rng_generate(seed, SPHINCSPLUS_SEED_SIZE);
	sphincsplus_sign_seed_keypair(pk, sk, seed);
}

void sphincsplus_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen, const uint8_t* sk, void (*rng_generate)(uint8_t*, size_t))
{
	/* Returns an array containing the signature followed by the message. */

	size_t siglen;

	sphincsplus_sign_signature(sm, &siglen, m, (size_t)mlen, sk, rng_generate);

	memmove(sm + SPX_BYTES, m, mlen);
	*smlen = siglen + mlen;
}

bool sphincsplus_verify(uint8_t* m, size_t* mlen, const uint8_t* sm, size_t smlen, const uint8_t* pk)
{
	bool res;

	res = true;

	/* The API caller does not necessarily know what size a signature should be
	   but SPHINCS+ signatures are always exactly SPX_BYTES. */
	if (smlen < SPX_BYTES)
	{
		memset(m, 0, smlen);
		*mlen = 0;
		res = false;
	}

	if (res == true)
	{
		*mlen = smlen - SPX_BYTES;

		if (sphincsplus_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, *mlen, pk) != 0)
		{
			memset(m, 0, smlen);
			*mlen = 0;
			res = false;
		}

		if (res == true)
		{
			/* If verification was successful, move the message to the right place. */
			memmove(m, sm + SPX_BYTES, *mlen);
		}
	}

	return res;
}
