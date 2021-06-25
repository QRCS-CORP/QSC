#include "sphincsplusbase.h"
#include "sha3.h"
#include <stdlib.h>

/* params.h */

#if defined(QSC_SPHINCSPLUS_S1S128SHAKE)
	/* toggles modes between the three shake-based K modes; 128,192,256 = 1,2,3 */
#   define QCX_SPX_MODE 1
#elif defined(QSC_SPHINCSPLUS_S2S192SHAKE)
#   define QCX_SPX_MODE 2
#elif defined(QSC_SPHINCSPLUS_S3S256SHAKE)
#   define QCX_SPX_MODE 3
#else
#	error No SphincsPlus implementation is defined, check common.h!
#endif

/* implement the S 'robust' version of the signature scheme */
#define SPX_VERSION_SMALL

/* note: kats are small version, fast version kats not implemented */
#ifdef SPX_VERSION_SMALL
#	if (QCX_SPX_MODE == 3)
		/* Hash output length in bytes. */
#		define SPX_N 32
		/* Height of the hypertree. */
#		define SPX_FULL_HEIGHT 64
		/* Number of subtree layer. */
#		define SPX_D 8
		/* FORS tree dimensions. */
#		define SPX_FORS_HEIGHT 14
#		define SPX_FORS_TREES 22
		/* Winternitz parameter, */
#		define SPX_WOTS_W 16
#	elif (QCX_SPX_MODE == 2)
#		define SPX_N 24
#		define SPX_FULL_HEIGHT 64
#		define SPX_D 8
#		define SPX_FORS_HEIGHT 16
#		define SPX_FORS_TREES 14
#		define SPX_WOTS_W 16
#	elif (QCX_SPX_MODE == 1)
#		define SPX_N 16
#		define SPX_FULL_HEIGHT 64
#		define SPX_D 8
#		define SPX_FORS_HEIGHT 15
#		define SPX_FORS_TREES 10
#		define SPX_WOTS_W 16
#	else
#		error the sphincsplus mode is invalid!
#	endif
#else
#	if (QCX_SPX_MODE == 3)
#		define SPX_N 32
#		define SPX_FULL_HEIGHT 68
#		define SPX_D 17
#		define SPX_FORS_HEIGHT 10
#		define SPX_FORS_TREES 30
#		define SPX_WOTS_W 16
#	elif (QCX_SPX_MODE == 2)
#		define SPX_N 24
#		define SPX_FULL_HEIGHT 66
#		define SPX_D 22
#		define SPX_FORS_HEIGHT 8
#		define SPX_FORS_TREES 33
#		define SPX_WOTS_W 16
#	elif (QCX_SPX_MODE == 1)
#		define SPX_N 16
#		define SPX_FULL_HEIGHT 60
#		define SPX_D 20
#		define SPX_FORS_HEIGHT 9
#		define SPX_FORS_TREES 30
#		define SPX_WOTS_W 16
#	else
#		error the sphincsplus mode is invalid!
#	endif
#endif

#define SPX_ADDR_BYTES 32

/* WOTS parameters */
#if SPX_WOTS_W == 256
#	define SPX_WOTS_LOGW 8
#elif SPX_WOTS_W == 16
#	define SPX_WOTS_LOGW 4
#else
#	error SPX_WOTS_W assumed 16 or 256
#endif

#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)

/* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#if SPX_WOTS_W == 256
#	if SPX_N <= 1
#		define SPX_WOTS_LEN2 1
#	elif SPX_N <= 256
#		define SPX_WOTS_LEN2 2
#	else
#		error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
#	endif
#elif SPX_WOTS_W == 16
#	if SPX_N <= 8
#		define SPX_WOTS_LEN2 2
#	elif SPX_N <= 136
#		define SPX_WOTS_LEN2 3
#	elif SPX_N <= 256
#		define SPX_WOTS_LEN2 4
#	else
#		error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
#	endif
#endif

#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if (SPX_TREE_HEIGHT * SPX_D) != SPX_FULL_HEIGHT
#	error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* FORS parameters */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

/* Optionally, signing can be made non-deterministic using optrand.
   This can help counter side-channel attacks that would benefit from
   getting a large number of traces when the signer uses the same nodes. */
#define SPX_OPTRAND_BYTES 32
#define SPHINCSPLUS_SEED_SIZE 3 * SPX_N

/* address.h */

#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK 4

#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

/* utils.c */

static void ull_to_bytes(uint8_t* out, size_t outlen, uint64_t in)
{
	do
	{
		--outlen;
		out[outlen] = in & 0xFFU;
		in = in >> 8;
	} while (outlen != 0);
}

static uint64_t bytes_to_ull(const uint8_t* in, size_t inlen)
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

/* address.c */

static void addr_to_bytes(uint8_t* bytes, const uint32_t addr[8])
{
	size_t i;

	for (i = 0; i < 8; i++)
	{
		ull_to_bytes(bytes + (i * sizeof(uint32_t)), sizeof(uint32_t), addr[i]);
	}
}

static void set_layer_addr(uint32_t addr[8], uint32_t layer)
{
	addr[0] = layer;
}

static void set_tree_addr(uint32_t addr[8], uint64_t tree)
{
#if (SPX_TREE_HEIGHT * (SPX_D - 1)) > 64
#error Subtree addressing is currently limited to at most 2^64 trees
#endif
	addr[1] = 0;
	addr[2] = (uint32_t)(tree >> 32);
	addr[3] = (uint32_t)tree;
}

static void set_type(uint32_t addr[8], uint32_t type)
{
	addr[4] = type;
}

static void copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
{
	out[0] = in[0];
	out[1] = in[1];
	out[2] = in[2];
	out[3] = in[3];
}

/* These functions are used for OTS addresses. */

static void set_keypair_addr(uint32_t addr[8], uint32_t keypair)
{
	addr[5] = keypair;
}

static void copy_keypair_addr(uint32_t out[8], const uint32_t in[8])
{
	out[0] = in[0];
	out[1] = in[1];
	out[2] = in[2];
	out[3] = in[3];
	out[5] = in[5];
}

static void set_chain_addr(uint32_t addr[8], uint32_t chain)
{
	addr[6] = chain;
}

static void set_hash_addr(uint32_t addr[8], uint32_t hash)
{
	addr[7] = hash;
}

static void set_tree_height(uint32_t addr[8], uint32_t tree_height)
{
	addr[6] = tree_height;
}

static void set_tree_index(uint32_t addr[8], uint32_t tree_index)
{
	addr[7] = tree_index;
}

/* hash.c */

static void initialize_hash_function(const uint8_t* pub_seed, const uint8_t* sk_seed)
{
	(void)pub_seed; /* Suppress an 'unused parameter' warning. */
	(void)sk_seed;	/* Suppress an 'unused parameter' warning. */
}

static void prf_addr(uint8_t* out, const uint8_t* key, const uint32_t addr[8])
{
	uint8_t buf[SPX_N + SPX_ADDR_BYTES];

	memcpy(buf, key, SPX_N);
	addr_to_bytes(buf + SPX_N, addr);

	qsc_shake256_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES);
}

static void gen_message_random(uint8_t* R, const uint8_t* sk_prf, const uint8_t* optrand, const uint8_t* m, size_t mlen)
{
	uint8_t* tmp = (uint8_t*)malloc((SPX_N * 2) + mlen);

	assert(tmp != NULL);

	if (tmp != NULL)
	{
		memcpy(tmp, sk_prf, SPX_N);
		memcpy(tmp + SPX_N, optrand, SPX_N);
		memcpy(tmp + (2 * SPX_N), m, mlen);
		qsc_shake256_compute(R, SPX_N, tmp, SPX_N * 2 + mlen);
		free(tmp);
	}
}

static void hash_message(uint8_t* digest, uint64_t* tree, uint32_t* leaf_idx, const uint8_t* R, const uint8_t* pk, const uint8_t* m, size_t mlen)
{
	uint8_t buf[SPX_DGST_BYTES] = { 0 };
	uint8_t* bufp = buf;
	uint8_t* tmp = (uint8_t*)malloc(SPX_N + SPX_PK_BYTES + mlen);

	assert(tmp != NULL);

	if (tmp != NULL)
	{
		memcpy(tmp, R, SPX_N);
		memcpy(tmp + SPX_N, pk, SPX_PK_BYTES);
		memcpy(tmp + SPX_N + SPX_PK_BYTES, m, mlen);
		qsc_shake256_compute(buf, SPX_DGST_BYTES, tmp, SPX_N + SPX_PK_BYTES + mlen);
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

/* thash.c */

static void thash(uint8_t* out, const uint8_t* in, size_t inblocks, const uint8_t* pub_seed, uint32_t addr[8])
{
	uint8_t* buf = (uint8_t*)malloc((size_t)SPX_N + SPX_ADDR_BYTES + (inblocks * SPX_N));
	uint8_t* bitmask = (uint8_t*)malloc((size_t)inblocks * SPX_N);
	size_t i;

	assert(buf != NULL && bitmask != NULL);

	if (buf != NULL && bitmask != NULL)
	{
		memcpy(buf, pub_seed, SPX_N);
		addr_to_bytes(buf + SPX_N, addr);

		qsc_shake256_compute(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_ADDR_BYTES);

		for (i = 0; i < (inblocks * SPX_N); ++i)
		{
			buf[SPX_N + SPX_ADDR_BYTES + i] = (in[i] ^ bitmask[i]);
		}

		qsc_shake256_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);

		free(buf);
		free(bitmask);
	}
}

static void compute_root(uint8_t* root, const uint8_t* leaf, uint32_t leaf_idx, uint32_t idx_offset,
	const uint8_t* auth_path, uint32_t tree_height, const uint8_t* pub_seed, uint32_t addr[8])
{
	uint32_t i;
	uint8_t buffer[2 * SPX_N];

	/* If leaf_idx is odd (last bit = 1), current path element is a right child
	   and auth_path has to go left. Otherwise it is the other way around. */
	if (leaf_idx & 1U)
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
		if (leaf_idx & 1U)
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

static void treehash(uint8_t* root, uint8_t* auth_path, const uint8_t* sk_seed, const uint8_t* pub_seed, uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
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
			if ((leaf_idx ^ 0x01U) == idx)
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
				if (((leaf_idx >> heights[offset - 1]) ^ 0x01U) == tree_idx)
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

/* wots.c */

static void wots_gen_sk(uint8_t* sk, const uint8_t* sk_seed, uint32_t wots_addr[8])
{
	/* Computes the starting value for a chain, i.e. the secret key.
	 * Expects the address to be complete up to the chain address. */

	 /* Make sure that the hash address is actually zeroed. */
	set_hash_addr(wots_addr, 0);
	/* Generate sk element. */
	prf_addr(sk, sk_seed, wots_addr);
}

static void gen_chain(uint8_t* out, const uint8_t* in, uint32_t start, uint32_t steps, const uint8_t* pub_seed, uint32_t addr[8])
{
	/* Computes the chaining function.
	 * out and in have to be n-byte arrays.
	 *
	 * Interprets in as start-th value of the chain.
	 * addr has to contain the address of the chain. */

	uint32_t i;

	/* Initialize out with the value at position 'start'. */
	memcpy(out, in, SPX_N);

	/* Iterate 'steps' calls to the hash function. */
	for (i = start; i < (start + steps) && i < SPX_WOTS_W; ++i)
	{
		set_hash_addr(addr, i);
		thash(out, out, 1, pub_seed, addr);
	}
}

static void base_w(int32_t* output, size_t outlen, const uint8_t* input)
{
	/* base_w algorithm as described in draft.
	 * Interprets an array of bytes as integers in base w.
	 * This only works when log_w is a divisor of 8. */

	size_t c;
	size_t i;
	size_t j;
	int32_t bits;
	uint8_t total;

	bits = 0;
	i = 0;
	j = 0;

	for (c = 0; c < outlen; ++c)
	{
		if (bits == 0)
		{
			total = input[i];
			++i;
			bits += 8;
		}

		bits -= SPX_WOTS_LOGW;
		output[j] = (total >> bits) & (SPX_WOTS_W - 1);
		++j;
	}
}

static void wots_checksum(int32_t* csum_base_w, const int32_t* msg_base_w)
{
	/* Computes the WOTS+ checksum over a message (in base_w). */

	int32_t csum;
	uint8_t csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
	uint32_t i;

	csum = 0;

	/* Compute checksum. */
	for (i = 0; i < SPX_WOTS_LEN1; i++)
	{
		csum += SPX_WOTS_W - 1 - msg_base_w[i];
	}

	/* Convert checksum to base_w. */
	/* Make sure expected empty zero bits are the least significant bits. */
	if ((SPX_WOTS_LOGW % 8) != 0) 
	{
		csum = csum << (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8));
	}

	ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
	base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

static void chain_lengths(int32_t* lengths, const uint8_t* msg)
{
	/* Takes a message and derives the matching chain lengths. */
	base_w(lengths, SPX_WOTS_LEN1, msg);
	wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
}

static void wots_gen_pk(uint8_t* pk, const uint8_t* sk_seed, const uint8_t* pub_seed, uint32_t addr[8])
{
	size_t i;

	for (i = 0; i < SPX_WOTS_LEN; i++)
	{
		set_chain_addr(addr, (uint32_t)i);
		wots_gen_sk(pk + (i * SPX_N), sk_seed, addr);
		gen_chain(pk + (i * SPX_N), pk + (i * SPX_N), 0, SPX_WOTS_W - 1, pub_seed, addr);
	}
}

static void wots_sign(uint8_t* sig, const uint8_t* msg, const uint8_t* sk_seed, const uint8_t* pub_seed, uint32_t addr[8])
{
	int32_t lengths[SPX_WOTS_LEN];
	uint32_t i;

	chain_lengths(lengths, msg);

	for (i = 0; i < SPX_WOTS_LEN; i++)
	{
		set_chain_addr(addr, i);
		wots_gen_sk(sig + (i * SPX_N), sk_seed, addr);
		gen_chain(sig + (i * SPX_N), sig + (i * SPX_N), 0, lengths[i], pub_seed, addr);
	}
}

static void wots_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* msg, const uint8_t* pub_seed, uint32_t addr[8])
{
	int32_t lengths[SPX_WOTS_LEN];
	uint32_t i;

	chain_lengths(lengths, msg);

	for (i = 0; i < SPX_WOTS_LEN; i++)
	{
		set_chain_addr(addr, i);
		gen_chain(pk + (i * SPX_N), sig + (i * SPX_N), lengths[i], SPX_WOTS_W - 1 - lengths[i], pub_seed, addr);
	}
}

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

/* fors.c */

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
			indices[i] ^= ((m[offset >> 3] >> (offset & 0x07U)) & 0x01U) << j;
			offset++;
		}
	}
}

static void fors_sign(uint8_t* sig, uint8_t* pk, const uint8_t* m, const uint8_t* sk_seed, const uint8_t* pub_seed, const uint32_t fors_addr[8])
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
		idx_offset = (uint32_t)i * (1UL << (uint32_t)SPX_FORS_HEIGHT);

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

static void fors_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* m, const uint8_t* pub_seed, const uint32_t fors_addr[8])
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
		idx_offset = (uint32_t)i * (1UL << (uint32_t)SPX_FORS_HEIGHT);

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

/* sign.c */

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
