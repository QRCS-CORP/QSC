#include "common.h"
#include "hash.h"
#include "haddress.h"
#include "params.h"
#include "sha3.h"
#include "utils.h"

static void addr_to_bytes(uint8_t* bytes, const uint32_t addr[8])
{
    size_t i;

    for (i = 0; i < 8; i++) 
	{
        ull_to_bytes(bytes + (i * 4), 4, addr[i]);
    }
}

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(const uint8_t* pkseed, const uint8_t* skseed)
{
    (void)pkseed; /* Suppress an 'unused parameter' warning. */
    (void)skseed;  /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(key, addr), given a secret key of SPX_N bytes and an address
 */
void prf_addr(uint8_t* out, const uint8_t* key, const uint32_t addr[8])
{
    uint8_t buf[SPX_N + SPX_ADDR_BYTES];

    memcpy(buf, key, SPX_N);
    addr_to_bytes(buf + SPX_N, addr);

    shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value prefixed to the message.
 * This requires m to have at least 2*SPX_N bytes * bytes of space available in
 * front of the pointer, i.e. before the message to use for the prefix. This is
 * necessary to prevent having to move the message around (and allocate memory
 * for it).
 */
void gen_message_random(uint8_t* R, const uint8_t* sk_prf, const uint8_t* optrand, uint8_t* m, uint64_t mlen)
{
    memcpy(m - (2 * SPX_N), sk_prf, SPX_N);
    memcpy(m - SPX_N, optrand, SPX_N);
    shake256(R, SPX_N, m - (2 * SPX_N), mlen + (2 * SPX_N));
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Notably, it requires m to have SPX_N + SPX_PK_BYTES bytes of space available
 * in front of the pointer, i.e. before the message, to use for the prefix.
 * This is necessary to prevent having to move the * message around (and
 * allocate memory for it).
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(uint8_t* digest, uint64_t* tree, uint32_t* leaf_idx, const uint8_t* R, const uint8_t* pk, uint8_t* m, uint64_t mlen)
{
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    uint8_t buf[SPX_DGST_BYTES];
    uint8_t *bufp = buf;

    memcpy(m - SPX_N - SPX_PK_BYTES, R, SPX_N);
    memcpy(m - SPX_PK_BYTES, pk, SPX_PK_BYTES);
    shake256(buf, SPX_DGST_BYTES, m - SPX_N - SPX_PK_BYTES, mlen + SPX_N + SPX_PK_BYTES);
    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;
    *leaf_idx = bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}

/*lint -e647 */
/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(uint8_t* out, const uint8_t* in, const uint32_t inblocks, const uint8_t* pub_seed, uint32_t addr[8], uint8_t* buf, uint8_t* mask)
{
	uint32_t i;

	memset(buf, 0, sizeof(buf));
	memset(mask, 0, sizeof(mask));
	memcpy(buf, pub_seed, SPX_N);

	addr_to_bytes(buf + SPX_N, addr);
	shake256(mask, inblocks * SPX_N, buf, SPX_N + SPX_ADDR_BYTES);

	for (i = 0; i < inblocks * SPX_N; i++)
	{
		buf[SPX_N + SPX_ADDR_BYTES + i] = in[i] ^ mask[i];
	}

	shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
}
/*lint -restore */