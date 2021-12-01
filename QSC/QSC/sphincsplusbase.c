#include "sphincsplusbase.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

/* params.h */

#if defined(QSC_SPHINCSPLUS_S3S192SHAKERF)

/* Hash output length in bytes. */
#define SPX_N 24
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 66
/* Number of subtree layer. */
#define SPX_D 22
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 8
#define SPX_FORS_TREES 33
/* Winternitz parameter, */
#define SPX_WOTS_W 16

#elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)

/* Hash output length in bytes. */
#define SPX_N 24
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 63
/* Number of subtree layer. */
#define SPX_D 7
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 14
#define SPX_FORS_TREES 17
/* Winternitz parameter, */
#define SPX_WOTS_W 16

#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF)

/* Hash output length in bytes. */
#define SPX_N 32
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 68
/* Number of subtree layer. */
#define SPX_D 17
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 9
#define SPX_FORS_TREES 35
/* Winternitz parameter, */
#define SPX_WOTS_W 16

#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)

/* Hash output length in bytes. */
#define SPX_N 32
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 64
/* Number of subtree layer. */
#define SPX_D 8
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 14
#define SPX_FORS_TREES 22
/* Winternitz parameter, */
#define SPX_WOTS_W 16

#endif

 /* For clarity */
#define SPX_ADDR_BYTES 32

/* WOTS parameters. */
#if SPX_WOTS_W == 256
#   define SPX_WOTS_LOGW 8
#elif SPX_WOTS_W == 16
#   define SPX_WOTS_LOGW 4
#else
#   error SPX_WOTS_W assumed 16 or 256
#endif

#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)

/* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#if SPX_WOTS_W == 256
#   if SPX_N <= 1
#       define SPX_WOTS_LEN2 1
#   elif SPX_N <= 256
#       define SPX_WOTS_LEN2 2
#   else
#       error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
#   endif
#elif SPX_WOTS_W == 16
#   if SPX_N <= 8
#       define SPX_WOTS_LEN2 2
#   elif SPX_N <= 136
#       define SPX_WOTS_LEN2 3
#   elif SPX_N <= 256
#       define SPX_WOTS_LEN2 4
#   else
#       error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
#   endif
#endif

#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size. */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
#   error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* FORS parameters. */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes. */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size. */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
#   error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* Optionally, signing can be made non-deterministic using optrand.
This can help counter side-channel attacks that would benefit from
getting a large number of traces when the signer uses the same nodes. */
#define SPX_OPTRAND_BYTES 32

/* Offsets of various fields in the address structure when we use SHAKE as the Sphincs+ hash function */
/* The byte used to specify the Merkle tree layer */
#define SPX_OFFSET_LAYER 3
/* The start of the 8 byte field used to specify the tree */
#define SPX_OFFSET_TREE 8
/* The byte used to specify the hash type (reason) */
#define SPX_OFFSET_TYPE 19
/* The high byte used to specify the key pair (which one-time signature) */
#define SPX_OFFSET_KP_ADDR2 22
/* The low byte used to specify the key pair */
#define SPX_OFFSET_KP_ADDR1 23
/* The byte used to specify the chain address (which Winternitz chain) */
#define SPX_OFFSET_CHAIN_ADDR 27
/* The byte used to specify the hash address (where in the Winternitz chain) */
#define SPX_OFFSET_HASH_ADDR 31
/* The byte used to specify the height of this node in the FORS or Merkle tree */
#define SPX_OFFSET_TREE_HGT  27
/* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */
#define SPX_OFFSET_TREE_INDEX 28

/* The hash types that are passed to set_type */
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

#define SPHINCSPLUS_PRIVATEKEY_SIZE SPX_SK_BYTES
#define SPHINCSPLUS_PUBLICKEY_SIZE SPX_PK_BYTES
#define SPHINCSPLUS_SIGNATURE_SIZE SPX_BYTES
#define SPHINCSPLUS_CRYPTO_SEEDBYTES 3 * SPX_N

/* utils.c */

static void sphincsplus_ull_to_bytes(uint8_t* out, uint32_t outlen, uint64_t in)
{
    size_t pos;

    pos = outlen;

    do
    {
        --pos;
        out[pos] = in & 0xFF;
        in = in >> 8;
    } 
    while (pos > 0);
}

static void sphincsplus_u32_to_bytes(uint8_t* out, uint32_t in)
{
    out[0] = (uint8_t)(in >> 24);
    out[1] = (uint8_t)(in >> 16);
    out[2] = (uint8_t)(in >> 8);
    out[3] = (uint8_t)in;
}

static uint64_t sphincsplus_bytes_to_ull(const uint8_t* in, uint32_t inlen)
{
    uint64_t ret;

    ret = 0;

    for (size_t i = 0; i < inlen; ++i)
    {
        ret |= ((uint64_t)in[i]) << (8 * (inlen - 1 - i));
    }

    return ret;
}

/* address.c */

/* These functions are used for all hash tree addresses (including FORS). */

static void sphincsplus_set_layer_addr(uint32_t addr[8], uint32_t layer)
{
    /* Specify which level of Merkle tree (the "layer") we're working on */

    ((uint8_t*)addr)[SPX_OFFSET_LAYER] = (uint8_t)layer;
}

static void sphincsplus_set_tree_addr(uint32_t addr[8], uint64_t tree)
{
    /* Specify which Merkle tree within the level (the "tree address") we're working on */

#if ((SPX_TREE_HEIGHT * (SPX_D - 1)) > 64)
#   error Subtree addressing is currently limited to at most 2^64 trees
#endif

    qsc_intutils_be64to8((uint8_t*)addr + SPX_OFFSET_TREE, tree);
}

static void sphincsplus_set_type(uint32_t addr[8], uint32_t type)
{
    /* Specify the reason we'll use this address structure for, that is, what
       hash will we compute with it.  This is used so that unrelated types of
       hashes don't accidentally get the same address structure.  The type will be
       one of the SPX_ADDR_TYPE constants */

    ((uint8_t*)addr)[SPX_OFFSET_TYPE] = (uint8_t)type;
}

static void sphincsplus_copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
{
    /* Copy the layer and tree fields of the address structure.  This is used
       when we're doing multiple types of hashes within the same Merkle tree */

    qsc_memutils_copy((uint8_t*)out, (const uint8_t*)in, SPX_OFFSET_TREE + 8);
}

static void sphincsplus_set_keypair_addr(uint32_t addr[8], uint32_t keypair)
{
    /* Specify which Merkle leaf we're working on; that is, 
       which OTS keypair we're talking about. */

#if (SPX_FULL_HEIGHT/SPX_D > 8)
    /* We have > 256 OTS at the bottom of the Merkle tree; to specify
       which one, we'd need to express it in two bytes */
    ((uint8_t*)addr)[SPX_OFFSET_KP_ADDR2] = keypair >> 8;
#endif

    ((uint8_t*)addr)[SPX_OFFSET_KP_ADDR1] = (uint8_t)keypair;
}

static void sphincsplus_copy_keypair_addr(uint32_t out[8], const uint32_t in[8])
{
    /* Copy the layer, tree and keypair fields of the address structure.
       This is used when we're doing multiple things within the same OTS keypair */

    qsc_memutils_copy((uint8_t*)out, (const uint8_t*)in, SPX_OFFSET_TREE + 8);

#if (SPX_FULL_HEIGHT/SPX_D > 8)
    ((uint8_t*)out)[SPX_OFFSET_KP_ADDR2] = ((uint8_t*)in)[SPX_OFFSET_KP_ADDR2];
#endif
    ((uint8_t*)out)[SPX_OFFSET_KP_ADDR1] = ((const uint8_t*)in)[SPX_OFFSET_KP_ADDR1];
}

static void sphincsplus_set_chain_addr(uint32_t addr[8], uint32_t chain)
{
    /* Specify which Merkle chain within the OTS we're working with (the chain address) */

    ((uint8_t*)addr)[SPX_OFFSET_CHAIN_ADDR] = (uint8_t)chain;
}

static void sphincsplus_set_hash_addr(uint32_t addr[8], uint32_t hash)
{
    /* Specify where in the Merkle chain we are (the hash address) */

    ((uint8_t*)addr)[SPX_OFFSET_HASH_ADDR] = (uint8_t)hash;
}

static void sphincsplus_set_tree_height(uint32_t addr[8], uint32_t tree_height)
{
    /* Specify the height of the node in the Merkle/FORS tree we are in (the tree height) */

    ((uint8_t*)addr)[SPX_OFFSET_TREE_HGT] = (uint8_t)tree_height;
}

static void sphincsplus_set_tree_index(uint32_t addr[8], uint32_t tree_index)
{
    /* Specify the distance from the left edge of the node in the Merkle/FORS tree (the tree index) */

    sphincsplus_u32_to_bytes((uint8_t*)addr + SPX_OFFSET_TREE_INDEX, tree_index);
}

/* hash_shake256.c */

static void sphincsplus_prf_addr(uint8_t* out, const uint8_t* key, const uint32_t addr[8])
{
    /* Computes PRF(key, addr), given a secret key of SPX_N bytes and an address */

    uint8_t buf[SPX_N + SPX_ADDR_BYTES];

    qsc_memutils_copy(buf, key, SPX_N);
    qsc_memutils_copy(buf + SPX_N, (const uint8_t*)addr, SPX_ADDR_BYTES);

    qsc_shake256_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES);
}

static void sphincsplus_gen_message_random(uint8_t* R, const uint8_t* sk_prf, const uint8_t* optrand, const uint8_t* m, uint64_t mlen)
{
    /* Computes the message-dependent randomness R, using a secret seed and an
       optional randomization value as well as the message. */
    qsc_keccak_state kctx = { 0 };

    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, sk_prf, SPX_N);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, optrand, SPX_N);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, m, mlen);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, R, SPX_N);
}

static void sphincsplus_hash_message(uint8_t* digest, uint64_t* tree, uint32_t* leaf_idx, const uint8_t* R, const uint8_t* pk, const uint8_t* m, uint64_t mlen)
{
    /* Computes the message hash using R, the public key, and the message.
       Outputs the message digest and the index of the leaf. The index is split in
       the tree index and the leaf index, for convenient copying to an address. */

    uint8_t buf[SPX_DGST_BYTES] = { 0 };
    const uint8_t* bufp = buf;
    qsc_keccak_state kctx = { 0 };

    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, R, SPX_N);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, pk, SPX_PK_BYTES);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, m, mlen);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, buf, SPX_DGST_BYTES);

    qsc_memutils_copy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
#error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = sphincsplus_bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)sphincsplus_bytes_to_ull(bufp, (uint32_t)SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}

static void sphincsplus_thash(uint8_t* out, const uint8_t* in, uint32_t inblocks, const uint8_t* pubseed, uint32_t addr[8])
{
    /* Takes an array of inblocks concatenated arrays of SPX_N bytes */
    const size_t BLKLEN = inblocks * SPX_N;
    const size_t KEYLEN = SPX_N + SPX_ADDR_BYTES;
    uint8_t* buf;
    uint8_t* bitmask;

    buf = (uint8_t*)qsc_memutils_malloc(KEYLEN + BLKLEN);
    bitmask = (uint8_t*)qsc_memutils_malloc(BLKLEN);
    assert(buf != NULL && bitmask != NULL);

    if (buf != NULL && bitmask != NULL)
    {
        qsc_memutils_copy(buf, pubseed, SPX_N);
        qsc_memutils_copy(buf + SPX_N, (uint8_t*)addr, SPX_ADDR_BYTES);

        qsc_shake256_compute(bitmask, BLKLEN, buf, KEYLEN);

        for (size_t i = 0; i < BLKLEN; ++i)
        {
            buf[KEYLEN + i] = in[i] ^ bitmask[i];
        }

        qsc_shake256_compute(out, SPX_N, buf, KEYLEN + BLKLEN);
        qsc_memutils_alloc_free(bitmask);
        qsc_memutils_alloc_free(buf);
    }
}

static void sphincsplus_compute_root(uint8_t* root, const uint8_t* leaf, uint32_t leaf_idx, uint32_t idx_offset, const uint8_t* auth_path,
    uint32_t tree_height, const uint8_t* pubseed, uint32_t addr[8])
{
    /* Computes a root node given a leaf and an auth path.
       Expects address to be complete other than the tree_height and tree_index */

    uint8_t buffer[2 * SPX_N] = { 0 };

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if ((leaf_idx & 1) != 0)
    {
        qsc_memutils_copy(buffer + SPX_N, leaf, SPX_N);
        qsc_memutils_copy(buffer, auth_path, SPX_N);
    }
    else
    {
        qsc_memutils_copy(buffer, leaf, SPX_N);
        qsc_memutils_copy(buffer + SPX_N, auth_path, SPX_N);
    }

    auth_path += SPX_N;

    for (size_t i = 0; i < tree_height - 1; ++i)
    {
        leaf_idx >>= 1;
        idx_offset >>= 1;

        /* Set the address of the node we're creating. */
        sphincsplus_set_tree_height(addr, (uint32_t)i + 1);
        sphincsplus_set_tree_index(addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if ((leaf_idx & 1) != 0)
        {
            sphincsplus_thash(buffer + SPX_N, buffer, 2, pubseed, addr);
            qsc_memutils_copy(buffer, auth_path, SPX_N);
        }
        else
        {
            sphincsplus_thash(buffer, buffer, 2, pubseed, addr);
            qsc_memutils_copy(buffer + SPX_N, auth_path, SPX_N);
        }

        auth_path += SPX_N;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    sphincsplus_set_tree_height(addr, tree_height);
    sphincsplus_set_tree_index(addr, leaf_idx + idx_offset);
    sphincsplus_thash(root, buffer, 2, pubseed, addr);
}

static void sphincsplus_treehash(uint8_t* root, uint8_t* auth_path, const uint8_t* sk_seed, const uint8_t* pubseed,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        uint8_t*,            /* leaf */
        const uint8_t*,      /* sk_seed */
        const uint8_t*,      /* pubseed */
        uint32_t,            /* addr_idx */
        const uint32_t[8]),  /* tree_addr */
    uint32_t tree_addr[8])
{
    /* For a given leaf index, computes the authentication path and the resulting
       root node using Merkle's TreeHash algorithm.
       Expects the layer and tree parts of the tree_addr to be set, as well as the
       tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
       Applies the offset idx_offset to indices before building addresses, so that
       it is possible to continue counting indices across trees. */

    uint8_t* stack;
    uint32_t* heights;
    uint32_t offset;
    uint32_t tree_idx;

    offset = 0;
    stack = (uint8_t*)qsc_memutils_malloc(((size_t)tree_height + 1) * SPX_N);
    heights = (uint32_t*)qsc_memutils_malloc(((size_t)tree_height + 1) * sizeof(uint32_t));
    assert(stack != NULL && heights != NULL);

    if (stack != NULL && heights != NULL)
    {
        for (uint32_t idx = 0; idx < (uint32_t)(1 << tree_height); ++idx)
        {
            /* Add the next leaf node to the stack. */
            gen_leaf(stack + offset * SPX_N, sk_seed, pubseed, idx + idx_offset, tree_addr);
            offset++;
            heights[offset - 1] = 0;

            /* If this is a node we need for the auth path.. */
            if ((leaf_idx ^ 0x1) == idx)
            {
                qsc_memutils_copy(auth_path, stack + (offset - 1) * SPX_N, SPX_N);
            }

            /* While the top-most nodes are of equal height.. */
            while (offset >= 2 && heights[offset - 1] == heights[offset - 2])
            {
                /* Compute index of the new node, in the next layer. */
                tree_idx = (idx >> (heights[offset - 1] + 1));

                /* Set the address of the node we're creating. */
                sphincsplus_set_tree_height(tree_addr, heights[offset - 1] + 1);
                sphincsplus_set_tree_index(tree_addr, tree_idx + (idx_offset >> (heights[offset - 1] + 1)));
                /* Hash the top-most nodes from the stack together. */
                sphincsplus_thash(stack + (offset - 2) * SPX_N, stack + (offset - 2) * SPX_N, 2, pubseed, tree_addr);
                --offset;
                /* Note that the top-most node is now one layer higher. */
                ++heights[offset - 1];

                /* If this is a node we need for the auth path.. */
                if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx)
                {
                    qsc_memutils_copy(auth_path + heights[offset - 1] * SPX_N, stack + (offset - 1) * SPX_N, SPX_N);
                }
            }
        }

        qsc_memutils_copy(root, stack, SPX_N);
        qsc_memutils_alloc_free(heights);
        qsc_memutils_alloc_free(stack);
    }
}

/* fors.c */

static void sphincsplus_fors_gen_sk(uint8_t* sk, const uint8_t* sk_seed, const uint32_t fors_leaf_addr[8])
{
    sphincsplus_prf_addr(sk, sk_seed, fors_leaf_addr);
}

static void sphincsplus_fors_sk_to_leaf(uint8_t* leaf, const uint8_t* sk, const uint8_t* pubseed, uint32_t fors_leaf_addr[8])
{
    sphincsplus_thash(leaf, sk, 1, pubseed, fors_leaf_addr);
}

static void sphincsplus_fors_gen_leaf(uint8_t* leaf, const uint8_t* sk_seed, const uint8_t* pubseed, uint32_t addr_idx, const uint32_t fors_tree_addr[8])
{
    uint32_t fors_leaf_addr[8] = { 0 };

    /* Only copy the parts that must be kept in fors_leaf_addr. */
    sphincsplus_copy_keypair_addr(fors_leaf_addr, fors_tree_addr);
    sphincsplus_set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    sphincsplus_set_tree_index(fors_leaf_addr, addr_idx);

    sphincsplus_fors_gen_sk(leaf, sk_seed, fors_leaf_addr);
    sphincsplus_fors_sk_to_leaf(leaf, leaf, pubseed, fors_leaf_addr);
}

static void sphincsplus_message_to_indices(uint32_t* indices, const uint8_t* m)
{
    /* Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
       Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
       Assumes indices has space for SPX_FORS_TREES integers. */

    size_t oft;

    oft = 0;

    for (size_t i = 0; i < SPX_FORS_TREES; ++i)
    {
        indices[i] = 0;

        for (size_t j = 0; j < SPX_FORS_HEIGHT; ++j)
        {
            indices[i] ^= ((m[oft >> 3] >> (oft & 0x7)) & 0x1) << j;
            ++oft;
        }
    }
}

static void sphincsplus_fors_sign(uint8_t* sig, uint8_t* pk, const uint8_t* m, const uint8_t* sk_seed, const uint8_t* pubseed, const uint32_t fors_addr[8])
{
    /* Signs a message m, deriving the secret key from sk_seed and the FTS address.
       Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits. */
    uint32_t indices[SPX_FORS_TREES];
    uint8_t roots[SPX_FORS_TREES * SPX_N] = { 0 };
    uint32_t fors_tree_addr[8] = { 0 };
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;

    sphincsplus_copy_keypair_addr(fors_tree_addr, fors_addr);
    sphincsplus_copy_keypair_addr(fors_pk_addr, fors_addr);

    sphincsplus_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    sphincsplus_set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    sphincsplus_message_to_indices(indices, m);

    for (uint32_t i = 0; i < SPX_FORS_TREES; ++i)
    {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        sphincsplus_set_tree_height(fors_tree_addr, 0);
        sphincsplus_set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Include the secret key part that produces the selected leaf node. */
        sphincsplus_fors_gen_sk(sig, sk_seed, fors_tree_addr);
        sig += SPX_N;

        /* Compute the authentication path for this leaf node. */
        sphincsplus_treehash(roots + i * SPX_N, sig, sk_seed, pubseed, indices[i], idx_offset, SPX_FORS_HEIGHT, sphincsplus_fors_gen_leaf, fors_tree_addr);

        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    sphincsplus_thash(pk, roots, SPX_FORS_TREES, pubseed, fors_pk_addr);
}

static void sphincsplus_fors_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* m, const uint8_t* pubseed, const uint32_t fors_addr[8])
{
    /* Derives the FORS public key from a signature.
       This can be used for verification by comparing to a known public key, or to
       subsequently verify a signature on the derived public key. The latter is the
       typical use-case when used as an FTS below an OTS in a hypertree.
       Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits. */

    uint32_t indices[SPX_FORS_TREES];
    uint8_t roots[SPX_FORS_TREES * SPX_N] = { 0 };
    uint8_t leaf[SPX_N];
    uint32_t fors_tree_addr[8] = { 0 };
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;

    sphincsplus_copy_keypair_addr(fors_tree_addr, fors_addr);
    sphincsplus_copy_keypair_addr(fors_pk_addr, fors_addr);

    sphincsplus_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    sphincsplus_set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    sphincsplus_message_to_indices(indices, m);

    for (uint32_t i = 0; i < SPX_FORS_TREES; ++i)
    {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        sphincsplus_set_tree_height(fors_tree_addr, 0);
        sphincsplus_set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        sphincsplus_fors_sk_to_leaf(leaf, sig, pubseed, fors_tree_addr);
        sig += SPX_N;

        /* Derive the corresponding root node of this tree. */
        sphincsplus_compute_root(roots + i * SPX_N, leaf, indices[i], idx_offset,
            sig, SPX_FORS_HEIGHT, pubseed, fors_tree_addr);

        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    sphincsplus_thash(pk, roots, SPX_FORS_TREES, pubseed, fors_pk_addr);
}

/* wots.c */

static void sphincsplus_wots_gen_sk(uint8_t* sk, const uint8_t* sk_seed, uint32_t wots_addr[8])
{
    /* Computes the starting value for a chain, i.e. the secret key.
       Expects the address to be complete up to the chain address. */

    /* Make sure that the hash address is actually zeroed. */
    sphincsplus_set_hash_addr(wots_addr, 0);

    /* Generate sk element. */
    sphincsplus_prf_addr(sk, sk_seed, wots_addr);
}

static void sphincsplus_gen_chain(uint8_t* out, const uint8_t* in, uint32_t start, uint32_t steps, const uint8_t* pubseed, uint32_t addr[8])
{
    /* Computes the chaining function.
       out and in have to be n-byte arrays.
       Interprets in as start-th value of the chain.
       addr has to contain the address of the chain. */

    /* Initialize out with the value at position 'start'. */
    qsc_memutils_copy(out, in, SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for (size_t i = start; i < (start + steps) && i < SPX_WOTS_W; ++i)
    {
        sphincsplus_set_hash_addr(addr, (uint32_t)i);
        sphincsplus_thash(out, out, 1, pubseed, addr);
    }
}

static void sphincsplus_base_w(uint32_t* output, const int out_len, const uint8_t* input)
{
    /* sphincsplus_base_w algorithm as described in draft.
       Interprets an array of bytes as integers in base w.
       This only works when log_w is a divisor of 8. */

    size_t ictr;
    size_t octr;
    uint8_t total;
    int32_t bits;

    bits = 0;
    ictr = 0;
    octr = 0;

    for (int32_t consumed = 0; consumed < out_len; ++consumed)
    {
        if (bits == 0)
        {
            total = input[ictr];
            ++ictr;
            bits += 8;
        }

        bits -= SPX_WOTS_LOGW;
        output[octr] = (total >> bits) & (SPX_WOTS_W - 1);
        ++octr;
    }
}

static void sphincsplus_wots_checksum(uint32_t* csum_base_w, const uint32_t* msg_base_w)
{
    /* Computes the WOTS+ checksum over a message (in sphincsplus_base_w). */

    uint8_t csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    uint32_t csum;

    csum = 0;

    /* Compute checksum. */
    for (size_t i = 0; i < SPX_WOTS_LEN1; ++i)
    {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    /* Convert checksum to sphincsplus_base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    sphincsplus_ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    sphincsplus_base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

static void sphincsplus_chain_lengths(uint32_t* lengths, const uint8_t* msg)
{
    /* Takes a message and derives the matching chain lengths */

    sphincsplus_base_w(lengths, SPX_WOTS_LEN1, msg);
    sphincsplus_wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
}

static void sphincsplus_wots_gen_pk(uint8_t* pk, const uint8_t* sk_seed, const uint8_t* pubseed, uint32_t addr[8])
{
    /* WOTS key generation. Takes a 32 byte sk_seed, expands it to WOTS private key
       elements and computes the corresponding public key.
       It requires the seed pubseed (used to generate bitmasks and hash keys)
       and the address of this WOTS key pair.
       Writes the computed public key to 'pk'. */

    for (size_t i = 0; i < SPX_WOTS_LEN; ++i)
    {
        sphincsplus_set_chain_addr(addr, (uint32_t)i);
        sphincsplus_wots_gen_sk(pk + i * SPX_N, sk_seed, addr);
        sphincsplus_gen_chain(pk + i * SPX_N, pk + i * SPX_N, 0, SPX_WOTS_W - 1, pubseed, addr);
    }
}

static void sphincsplus_wots_sign(uint8_t* sig, const uint8_t* msg, const uint8_t* sk_seed, const uint8_t* pubseed, uint32_t addr[8])
{
    /* Takes a n-byte message and the 32-byte sk_see to compute a signature 'sig'. */

    uint32_t lengths[SPX_WOTS_LEN];

    sphincsplus_chain_lengths(lengths, msg);

    for (size_t i = 0; i < SPX_WOTS_LEN; ++i)
    {
        sphincsplus_set_chain_addr(addr, (uint32_t)i);
        sphincsplus_wots_gen_sk(sig + i * SPX_N, sk_seed, addr);
        sphincsplus_gen_chain(sig + i * SPX_N, sig + i * SPX_N, 0, lengths[i], pubseed, addr);
    }
}

static void sphincsplus_wots_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* msg, const uint8_t* pubseed, uint32_t addr[8])
{
    /* Takes a WOTS signature and an n-byte message, computes a WOTS public key.
       Writes the computed public key to 'pk'. */

    uint32_t lengths[SPX_WOTS_LEN];

    sphincsplus_chain_lengths(lengths, msg);

    for (size_t i = 0; i < SPX_WOTS_LEN; ++i)
    {
        sphincsplus_set_chain_addr(addr, (uint32_t)i);
        sphincsplus_gen_chain(pk + i * SPX_N, sig + i * SPX_N, lengths[i], SPX_WOTS_W - 1 - lengths[i], pubseed, addr);
    }
}

static void sphincsplus_wots_gen_leaf(uint8_t* leaf, const uint8_t* sk_seed, const uint8_t* pubseed, uint32_t addr_idx, const uint32_t tree_addr[8])
{
    /* Computes the leaf at a given address. First generates the WOTS key pair,
       then computes leaf by hashing horizontally. */

    uint8_t pk[SPX_WOTS_BYTES];
    uint32_t wots_addr[8] = { 0 };
    uint32_t wots_pk_addr[8] = { 0 };

    sphincsplus_set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    sphincsplus_set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    sphincsplus_copy_subtree_addr(wots_addr, tree_addr);
    sphincsplus_set_keypair_addr(wots_addr, addr_idx);
    sphincsplus_wots_gen_pk(pk, sk_seed, pubseed, wots_addr);

    sphincsplus_copy_keypair_addr(wots_pk_addr, wots_addr);
    sphincsplus_thash(leaf, pk, SPX_WOTS_LEN, pubseed, wots_pk_addr);
}

/* sign.c */

size_t sphincsplus_ref_sign_secretkeybytes(void)
{
    /* Returns the length of a secret key, in bytes */

    return SPHINCSPLUS_PRIVATEKEY_SIZE;
}

size_t sphincsplus_ref_sign_publickeybytes(void)
{
    /* Returns the length of a public key, in bytes */

    return SPHINCSPLUS_PUBLICKEY_SIZE;
}

size_t sphincsplus_ref_sign_bytes(void)
{
    /* Returns the length of a signature, in bytes */

    return SPHINCSPLUS_SIGNATURE_SIZE;
}

size_t sphincsplus_ref_sign_seedbytes(void)
{
    /* Returns the length of the seed required to generate a key pair, in bytes */

    return SPHINCSPLUS_CRYPTO_SEEDBYTES;
}

int32_t sphincsplus_ref_generate_seed_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed)
{
    /* Generates an SPX key pair given a seed of length
       Format sk [SK_SEED || SK_PRF || PUB_SEED || root]
       Format pk [PUB_SEED || root] */
    /* We do not need the auth path in key generation, but it simplifies the
        code to have just one sphincsplus_treehash routine that computes both root and path
        in one function. */

    uint8_t auth_path[SPX_TREE_HEIGHT * SPX_N];
    uint32_t top_tree_addr[8] = { 0 };

    sphincsplus_set_layer_addr(top_tree_addr, SPX_D - 1);
    sphincsplus_set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    qsc_memutils_copy(sk, seed, SPHINCSPLUS_CRYPTO_SEEDBYTES);
    qsc_memutils_copy(pk, sk + 2 * SPX_N, SPX_N);

    /* Compute root node of the top-most subtree. */
    sphincsplus_treehash(sk + 3 * SPX_N, auth_path, sk, sk + 2 * SPX_N, 0, 0, SPX_TREE_HEIGHT, sphincsplus_wots_gen_leaf, top_tree_addr);

    qsc_memutils_copy(pk + SPX_N, sk + 3 * SPX_N, SPX_N);

    return 0;
}

void sphincsplus_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    /* Generates an SPX key pair.
       Format sk [SK_SEED || SK_PRF || PUB_SEED || root]
       Format pk [PUB_SEED || root] */

    uint8_t seed[SPHINCSPLUS_CRYPTO_SEEDBYTES];

    rng_generate(seed, SPHINCSPLUS_CRYPTO_SEEDBYTES);
    sphincsplus_ref_generate_seed_keypair(pk, sk, seed);
}

void sphincsplus_ref_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    /* Returns an array containing a detached signature */

    const uint8_t *sk_seed = sk;
    const uint8_t *sk_prf = sk + SPX_N;
    const uint8_t *pk = sk + 2 * SPX_N;
    const uint8_t *pubseed = pk;

    uint8_t optrand[SPX_N];
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t root[SPX_N];
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };

    sphincsplus_set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    sphincsplus_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    rng_generate(optrand, SPX_N);

    /* Compute the digest randomization value. */
    sphincsplus_gen_message_random(sig, sk_prf, optrand, m, mlen);

    /* Derive the message digest and leaf index from R, PK and M. */
    sphincsplus_hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen);
    sig += SPX_N;

    sphincsplus_set_tree_addr(wots_addr, tree);
    sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    sphincsplus_fors_sign(sig, root, mhash, sk_seed, pubseed, wots_addr);
    sig += SPX_FORS_BYTES;

    for (size_t i = 0; i < SPX_D; ++i)
    {
        sphincsplus_set_layer_addr(tree_addr, (uint32_t)i);
        sphincsplus_set_tree_addr(tree_addr, tree);

        sphincsplus_copy_subtree_addr(wots_addr, tree_addr);
        sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        sphincsplus_wots_sign(sig, root, sk_seed, pubseed, wots_addr);
        sig += SPX_WOTS_BYTES;

        /* Compute the authentication path for the used WOTS leaf. */
        sphincsplus_treehash(root, sig, sk_seed, pubseed, idx_leaf, 0,
            SPX_TREE_HEIGHT, sphincsplus_wots_gen_leaf, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *siglen = SPX_BYTES;
}

bool sphincsplus_ref_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk)
{
    /* Verifies a detached signature and message under a given public key */

    const uint8_t *pubseed = pk;
    const uint8_t *pub_root = pk + SPX_N;
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t wots_pk[SPX_WOTS_BYTES];
    uint8_t root[SPX_N];
    uint8_t leaf[SPX_N];
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };
    uint32_t wots_pk_addr[8] = { 0 };
    bool res;

    if (siglen == SPX_BYTES)
    {
        sphincsplus_set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
        sphincsplus_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
        sphincsplus_set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

        /* Derive the message digest and leaf index from R || PK || M */
        /* The additional SPX_N is a result of the hash domain separator. */
        sphincsplus_hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen);
        sig += SPX_N;

        /* Layer correctly defaults to 0, so no need to sphincsplus_set_layer_addr */
        sphincsplus_set_tree_addr(wots_addr, tree);
        sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

        sphincsplus_fors_pk_from_sig(root, sig, mhash, pubseed, wots_addr);
        sig += SPX_FORS_BYTES;

        /* For each subtree.. */
        for (uint32_t i = 0; i < SPX_D; ++i)
        {
            sphincsplus_set_layer_addr(tree_addr, i);
            sphincsplus_set_tree_addr(tree_addr, tree);

            sphincsplus_copy_subtree_addr(wots_addr, tree_addr);
            sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

            sphincsplus_copy_keypair_addr(wots_pk_addr, wots_addr);

            /* The WOTS public key is only correct if the signature was correct. */
            /* Initially, root is the FORS pk, but on subsequent iterations it is
               the root of the subtree below the currently processed subtree. */
            sphincsplus_wots_pk_from_sig(wots_pk, sig, root, pubseed, wots_addr);
            sig += SPX_WOTS_BYTES;

            /* Compute the leaf node using the WOTS public key. */
            sphincsplus_thash(leaf, wots_pk, SPX_WOTS_LEN, pubseed, wots_pk_addr);

            /* Compute the root node of this subtree. */
            sphincsplus_compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT, pubseed, tree_addr);
            sig += SPX_TREE_HEIGHT * SPX_N;

            /* Update the indices for the next layer. */
            idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
            tree = tree >> SPX_TREE_HEIGHT;
        }

        /* Check if the root node equals the root node in the public key. */
        res = (qsc_intutils_verify(root, pub_root, SPX_N) == 0);
    }
    else
    {
        res = false;
    }

    return res;
}

void sphincsplus_ref_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    /* Returns an array containing the signature followed by the message */

    size_t siglen;

    sphincsplus_ref_sign_signature(sm, &siglen, m, mlen, sk, rng_generate);
    qsc_memutils_copy(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;
}

bool sphincsplus_ref_sign_open(uint8_t* m, size_t* mlen, const uint8_t* sm, size_t smlen, const uint8_t* pk)
{
    /* Verifies a given signature-message pair under a given public key */

    bool res;

    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smlen >= SPX_BYTES)
    {
        *mlen = smlen - SPX_BYTES;
        res = sphincsplus_ref_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, *mlen, pk);

        if (res == true)
        {
            /* If verification was successful, move the message to the right place. */
            qsc_memutils_copy(m, sm + SPX_BYTES, *mlen);
        }
        else
        {
            qsc_memutils_clear(m, smlen);
            *mlen = 0;
            res = false;
        }
    }
    else
    {
        qsc_memutils_clear(m, smlen);
        *mlen = 0;
        res = false;
    }

    return res;
}
