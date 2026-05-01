#include "sphincsplusbase.h"
#include "memutils.h"
#include "sha3.h"

/* params.h */
#if defined(QSC_SPHINCSPLUS_S1S128SHAKERS)

/* the hash absorbtion rate */
#define SPX_HASH_RATE (QSC_KECCAK_256_RATE)
/* Hash output length in bytes. */
#define SPX_N 16U
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 63U
/* Number of subtree layer. */
#define SPX_D 7U
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 12U
#define SPX_FORS_TREES 14U
/* Winternitz parameter, */
#define SPX_WOTS_W 16U

#elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)

/* the hash absorbtion rate */
#define SPX_HASH_RATE (QSC_KECCAK_256_RATE)
/* Hash output length in bytes. */
#define SPX_N 24U
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 63U
/* Number of subtree layer. */
#define SPX_D 7U
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 14U
#define SPX_FORS_TREES 17U
/* Winternitz parameter, */
#define SPX_WOTS_W 16U

#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)

/* the hash absorbtion rate */
#define SPX_HASH_RATE (QSC_KECCAK_256_RATE)
/* Hash output length in bytes. */
#define SPX_N 32U
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 64U
/* Number of subtree layer. */
#define SPX_D 8U
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 14U
#define SPX_FORS_TREES 22U
/* Winternitz parameter, */
#define SPX_WOTS_W 16U

#elif defined(QSC_SPHINCSPLUS_S6S512SHAKERS)

/* the hash absorbtion rate */
#define SPX_HASH_RATE (QSC_KECCAK_512_RATE)
/* Hash output length in bytes. */
#define SPX_N 64U
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 70U
/* Number of subtree layer. */
#define SPX_D 10U
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 14U
#define SPX_FORS_TREES 26U
/* Winternitz parameter, */
#define SPX_WOTS_W 16U

#endif

 /* For clarity */
#define SPX_ADDR_BYTES 32U

/* WOTS parameters. */
#if SPX_WOTS_W == 256U
#   define SPX_WOTS_LOGW 8U
#elif SPX_WOTS_W == 16U
#   define SPX_WOTS_LOGW 4U
#else
#   error SPX_WOTS_W assumed 16 or 256
#endif

#define SPX_WOTS_LEN1 (8U * SPX_N / SPX_WOTS_LOGW)

/* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#if SPX_WOTS_W == 256U
#   if SPX_N <= 1
#       define SPX_WOTS_LEN2 1U
#   elif SPX_N <= 256
#       define SPX_WOTS_LEN2 2U
#   else
#       error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
#   endif
#elif SPX_WOTS_W == 16U
#   if SPX_N <= 8U
#       define SPX_WOTS_LEN2 2U
#   elif SPX_N <= 136U
#       define SPX_WOTS_LEN2 3U
#   elif SPX_N <= 256U
#       define SPX_WOTS_LEN2 4U
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
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7U) / 8U)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1U) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes. */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2U * SPX_N)
#define SPX_SK_BYTES (2U * SPX_N + SPX_PK_BYTES)

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
#define SPX_OPTRAND_BYTES 32U

/* Offsets of various fields in the address structure when we use SHAKE as the Sphincs+ hash function */
/* The byte used to specify the Merkle tree layer */
#define SPX_OFFSET_LAYER 3U
/* The start of the 8 byte field used to specify the tree */
#define SPX_OFFSET_TREE 8U
/* The byte used to specify the hash type (reason) */
#define SPX_OFFSET_TYPE 19U
/* The start of the 4 byte field used to specify the key pair address */ 
#define SPX_OFFSET_KP_ADDR 20U 
/* The low byte used to specify the key pair */
#define SPX_OFFSET_KP_ADDR1 23U
/* The high byte used to specify the key pair (which one-time signature) */
#define SPX_OFFSET_KP_ADDR2 22U
/* The byte used to specify the chain address (which Winternitz chain) */
#define SPX_OFFSET_CHAIN_ADDR 27U
/* The byte used to specify the hash address (where in the Winternitz chain) */
#define SPX_OFFSET_HASH_ADDR 31U
/* The byte used to specify the height of this node in the FORS or Merkle tree */
#define SPX_OFFSET_TREE_HGT  27U
/* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */
#define SPX_OFFSET_TREE_INDEX 28U

/* The hash types that are passed to set_type */
#define SPX_ADDR_TYPE_WOTS 0U
#define SPX_ADDR_TYPE_WOTSPK 1U
#define SPX_ADDR_TYPE_HASHTREE 2U
#define SPX_ADDR_TYPE_FORSTREE 3U
#define SPX_ADDR_TYPE_FORSPK 4U
#define SPX_ADDR_TYPE_WOTS_PRF 5U
#define SPX_ADDR_TYPE_FORS_PRF 6U

#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1U))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7U) / 8U)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7U) / 8U)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

#define SPHINCSPLUS_PRIVATEKEY_SIZE SPX_SK_BYTES
#define SPHINCSPLUS_PUBLICKEY_SIZE SPX_PK_BYTES
#define SPHINCSPLUS_SIGNATURE_SIZE SPX_BYTES
#define SPHINCSPLUS_CRYPTO_SEEDBYTES (3U * SPX_N)
#define SPHINCSPLUS_CONTEXT_SIZE 257U

typedef struct 
{
    uint8_t pub_seed[SPX_N];
    uint8_t sk_seed[SPX_N];
} spx_ctx;

typedef struct
{
    uint32_t leaf_addrx[8U];
} fors_gen_leaf_info;

/*
 * This is here to provide an interface to the internal wots_gen_leafx1
 * routine.  While this routine is not referenced in the package outside of
 * wots.c, it is called from the stand-alone benchmark code to characterize
 * the performance
 */
typedef struct 
{
    uint8_t* wots_sig;
    uint32_t wots_sign_leaf;
    uint32_t* wots_steps;
    uint32_t leaf_addr[8U];
    uint32_t pk_addr[8U];
} leaf_info_x1;

/* utils.c */

static void sphincsplus_ull_to_bytes(uint8_t* out, uint32_t otplen, uint64_t in)
{
    QSC_ASSERT(out != NULL);

    size_t pos;

    pos = otplen;

    do
    {
        --pos;
        out[pos] = in & 0xFFU;
        in = in >> 8;
    } 
    while (pos > 0U);
}

static void sphincsplus_u32_to_bytes(uint8_t* out, uint32_t in)
{
    QSC_ASSERT(out != NULL);

    out[0U] = (uint8_t)(in >> 24);
    out[1U] = (uint8_t)(in >> 16);
    out[2U] = (uint8_t)(in >> 8);
    out[3U] = (uint8_t)in;
}

static uint64_t sphincsplus_bytes_to_ull(const uint8_t* in, uint32_t inlen)
{
    QSC_ASSERT(in != NULL);

    uint64_t ret;

    ret = 0U;

    for (size_t i = 0U; i < inlen; ++i)
    {
        ret |= ((uint64_t)in[i]) << (8U * (inlen - 1U - i));
    }

    return ret;
}

/* address */

static void sphincsplus_set_layer_addr(uint32_t addr[8U], uint32_t layer)
{
    /* Specify which level of Merkle tree (the "layer") we're working on */
    ((unsigned char *)addr)[SPX_OFFSET_LAYER] = (unsigned char)layer;
}

static void sphincsplus_set_tree_addr(uint32_t addr[8U], uint64_t tree)
{
    /* Specify which Merkle tree within the level (the "tree address") we're working on */
#if (SPX_TREE_HEIGHT * (SPX_D - 1)) > 64U
    #error Subtree addressing is currently limited to at most 2^64 trees
#endif
    sphincsplus_ull_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE], 8U, tree );
}

static void sphincsplus_set_type(uint32_t addr[8U], uint32_t type)
{
/* Specify the reason we'll use this address structure for, that is, what
 * hash will we compute with it.  This is used so that unrelated types of
 * hashes don't accidentally get the same address structure.  The type will be
 * one of the SPX_ADDR_TYPE constants */
    ((unsigned char *)addr)[SPX_OFFSET_TYPE] = (unsigned char)type;
}

static void sphincsplus_copy_subtree_addr(uint32_t out[8U], const uint32_t in[8U])
{
    /* Copy the layer and tree fields of the address structure.  This is used
     * when we're doing multiple types of hashes within the same Merkle tree */
    qsc_memutils_copy(out, in, SPX_OFFSET_TREE + 8U);
}

/* These functions are used for OTS addresses. */

static void sphincsplus_set_keypair_addr(uint32_t addr[8U], uint32_t keypair)
{
    /* Specify which Merkle leaf we're working on; that is, which OTS keypair
     * we're talking about. */
    sphincsplus_u32_to_bytes(&((unsigned char*)addr)[SPX_OFFSET_KP_ADDR], keypair);
}

static void sphincsplus_copy_keypair_addr(uint32_t out[8U], const uint32_t in[8U])
{
    /* Copy the layer, tree and keypair fields of the address structure.  This is
     * used when we're doing multiple things within the same OTS keypair */
    qsc_memutils_copy(out, in, SPX_OFFSET_TREE + 8U);
    qsc_memutils_copy( (unsigned char *)out + SPX_OFFSET_KP_ADDR, (unsigned char*)in + SPX_OFFSET_KP_ADDR, 4U); 
}

static void sphincsplus_set_chain_addr(uint32_t addr[8U], uint32_t chain)
{
    /* Specify which Merkle chain within the OTS we're working with (the chain address) */
    ((unsigned char*)addr)[SPX_OFFSET_CHAIN_ADDR] = (unsigned char)chain;
}

static void sphincsplus_set_hash_addr(uint32_t addr[8U], uint32_t hash)
{
    /* Specify where in the Merkle chain we are (the hash address) */
    ((unsigned char*)addr)[SPX_OFFSET_HASH_ADDR] = (unsigned char)hash;
}

static void sphincsplus_set_tree_height(uint32_t addr[8U], uint32_t tree_height)
{
    /* Specify the height of the node in the Merkle/FORS tree we are in (the tree height) */
    ((unsigned char *)addr)[SPX_OFFSET_TREE_HGT] = (unsigned char)tree_height;
}

static void sphincsplus_set_tree_index(uint32_t addr[8U], uint32_t tree_index)
{
    /* Specify the distance from the left edge of the node in the Merkle/FORS tree (the tree index) */
    sphincsplus_u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE_INDEX], tree_index );
}

/* hash_shake.c */

static void sphincsplus_prf_addr(uint8_t* out, const spx_ctx* ctx, const uint32_t addr[8U])
{
    /* Computes PRF(pk_seed, sk_seed, addr) */

    uint8_t buf[(2U * SPX_N) + SPX_ADDR_BYTES];

    qsc_memutils_copy(buf, ctx->pub_seed, SPX_N);
    qsc_memutils_copy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    qsc_memutils_copy(buf + SPX_N + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);

#if defined(QSC_SPHINCSPLUS_EXTENDED)
    qsc_shake512_compute(out, SPX_N, buf, (2U * SPX_N) + SPX_ADDR_BYTES);
#else
    qsc_shake256_compute(out, SPX_N, buf, (2U * SPX_N) + SPX_ADDR_BYTES);
#endif
}

static void sphincsplus_gen_message_random(uint8_t* R, const uint8_t* sk_prf, const uint8_t* optrand, const uint8_t* m, size_t mlen, const uint8_t* c, size_t clen)
{
    /* Computes the message-dependent randomness R, using a secret seed and an
       optional randomization value as well as the message. */
    qsc_keccak_state kctx = { 0U };

    qsc_keccak_incremental_absorb(&kctx, SPX_HASH_RATE, sk_prf, SPX_N);
    qsc_keccak_incremental_absorb(&kctx, SPX_HASH_RATE, optrand, SPX_N);

    if (c != NULL && clen > 0)
    {
        qsc_keccak_incremental_absorb(&kctx, SPX_HASH_RATE, c, clen);
    }

    qsc_keccak_incremental_absorb(&kctx, SPX_HASH_RATE, m, mlen);
    qsc_keccak_incremental_finalize(&kctx, SPX_HASH_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(&kctx, SPX_HASH_RATE, R, SPX_N);
}

static void sphincsplus_hash_message(uint8_t* digest, uint64_t* tree, uint32_t* leaf_idx, const uint8_t* R, const uint8_t* pk, const uint8_t* m, size_t mlen, const uint8_t* c, size_t clen)
{
    /* Computes the message hash using R, the public key, and the message.
     * Outputs the message digest and the index of the leaf. The index is split in
     * the tree index and the leaf index, for convenient copying to an address. */

    uint8_t buf[SPX_DGST_BYTES] = { 0U };
    const uint8_t* bufp = buf;
    qsc_keccak_state kctx = { 0U };

    qsc_keccak_incremental_absorb(&kctx, SPX_HASH_RATE, R, SPX_N);
    qsc_keccak_incremental_absorb(&kctx, SPX_HASH_RATE, pk, SPX_PK_BYTES);

    if (c != NULL && clen > 0)
    {
        qsc_keccak_incremental_absorb(&kctx, SPX_HASH_RATE, c, clen);
    }

    qsc_keccak_incremental_absorb(&kctx, SPX_HASH_RATE, m, mlen);
    qsc_keccak_incremental_finalize(&kctx, SPX_HASH_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(&kctx, SPX_HASH_RATE, buf, SPX_DGST_BYTES);

    qsc_memutils_copy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64U
#error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = sphincsplus_bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64U - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)sphincsplus_bytes_to_ull(bufp, (uint32_t)SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0U) >> (32U - SPX_LEAF_BITS);
}

/* thash_shake_simple.c */

static void sphincsplus_thash_x1(uint8_t* out, const uint8_t* in, const spx_ctx* ctx, uint32_t addr[8U])
{
    /* Takes a single arrays of SPX_N bytes. */

    uint8_t buf[SPX_N + SPX_ADDR_BYTES + SPX_N] = { 0 };

    qsc_memutils_copy(buf, ctx->pub_seed, SPX_N);
    qsc_memutils_copy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    qsc_memutils_copy(buf + SPX_N + SPX_ADDR_BYTES, in, SPX_N);

#if defined(QSC_SPHINCSPLUS_EXTENDED)
    qsc_shake512_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + SPX_N);
#else
    qsc_shake256_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + SPX_N);
#endif
}

static void sphincsplus_thash_x2(uint8_t* out, const uint8_t* in, const spx_ctx* ctx, uint32_t addr[8U])
{
    /* Takes a single arrays of SPX_N bytes. */

    uint8_t buf[SPX_N + SPX_ADDR_BYTES + (SPX_N * 2U)] = { 0 };

    qsc_memutils_copy(buf, ctx->pub_seed, SPX_N);
    qsc_memutils_copy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    qsc_memutils_copy(buf + SPX_N + SPX_ADDR_BYTES, in, (SPX_N * 2U));

#if defined(QSC_SPHINCSPLUS_EXTENDED)
    qsc_shake512_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + (SPX_N * 2U));
#else
    qsc_shake256_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + (SPX_N * 2U));
#endif
}

static void sphincsplus_thash_fors(uint8_t* out, const uint8_t* in, const spx_ctx* ctx, uint32_t addr[8U])
{
    /* Takes a single arrays of SPX_N bytes. */

    uint8_t buf[SPX_N + SPX_ADDR_BYTES + (SPX_FORS_TREES * SPX_N)] = { 0 };

    qsc_memutils_copy(buf, ctx->pub_seed, SPX_N);
    qsc_memutils_copy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    qsc_memutils_copy(buf + SPX_N + SPX_ADDR_BYTES, in, SPX_FORS_TREES * SPX_N);

    qsc_shake256_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + (SPX_FORS_TREES * SPX_N));
}

static void sphincsplus_thash_wots(uint8_t* out, const uint8_t* in, const spx_ctx* ctx, uint32_t addr[8U])
{
    /* Takes a single arrays of SPX_N bytes. */

    uint8_t buf[SPX_N + SPX_ADDR_BYTES + (SPX_WOTS_LEN * SPX_N)] = { 0U };

    qsc_memutils_copy(buf, ctx->pub_seed, SPX_N);
    qsc_memutils_copy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    qsc_memutils_copy(buf + SPX_N + SPX_ADDR_BYTES, in, SPX_WOTS_LEN * SPX_N);

#if defined(QSC_SPHINCSPLUS_EXTENDED)
    qsc_shake512_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + (SPX_WOTS_LEN * SPX_N));
#else
    qsc_shake256_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + (SPX_WOTS_LEN * SPX_N));
#endif
}

/* fors.c */

static void sphincsplus_fors_gen_sk(uint8_t* sk, const spx_ctx* ctx, uint32_t fors_leaf_addr[8U])
{
    sphincsplus_prf_addr(sk, ctx, fors_leaf_addr);
}

static void sphincsplus_fors_sk_to_leaf(uint8_t* leaf, const uint8_t* sk, const spx_ctx* ctx, uint32_t fors_leaf_addr[8U])
{
    sphincsplus_thash_x1(leaf, sk, ctx, fors_leaf_addr);
}

static void sphincsplus_fors_gen_leafx1(unsigned char *leaf, const spx_ctx *ctx, uint32_t addr_idx, fors_gen_leaf_info* info)
{
    uint32_t* fors_leaf_addr = info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    sphincsplus_set_tree_index(fors_leaf_addr, addr_idx);
    sphincsplus_set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORS_PRF);
    sphincsplus_fors_gen_sk(leaf, ctx, fors_leaf_addr);

    sphincsplus_set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    sphincsplus_fors_sk_to_leaf(leaf, leaf, ctx, fors_leaf_addr);
}

static void sphincsplus_message_to_indices(uint32_t indices[SPX_FORS_TREES], const uint8_t *digest)
{
    size_t offset = 0;

    for (size_t t = 0; t < SPX_FORS_TREES; t++)
    {
        uint32_t idx = 0;

        /* Pull FORS_HEIGHT bits in big-endian order from the digest */
        for (size_t i = 0; i < SPX_FORS_HEIGHT; i++)
        {
            size_t bitpos = offset + i;
            size_t bytepos = bitpos / 8;
            size_t bit_in_byte = bitpos % 8;
            /* take the bit from the **MSB** side of the octet */
            uint8_t b = digest[bytepos];
            uint8_t bit = (b >> (7 - bit_in_byte)) & 0x1;
            /* and make it the (FORS_HEIGHT-1-i)th bit of idx */
            idx |= bit << (SPX_FORS_HEIGHT - 1 - i);
        }

        indices[t] = idx;
        offset += SPX_FORS_HEIGHT;
    }
}

static void sphincsplus_treehash_fors(uint8_t* root, uint8_t* auth_path, const spx_ctx *ctx, uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_addr[8U], void *info)
{
    /* Generate the entire Merkle tree, computing the authentication path for
     * leaf_idx, and the resulting root node using Merkle's TreeHash algorithm.
     * Expects the layer and tree parts of the tree_addr to be set, as well as the
     * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE)
     * This expects tree_addr to be initialized to the addr structures for the Merkle tree nodes
     * Applies the offset idx_offset to indices before building addresses, so that
     * it is possible to continue counting indices across trees.
     * This works by using the standard Merkle tree building algorithm. */

    /* This is where we keep the intermediate nodes */
    uint8_t stack[SPX_FORS_HEIGHT * SPX_N] = { 0U };
    uint32_t idx;
    uint32_t max_idx;

    max_idx = (uint32_t)((1 << SPX_FORS_HEIGHT) - 1U);

    for (idx = 0U;; ++idx) 
    {
        uint8_t current[2U * SPX_N];

        /* Current logical node is at index[SPX_N].  We do this to minimize the number of copies needed during a thash */
        sphincsplus_fors_gen_leafx1(&current[SPX_N], ctx, idx + idx_offset, info);

        /* Now combine the freshly generated right node with previously generated left ones */
        uint32_t internal_idx_offset = idx_offset;
        uint32_t internal_idx = idx;
        uint32_t internal_leaf = leaf_idx;
        uint32_t h;     /* The height we are in the Merkle tree */
        uint8_t* left;

        for (h=0U;; h++, internal_idx >>= 1U, internal_leaf >>= 1U) 
        {
            /* Check if we hit the top of the tree */
            if (h == SPX_FORS_HEIGHT)
            {
                /* We hit the root; return it */
                qsc_memutils_copy( root, &current[SPX_N], SPX_N );
                return;
            }

            /*
             * Check if the node we have is a part of the
             * authentication path; if it is, write it out
             */
            if ((internal_idx ^ internal_leaf) == 0x01U)
            {
                qsc_memutils_copy(&auth_path[h * SPX_N], &current[SPX_N], SPX_N);
            }

            /*
             * Check if we're at a left child; if so, stop going up the stack
             * Exception: if we've reached the end of the tree, keep on going
             * (so we combine the last 4 nodes into the one root node in two
             * more iterations)
             */
            if ((internal_idx & 1U) == 0U && idx < max_idx)
            {
                break;
            }

            /* Ok, we're at a right node */
            /* Now combine the left and right logical nodes together */

            /* Set the address of the node we're creating. */
            internal_idx_offset >>= 1U;
            sphincsplus_set_tree_height(tree_addr, h + 1U);
            sphincsplus_set_tree_index(tree_addr, (internal_idx / 2U) + internal_idx_offset);

            left = &stack[h * SPX_N];

            qsc_memutils_copy(&current[0U], left, SPX_N);
            sphincsplus_thash_x2(&current[1U * SPX_N], &current[0U * SPX_N], ctx, tree_addr);
        }

        /* We've hit a left child; save the current for when we get the corresponding right right */
        qsc_memutils_copy(&stack[h * SPX_N], &current[SPX_N], SPX_N);
    }
}

static void sphincsplus_fors_sign(uint8_t* sig, uint8_t* pk, const uint8_t* m, const spx_ctx* ctx, const uint32_t fors_addr[8U])
{
    /* Signs a message m, deriving the secret key from sk_seed and the FTS address.
     * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits. */

    uint32_t indices[SPX_FORS_TREES];
    uint8_t roots[SPX_FORS_TREES * SPX_N];
    uint32_t fors_tree_addr[8U] = { 0U };
    fors_gen_leaf_info fors_info = { 0U };
    uint32_t* fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8U] = { 0U };
    uint32_t idx_offset;
    uint32_t i;

    sphincsplus_copy_keypair_addr(fors_tree_addr, fors_addr);
    sphincsplus_copy_keypair_addr(fors_leaf_addr, fors_addr);

    sphincsplus_copy_keypair_addr(fors_pk_addr, fors_addr);
    sphincsplus_set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    sphincsplus_message_to_indices(indices, m);

    for (i = 0U; i < SPX_FORS_TREES; ++i) 
    {
        idx_offset = i * (1U << SPX_FORS_HEIGHT);

        sphincsplus_set_tree_height(fors_tree_addr, 0U);
        sphincsplus_set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        sphincsplus_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORS_PRF);

        /* Include the secret key part that produces the selected leaf node. */
        sphincsplus_fors_gen_sk(sig, ctx, fors_tree_addr);
        sphincsplus_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N;

        /* Compute the authentication path for this leaf node. */
        sphincsplus_treehash_fors(roots + (i * SPX_N), sig, ctx, indices[i], idx_offset, fors_tree_addr, &fors_info);

        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    sphincsplus_thash_fors(pk, roots, ctx, fors_pk_addr);
}

static void sphincsplus_compute_root(uint8_t* root, const uint8_t* leaf, uint32_t leaf_idx, uint32_t idx_offset, const uint8_t* auth_path, 
    uint32_t tree_height, const spx_ctx *ctx, uint32_t addr[8U])
{
    /* Computes a root node given a leaf and an auth path.
     * Expects address to be complete other than the tree_height and tree_index. */

    uint8_t buffer[2U * SPX_N];

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx & 1U) 
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

    for (uint32_t i = 0; i < tree_height - 1U; i++) 
    {
        leaf_idx >>= 1U;
        idx_offset >>= 1U;

        /* Set the address of the node we're creating. */
        sphincsplus_set_tree_height(addr, i + 1U);
        sphincsplus_set_tree_index(addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leaf_idx & 1U) 
        {
            sphincsplus_thash_x2(buffer + SPX_N, buffer, ctx, addr);
            qsc_memutils_copy(buffer, auth_path, SPX_N);
        }
        else 
        {
            sphincsplus_thash_x2(buffer, buffer, ctx, addr);
            qsc_memutils_copy(buffer + SPX_N, auth_path, SPX_N);
        }

        auth_path += SPX_N;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1U;
    idx_offset >>= 1U;
    sphincsplus_set_tree_height(addr, tree_height);
    sphincsplus_set_tree_index(addr, leaf_idx + idx_offset);
    sphincsplus_thash_x2(root, buffer, ctx, addr);
}

static void sphincsplus_fors_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* m, const spx_ctx* ctx, const uint32_t fors_addr[8U])
{
    /* Derives the FORS public key from a signature.
     * This can be used for verification by comparing to a known public key, or to
     * subsequently verify a signature on the derived public key. The latter is the
     * typical use-case when used as an FTS below an OTS in a hypertree.
     * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits. */

    uint32_t indices[SPX_FORS_TREES];
    uint8_t roots[SPX_FORS_TREES * SPX_N];
    uint8_t leaf[SPX_N];
    uint32_t fors_tree_addr[8U] = { 0U };
    uint32_t fors_pk_addr[8U] = { 0U };
    uint32_t idx_offset;

    sphincsplus_copy_keypair_addr(fors_tree_addr, fors_addr);
    sphincsplus_copy_keypair_addr(fors_pk_addr, fors_addr);

    sphincsplus_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    sphincsplus_set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    sphincsplus_message_to_indices(indices, m);

    for (uint32_t i = 0U; i < SPX_FORS_TREES; i++)
    {
        idx_offset = i * (1U << SPX_FORS_HEIGHT);

        sphincsplus_set_tree_height(fors_tree_addr, 0U);
        sphincsplus_set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        sphincsplus_fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N;

        /* Derive the corresponding root node of this tree. */
        sphincsplus_compute_root(roots + (i * SPX_N), leaf, indices[i], idx_offset, sig, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    sphincsplus_thash_fors(pk, roots, ctx, fors_pk_addr);
}

/* wotsx1.c */

static void sphincsplus_wots_gen_leafx1(uint8_t* dest, const spx_ctx* ctx, uint32_t leaf_idx, leaf_info_x1* info)
{
    uint8_t pk_buffer[SPX_WOTS_BYTES];
    uint32_t* leaf_addr;
    uint32_t* pk_addr;
    uint8_t* buffer;
    uint32_t wots_k_mask;

    leaf_addr = info->leaf_addr;
    pk_addr = info->pk_addr;

    /* This generates a WOTS public key
     * It also generates the WOTS signature if leaf_info indicates
     * that we're signing with this WOTS key */
    if (leaf_idx == info->wots_sign_leaf) 
    {
        /* We're traversing the leaf that's signing; generate the WOTS signature */
        wots_k_mask = 0;
    }
    else
    {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = (uint32_t)~0;
    }

    sphincsplus_set_keypair_addr( leaf_addr, leaf_idx );
    sphincsplus_set_keypair_addr( pk_addr, leaf_idx );
    buffer = pk_buffer;

    for (uint32_t i = 0; i < SPX_WOTS_LEN; ++i)
    {
        /* Set wots_k to the step if we're generating a signature, ~0 if we're not */
        uint32_t wots_k; 

        wots_k = info->wots_steps[i] | wots_k_mask; 

        /* Start with the secret seed */
        sphincsplus_set_chain_addr(leaf_addr, i);
        sphincsplus_set_hash_addr(leaf_addr, 0);
        sphincsplus_set_type(leaf_addr, SPX_ADDR_TYPE_WOTS_PRF);

        sphincsplus_prf_addr(buffer, ctx, leaf_addr);
        sphincsplus_set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (uint32_t k = 0;; ++k) 
        {
            /* Check if this is the value that needs to be saved as a part of the WOTS signature */
            if (k == wots_k)
            {
                qsc_memutils_copy(info->wots_sig + (i * SPX_N), buffer, SPX_N );
            }

            /* Check if we hit the top of the chain */
            if (k == SPX_WOTS_W - 1U)
            {
                break;
            }

            /* Iterate one step on the chain */
            sphincsplus_set_hash_addr(leaf_addr, k);

            sphincsplus_thash_x1(buffer, buffer, ctx, leaf_addr);
        }

        buffer += SPX_N;
    }

    /* Do the final thash to generate the public keys */
    sphincsplus_thash_wots(dest, pk_buffer, ctx, pk_addr);
}

/* utils.c */

static void sphincsplus_treehash_wots(uint8_t* root, uint8_t* auth_path, const spx_ctx *ctx, uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_addr[8U], leaf_info_x1* info)
{
    /* Generate the entire Merkle tree, computing the authentication path for
     * leaf_idx, and the resulting root node using Merkle's TreeHash algorithm.
     * Expects the layer and tree parts of the tree_addr to be set, as well as the
     * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE)
     * This expects tree_addr to be initialized to the addr structures for the Merkle tree nodes
     * Applies the offset idx_offset to indices before building addresses, so that
     * it is possible to continue counting indices across trees.
     * This works by using the standard Merkle tree building algorithm. */

    /* This is where we keep the intermediate nodes */
    uint8_t stack[SPX_TREE_HEIGHT * SPX_N] = { 0U };
    uint32_t idx;
    uint32_t max_idx;
    uint32_t internal_idx_offset;
    uint32_t internal_idx;
    uint32_t internal_leaf;
    uint32_t h;     /* The height we are in the Merkle tree */
    uint8_t* left;

    max_idx = (uint32_t)((1U << SPX_TREE_HEIGHT) - 1U);

    for (idx = 0U;; ++idx) 
    {
        uint8_t current[2U * SPX_N];

        /* Current logical node is at index[SPX_N].  We do this to minimize the number of copies needed during a thash */
        sphincsplus_wots_gen_leafx1(&current[SPX_N], ctx, idx + idx_offset, info);

        /* Now combine the freshly generated right node with previously generated left ones */
        internal_idx_offset = idx_offset;
        internal_idx = idx;
        internal_leaf = leaf_idx;

        for (h=0U;; h++, internal_idx >>= 1U, internal_leaf >>= 1U) 
        {
            /* Check if we hit the top of the tree */
            if (h == SPX_TREE_HEIGHT)
            {
                /* We hit the root; return it */
                qsc_memutils_copy( root, &current[SPX_N], SPX_N );
                return;
            }

            /*
             * Check if the node we have is a part of the
             * authentication path; if it is, write it out
             */
            if ((internal_idx ^ internal_leaf) == 0x01U)
            {
                qsc_memutils_copy(&auth_path[h * SPX_N], &current[SPX_N], SPX_N);
            }

            /*
             * Check if we're at a left child; if so, stop going up the stack
             * Exception: if we've reached the end of the tree, keep on going
             * (so we combine the last 4 nodes into the one root node in two
             * more iterations)
             */
            if ((internal_idx & 1U) == 0U && idx < max_idx)
            {
                break;
            }

            /* Ok, we're at a right node */
            /* Now combine the left and right logical nodes together */

            /* Set the address of the node we're creating. */
            internal_idx_offset >>= 1U;
            sphincsplus_set_tree_height(tree_addr, h + 1U);
            sphincsplus_set_tree_index(tree_addr, (internal_idx / 2U) + internal_idx_offset);

            left = &stack[h * SPX_N];

            qsc_memutils_copy(&current[0], left, SPX_N);
            sphincsplus_thash_x2(&current[1 * SPX_N], &current[0U * SPX_N], ctx, tree_addr);
        }

        /* We've hit a left child; save the current for when we get the corresponding right right */
        qsc_memutils_copy(&stack[h * SPX_N], &current[SPX_N], SPX_N);
    }
}

/* wots.c */

static void sphincsplus_gen_chain(uint8_t* out, const uint8_t* in, uint32_t start, uint32_t steps, const spx_ctx *ctx, uint32_t addr[8U])
{
    /* Computes the chaining function out and in have to be n-byte arrays.
     * Interprets in as start-th value of the chain, addr has to contain the address of the chain. */

    /* Initialize out with the value at position 'start'. */
    qsc_memutils_copy(out, in, SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for (uint32_t i = start; i < (start+steps) && i < SPX_WOTS_W; ++i)
    {
        sphincsplus_set_hash_addr(addr, i);
        sphincsplus_thash_x1(out, out, ctx, addr);
    }
}

static void sphincsplus_base_w(uint32_t* output, const int32_t out_len, const uint8_t* input)
{
    /* base_w algorithm as described in draft.
     * Interprets an array of bytes as integers in base w.
     * This only works when log_w is a divisor of 8. */

    int32_t bits;
    int32_t consumed;
    int32_t in;
    int32_t out;
    uint8_t total;

    in = 0;
    out = 0;
    bits = 0;
    total = 0;

    for (consumed = 0; consumed < out_len; consumed++) 
    {
        if (bits == 0)
        {
            total = input[in];
            in++;
            bits += 8;
        }

        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W - 1U);
        ++out;
    }
}

static void sphincsplus_wots_checksum(uint32_t* csum_base_w, const uint32_t* msg_base_w)
{
    /* Computes the WOTS+ checksum over a message (in base_w). */

    uint8_t csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7U) / 8U];
    uint32_t csum;

    csum = 0U;

    /* Compute checksum. */
    for (uint32_t i = 0U; i < SPX_WOTS_LEN1; ++i) 
    {
        csum += SPX_WOTS_W - 1U - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8U - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8U)) % 8U);
    sphincsplus_ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    sphincsplus_base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

static void sphincsplus_chain_lengths(uint32_t* lengths, const uint8_t* msg)
{
    /* Takes a message and derives the matching chain lengths. */

    sphincsplus_base_w(lengths, SPX_WOTS_LEN1, msg);
    sphincsplus_wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
}

static void sphincsplus_wots_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* msg, const spx_ctx *ctx, uint32_t addr[8U])
{
    /* Takes a WOTS signature and an n-byte message, computes a WOTS public key.
     * Writes the computed public key to 'pk'. */

    uint32_t lengths[SPX_WOTS_LEN] = { 0U };

    sphincsplus_chain_lengths(lengths, msg);

    for (uint32_t i = 0U; i < SPX_WOTS_LEN; i++) 
    {
        sphincsplus_set_chain_addr(addr, i);
        sphincsplus_gen_chain(pk + (i * SPX_N), sig + (i * SPX_N), lengths[i], SPX_WOTS_W - 1U - lengths[i], ctx, addr);
    }
}

/* merkle.c */

static void sphincsplus_merkle_sign(uint8_t* sig, uint8_t* root, const spx_ctx *ctx, uint32_t wots_addr[8U], uint32_t tree_addr[8U], uint32_t idx_leaf)
{
    /* This generates a Merkle signature (WOTS signature followed by the Merkle
     * authentication path).  This is in this file because most of the complexity
     * is involved with the WOTS signature; the Merkle authentication path logic
     * is mostly hidden in treehashx4 */

    uint32_t steps[SPX_WOTS_LEN];
    uint8_t* auth_path;
    leaf_info_x1 info = { 0U };

    auth_path = sig + SPX_WOTS_BYTES;
    info.wots_sig = sig;
    sphincsplus_chain_lengths(steps, root);
    info.wots_steps = steps;

    sphincsplus_set_type(&tree_addr[0U], SPX_ADDR_TYPE_HASHTREE);
    sphincsplus_set_type(&info.pk_addr[0U], SPX_ADDR_TYPE_WOTSPK);
    sphincsplus_copy_subtree_addr(&info.leaf_addr[0U], wots_addr);
    sphincsplus_copy_subtree_addr(&info.pk_addr[0U], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    sphincsplus_treehash_wots(root, auth_path, ctx, idx_leaf, 0U, tree_addr, &info);
}

static void sphincsplus_merkle_gen_root(uint8_t* root, const spx_ctx* ctx)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    uint8_t auth_path[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint32_t top_tree_addr[8U] = { 0U };
    uint32_t wots_addr[8U] = { 0U };

    sphincsplus_set_layer_addr(top_tree_addr, SPX_D - 1U);
    sphincsplus_set_layer_addr(wots_addr, SPX_D - 1U);
    /* ~0 means "don't bother generating an auth path */ 
    sphincsplus_merkle_sign(auth_path, root, ctx, wots_addr, top_tree_addr, (uint32_t)~0);
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

bool sphincsplus_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    /* Generates an SPX key pair.
       Format sk [SK_SEED || SK_PRF || PUB_SEED || root]
       Format pk [PUB_SEED || root] */

    uint8_t seed[SPHINCSPLUS_CRYPTO_SEEDBYTES] = { 0U };
    bool res;

    res = rng_generate(seed, SPHINCSPLUS_CRYPTO_SEEDBYTES);

    if (res == true)
    {
        res = sphincsplus_ref_generate_seeded_keypair(pk, sk, seed);
    }

    return res;
}

bool sphincsplus_ref_generate_seeded_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed)
{
    spx_ctx ctx = { 0U };
    bool res;

    res = false;

    if (pk != NULL && sk != NULL && seed != NULL)
    {
        /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
        qsc_memutils_copy(sk, seed, SPHINCSPLUS_CRYPTO_SEEDBYTES);
        qsc_memutils_copy(pk, sk + (2U * SPX_N), SPX_N);
        qsc_memutils_copy(ctx.pub_seed, pk, SPX_N);
        qsc_memutils_copy(ctx.sk_seed, sk, SPX_N);

        /* Compute root node of the top-most subtree. */
        sphincsplus_merkle_gen_root(sk + (3 * SPX_N), &ctx);
        qsc_memutils_copy(pk + SPX_N, sk + (3U * SPX_N), SPX_N);
        res = true;
    }

    return res;
}

bool sphincsplus_ref_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* sk, const uint8_t* seed)
{
    bool res;

    res = false;

    if (ctxlen <= 255U)
    {
        uint8_t prec[SPHINCSPLUS_CONTEXT_SIZE] = { 0U };

        /* prepare pre = (0, contextlen, ctx) */
        prec[0U] = 0U;
        prec[1U] = (uint8_t)ctxlen;

        if (context != NULL && ctxlen != 0)
        {
            qsc_memutils_copy(prec + 2U, context, ctxlen);
        }

        for (size_t i = 0U; i < msglen; ++i)
        {
            signedmsg[SPHINCSPLUS_SIGNATURE_SIZE + msglen - 1U - i] = message[msglen - 1U - i];
        }

        res = sphincsplus_ref_sign_signature(signedmsg, smsglen, signedmsg + SPHINCSPLUS_SIGNATURE_SIZE, msglen, prec, ctxlen + 2U, sk, seed);
        *smsglen += msglen;
    }

    return res;
}

bool sphincsplus_ref_sign_signature(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* sk, const uint8_t* seed)
{
    spx_ctx sctx = { 0U };
    uint32_t wots_addr[8U] = { 0U };
    uint32_t tree_addr[8U] = { 0U };
    uint8_t mhash[SPX_FORS_MSG_BYTES] = { 0U };
    uint8_t root[SPX_N] = { 0U };
    uint64_t tree;
    uint32_t i;
    uint32_t idx_leaf;
    bool res;

    const uint8_t* sk_prf = sk + SPX_N;
    const uint8_t* pk = sk + (2U * SPX_N);
    res = false;

    if (signedmsg != NULL && smsglen != NULL && message != NULL && context != NULL && sk != NULL && seed != NULL)
    {
        qsc_memutils_copy(sctx.sk_seed, sk, SPX_N);
        qsc_memutils_copy(sctx.pub_seed, pk, SPX_N);

        sphincsplus_set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
        sphincsplus_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

        /* Compute the digest randomization value. */
        sphincsplus_gen_message_random(signedmsg, sk_prf, seed, message, msglen, context, ctxlen);

        /* Derive the message digest and leaf index from R, PK and M. */
        sphincsplus_hash_message(mhash, &tree, &idx_leaf, signedmsg, pk, message, msglen, context, ctxlen);
        signedmsg += SPX_N;

        sphincsplus_set_tree_addr(wots_addr, tree);
        sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

        /* Sign the message hash using FORS. */
        sphincsplus_fors_sign(signedmsg, root, mhash, &sctx, wots_addr);
        signedmsg += SPX_FORS_BYTES;

        for (i = 0U; i < SPX_D; i++)
        {
            sphincsplus_set_layer_addr(tree_addr, i);
            sphincsplus_set_tree_addr(tree_addr, tree);

            sphincsplus_copy_subtree_addr(wots_addr, tree_addr);
            sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

            sphincsplus_merkle_sign(signedmsg, root, &sctx, wots_addr, tree_addr, idx_leaf);
            signedmsg += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

            /* Update the indices for the next layer. */
            idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1U));
            tree = tree >> SPX_TREE_HEIGHT;
        }

        qsc_memutils_secure_erase(&sctx, sizeof(spx_ctx));
        *smsglen = SPX_BYTES;
        res = true;
    }

    return res;
}

bool sphincsplus_ref_verify(const uint8_t* signedmsg, size_t smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* pk)
{
    spx_ctx sctx = { 0U };
    uint8_t mhash[SPX_FORS_MSG_BYTES] = { 0U };
    uint8_t wots_pk[SPX_WOTS_BYTES] = { 0U };
    uint8_t root[SPX_N] = { 0U };
    uint8_t leaf[SPX_N] = { 0U };
    uint32_t wots_addr[8U] = { 0U };
    uint32_t tree_addr[8U] = { 0U };
    uint32_t wots_pk_addr[8U] = { 0U };
    uint64_t tree;
    uint32_t idx_leaf;
    bool res;

    const uint8_t* pub_root = pk + SPX_N;
    res = false;

    if (signedmsg != NULL && message != NULL && context != NULL && pk != NULL && smsglen >= SPX_BYTES)
    {
        qsc_memutils_copy(sctx.pub_seed, pk, SPX_N);

        sphincsplus_set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
        sphincsplus_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
        sphincsplus_set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

        /* Derive the message digest and leaf index from R || PK || M. */
        /* The additional SPX_N is a result of the hash domain separator. */
        sphincsplus_hash_message(mhash, &tree, &idx_leaf, signedmsg, pk, message, msglen, context, ctxlen);
        signedmsg += SPX_N;

        /* Layer correctly defaults to 0, so no need to set_layer_addr */
        sphincsplus_set_tree_addr(wots_addr, tree);
        sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

        sphincsplus_fors_pk_from_sig(root, signedmsg, mhash, &sctx, wots_addr);
        signedmsg += SPX_FORS_BYTES;

        /* For each subtree.. */
        for (uint32_t i = 0U; i < SPX_D; i++) 
        {
            sphincsplus_set_layer_addr(tree_addr, i);
            sphincsplus_set_tree_addr(tree_addr, tree);

            sphincsplus_copy_subtree_addr(wots_addr, tree_addr);
            sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

            sphincsplus_copy_keypair_addr(wots_pk_addr, wots_addr);

            /* The WOTS public key is only correct if the signature was correct. */
            /* Initially, root is the FORS pk, but on subsequent iterations it is
               the root of the subtree below the currently processed subtree. */
            sphincsplus_wots_pk_from_sig(wots_pk, signedmsg, root, &sctx, wots_addr);
            signedmsg += SPX_WOTS_BYTES;

            /* Compute the leaf node using the WOTS public key. */
            sphincsplus_thash_wots(leaf, wots_pk, &sctx, wots_pk_addr);

            /* Compute the root node of this subtree. */
            sphincsplus_compute_root(root, leaf, idx_leaf, 0U, signedmsg, SPX_TREE_HEIGHT, &sctx, tree_addr);
            signedmsg += SPX_TREE_HEIGHT * SPX_N;

            /* Update the indices for the next layer. */
            idx_leaf = (tree & ((1U << SPX_TREE_HEIGHT) - 1U));
            tree = tree >> SPX_TREE_HEIGHT;
        }

        /* Check if the root node equals the root node in the public key. */
        res = qsc_memutils_are_equal(root, pub_root, SPX_N);
    }

    return res;
}

bool sphincsplus_ref_open(uint8_t* message, size_t* msglen, const uint8_t* context, size_t ctxlen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* pk)
{
    bool res;

    *msglen = 0U;
    res = false;

    if (ctxlen <= 255U)
    {
        uint8_t prec[SPHINCSPLUS_CONTEXT_SIZE] = { 0U };

        /* prepare pre = (0, ctxlen, ctx) */
        prec[0U] = 0U;
        prec[1U] = (uint8_t)ctxlen;

        if (context != NULL && ctxlen != 0)
        {
            qsc_memutils_copy(prec + 2U, context, ctxlen);
        }

        if (smsglen >= SPHINCSPLUS_SIGNATURE_SIZE)
        {
            *msglen = smsglen - SPHINCSPLUS_SIGNATURE_SIZE;
            res = sphincsplus_ref_verify(signedmsg, smsglen, signedmsg + SPHINCSPLUS_SIGNATURE_SIZE, *msglen, prec, ctxlen + 2U, pk);
            
            if (res == true)
            {
                /* All good, copy msg, return 0 */
                qsc_memutils_copy(message, signedmsg + SPHINCSPLUS_SIGNATURE_SIZE, *msglen);
            }
        }
    }

    if (res == false && smsglen >= SPHINCSPLUS_SIGNATURE_SIZE)
    {
        qsc_memutils_secure_erase(message, smsglen - SPHINCSPLUS_SIGNATURE_SIZE);
    }

    return res;
}
