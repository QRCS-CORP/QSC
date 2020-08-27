#ifndef QSC_SPHINCSPLUS_SUPPORT_H
#define QSC_SPHINCSPLUS_SUPPORT_H

#include "common.h"

/* params.h */

/* The secret seed size */
#define QSC_SPHINCSPLUS_SEEDSIZE 32

#if defined(QSC_SPHINCSPLUS_S1S128SHAKE)
    /* Toggles modes between the three shake-based K modes; 128,192,256 = 1,2,3 */
#   define QCX_SPX_MODE 1
#elif defined(QSC_SPHINCSPLUS_S2S192SHAKE)
#   define QCX_SPX_MODE 2
#elif defined(QSC_SPHINCSPLUS_S3S256SHAKE)
#   define QCX_SPX_MODE 3
#else
#	error No SphincsPlus implementation is defined, check common.h!
#endif

/* Implement the S 'robust' version of the signature scheme */
#define SPX_VERSION_SMALL

#ifndef QCX_SPX_MODE
#	define QCX_SPX_MODE 3
#endif

/* Note: kats are small version, fast version kats not implemented */
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

/* For clarity */
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
#error SPX_D should always divide SPX_FULL_HEIGHT
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

   /*!
   \def SPHINCSPLUS_ALGNAME
   * Read Only: The formal algorithm name
   */
#define SPHINCSPLUS_ALGNAME "SPHINCS+"

   /*!
   \def SPHINCSPLUS_PUBLICKEY_SIZE
   * Read Only: The public key size in bytes
   */
#define SPHINCSPLUS_PUBLICKEY_SIZE SPX_PK_BYTES

   /*!
   \def SPHINCSPLUS_SECRETKEY_SIZE
   * Read Only: The private key size in bytes
   */
#define SPHINCSPLUS_SECRETKEY_SIZE SPX_SK_BYTES

   /*!
   \def SPHINCSPLUS_PUBLICKEY_SIZE
   * Read Only: The seed size in bytes
   */
#define SPHINCSPLUS_SEED_SIZE 3 * SPX_N

   /*!
   \def SPHINCSPLUS_SIGNATURE_SIZE
   * Read Only: The signature size in bytes
   */
#define SPHINCSPLUS_SIGNATURE_SIZE SPX_BYTES

/* address.h */

#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK 4

void addr_to_bytes(uint8_t* bytes, const uint32_t addr[8]);

/* Copies the layer and tree part of one address into the other */
void copy_subtree_addr(uint32_t out[8], const uint32_t in[8]);

void set_layer_addr(uint32_t addr[8], uint32_t layer);

void set_tree_addr(uint32_t addr[8], uint64_t tree);

void set_type(uint32_t addr[8], uint32_t type);

/* These functions are used for WOTS and FORS addresses. */

void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]);

void set_chain_addr(uint32_t addr[8], uint32_t chain);

void set_keypair_addr(uint32_t addr[8], uint32_t keypair);

void set_hash_addr(uint32_t addr[8], uint32_t hash);

/* These functions are used for all hash tree addresses (including FORS). */

void set_tree_height(uint32_t addr[8], uint32_t tree_height);

void set_tree_index(uint32_t addr[8], uint32_t tree_index);

/* fors.h */

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* m, const uint8_t* pub_seed, const uint32_t fors_addr[8]);

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_sign(uint8_t* sig, uint8_t* pk, const uint8_t* m, const uint8_t* sk_seed, const uint8_t* pub_seed, const uint32_t fors_addr[8]);

/* hash.h */

/**
* Computes the message-dependent randomness R, using a secret
* seed and an optional randomization value as well as the message.
*/
void gen_message_random(uint8_t* R, const uint8_t* sk_seed, const uint8_t* optrand, const uint8_t* m, size_t mlen);

/**
* Computes the message hash using R, the public key, and the message.
* Outputs the message digest and the index of the leaf. The index is split in
* the tree index and the leaf index, for convenient copying to an address.
*/
void hash_message(uint8_t* digest, uint64_t* tree, uint32_t* leaf_idx, const uint8_t* R, const uint8_t* pk, const uint8_t* m, size_t mlen);

/**
* For SHAKE256, there is no immediate reason to initialize at the start,
* so this function is an empty operation.
*/
void initialize_hash_function(const uint8_t* pub_seed, const uint8_t* sk_seed);

/**
* Computes PRF(key, addr), given a secret key of SPX_N bytes and an address
*/
void prf_addr(uint8_t* out, const uint8_t* key, const uint32_t addr[8]);

/* sign.h */


/**
* \brief Generates a SphincsPlus public/private key-pair.
* Arrays must be sized to SPHINCSPLUS_PUBLICKEY_SIZE and SPHINCS_SECRETKEY_SIZE.
*
* \param publickey The public verification key
* \param secretkey The private signature key
*/
void sphincsplus_generate(uint8_t* publickey, uint8_t* secretkey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \param signedmsg The signed message
* \param smsglen The signed message length
* \param message The message to be signed
* \param msglen The message length
* \param secretkey The private signature key
*/
void sphincsplus_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* secretkey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message The message to be signed
* \param msglen The message length
* \param signedmsg The signed message
* \param smsglen The signed message length
* \param publickey The public verification key
* \return Returns true for success
*/
bool sphincsplus_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

/* thash.h */

/*
* Takes an array of inblocks concatenated arrays of SPX_N bytes.
*/
void thash(uint8_t* out, const uint8_t* in, size_t inblocks, const uint8_t* pub_seed, uint32_t addr[8]);

/*utils.h */

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

/* wots.h*/

/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_gen_pk(uint8_t* pk, const uint8_t* seed, const uint8_t* pub_seed, uint32_t addr[8]);

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* msg, const uint8_t* pub_seed, uint32_t addr[8]);

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void wots_sign(uint8_t* sig, const uint8_t* msg, const uint8_t* seed, const uint8_t* pub_seed, uint32_t addr[8]);

#endif