#include "common.h"
#include "fors.h"
#include "haddress.h"
#include "hash.h"
#include "sign.h"
#include "sysrand.h"
#include "utils.h"
#include "wots.h"

/* Internal */

static void wots_gen_leaf(uint8_t* leaf, const uint8_t* skseed, const uint8_t* pkseed, uint32_t addridx, const uint32_t treeaddr[8])
{
	/* Computes the leaf at a given address. First generates the WOTS key pair,
	   then computes leaf by hashing horizontally. */
	
	uint8_t buf[SPX_N + SPX_ADDR_BYTES + SPX_WOTS_LEN * SPX_N];
	uint8_t mask[SPX_WOTS_LEN * SPX_N];
    uint8_t pk[SPX_WOTS_BYTES];
    uint32_t wotsaddr[8] = {0};
    uint32_t wotspkaddr[8] = {0};

    set_type(wotsaddr, SPX_ADDR_TYPE_WOTS);
    set_type(wotspkaddr, SPX_ADDR_TYPE_WOTSPK);

    copy_subtree_addr(wotsaddr, treeaddr);
    set_keypair_addr(wotsaddr, addridx);
    wots_gen_pk(pk, skseed, pkseed, wotsaddr);

    copy_keypair_addr(wotspkaddr, wotsaddr);
	thash(leaf, pk, SPX_WOTS_LEN, pkseed, wotspkaddr, buf, mask);
}

/* Public API */

qcc_status sphincs_generate(uint8_t* publickey, uint8_t* secretkey)
{
	/* Generates an SPX key pair.
	   Format secretkey: [SK_SEED || SK_PRF || PUB_SEED || root]
	   Format publickey: [PUB_SEED || root] */

    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */

    uint8_t authpath[SPX_TREE_HEIGHT * SPX_N];
	uint32_t heights[SPX_TREE_HEIGHT + 1];
	uint8_t stack[(SPX_TREE_HEIGHT + 1) * SPX_N];
    uint32_t toptreeaddr[8] = {0};

    set_layer_addr(toptreeaddr, SPX_D - 1);
    set_type(toptreeaddr, SPX_ADDR_TYPE_HASHTREE);

    /* Initialize SK_SEED, SK_PRF and PUB_SEED. */
	if (sysrand_getbytes(secretkey, 3 * SPX_N) != QCC_STATUS_SUCCESS)
	{
		return QCC_ERROR_RANDFAIL;
	}

    memcpy(publickey, secretkey + 2*SPX_N, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(publickey, secretkey);

    /* Compute root node of the top-most subtree. */
	treehash(secretkey + (3 * SPX_N), authpath, secretkey, secretkey + (2 * SPX_N), 0, 0, SPX_TREE_HEIGHT, wots_gen_leaf, toptreeaddr, stack, heights);
    memcpy(publickey + SPX_N, secretkey + (3 * SPX_N), SPX_N);

    return QCC_STATUS_SUCCESS;
}

qcc_status sphincs_sign(uint8_t* signedmsg, uint64_t* smsglen, const uint8_t* message, uint64_t msglen, const uint8_t* secretkey)
{
	/* Returns an array containing the signature followed by the message. */
    const uint8_t* pk = secretkey + (2 * SPX_N);
    const uint8_t* pkseed = pk;
    const uint8_t* skprf = secretkey + SPX_N;
    const uint8_t* skseed = secretkey;
	uint32_t heights[SPX_FORS_HEIGHT + 1];
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t optrand[SPX_N];
    uint8_t root[SPX_N];
	uint8_t stack[(SPX_FORS_HEIGHT + 1) * SPX_N];
    uint32_t treeaddr[8] = {0};
    uint32_t wotsaddr[8] = {0};
    uint64_t i;
    uint32_t idxleaf;
    uint64_t tree;

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pkseed, skseed);

    set_type(wotsaddr, SPX_ADDR_TYPE_WOTS);
    set_type(treeaddr, SPX_ADDR_TYPE_HASHTREE);

    /* Already put the message in the right place, to make it easier to prepend
       things when computing the hash over the message. */
    /* We need to do this from back to front, so that it works when signedmsg = message */
    for (i = msglen; i > 0; i--) 
	{
        signedmsg[SPX_BYTES + i - 1] = message[i - 1];
    }
    *smsglen = SPX_BYTES + msglen;

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
	if (sysrand_getbytes(optrand, SPX_N) != QCC_STATUS_SUCCESS)
	{
		return QCC_ERROR_RANDFAIL;
	}

    /* Compute the digest randomization value. */
    gen_message_random(signedmsg, skprf, optrand, signedmsg + SPX_BYTES, msglen);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idxleaf, signedmsg, pk, signedmsg + SPX_BYTES, msglen);
    signedmsg += SPX_N;

    set_tree_addr(wotsaddr, tree);
    set_keypair_addr(wotsaddr, idxleaf);

    /* Sign the message hash using FORS. */
    fors_sign(signedmsg, root, mhash, skseed, pkseed, wotsaddr);
    signedmsg += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) 
	{
        set_layer_addr(treeaddr, i);
        set_tree_addr(treeaddr, tree);

        copy_subtree_addr(wotsaddr, treeaddr);
        set_keypair_addr(wotsaddr, idxleaf);

        /* Compute a WOTS signature. */
        wots_sign(signedmsg, root, skseed, pkseed, wotsaddr);
        signedmsg += SPX_WOTS_BYTES;

        /* Compute the authentication path for the used WOTS leaf. */
		treehash(root, signedmsg, skseed, pkseed, idxleaf, 0, SPX_TREE_HEIGHT, wots_gen_leaf, treeaddr, stack, heights);
        signedmsg += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idxleaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    return QCC_STATUS_SUCCESS;
}

qcc_status sphincs_verify(uint8_t* message, uint64_t* msglen, const uint8_t* signedmsg, uint64_t smsglen, const uint8_t* publickey)
{
	/* Verifies a given signature-message pair under a given public key. */

    const uint8_t* pkroot = publickey + SPX_N;
    const uint8_t* pkseed = publickey;
	uint8_t buf[SPX_N + SPX_ADDR_BYTES + SPX_WOTS_LEN * SPX_N];
    uint8_t leaf[SPX_N];
	uint8_t mask[SPX_WOTS_LEN * SPX_N];
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t root[SPX_N];
    uint8_t sig[SPX_BYTES];
    uint8_t* sigptr = sig;
    uint32_t treeaddr[8] = {0};
    uint32_t wotsaddr[8] = {0};
    uint8_t wotspk[SPX_WOTS_BYTES];
    uint32_t wotspkaddr[8] = {0};
    uint64_t tree;
    uint32_t i;
    uint32_t idxleaf;

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pkseed, NULL);

    set_type(wotsaddr, SPX_ADDR_TYPE_WOTS);
    set_type(treeaddr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wotspkaddr, SPX_ADDR_TYPE_WOTSPK);

    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smsglen < SPX_BYTES) 
	{
        memset(message, 0, smsglen);
        *msglen = 0;

		return QCC_ERROR_AUTHFAIL;
    }

    *msglen = smsglen - SPX_BYTES;

    /* Put the message all the way at the end of the message buffer, so that we can
     * prepend the required other inputs for the hash function. */
    memcpy(message + SPX_BYTES, signedmsg + SPX_BYTES, *msglen);

    /* Create a copy of the signature so that message = signedmsg is not an issue */
    memcpy(sig, signedmsg, SPX_BYTES);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idxleaf, sigptr, publickey, message + SPX_BYTES, *msglen);
    sigptr += SPX_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wotsaddr, tree);
    set_keypair_addr(wotsaddr, idxleaf);

    fors_pk_from_sig(root, sigptr, mhash, pkseed, wotsaddr);
    sigptr += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) 
	{
        set_layer_addr(treeaddr, i);
        set_tree_addr(treeaddr, tree);
        copy_subtree_addr(wotsaddr, treeaddr);
        set_keypair_addr(wotsaddr, idxleaf);
        copy_keypair_addr(wotspkaddr, wotsaddr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS publickey, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig(wotspk, sigptr, root, pkseed, wotsaddr);
        sigptr += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
		thash(leaf, wotspk, SPX_WOTS_LEN, pkseed, wotspkaddr, buf, mask);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idxleaf, 0, sigptr, SPX_TREE_HEIGHT, pkseed, treeaddr);
        sigptr += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idxleaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pkroot, SPX_N))
	{
        /* If not, zero the message */
        memset(message, 0, smsglen);
        *msglen = 0;

        return QCC_ERROR_AUTHFAIL;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(message, message + SPX_BYTES, *msglen);

    return QCC_STATUS_SUCCESS;
}
