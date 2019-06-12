#include "common.h"
#include "hash.h"
#include "haddress.h"
#include "params.h"
#include "utils.h"
#include "wots.h"

/**
 * Computes the starting value for a chain, i.e. the secret key.
 * Expects the address to be complete up to the chain address.
 */
static void wots_gen_sk(uint8_t* sk, const uint8_t* skseed, uint32_t wotsaddr[8])
{
    /* Make sure that the hash address is actually zeroed. */
    set_hash_addr(wotsaddr, 0);
    /* Generate sk element. */
    prf_addr(sk, skseed, wotsaddr);
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(uint8_t* output, const uint8_t* input, uint32_t start, uint32_t steps, const uint8_t* pkseed, uint32_t addr[8])
{
	uint8_t buf[SPX_N + SPX_ADDR_BYTES + 1 * SPX_N];
	uint8_t mask[1 * SPX_N];
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(output, input, SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < SPX_WOTS_W; ++i) 
	{
        set_hash_addr(addr, i);
        thash(output, output, 1, pkseed, addr, buf, mask);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(int32_t* output, const size_t outlen, const uint8_t* input)
{
	size_t i;
	int32_t bits;
    int32_t inoffset;
	int32_t outoffset;
    uint8_t total;

	bits = 0;
	inoffset = 0;
	outoffset = 0;
	total = 0;

    for (i = 0; i < outlen; ++i) 
	{
        if (bits == 0) 
		{
            total = input[inoffset];
			inoffset++;
            bits += 8;
        }

        bits -= SPX_WOTS_LOGW;
        output[outoffset] = (total >> bits) & (SPX_WOTS_W - 1);
        ++outoffset;
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(int32_t* csumbasew, const int32_t* msgbasew)
{
    uint8_t csumbytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
	int32_t csum;
    uint32_t i;

	csum = 0;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1; ++i) 
	{
        csum += (SPX_WOTS_W - 1) - msgbasew[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8));
    ull_to_bytes(csumbytes, sizeof(csumbytes), csum);
    base_w(csumbasew, SPX_WOTS_LEN2, csumbytes);
}

/* Takes a message and derives the matching chain lengths. */
static void chain_lengths(int32_t* lengths, const uint8_t* msg)
{
    base_w(lengths, SPX_WOTS_LEN1, msg);
    wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
}

/**
 * WOTS key generation. Takes a 32 byte sk_seed, expands it to WOTS private key
 * elements and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_gen_pk(uint8_t* pk, const uint8_t* skseed, const uint8_t* pkseed, uint32_t addr[8])
{
    uint32_t i;

    for (i = 0; i < SPX_WOTS_LEN; ++i) 
	{
        set_chain_addr(addr, i);
        wots_gen_sk(pk + i * SPX_N, skseed, addr);
        gen_chain(pk + (i * SPX_N), pk + (i * SPX_N), 0, SPX_WOTS_W - 1, pkseed, addr);
    }
}

/**
 * Takes a n-byte message and the 32-byte sk_see to compute a signature 'sig'.
 */
void wots_sign(uint8_t* signature, const uint8_t* message, const uint8_t* skseed, const uint8_t* pkseed, uint32_t addr[8])
{
	int32_t lengths[SPX_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, message);

    for (i = 0; i < SPX_WOTS_LEN; ++i) 
	{
        set_chain_addr(addr, i);
        wots_gen_sk(signature + (i * SPX_N), skseed, addr);
        gen_chain(signature + (i * SPX_N), signature + (i * SPX_N), 0, lengths[i], pkseed, addr);
    }
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(uint8_t* pk, const uint8_t* signature, const uint8_t* message, const uint8_t* pkseed, uint32_t addr[8])
{
    int lengths[SPX_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, message);

    for (i = 0; i < SPX_WOTS_LEN; ++i) 
	{
        set_chain_addr(addr, i);
        gen_chain(pk + (i * SPX_N), signature + (i * SPX_N), lengths[i], (SPX_WOTS_W - 1) - lengths[i], pkseed, addr);
    }
}
