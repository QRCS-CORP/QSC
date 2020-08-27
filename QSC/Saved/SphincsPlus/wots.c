#include "wots.h"
#include "address.h"
#include "hash.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include <string.h>

// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

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
	csum = csum << (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8));
	ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
	base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

static void chain_lengths(int32_t* lengths, const uint8_t* msg)
{
	/* Takes a message and derives the matching chain lengths. */
	base_w(lengths, SPX_WOTS_LEN1, msg);
	wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
}

void wots_gen_pk(uint8_t* pk, const uint8_t* sk_seed, const uint8_t* pub_seed, uint32_t addr[8])
{
	size_t i;

	for (i = 0; i < SPX_WOTS_LEN; i++)
	{
		set_chain_addr(addr, i);
		wots_gen_sk(pk + (i * SPX_N), sk_seed, addr);
		gen_chain(pk + (i * SPX_N), pk + (i * SPX_N), 0, SPX_WOTS_W - 1, pub_seed, addr);
	}
}

void wots_sign(uint8_t* sig, const uint8_t* msg, const uint8_t* sk_seed, const uint8_t* pub_seed, uint32_t addr[8])
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

void wots_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* msg, const uint8_t* pub_seed, uint32_t addr[8])
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
