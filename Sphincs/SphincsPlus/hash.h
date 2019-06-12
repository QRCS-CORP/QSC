/**
* \file hash.h
* \brief <b>Sphincs hashing helper functions</b> \n
* This is an internal class.
*
* \date October 29, 2018
*/

#ifndef SPX_HASH_H
#define SPX_HASH_H

void gen_message_random(uint8_t* R, const uint8_t* sk_seed, const uint8_t* optrand, uint8_t* m_with_prefix, uint64_t mlen);

void hash_message(uint8_t* digest, uint64_t* tree, uint32_t* leaf_idx, const uint8_t* R, const uint8_t* pk, uint8_t* m_with_prefix, uint64_t mlen);

void initialize_hash_function(const uint8_t* pub_seed, const uint8_t* sk_seed);

void prf_addr(uint8_t* out, const uint8_t* key, const uint32_t addr[8]);

void thash(uint8_t* out, const uint8_t* in, const uint32_t inblocks, const uint8_t* pub_seed, uint32_t addr[8], uint8_t* buf, uint8_t* mask);

#endif
