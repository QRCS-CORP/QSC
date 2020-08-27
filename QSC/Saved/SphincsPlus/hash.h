#ifndef QCX_SPX_HASH_H
#define QCX_SPX_HASH_H

#include "common.h"

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

#endif
