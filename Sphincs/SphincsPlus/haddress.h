/**
* \file haddress.h
* \brief <b>Sphincs FORS and WOTS address helper functions</b> \n
* This is an internal class.
*
* \date October 29, 2018
*/

#ifndef SPX_HASH_ADDRESS_H
#define SPX_HASH_ADDRESS_H

#include "common.h"

#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK 4

void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]);

void copy_subtree_addr(uint32_t out[8], const uint32_t in[8]);

void set_chain_addr(uint32_t addr[8], uint32_t chain);

void set_hash_addr(uint32_t addr[8], uint32_t hash);

void set_keypair_addr(uint32_t addr[8], uint32_t keypair);

void set_layer_addr(uint32_t addr[8], uint32_t layer);

void set_tree_addr(uint32_t addr[8], uint64_t tree);

void set_tree_height(uint32_t addr[8], uint32_t tree_height);

void set_tree_index(uint32_t addr[8], uint32_t tree_index);

void set_type(uint32_t addr[8], uint32_t type);

#endif
