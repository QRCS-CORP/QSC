#ifndef QCX_SPX_THASH_H
#define QCX_SPX_THASH_H

#include "common.h"

/*
* Takes an array of inblocks concatenated arrays of SPX_N bytes.
*/
void thash(uint8_t* out, const uint8_t* in, size_t inblocks, const uint8_t* pub_seed, uint32_t addr[8]);

#endif
