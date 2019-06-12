#ifndef VEC_H
#define VEC_H

#include "common.h"
#include "params.h"

void vec_add(uint64_t* z, uint64_t* x, uint64_t* y);

void vec_mul(uint64_t* h, uint64_t* f, const uint64_t* g);

void vec_sq(uint64_t* out, uint64_t* in);

void vec_copy(uint64_t* out, const uint64_t* in);

uint64_t vec_or(const uint64_t* in);

void vec_inv(uint64_t* out, const uint64_t* in);

#endif
