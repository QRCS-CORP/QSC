#ifndef GF_H
#define GF_H

#include "common.h"
#include "params.h"

uint16_t gf_diff(uint16_t a, uint16_t b);

uint16_t gf_inv(uint16_t in);

uint16_t gf_mul(uint16_t in0, uint16_t in1);

void gf_mulm(uint16_t* out, uint16_t* in0, uint16_t* in1);

uint16_t gf_sq(uint16_t in);

#endif
