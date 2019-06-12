/*
  This file is for functions required for generating the condition bits of the Benes network w.r.t. a random permutation
  see the Lev-Pippenger-Valiant paper https://www.computer.org/csdl/trans/tc/1981/02/06312171.pdf
*/

#ifndef CONTROLBITS_H
#define CONTROLBITS_H

#include "common.h"

void controlbits(uint8_t* out, const uint32_t* pi);
void sort_63b(uint32_t n, uint64_t* x);

#endif

