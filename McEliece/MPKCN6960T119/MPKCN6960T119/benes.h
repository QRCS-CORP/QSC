/*
  This file is for Benes network related functions
*/

#ifndef BENES_H
#define BENES_H

#include "common.h"
#include "gf.h"

void apply_benes(uint8_t* r, const uint8_t* bits, int32_t rev);

void support_gen(gf* s, const uint8_t* c);

#endif

