/*
  This file is for syndrome computation
*/

#ifndef SYND_H
#define SYND_H

#include "common.h"
#include "gf.h"

/* input: Goppa polynomial f, support L, received word r */
/* output: out, the syndrome of length 2t */
void synd(gf* out, const gf* f, const gf* L, const uint8_t* r);

#endif

