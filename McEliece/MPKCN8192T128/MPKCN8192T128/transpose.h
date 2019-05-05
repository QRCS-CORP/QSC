/*
  This file is for matrix transposition
*/

#ifndef TRANSPOSE_H
#define TRANSPOSE_H

#include "common.h"

/* input: in, a 64x64 matrix over GF(2) */
/* output: out, transpose of in */
void transpose_64x64(uint64_t* out, const uint64_t* in);

#endif

