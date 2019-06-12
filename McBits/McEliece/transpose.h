/*
  This file is for matrix transposition
*/

#ifndef TRANSPOSE_H
#define TRANSPOSE_H

#include "common.h"
#include "params.h"

void transpose_64x64_compact(uint64_t* out, uint64_t* in);

void transpose_8x64(uint64_t* in);

#endif
