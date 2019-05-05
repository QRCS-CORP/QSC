/*
  This file is for the Berlekamp-Massey algorithm
  see http://crypto.stanford.edu/~mironov/cs359/massey.pdf
*/

#ifndef BM_H
#define BM_H

#include "common.h"

void bm(gf *out, gf *s);

#endif
