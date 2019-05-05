/*
  This file is for evaluating a polynomial at one or more field elements
*/

#ifndef ROOT_H
#define ROOT_H

#include "common.h"
#include "gf.h"

gf eval(const gf* f, gf a);

void root(gf* out, gf* f, gf* L);

#endif

