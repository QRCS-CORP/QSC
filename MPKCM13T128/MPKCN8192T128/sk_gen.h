/*
  This file is for secret-key generation
*/

#ifndef SK_GEN_H
#define SK_GEN_H

#include "common.h"
#include "gf.h"

/* output: sk, the secret key */
int32_t sk_part_gen(uint8_t* sk);

#endif

