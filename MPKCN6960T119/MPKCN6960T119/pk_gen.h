/*
  This file is for public-key generation
*/

#ifndef PK_GEN_H
#define PK_GEN_H

#include "common.h"
#include "gf.h"

/* input: secret key sk */
/* output: public key pk */
int32_t pk_gen(uint8_t* pk, const uint8_t* sk);

#endif

