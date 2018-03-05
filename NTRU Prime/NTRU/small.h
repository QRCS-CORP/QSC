#ifndef NTRU_SMALL_H
#define NTRU_SMALL_H

#include "common.h"

void small_encode(uint8_t* c, const int8_t* f);

void small_decode(int8_t* f, const uint8_t* c);

#endif
