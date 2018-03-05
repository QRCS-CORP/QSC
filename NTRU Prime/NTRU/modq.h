#ifndef NTRU_MODQ_H
#define NTRU_MODQ_H

#include "common.h"

int16_t modq_freeze(int32_t a);

int16_t modq_fromuint32(uint32_t a);

int16_t modq_plusproduct(int16_t a, int16_t b, int16_t c);

int16_t modq_sum(int16_t a, int16_t b);

#endif
