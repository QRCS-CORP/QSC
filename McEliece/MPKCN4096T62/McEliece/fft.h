#ifndef FFT_H
#define FFT_H

#include "common.h"
#include "params.h"

void fft(uint64_t out[][MCELIECE_GFBITS], uint64_t* in);

#endif
