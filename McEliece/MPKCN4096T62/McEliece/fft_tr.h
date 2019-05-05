#ifndef FFT_TR_H
#define FFT_TR_H

#include "common.h"
#include "params.h"

void fft_tr(uint64_t out[][MCELIECE_GFBITS], uint64_t in[][MCELIECE_GFBITS]);

#endif
