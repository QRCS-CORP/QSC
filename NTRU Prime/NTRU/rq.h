#ifndef NTRU_RQ_H
#define NTRU_RQ_H

#include "common.h"

void rq_decoderounded(int16_t* f, const uint8_t* c);

void rq_encoderounded(uint8_t* c, const int16_t* f);

void rq_fromseed(int16_t* h, const uint8_t* K);

void rq_mult(int16_t* h, const int16_t* f, const int8_t* g);

void rq_round3(int16_t* h, const int16_t* f);

#endif
