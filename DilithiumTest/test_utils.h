#ifndef QSC_TEST_UTILS_H
#define QSC_TEST_UTILS_H

#include "common.h"

void hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

void print_hex(const uint8_t* input, size_t inputlen, size_t linelen);

#endif
