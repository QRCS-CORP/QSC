#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include "common.h"

bool are_equal8(const uint8_t* a, const uint8_t* b, size_t length);

void hex_to_bin(const char* str, uint8_t* output, size_t length);

#endif