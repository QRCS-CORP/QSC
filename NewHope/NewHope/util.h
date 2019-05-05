/*
  This file is for loading/storing data in a little-endian format
*/

#ifndef UTIL_H
#define UTIL_H

#include <cstdbool>
#include <stdint.h>

/* bogus integral type warnings */
/*lint -e970 */

bool are_equal8(const uint8_t* a, const uint8_t* b, size_t length);

void bin_to_hex(const uint8_t* input, char* output, size_t length);

void clear8(uint8_t* a, size_t count);

void clear32(uint32_t* a, size_t count);

void clear64(uint64_t* a, size_t count);

void hex_to_bin(const char* input, uint8_t* output, size_t length);

uint32_t le8to32(const uint8_t* input);

uint64_t le8to64(const uint8_t* input);

void le32to8(uint8_t* output, uint32_t value);

void le64to8(uint8_t* output, uint64_t value);

#endif
