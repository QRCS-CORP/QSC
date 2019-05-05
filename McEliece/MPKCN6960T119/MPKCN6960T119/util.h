/*
  This file is for loading/storing data in a little-endian format
*/

#ifndef UTIL_H
#define UTIL_H

#include "common.h"
#include "gf.h"

bool are_equal8(const uint8_t* a, const uint8_t* b, size_t length);

void bin_to_hex(uint8_t* input, char* output, size_t length);

void clear8(uint8_t* a, size_t count);

void clear32(uint32_t* a, size_t count);

void clear64(uint64_t* a, size_t count);

void hex_to_bin(const char* input, uint8_t* output, size_t length);

uint32_t le8to32(const uint8_t* input);

uint64_t le8to64(const uint8_t* input);

void le32to8(uint8_t* output, uint32_t value);

void le64to8(uint8_t* output, uint64_t value);

uint16_t load2(const uint8_t* src);

uint64_t load8(const uint8_t* in);

uint32_t rotl32(uint32_t value, uint32_t shift);

uint64_t rotl64(uint64_t value, uint32_t shift);

uint32_t rotr32(uint32_t value, uint32_t shift);

uint64_t rotr64(uint64_t value, uint32_t shift);

void store2(uint8_t* dest, gf a);

void store8(uint8_t* out, uint64_t in);

int32_t verify(const uint8_t* a, const uint8_t* b, size_t length);

#endif
