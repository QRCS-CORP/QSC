#ifndef UTIL_H
#define UTIL_H

#include "common.h"
void clear8(uint8_t* a, size_t count);

void clear32(uint32_t* a, size_t count);

void clear64(uint64_t* a, size_t count);

uint32_t le8to32(const uint8_t* input);

uint64_t le8to64(const uint8_t* input);

void le32to8(uint8_t* output, uint32_t value);

void le64to8(uint8_t* output, uint64_t value);

uint32_t rotl32(uint32_t value, uint32_t shift);

uint64_t rotL64(uint64_t value, uint32_t shift);

uint32_t rotr32(uint32_t value, uint32_t shift);

uint64_t rotr64(uint64_t value, uint32_t shift);

int32_t verify(const uint8_t* a, const uint8_t* b, size_t length);

#endif
