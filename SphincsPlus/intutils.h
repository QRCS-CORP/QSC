/*
* \file intutils.h
* \brief <b>Integer utilities</b> \n
  This file is contains common integer functions
*/

#ifndef QCX_INTUTILS_H
#define QCX_INTUTILS_H

#include "common.h"

/**
* \brief Compare two byte 8=bit integer for equality
*
* \param a the first array to compare
* \param b the second array to compare
* \param the number of bytes to compare
* \return Returns zero (QCX_STATUS_SUCCESS) for equal values
*/
int32_t are_equal8(const uint8_t* a, const uint8_t* b, size_t length);

/**
* \brief Convert an 8-bit integer array to a 32-bit big-endian integer
*
* \param input the source integer 8-bit array
* \return the 32-bit big endian integer
*/
uint32_t be8to32(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 64-bit big-endian integer
*
* \param input the source integer 8-bit array
* \return the 64-bit big endian integer
*/
uint64_t be8to64(const uint8_t* input);

/**
* \brief Convert a 32-bit integer to a big-endian 8-bit integer array
*
* \param output the 8-bit integer array
* \param value the 32-bit integer
*/
void be32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert a 64-bit integer to a big-endian 8-bit integer array
*
* \param output the 8-bit integer array
* \param value the 64-bit integer
*/
void be64to8(uint8_t* output, uint64_t value);

/**
* \brief Set an an 8-bit integer array to zeroes
*
* \param a the array to clear
* \param count the number of integers to clear
*/
void clear8(uint8_t* a, size_t count);

/**
* \brief Set an an 32-bit integer array to zeroes
*
* \param a the array to clear
* \param count the number of integers to clear
*/
void clear32(uint32_t* a, size_t count);

/**
* \brief Set an an 64-bit integer array to zeroes
*
* \param a the array to clear
* \param count the number of integers to clear
*/
void clear64(uint64_t* a, size_t count);

/**
* \brief Convert an 8-bit integer array to a 32-bit little-endian integer
*
* \param input the source integer 8-bit array
* \return the 32-bit little endian integer
*/
uint32_t le8to32(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 64-bit little-endian integer
*
* \param input the source integer 8-bit array
* \return the 64-bit little endian integer
*/
uint64_t le8to64(const uint8_t* input);

/**
* \brief Convert a 32-bit integer to a little-endian 8-bit integer array
*
* \param output the 8-bit integer array
* \param value the 32-bit integer
*/
void le32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert a 64-bit integer to a little-endian 8-bit integer array
*
* \param output the 8-bit integer array
* \param value the 64-bit integer
*/
void le64to8(uint8_t* output, uint64_t value);

#endif
