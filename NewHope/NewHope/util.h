/*
  This file is for loading/storing data in a little-endian format
*/

#ifndef UTIL_H
#define UTIL_H

#include <cstdbool>
#include <stdint.h>

/* bogus integral type warnings */
/*lint -e970 */

/**
* \brief Compare two byte 8=bit integer for equality
*
* \param a the first array to compare
* \param b the second array to compare
* \param the number of bytes to compare
* \return Returns true for equal values
*/
bool are_equal8(const uint8_t* a, const uint8_t* b, size_t length);

/**
* \brief Convert a byte array to hexidecimal format
*
* \param input the array to be converted
* \param output the output array
* \param the number of bytes to convert
*/
void bin_to_hex(const uint8_t* input, char* output, size_t length);

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
* \brief Convert a hexidecimal array to an unformatted 8-bit array
*
* \param input the hexidecimal array
* \param output the 8-bit integer array
* \param length the number of integers to convert
*/
void hex_to_bin(const char* input, uint8_t* output, size_t length);

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
