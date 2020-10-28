#ifndef QSC_TRANSPOSE_H
#define QSC_TRANSPOSE_H

#include "common.h"
#include "intutils.h"

/**
* \brief Convert 32-bit integers in big-endian format to 8-bit integers
*
* \param output: Pointer to the output 8-bit integer array
* \param input: Pointer to the input 8-bit character array
* \param length: The number of 8-bit integers to convert
*/
void qsc_transpose_bytes_to_native(uint32_t* output, const uint8_t* input, size_t length);

/**
* \brief Convert a hexidecimal string to a decimal 8-bit array
*
* \param output: Pointer to the output 8-bit integer array
* \param input: Pointer to the input 8-bit character array
* \param length: The number of hex characters to convert
*/
void qsc_transpose_hex_to_bin(uint8_t* output, const char* input, size_t length);

/**
* \brief Convert 8-bit integers to 32-bit integers in big-endian format
*
* \param output: Pointer to the output 8-bit integer array
* \param input: Pointer to the input 8-bit character array
* \param length: The number of 8-bit integers to convert
*/
void qsc_transpose_native_to_bytes(uint8_t* output, const uint32_t* input, size_t length);

 /**
 * \brief Convert a 8-bit character array to zero padded 32-bit scalar integers
 *
 * \param output: Pointer to the output 32-bit integer array
 * \param input: Pointer to the input 8-bit character array
 * \param length: The number of 8-bit integers to convert
 */
void qsc_transpose_string_to_scalar(uint32_t* output, const char* input, size_t count);

#endif