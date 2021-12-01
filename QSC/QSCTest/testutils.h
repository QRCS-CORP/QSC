#ifndef QSCTEST_TESTUTILS_H
#define QSCTEST_TESTUTILS_H

#include "common.h"
/**
* \file testutils.h
* \brief Test support functions
*/

/**
* \brief Get a single character from the console
*
* \return Returns the character detected
*/
char qsctest_get_char(void);

/**
* \brief Pause the console until user input is detected
*
* \return Returns the character detected
*/
uint8_t qsctest_get_wait(void);

/**
* \brief Convert a hexadecimal character string to a binary byte array
*
* \param hexstr: the string to convert
* \param output: the binary output array
* \param length: the number of bytes to convert
*/
void qsctest_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
* \brief Convert a uint16 array to a hexadecimal array, delineated with commas, and print to the console
*
* \param input: the uint16 array
* \param inputlen: the number of bytes to process
* \param linelen: the length of output to print, before starting a new line
*/
void qsctest_print_hex_uint16(const uint16_t* input, size_t inputlen, size_t linelen);

/**
* \brief Convert a uint32 array to a hexadecimal array, delineated with commas, and print to the console
*
* \param input: the uint32 array
* \param inputlen: the number of bytes to process
* \param linelen: the length of output to print, before starting a new line
*/
void qsctest_print_hex_uint32(const uint32_t* input, size_t inputlen, size_t linelen);

/**
* \brief Convert a uint64 array to a hexadecimal array, delineated with commas, and print to the console
*
* \param input: the uint64 array
* \param inputlen: the number of bytes to process
* \param linelen: the length of output to print, before starting a new line
*/
void qsctest_print_hex_uint64(const uint64_t* input, size_t inputlen, size_t linelen);

/**
* \brief Convert a binary array to a hexadecimal string, add quotation marks, and print to the console
*
* \param input: the binary array
* \param inputlen: the number of bytes to process
* \param linelen: the length of output to print, before starting a new line
*/
void qsctest_print_hex_quot(const uint8_t* input, size_t inputlen, size_t linelen);

/**
* \brief Convert a binary array to a hexadecimal string and print to the console
*
* \param input: the binary array
* \param inputlen: the number of bytes to process
* \param linelen: the length of output to print, before starting a new line
*/
void qsctest_print_hex(const uint8_t* input, size_t inputlen, size_t linelen);

/**
* \brief Print an array of characters to the console
*
* \param input: the character array to print
*/
void qsctest_print_safe(const char* input);

/**
* \brief Print an array of characters to the console with a line break
*
* \param input: the character array to print
*/
void qsctest_print_line(const char* input);

/**
* \brief Print an unsigned 64-bit integer
*
* \param digit: the number to print
*/
void qsctest_print_ulong(uint64_t digit);

/**
* \brief Print a double integer
*
* \param digit: the number to print
*/
void qsctest_print_double(double digit);

/**
* \brief User confirmation that and action can continue(Y/N y/n)
*
* \param message: the message to print
*/
bool qsctest_test_confirm(const char* message);

#endif
