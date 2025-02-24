/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_CONSOLEUTILS_H
#define QSC_CONSOLEUTILS_H

#include "common.h"

/**
 * \file consoleutils.h
 * \brief Console support functions.
 *
 * \details
 * This header provides a comprehensive set of functions for console input/output operations.
 * The functionality includes:
 *   - Printing messages with customizable colors and styles.
 *   - Reading individual characters and complete lines from the console.
 *   - Formatting and printing arrays, hexadecimal data, and numerical values.
 *   - Managing console window properties such as buffer size, window dimensions, title, and prompt.
 *   - Enabling virtual terminal processing to support advanced text formatting.
 *
 * \par Example Usage:
 * \code
 * #include "consoleutils.h"
 *
 * // Print a colored message.
 * qsc_consoleutils_colored_message("Welcome to QRCS Console!", blue);
 *
 * // Read a formatted line from the console.
 * char input[QSC_CONSOLE_MAX_LINE];
 * size_t len = qsc_consoleutils_get_formatted_line(input, QSC_CONSOLE_MAX_LINE);
 *
 * // Set the console window title.
 * qsc_consoleutils_set_window_title("QRCS Application");
 * \endcode
 *
 * \section conutils_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/console/console-reference">Microsoft Console API Documentation</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/termios.h.html">POSIX Terminal Interface Documentation</a>
 */

/*! 
 * \def QSC_CONSOLE_MAX_LINE
 * \brief The maximum length of a console string.
 */
#define QSC_CONSOLE_MAX_LINE 128ULL

/*!
 * \enum qsc_console_font_color
 * \brief The console font color choices.
 */
typedef enum
{
	white = 0x00U,		/*!< White */
	blue = 0x01U,		/*!< Blue */
	green = 0x02U,		/*!< Green */
	red = 0x03U			/*!< Red */
} qsc_console_font_color;

/*!
 * \enum qsc_console_font_style
 * \brief The console font style options.
 */
typedef enum
{
	regular = 0x00U,    /*!< Regular */
	bold = 0x01U,       /*!< Bold */
	italic = 0x02U,     /*!< Italic */
	bolditalic = 0x03U  /*!< Bold and Italic */
} qsc_console_font_style;

/**
 * \brief Print a colored console message.
 *
 * Changes the console text color, prints the message, then resets the color.
 *
 * \param message:	[const char*] A pointer to the constant message string.
 * \param color:	[qsc_console_font_color] The desired font color (from qsc_console_font_color).
 */
QSC_EXPORT_API void qsc_consoleutils_colored_message(const char* message, qsc_console_font_color color);

/**
 * \brief Get a character from the console in a blocking manner.
 *
 * \return Returns	[char] the character read from console input.
 */
QSC_EXPORT_API char qsc_consoleutils_get_char(void);

/**
 * \brief Get a formatted line of text from the console.
 *
 * Reads a line of text from the console, converts it to lowercase, and trims trailing newline characters.
 *
 * \param line:		[char*] A pointer to the character array that receives the text.
 * \param maxlen:	[size_t] The maximum number of characters to read.
 * \return			[size_t] Returns the number of characters read.
 */
QSC_EXPORT_API size_t qsc_consoleutils_get_formatted_line(char* line, size_t maxlen);

/**
 * \brief Get a line of text from the console.
 *
 * Reads a line of text from the console.
 *
 * \param line:		[char*] A pointer to the character array that receives the text.
 * \param maxlen:	[size_t] The maximum number of characters to read.
 * \return			[size_t] Returns the number of characters read.
 */
QSC_EXPORT_API size_t qsc_consoleutils_get_line(char* line, size_t maxlen);

/**
 * \brief Extract a quoted string from input.
 *
 * Searches the input for a quoted substring (using either double or single quotes)
 * and copies it to the output array.
 *
 * \param output:	[char*] A pointer to the destination array for the extracted string.
 * \param input:	[const char*] A pointer to the input string.
 * \param maxlen:	[size_t] The maximum number of characters to extract.
 * \return			[size_t] Returns the number of characters in the quoted string.
 */
QSC_EXPORT_API size_t qsc_consoleutils_get_quoted_string(char* output, const char* input, size_t maxlen);

/**
 * \brief Wait for user input from the console.
 *
 * Blocks until a character is input by the user.
 *
 * \return			[char] Returns the character read from console input.
 */
QSC_EXPORT_API char qsc_consoleutils_get_wait(void);

/**
 * \brief Convert a hexadecimal string to a binary (byte) array.
 *
 * \param hexstr:	[const char*] A pointer to the constant hexadecimal string.
 * \param output:	[uint8_t*] A pointer to the output byte array.
 * \param length:	[size_t] The number of bytes to convert.
 */
QSC_EXPORT_API void qsc_consoleutils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
 * \brief Check if a line of text contains a given token.
 *
 * \param line:		[const char*] A pointer to the constant input line.
 * \param token:	[const char*] A pointer to the constant token string to search for.
 * \return			[bool] Returns true if the token is found; otherwise, false.
 */
QSC_EXPORT_API bool qsc_consoleutils_line_contains(const char* line, const char* token);

/**
 * \brief Compare two lines of text for equivalence.
 *
 * \param line1:	[const char*] A pointer to the first constant input string.
 * \param line2:	[const char*] A pointer to the second constant input string.
 * \return			[bool] Returns true if the strings are equal; otherwise, false.
 */
QSC_EXPORT_API bool qsc_consoleutils_line_equals(const char* line1, const char* line2);

/**
 * \brief Read a masked password from the console.
 *
 * Displays masking characters (e.g., asterisks) as the user types and stores the password.
 *
 * \param output:	[char*] A pointer to the output character array to store the password.
 * \param otplen:	[size_t] The maximum size of the output array.
 * \return			[size_t] Returns the number of characters in the password.
 */
QSC_EXPORT_API size_t qsc_consoleutils_masked_password(char* output, size_t otplen);

/**
 * \brief Display a confirmation message and wait for a Y/N response.
 *
 * \param message:	[const char*] A pointer to the confirmation dialog message.
 * \return			[bool] Returns true if the user confirms (Y/y), otherwise false.
 */
QSC_EXPORT_API bool qsc_consoleutils_message_confirm(const char* message);

/**
 * \brief Print a byte array to the console.
 *
 * Prints the array in a formatted manner with a specified number of characters per line.
 *
 * \param input:	[const uint8_t*] A pointer to the constant byte array.
 * \param inplen:	[size_t] The number of bytes in the array.
 * \param linelen:	[size_t] The number of bytes to print per line.
 */
QSC_EXPORT_API void qsc_consoleutils_print_array(const uint8_t* input, size_t inplen, size_t linelen);

/**
 * \brief Print a byte array as hexadecimal values to the console.
 *
 * \param input:	[const uint8_t*] A pointer to the constant byte array.
 * \param inplen:	[size_t] The number of bytes in the array.
 * \param linelen:	[size_t] The number of bytes to print per line before starting a new line.
 */
QSC_EXPORT_API void qsc_consoleutils_print_hex(const uint8_t* input, size_t inplen, size_t linelen);

/**
 * \brief Print a formatted string to the console, ignoring special characters.
 *
 * \param input:	[const char*] A pointer to the constant string.
 * \param inplen:	[size_t] The number of characters to print.
 */
QSC_EXPORT_API void qsc_consoleutils_print_formatted(const char* input, size_t inplen);

/**
 * \brief Print a formatted string to the console with a line break.
 *
 * \param input:	[const char*] A pointer to the constant string.
 * \param inplen:	[size_t] The number of characters to print.
 */
QSC_EXPORT_API void qsc_consoleutils_print_formatted_line(const char* input, size_t inplen);

/**
 * \brief Print a string safely to the console.
 *
 * Prints the string while ignoring any potentially unsafe characters.
 *
 * \param input:	[const char*] A pointer to the constant string.
 */
QSC_EXPORT_API void qsc_consoleutils_print_safe(const char* input);

/**
 * \brief Print a string to the console with a trailing line break.
 *
 * \param input:	[const char*] A pointer to the constant string.
 */
QSC_EXPORT_API void qsc_consoleutils_print_line(const char* input);

/**
 * \brief Print an unsigned 32-bit integer to the console.
 *
 * \param digit:	[uint32_t] The 32-bit unsigned integer to print.
 */
QSC_EXPORT_API void qsc_consoleutils_print_uint(uint32_t digit);

/**
 * \brief Print an unsigned 64-bit integer to the console.
 *
 * \param digit:	[uint64_t] The 64-bit unsigned integer to print.
 */
QSC_EXPORT_API void qsc_consoleutils_print_ulong(uint64_t digit);

/**
 * \brief Print a double-precision floating point number to the console.
 *
 * \param digit:	[double] The double value to print.
 */
QSC_EXPORT_API void qsc_consoleutils_print_double(double digit);

/**
 * \brief Print a double-precision floating point number to the console.
 *
 * \param input:	[const char**] A pointer to the constant string array.
 * \param count:	[size_t] The number of strings in the array.
 */
QSC_EXPORT_API void qsc_consoleutils_print_concatenated_line(const char** input, size_t count);

/**
 * \brief Display a small spinning progress counter for a specified duration.
 *
 * \param seconds:	[int32_t] The number of seconds to run the progress counter.
 */
QSC_EXPORT_API void qsc_consoleutils_progress_counter(int32_t seconds);

/**
 * \brief Send an "enter" (newline) command to the console.
 */
QSC_EXPORT_API void qsc_consoleutils_send_enter(void);

/**
 * \brief Set the vertical scroll buffer size of the console window.
 *
 * \param width:	[size_t] The desired buffer width.
 * \param height:	[size_t] The desired buffer height.
 */
QSC_EXPORT_API void qsc_consoleutils_set_window_buffer(size_t width, size_t height);

/**
 * \brief Clear all text from the console window.
 */
QSC_EXPORT_API void qsc_consoleutils_set_window_clear(void);

/**
 * \brief Set the console window prompt string.
 *
 * \param prompt:	[const char*] A pointer to the prompt string.
 */
QSC_EXPORT_API void qsc_consoleutils_set_window_prompt(const char* prompt);

/**
 * \brief Set the size of the console window.
 *
 * \param width:	[size_t] The desired window width.
 * \param height:	[size_t] The desired window height.
 */
QSC_EXPORT_API void qsc_consoleutils_set_window_size(size_t width, size_t height);

/**
 * \brief Set the title of the console window.
 *
 * \param title:	[const char*] A pointer to the title string.
 */
QSC_EXPORT_API void qsc_consoleutils_set_window_title(const char* title);

/**
 * \brief Enable virtual terminal processing mode in the console.
 */
QSC_EXPORT_API void qsc_consoleutils_set_virtual_terminal(void);

#endif
