/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* An implementation of common console support functions
* Written by John G. Underhill
* Written on January 24, 2021
* Contact: support@vtdev.com
*/

/*
* \file consoleutils.h
* \brief <b>Console utilities; common console support functions</b> \n
* January 24, 2021
*/

#ifndef QSC_CONSOLEUTILS_H
#define QSC_CONSOLEUTILS_H

/* bogus winbase.h error */
#pragma warning(disable : 5105)

#include "common.h"

#define CONSOLE_MAX_LINE 128

typedef enum qsc_console_font_color
{
	white = 0,
	blue = 1,
	green = 2,
	red = 3
} qsc_console_font_color;

typedef enum qsc_console_font_style
{
	regular = 0,
	bold = 1,
	italic = 2,
	bolditalic = 3
} qsc_console_font_style;

/**
* \brief color a line of console text
*
* \return Returns the character detected
*/
QSC_EXPORT_API void qsc_consoleutils_colored_message(const char* message, qsc_console_font_color color);

/**
* \brief Get a single character from the console
*
* \return Returns the character detected
*/
QSC_EXPORT_API char qsc_consoleutils_get_char();

/**
* \brief Get a string of characters from the console
*
* \param line: the string of text received
* \param maxlen: the maximum text length
*
* \return Returns the number of characters in the line
*/
QSC_EXPORT_API size_t qsc_consoleutils_get_line(char* line, size_t maxlen);

/**
* \brief Get a string of characters from the console that is lowercase and trimmed
*
* \param line: the string of text received
* \return Returns the number of characters in the line
*/
QSC_EXPORT_API size_t qsc_consoleutils_get_formatted_line(char* line, size_t maxlen);

/**
* \brief Pause the console until user input is detected
*/
QSC_EXPORT_API void qsc_consoleutils_get_wait();

/**
* \brief Convert a hexadecimal character string to a character byte array
*
* \param hexstr: the string to convert
* \param output: the character output array
* \param length: the number of characters to convert
*/
QSC_EXPORT_API void qsc_consoleutils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
* \brief Get a string
of characters from the console
*
* \param line: the string of text received
* \return Returns the number of characters in the line
*/
QSC_EXPORT_API bool qsc_consoleutils_line_contains(const char* line, const char* token);

/**
* \brief Gets a password masked on the console screen
*
* \param output: the character output array
* \param length: the size of the output array
* \return Returns the size of ther password
*/
QSC_EXPORT_API size_t qsc_consoleutils_masked_password(uint8_t* output, size_t outlen);

/**
* \brief User confirmation that and action can continue(Y/N y/n)
*
* \param message: the message to print
*/
QSC_EXPORT_API bool qsc_consoleutils_message_confirm(const char* message);

/**
* \brief Convert a character array to a hexidecimal string and print to the console
*
* \param input: the character array
* \param inputlen: the number of characters to print
* \param linelen: the length of output to print, before starting a new line
*/
QSC_EXPORT_API void qsc_consoleutils_print_hex(const uint8_t* input, size_t inputlen, size_t linelen);

/**
* \brief Print a string to the console, ignoring special characters
*
* \param input: the character array
* \param inputlen: the number of characters to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_formatted(const char* input, size_t inputlen);

/**
* \brief Print a string to the console, ignoring special characters, and add a line break
*
* \param input: the character array
* \param inputlen: the number of characters to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_formatted_line(const char* input, size_t inputlen);

/**
* \brief Print an array of characters to the console
*
* \param input: the character array to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_safe(const char* input);

/**
* \brief Print an array of characters to the console with a line break
*
* \param input: the character array to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_line(const char* input);

/**
* \brief Print a concatonated set of three character arrays to the console with a line break
*
* \param input: the two dimensional character array to print
* \param count: the number of arrays contained in input
*/
QSC_EXPORT_API void qsc_consoleutils_print_concatonated_line(const char** input, size_t count);

/**
* \brief Print an unsigned 32-bit integer
*
* \param digit: the number to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_uint(uint32_t digit);

/**
* \brief Print an unsigned 64-bit integer
*
* \param digit: the number to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_ulong(uint64_t digit);

/**
* \brief Print a double integer
*
* \param digit: the number to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_double(double digit);

/**
* \brief Prints a small spinning counter
*
* \param seconds: the number of seconds to run
*/
QSC_EXPORT_API void qsc_consoleutils_progress_counter(int32_t seconds);

/**
* \brief Set the size of the window scroll buffer
*
* \param width: the scroll buffer width
* \param height: the scroll buffer height
*/
QSC_EXPORT_API void qsc_consoleutils_set_window_buffer(size_t width, size_t height);

/**
* \brief Clear text from the window
*/
QSC_EXPORT_API void qsc_consoleutils_set_window_clear();

/**
* \brief Set the window prompt string
*
* \param prompt: the prompt string
*/
QSC_EXPORT_API void qsc_consoleutils_set_window_prompt(const char* prompt);

/**
* \brief Set the initial size of the console window
*
* \param width: the window width
* \param height: the window height
*/
QSC_EXPORT_API void qsc_consoleutils_set_window_size(size_t width, size_t height);

/**
* \brief Set the window title string
*
* \param title: the title string
*/
QSC_EXPORT_API void qsc_consoleutils_set_window_title(const char* title);

/**
* \brief Enable virtual terminal mode
*/
QSC_EXPORT_API void qsc_consoleutils_set_virtual_terminal();

#endif