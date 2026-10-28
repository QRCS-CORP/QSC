/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "consoleutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdio.h>
#include <limits.h>
#include <limits.h>
#include <string.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
	/* bogus winbase.h error */
	QSC_SYSTEM_CONDITION_IGNORE(5105)
#if !defined(WIN32_LEAN_AND_MEAN)
#	define WIN32_LEAN_AND_MEAN
#endif
#if !defined(NOMINMAX)
#	define NOMINMAX
#endif
#	include <conio.h>
#	include <tchar.h>
#	include <Windows.h>
#   if defined(QSC_SYSTEM_COMPILER_MSC)
#	    pragma comment(lib, "user32.lib")
#   endif
#else
#	define _XOPEN_SOURCE 700
#	define _DARWIN_C_SOURCE
#   include <unistd.h>
#	include <termios.h>
#	include <unistd.h>
#endif

#if !defined(QSC_SYSTEM_OS_WINDOWS)
static char getch(void)
{
	char buf = 0U;
	struct termios oldt;
	struct termios newt;

	fflush(stdout);

	if (tcgetattr(STDIN_FILENO, &oldt) == 0)
	{
		newt = oldt;
		newt.c_lflag &= ~ICANON;
		newt.c_lflag &= ~ECHO;
		newt.c_cc[VMIN] = 1;
		newt.c_cc[VTIME] = 0U;

		if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) == 0)
		{
			if (read(STDIN_FILENO, &buf, 1) < 0)
			{
				perror("read()");
			}

			if (tcsetattr(STDIN_FILENO, TCSADRAIN, &oldt) != 0)
			{
				perror("tcsetattr restore");
			}
		}
	}

	return buf;
}
#endif

void qsc_consoleutils_colored_message(const char* message, qsc_console_font_color color)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	QSC_ASSERT(message != NULL);

	int32_t tcol;

	if (message != NULL)
	{
		HANDLE hcon = GetStdHandle(STD_OUTPUT_HANDLE);

		if (color == blue)
		{
			tcol = FOREGROUND_BLUE;
		}
		else if (color == green)
		{
			tcol = FOREGROUND_GREEN;
		}
		else if (color == red)
		{
			tcol = FOREGROUND_RED;
		}
		else
		{
			tcol = 0U;
		}

		SetConsoleTextAttribute(hcon, (WORD)tcol);
		qsc_consoleutils_print_line(message);
		SetConsoleTextAttribute(hcon, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
	}
#else
	const char* codes[] = { "0", "34", "32", "31" };

	if (message != NULL && (size_t)color < 4U)
	{
		fprintf(stdout, "\033[%sm%s\033[0m\n", codes[(size_t)color], message);
	}
#endif
}

char qsc_consoleutils_get_char(void)
{
	char res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (char)getwchar();
#else
	res = getchar();
#endif

	return res;
}

size_t qsc_consoleutils_get_line(char* line, size_t maxlen)
{
	QSC_ASSERT(line != NULL);

	size_t slen;
	int32_t limit;
	int32_t next;
	bool complete;

	slen = 0U;

	if (line != NULL && maxlen != 0U)
	{
		line[0] = '\0';

		if (maxlen > 1U)
		{
			limit = (maxlen > (size_t)INT_MAX) ? INT_MAX : (int32_t)maxlen;

			if (fgets(line, limit, stdin) != NULL)
			{
				slen = strlen(line);
				complete = (slen != 0U && line[slen - 1U] == '\n');

				if (complete == true)
				{
					--slen;
					line[slen] = '\0';
				}
				else if (feof(stdin) == 0)
				{
					next = getchar();

					if (next == '\n')
					{
						complete = true;
					}
					else if (next == EOF)
					{
						complete = (feof(stdin) != 0);
					}
					else
					{
						while ((next = getchar()) != EOF && next != '\n')
						{
						}
					}

					if (complete == false)
					{
						line[0] = '\0';
						slen = 0U;
					}
				}
			}
		}
	}

	return slen;
}

size_t qsc_consoleutils_get_formatted_line(char* line, size_t maxlen)
{
	QSC_ASSERT(line != NULL);

	size_t slen;
	int32_t limit;

	slen = 0U;

	if (line != NULL && maxlen > 1U)
	{
		limit = (maxlen > (size_t)INT_MAX) ? INT_MAX : (int32_t)maxlen;

		if (fgets(line, limit, stdin) != NULL)
		{
			qsc_stringutils_to_lowercase(line);
			qsc_stringutils_trim_newline(line);
			slen = qsc_stringutils_string_size(line);
		}
	}

	return slen;
}

size_t qsc_consoleutils_get_quoted_string(char* output, const char* input, size_t maxlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	const char* first;
	const char* last;
	size_t len;

	len = 0U;

	if (output != NULL && input != NULL && maxlen != 0U)
	{
		output[0] = '\0';
		first = strchr(input, '"');

		if (first != NULL)
		{
			last = strchr(first + 1, '"');
		}
		else
		{
			first = strchr(input, '\'');
			last = (first != NULL) ? strchr(first + 1, '\'') : NULL;
		}

		if (first != NULL && last != NULL)
		{
			len = (size_t)(last - first - 1);

			if (len < maxlen)
			{
				qsc_memutils_copy(output, first + 1, len);
				output[len] = '\0';
			}
			else
			{
				len = 0U;
			}
		}
	}

	return len;
}

char qsc_consoleutils_get_wait(void)
{
	char c;

	c = qsc_consoleutils_get_char();

	return c;
}

void qsc_consoleutils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	QSC_ASSERT(hexstr != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);

	if (hexstr != NULL && output != NULL && length != 0U)
	{
		uint8_t idx0;
		uint8_t idx1;

		const uint8_t hashmap[] =
		{
			0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
			0x08U, 0x09U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
			0x00U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x00U,
			0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
		};

		if (hexstr != NULL && output != NULL && length != 0U)
		{
			qsc_memutils_clear(output, length);

			for (size_t pos = 0U; pos < (length * 2U); pos += 2U)
			{
				idx0 = ((uint8_t)hexstr[pos] & 0x1FU) ^ 0x10U;
				idx1 = ((uint8_t)hexstr[pos + 1U] & 0x1FU) ^ 0x10U;
				output[pos / 2U] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
			}
		}
	}
}

bool qsc_consoleutils_line_contains(const char* line, const char* token)
{
	QSC_ASSERT(line != NULL);
	QSC_ASSERT(token != NULL);

	bool res;

	res = false;

	if (line != NULL && token != NULL)
	{
		res = (qsc_stringutils_find_string(line, token) != QSC_CONSOLE_STRING_NOT_FOUND);
	}

	return res;
}

bool qsc_consoleutils_line_equals(const char* line1, const char* line2)
{
	QSC_ASSERT(line1 != NULL);
	QSC_ASSERT(line2 != NULL);

	size_t slen;
	bool res;

	res = false;

	if (line1 != NULL && line2 != NULL)
	{
		slen = qsc_stringutils_string_size(line1);

		if (slen == qsc_stringutils_string_size(line2))
		{
			res = qsc_stringutils_compare_strings(line1, line2, slen);
		}
	}

	return res;
}

size_t qsc_consoleutils_masked_password(char* output, size_t otplen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(otplen != 0U);

	size_t ctr;
	size_t mlen;
	char c;

	ctr = 0U;
	mlen = otplen - 1U;

	if (output != NULL && otplen != 0U)
	{
		while (ctr < mlen)
		{
			if (ctr >= mlen)
			{
				break;
			}

#if defined(QSC_SYSTEM_OS_WINDOWS)
            c = (char)_getch();
#else
			c = getch();
#endif
			if (c != '\n' && c != '\r')
			{
				if (c != '\b')
				{
					qsc_consoleutils_print_safe("*");
					output[ctr] = c;
					++ctr;
				}
				else
				{
					if (ctr > 0U)
					{
						qsc_consoleutils_print_safe("\b \b");
						output[ctr - 1U] = '\0';
						--ctr;
					}
				}
			}
			else
			{
				break;
			}
		};

		output[ctr] = '\0';
	}

	qsc_consoleutils_print_line("");

	return ctr;
}

bool qsc_consoleutils_message_confirm(const char* message)
{
	QSC_ASSERT(message != NULL);

	char ans;
	bool res;

	res = false;

	if (message != NULL)
	{
		qsc_consoleutils_print_line(message);
		ans = qsc_consoleutils_get_char();

		if (ans == 'y' || ans == 'Y')
		{
			res = true;
		}
	}

	return res;
}

void qsc_consoleutils_print_array(const uint8_t* input, size_t inplen, size_t linelen)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(inplen != 0U);
	QSC_ASSERT(linelen != 0U);

	size_t i;

	if (input != NULL && inplen != 0U && linelen != 0U)
	{
		while (inplen >= linelen)
		{
			for (i = 0U; i < linelen; ++i)
			{
#if defined(QSC_SYSTEM_OS_WINDOWS)
				printf_s("%u", input[i]);
				printf_s(", ");
#else
				printf("%u", input[i]);
				printf(", ");
#endif
			}

			input += linelen;
			inplen -= linelen;
			qsc_consoleutils_print_safe("\n");
		}

		if (inplen != 0U)
		{
			for (i = 0U; i < inplen; ++i)
			{
#if defined(QSC_SYSTEM_OS_WINDOWS)
				printf_s("%u", input[i]);
				printf_s(", ");
#else
				printf("%u", input[i]);
				printf(", ");
#endif
			}
		}
	}
}

void qsc_consoleutils_print_double(double digit)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	printf_s("%.*lf", 3, digit);
#else
	printf("%.*lf", 3, digit);
#endif
}

void qsc_consoleutils_print_concatenated_line(const char** input, size_t count)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(count != 0U);

	if (input != NULL && count != 0U)
	{
		for (size_t i = 0U; i < count; ++i)
		{
			if (input[i] != NULL && qsc_stringutils_string_size(input[i]) != 0U)
			{
				qsc_consoleutils_print_safe(input[i]);
			}
		}
	}

	qsc_consoleutils_print_safe("\n");
}

void qsc_consoleutils_print_hex(const uint8_t* input, size_t inplen, size_t linelen)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(inplen != 0U);
	QSC_ASSERT(linelen != 0U);

	size_t i;

	if (input != NULL && inplen != 0U && linelen != 0U)
	{
		while (inplen >= linelen)
		{
			for (i = 0U; i < linelen; ++i)
			{
#if defined(QSC_SYSTEM_OS_WINDOWS)
				printf_s("%02X", input[i]);
#else
				printf("%02X", input[i]);
#endif
			}

			input += linelen;
			inplen -= linelen;
			qsc_consoleutils_print_safe("\n");
		}

		if (inplen != 0U)
		{
			for (i = 0U; i < inplen; ++i)
			{
#if defined(QSC_SYSTEM_OS_WINDOWS)
				printf_s("%02X", input[i]);
#else
				printf("%02X", input[i]);
#endif
			}
		}
	}
}

void qsc_consoleutils_print_formatted(const char* input, size_t inplen)
{
	QSC_ASSERT(input != NULL);

	if (input != NULL && inplen != 0U)
	{
		(void)fwrite(input, sizeof(char), inplen, stdout);
	}
}

void qsc_consoleutils_print_formatted_line(const char* input, size_t inplen)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(inplen != 0U);

	if (input != NULL && inplen != 0U)
	{
		qsc_consoleutils_print_formatted(input, inplen);
		qsc_consoleutils_print_line("");
	}
}

void qsc_consoleutils_print_line(const char* input)
{
	QSC_ASSERT(input != NULL);

	if (input != NULL)
	{
		qsc_consoleutils_print_safe(input);
	}

	qsc_consoleutils_print_safe("\n");
}

void qsc_consoleutils_print_safe(const char* input)
{
	QSC_ASSERT(input != NULL);

	if (input != NULL && qsc_stringutils_string_size(input) > 0U)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		printf_s("%s", input);
#else
		printf("%s", input);
#endif
	}
}

void qsc_consoleutils_print_uint(uint32_t digit)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	printf_s("%lu", digit);
#else
	printf("%lu", (unsigned long)digit);
#endif
}

void qsc_consoleutils_print_ulong(uint64_t digit)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	printf_s("%llu", digit);
#else
	printf("%llu", (unsigned long long)digit);
#endif
}

void qsc_consoleutils_progress_counter(int32_t seconds)
{
	const char schr[] = { "-\\|/-\\|/-" };
	size_t cnt;

	cnt = (seconds > 0 && (size_t)seconds <= (SIZE_MAX / 10U)) ? ((size_t)seconds * 10U) : 0U;

	for (size_t i = 0U; i < cnt; ++i)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		printf_s("%c", schr[i % (sizeof(schr) - 1U)]);
#else
		printf("%c", schr[i % (sizeof(schr) - 1U)]);
#endif

		qsc_consoleutils_print_safe("\b");

#if defined(QSC_SYSTEM_OS_WINDOWS)
		Sleep(100);
#else
		usleep(100000U);
#endif
	}
}

void qsc_consoleutils_send_enter(void) 
{
    putchar('\n');
}

void qsc_consoleutils_set_window_buffer(size_t width, size_t height)
{
	if (width != 0U && height != 0U)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		HANDLE con = GetStdHandle(STD_OUTPUT_HANDLE);
		if (con != NULL && con != INVALID_HANDLE_VALUE && width <= SHRT_MAX && height <= SHRT_MAX)
		{
			COORD cd = { (SHORT)width, (SHORT)height };
			(void)SetConsoleScreenBufferSize(con, cd);
		}
#else
		fprintf(stdout, "\033[8;%zu;%zut", height, width);
		fflush(stdout);
#endif
	}
}

void qsc_consoleutils_set_window_clear(void)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	HANDLE hcon;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	DWORD count;
	DWORD cells;
	COORD coords = { 0U, 0U };

	hcon = GetStdHandle(STD_OUTPUT_HANDLE);

	if (hcon != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(hcon, &csbi) == TRUE)
	{
		cells = csbi.dwSize.X * csbi.dwSize.Y;

		if (FillConsoleOutputCharacter(hcon, (TCHAR)' ', cells, coords, &count) == TRUE &&
			FillConsoleOutputAttribute(hcon, csbi.wAttributes, cells, coords, &count) == TRUE)
		{
			SetConsoleCursorPosition(hcon, coords);
		}
	}
#else
	fprintf(stdout, "\033[H\033[2J\033[3J");
	fflush(stdout);
#endif
}

void qsc_consoleutils_set_window_prompt(const char* prompt)
{
	QSC_ASSERT(prompt != NULL);

	if (prompt != NULL)
	{
		qsc_consoleutils_print_safe(prompt);
	}
}

void qsc_consoleutils_set_window_size(size_t width, size_t height)
{
	QSC_ASSERT(width != 0U);
	QSC_ASSERT(height != 0U);

	if (width != 0U && height != 0U)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		RECT r;
		HWND con = GetConsoleWindow();
		GetWindowRect(con, &r);
		MoveWindow(con, r.left, r.top, (int32_t)width, (int32_t)height, TRUE);
#else
		fprintf(stdout, "\033[8;%zu;%zut", height, width);
		fflush(stdout);
#endif
	}
}

void qsc_consoleutils_set_window_title(const char* title)
{
	QSC_ASSERT(title != NULL);

	if (title != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		SetConsoleTitle((LPCSTR)title);
#else
		fprintf(stdout, "\033]0;%s\007", title);
		fflush(stdout);
#endif
	}
}

void qsc_consoleutils_set_virtual_terminal(void)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	HANDLE hcon = GetStdHandle(STD_OUTPUT_HANDLE);

	if (hcon != INVALID_HANDLE_VALUE)
	{
		DWORD dwmode = 0U;

		if (GetConsoleMode(hcon, &dwmode) == TRUE)
		{
			dwmode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
			SetConsoleMode(hcon, dwmode);
		}
	}
#else
	fprintf(stdout, "\033[0m");
	fflush(stdout);
#endif
}

