#include "consoleutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdio.h>
#include <string.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
	/* bogus winbase.h error */
	QSC_SYSTEM_CONDITION_IGNORE(5105)
#	include <conio.h>
#	include <tchar.h>
#	include <Windows.h>
#   if defined(QSC_SYSTEM_COMPILER_MSC)
#	    pragma comment(lib, "user32.lib")
#   endif
#else
#	include <termios.h>
#	include <unistd.h>
#endif

#if !defined(QSC_SYSTEM_OS_WINDOWS)
static char getch(void)
{
    char buf = 0U;
    struct termios oldt, newt;
    fflush(stdout);

    if (tcgetattr(STDIN_FILENO, &oldt) != 0)
    {
        perror("tcgetattr");
        return 0;
    }

    newt = oldt;

    old.c_lflag &= ~ICANON;
    old.c_lflag &= ~ECHO;
    old.c_cc[VMIN] = 1;
    old.c_cc[VTIME] = 0U;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0)
    {
        perror("tcsetattr");
        return 0;
    }

    if (read(STDIN_FILENO, &buf, 1) < 0)
    {
        perror("read()");
    }

    old.c_lflag |= ICANON;
    old.c_lflag |= ECHO;

    if (tcsetattr(STDIN_FILENO, TCSADRAIN, &oldt) != 0)
    {
        perror("tcsetattr restore");
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
	/* TODO */
#endif
}

char qsc_consoleutils_get_char()
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
	QSC_ASSERT(maxlen != 0U);

	size_t slen;

	slen = 0U;

	if (line != NULL && maxlen != 0U)
	{
		if (fgets(line, (int32_t)maxlen, stdin) != NULL)
		{
			if (qsc_stringutils_string_contains(line, "\n") == true)
			{
				slen = qsc_stringutils_string_size(line);
				line[slen - 1] = '\0';
			}
			else
			{
				while (fgets(line, (int32_t)maxlen, stdin) != NULL) 
				{
					if (qsc_stringutils_string_contains(line, "\n") == true)
					{
						qsc_memutils_clear(line, maxlen);
						break;
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
	QSC_ASSERT(maxlen != 0U);

	size_t slen;

	slen = 0U;

	if (line != NULL && maxlen != 0U)
	{
		if (fgets(line, (int32_t)maxlen, stdin) != NULL)
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
	QSC_ASSERT(maxlen != 0U);

	size_t i;
	size_t len;
	size_t pos;

	len = 0U;
	pos = 0U;

	if (output != NULL && input != NULL && maxlen != 0U)
	{
		if (qsc_consoleutils_line_contains(input, "\"") == true)
		{
			for (i = 0U; i < maxlen; ++i)
			{
				if (input[i] == 34)
				{
					pos = i + 1;
					break;
				}
			}

			for (i = pos; i < maxlen; ++i)
			{
				if (input[i] == 34)
				{
					len = i - pos;
					break;
				}
			}
		}
		else if (qsc_consoleutils_line_contains(input, "\'") == true)
		{
			for (i = 0U; i < maxlen; ++i)
			{
				if (input[i] == 39)
				{
					pos = i + 1U;
					break;
				}
			}

			for (i = pos; i < maxlen; ++i)
			{
				if (input[i] == 39)
				{
					len = i - pos;
					break;
				}
			}
		}

		if (len > 0U && len <= maxlen)
		{
			qsc_memutils_copy(output, input + pos, len);
		}
	}

	return len;
}

char qsc_consoleutils_get_wait()
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
				idx1 = ((uint8_t)hexstr[pos + 1] & 0x1FU) ^ 0x10U;
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
		while (true)
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
						output[ctr - 1] = '0';
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
	QSC_ASSERT(inplen != 0U);

	if (input != NULL && inplen != 0U)
	{
		const char flag = '\\';
		char inp;

		for (size_t i = 0U; i < inplen; ++i)
		{
			inp = input[i];

			if (inp != flag)
			{
#if defined(QSC_SYSTEM_OS_WINDOWS)
				printf_s("%c", inp);
#else
				printf("%c", inp);
#endif
			}
			else
			{
#if defined(QSC_SYSTEM_OS_WINDOWS)
				printf_s("%c", flag);
#else
				printf("%c", flag);
#endif
			}
		}
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

	cnt = (size_t)seconds * 10U;

	for (size_t i = 0U; i < cnt; ++i)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		printf_s("%c", schr[i % sizeof(schr)]);
#else
		printf("%c", schr[i % sizeof(schr)]);
#endif

		qsc_consoleutils_print_safe("\b");

#if defined(QSC_SYSTEM_OS_WINDOWS)
		Sleep(100);
#else
		usleep(100000);
#endif
	}
}

void qsc_consoleutils_send_enter() 
{
    putchar('\n');
}

void qsc_consoleutils_set_window_buffer(size_t width, size_t height)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	RECT r;
	HWND con = GetConsoleWindow();
	GetWindowRect(con, &r);
	COORD cd = { (SHORT)width, (SHORT)height };
	SetConsoleScreenBufferSize(con, cd);
#else
	/* TODO: */
#endif
}

void qsc_consoleutils_set_window_clear()
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
	printf("\033[H\033[J");
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
		/* TODO: */
#endif
	}
}

void qsc_consoleutils_set_window_title(const char* title)
{
	QSC_ASSERT(title != NULL);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (title != NULL)
	{
		SetConsoleTitle((LPCSTR)title);
	}
#else
	/* TODO: */
#endif
}

void qsc_consoleutils_set_virtual_terminal()
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
	/* TODO: */
#endif
}
