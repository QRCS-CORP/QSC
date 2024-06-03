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
	/* TODO: not working in ubuntu */

    char buf = 0;
    struct termios old = {0};
    fflush(stdout);

    if(tcgetattr(0, &old) < 0)
    {
        perror("tcsetattr()");
    }

    old.c_lflag &= ~ICANON;
    old.c_lflag &= ~ECHO;
    old.c_cc[VMIN] = 1;
    old.c_cc[VTIME] = 0;

    if(tcsetattr(0, TCSANOW, &old) < 0)
    {
        perror("tcsetattr ICANON");
    }

    if(read(0, &buf, 1) < 0)
    {
        perror("read()");
    }

    old.c_lflag |= ICANON;
    old.c_lflag |= ECHO;

    if(tcsetattr(0, TCSADRAIN, &old) < 0)
    {
        perror("tcsetattr ~ICANON");
    }

    //printf("%c\n", buf);
    return buf;
 }
#endif

void qsc_consoleutils_colored_message(const char* message, qsc_console_font_color color)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	assert(message != NULL);

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
			tcol = 0;
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
	res = getwchar();
#else
	res = getchar();
#endif

	return res;
}

size_t qsc_consoleutils_get_line(char* line, size_t maxlen)
{
	assert(line != NULL);
	assert(maxlen != 0);

	size_t slen;

	slen = 0;

	if (line != NULL && maxlen != 0)
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
	assert(line != NULL);
	assert(maxlen != 0);

	size_t slen;

	slen = 0;

	if (line != NULL && maxlen != 0)
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
	assert(output != NULL);
	assert(input != NULL);
	assert(maxlen != 0);

	size_t i;
	size_t len;
	size_t pos;

	len = 0;
	pos = 0;

	if (output != NULL && input != NULL && maxlen != 0)
	{
		if (qsc_consoleutils_line_contains(input, "\"") == true)
		{
			for (i = 0; i < maxlen; ++i)
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
			for (i = 0; i < maxlen; ++i)
			{
				if (input[i] == 39)
				{
					pos = i + 1;
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

		if (len > 0 && len <= maxlen)
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
	assert(hexstr != NULL);
	assert(output != NULL);
	assert(length != 0);

	uint8_t idx0;
	uint8_t idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	if (hexstr != NULL && output != NULL && length != 0)
	{
		qsc_memutils_clear(output, length);

		for (size_t  pos = 0; pos < (length * 2); pos += 2)
		{
			idx0 = ((uint8_t)hexstr[pos] & 0x1FU) ^ 0x10U;
			idx1 = ((uint8_t)hexstr[pos + 1] & 0x1FU) ^ 0x10U;
			output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
		}
	}
}

bool qsc_consoleutils_line_contains(const char* line, const char* token)
{
	assert(line != NULL);
	assert(token != NULL);

	bool res;

	res = false;

	if (line != NULL && token != NULL)
	{
		res = (qsc_stringutils_find_string(line, token) != -1);
	}

	return res;
}

bool qsc_consoleutils_line_equals(const char* line1, const char* line2)
{
	assert(line1 != NULL);
	assert(line2 != NULL);

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
	assert(output != NULL);
	assert(otplen != 0);

	size_t ctr;
	size_t mlen;
	char c;

	ctr = 0;
	mlen = otplen - 1;
	c = 0;

	if (output != NULL && otplen != 0)
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
					if (ctr > 0)
					{
						qsc_consoleutils_print_safe("\b \b");
						output[ctr] = '0';
						--ctr;
					}
				}
			}
			else
			{
				break;
			}
		};
	}

	qsc_consoleutils_print_line("");

	return ctr;
}

bool qsc_consoleutils_message_confirm(const char* message)
{
	assert(message != NULL);

	char ans;
	bool res;

	if (message != NULL)
	{
		qsc_consoleutils_print_line(message);

		res = false;
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
	assert(input != NULL);
	assert(inplen != 0);
	assert(linelen != 0);

	size_t i;

	if (input != NULL && inplen != 0 && linelen != 0)
	{
		while (inplen >= linelen)
		{
			for (i = 0; i < linelen; ++i)
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

		if (inplen != 0)
		{
			for (i = 0; i < inplen; ++i)
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
	assert(input != NULL);
	assert(count != 0);

	if (input != NULL && count != 0)
	{
		for (size_t i = 0; i < count; ++i)
		{
			if (input[i] != NULL && qsc_stringutils_string_size(input[i]) != 0)
			{
				qsc_consoleutils_print_safe(input[i]);
			}
		}
	}

	qsc_consoleutils_print_safe("\n");
}

void qsc_consoleutils_print_hex(const uint8_t* input, size_t inplen, size_t linelen)
{
	assert(input != NULL);
	assert(inplen != 0);
	assert(linelen != 0);

	size_t i;

	if (input != NULL && inplen != 0 && linelen != 0)
	{
		while (inplen >= linelen)
		{
			for (i = 0; i < linelen; ++i)
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

		if (inplen != 0)
		{
			for (i = 0; i < inplen; ++i)
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
	assert(input != NULL);
	assert(inplen != 0);

	if (input != NULL && inplen != 0)
	{
		const char flag = '\\';
		char inp;

		for (size_t i = 0; i < inplen; ++i)
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
	assert(input != NULL);
	assert(inplen != 0);

	if (input != NULL && inplen != 0)
	{
		qsc_consoleutils_print_formatted(input, inplen);
		qsc_consoleutils_print_line("");
	}
}

void qsc_consoleutils_print_line(const char* input)
{
	assert(input != NULL);

	if (input != NULL)
	{
		qsc_consoleutils_print_safe(input);
	}

	qsc_consoleutils_print_safe("\n");
}

void qsc_consoleutils_print_safe(const char* input)
{
	assert(input != NULL);

	if (input != NULL && qsc_stringutils_string_size(input) > 0)
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

	cnt = (size_t)seconds * 10;

	for (size_t i = 0; i < cnt; ++i)
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
	COORD coords = { 0, 0 };

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
	assert(prompt != NULL);

	if (prompt != NULL)
	{
		qsc_consoleutils_print_safe(prompt);
	}
}

void qsc_consoleutils_set_window_size(size_t width, size_t height)
{
	assert(width != 0);
	assert(height != 0);

	if (width != 0 && height != 0)
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
	assert(title != NULL);

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
		DWORD dwmode = 0;

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
