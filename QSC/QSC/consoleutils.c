#include "consoleutils.h"
#include "stringutils.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <conio.h>
#	include <tchar.h>
#	include <Windows.h>
#	pragma comment(lib, "user32.lib")
#else
#	include <unistd.h>
#endif

#include <stdio.h>

void qsc_consoleutils_colored_message(const char* message, qsc_console_font_color color)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)

	assert(message != NULL);

	int32_t tcol;

	if (message != NULL)
	{
		tcol = 0;
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

		SetConsoleTextAttribute(hcon, tcol);
		qsc_consoleutils_print_line(message);
		SetConsoleTextAttribute(hcon, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);

#else

#endif
	}
}

char qsc_consoleutils_get_char()
{
	char line[8] = { 0 };
	fgets(line, sizeof(line), stdin);

	return line[0];
}

size_t qsc_consoleutils_get_line(char* line, size_t maxlen)
{
	assert(line != NULL);

	size_t slen;

	slen = 0;

	if (line != NULL)
	{
		if (fgets(line, (int32_t)maxlen, stdin) != NULL)
		{
			slen = strlen(line);
		}
	}

	return slen;
}

size_t qsc_consoleutils_get_formatted_line(char* line, size_t maxlen)
{
	assert(line != NULL);

	size_t slen;

	slen = 0;

	if (line != NULL)
	{
		if (fgets(line, (int32_t)maxlen, stdin) != NULL)
		{
			qsc_stringutils_to_lowercase(line);
			qsc_stringutils_trim_newline(line);
			slen = strlen(line);
		}
	}

	return slen;
}

void qsc_consoleutils_get_wait()
{
	wint_t res;

	res = getwchar();
}

void qsc_consoleutils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	assert(hexstr != NULL);
	assert(output != NULL);

	size_t  pos;
	uint8_t  idx0;
	uint8_t  idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	if (hexstr != NULL && output != NULL)
	{
		memset(output, 0, length);

		for (pos = 0; pos < (length * 2); pos += 2)
		{
			idx0 = ((uint8_t)hexstr[pos + 0] & 0x1FU) ^ 0x10U;
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

size_t qsc_consoleutils_masked_password(uint8_t* output, size_t outlen)
{
	assert(output != NULL);

	size_t ctr;
	char c;

	c = '0';
	ctr = 0;

	if (output != NULL)
	{
		do
		{
			c = _getch();

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
		} while (c != '\r' || ctr >= outlen);
	}

	qsc_consoleutils_print_line("");

	return ctr;
}

bool qsc_consoleutils_message_confirm(const char* message)
{
	char ans;
	bool res;

	if (message != NULL)
	{
		qsc_consoleutils_print_line(message);
	}

	res = false;
	ans = qsc_consoleutils_get_char();

	if (ans == 'y' || ans == 'Y')
	{
		res = true;
	}

	return res;
}

void qsc_consoleutils_print_hex(const uint8_t* input, size_t inputlen, size_t linelen)
{
	assert(input != NULL);

	size_t i;

	if (input != NULL)
	{
		while (inputlen >= linelen)
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
			inputlen -= linelen;
			qsc_consoleutils_print_safe("\n");
		}

		if (inputlen != 0)
		{
			for (i = 0; i < inputlen; ++i)
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

void qsc_consoleutils_print_formatted(const char* input, size_t inputlen)
{
	assert(input != NULL);

	if (input != NULL)
	{
		size_t i;
		const char FLG = '\\';
		const char RPC[] = "\\";
		char inp;

		for (i = 0; i < inputlen; ++i)
		{
			inp = input[i];

			if (inp != FLG)
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
				printf_s(RPC);
#else
				printf(RPC);
#endif
			}
		}
	}
}

void qsc_consoleutils_print_formatted_line(const char* input, size_t inputlen)
{
	qsc_consoleutils_print_formatted(input, inputlen);
	qsc_consoleutils_print_line("");
}

void qsc_consoleutils_print_safe(const char* input)
{
	assert(input != NULL);

	if (input != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		printf_s(input);
#else
		printf(input);
#endif
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

void qsc_consoleutils_print_concatonated_line(const char** input, size_t count)
{
	assert(input != NULL);

	size_t i;
	size_t slen;

	if (input != NULL)
	{
		for (i = 0; i < count; ++i)
		{
			if (input[i] != NULL)
			{
				slen = strlen(input[i]);

				if (slen != 0)
				{
					qsc_consoleutils_print_safe(input[i]);
				}
			}
		}
	}

	qsc_consoleutils_print_safe("\n");
}

void qsc_consoleutils_print_uint(uint32_t digit)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	printf_s("%lu", digit);
#else
	printf("%lu", digit);
#endif
}

void qsc_consoleutils_print_ulong(uint64_t digit)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	printf_s("%llu", digit);
#else
	printf("%llu", digit);
#endif
}

void qsc_consoleutils_print_double(double digit)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	printf_s("%.*lf", 3, digit);
#else
	printf("%.*lf", 3, digit);
#endif
}

void qsc_consoleutils_progress_counter(int32_t seconds)
{
	const char schr[] = { "-\\|/-\\|/-" };
	size_t i;
	size_t cnt;

	cnt = seconds * 10;

	for (i = 0; i < cnt; ++i)
	{
		putchar(schr[i % sizeof(schr)]);
		fflush(stdout);
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

	HWND con = GetConsoleWindow();
	RECT r;
	GetWindowRect(con, &r);
	COORD cd = { (SHORT)width, (SHORT)height };
	SetConsoleScreenBufferSize(con, cd);

#else

#endif
}

void qsc_consoleutils_set_window_clear()
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	system("cls");
#else
	system("clear");
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
#if defined(QSC_SYSTEM_OS_WINDOWS)

	HWND con = GetConsoleWindow();
	RECT r;
	GetWindowRect(con, &r);
	MoveWindow(con, r.left, r.top, (int32_t)width, (int32_t)height, TRUE);

#else

#endif
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

#endif
}
