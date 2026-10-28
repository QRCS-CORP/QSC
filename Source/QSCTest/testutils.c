#include "testutils.h"
#include "qsccommon.h"
#include "memutils.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/** \brief Maximum console output width, including status and identifiers. */
#define QSCTEST_CONSOLE_WIDTH 120U
/** \brief Maximum buffered diagnostic line before forced formatting. */
#define QSCTEST_CONSOLE_BUFFER 2048U

static char qsctest_section_id[6] = "00.01";
static uint32_t qsctest_section_test_id = 0U;
static uint32_t qsctest_tls_stage_count[38U] = { 0U };
static char qsctest_output_buffer[QSCTEST_CONSOLE_BUFFER] = { 0 };
static size_t qsctest_output_length = 0U;

/** \brief Print a line without exceeding the portable console width.
 * \param input: The complete printable line.
 * \param indent: Indentation to use on continuation lines.
 * \note The formatter is intended for sequential test-runner output.
 */
static void qsctest_console_wrapped(const char* input, size_t indent)
{
	size_t pos;
	size_t line;
	size_t end;
	size_t space;
	size_t limit;
	size_t j;

	pos = 0U;
	while (input[pos] != '\0')
	{
		line = 0U;
		if (pos != 0U)
		{
			for (j = 0U; j < indent; ++j)
			{
				(void)putchar(' ');
			}
			line = indent;
		}

		limit = QSCTEST_CONSOLE_WIDTH - line;
		end = pos;
		while ((end - pos) < limit && input[end] != '\0')
		{
			++end;
		}
		if (input[end] != '\0')
		{
			space = end;
			while (space > pos && input[space] != ' ')
			{
				--space;
			}
			if (space > pos)
			{
				end = space;
			}
		}
		(void)fwrite(input + pos, 1U, end - pos, stdout);
		(void)putchar('\n');
		pos = end;
		while (input[pos] == ' ')
		{
			++pos;
		}
	}
	if (input[0] == '\0')
	{
		(void)putchar('\n');
	}
}

/** \brief Emit one completed test diagnostic with its section identifier.
 * \param input: Original completed diagnostic text.
 */
static void qsctest_console_emit(const char* input)
{
	char message[QSCTEST_CONSOLE_BUFFER + 48U] = { 0 };
	const char* body;
	const char* status;
	size_t length;
	bool isresult;
	unsigned int stage;
	int stageparsed;
	const char* stageptr;
	char section[6U] = { 0 };

	body = input;
	status = "";
	isresult = false;
	while (*body == ' ' || *body == '\t')
	{
		++body;
	}
	if (strncmp(body, "Success!", 8U) == 0)
	{
		status = "[PASS]";
		body += 8U;
		isresult = true;
	}
	else if (strncmp(body, "Failure!", 8U) == 0)
	{
		status = "[FAIL]";
		body += 8U;
		isresult = true;
	}
	else if (strncmp(body, "[PASS]", 6U) == 0 || strncmp(body, "[FAIL]", 6U) == 0)
	{
		status = body[1] == 'P' ? "[PASS]" : "[FAIL]";
		body += 6U;
		isresult = true;
	}
	else if (strncmp(body, "PASS:", 5U) == 0 || strncmp(body, "FAIL:", 5U) == 0)
	{
		status = body[0] == 'P' ? "[PASS]" : "[FAIL]";
		body += 5U;
		isresult = true;
	}
	else if (strncmp(body, "PASS ", 5U) == 0 || strncmp(body, "FAIL ", 5U) == 0)
	{
		status = body[0] == 'P' ? "[PASS]" : "[FAIL]";
		body += 4U;
		isresult = true;
	}

	while (*body == ' ' || *body == '\t')
	{
		++body;
	}
	/* Statistical providers traditionally append a PASS/FAIL suffix. */
	if (isresult == false)
	{
		length = strlen(body);
		while (length > 0U && body[length - 1U] == ' ')
		{
			--length;
		}
		if (length >= 7U && strncmp(body + length - 7U, " : PASS", 7U) == 0)
		{
			status = "[PASS]";
			isresult = true;
		}
		else if (length >= 7U && strncmp(body + length - 7U, " : FAIL", 7U) == 0)
		{
			status = "[FAIL]";
			isresult = true;
		}
	}
	if (isresult == false &&
		(strncmp(body, "CSP:", 4U) == 0 || strncmp(body, "CSG:", 4U) == 0 ||
		 strncmp(body, "HCG:", 4U) == 0 || strncmp(body, "SCB:", 4U) == 0))
	{
		if (strstr(body, " test passed.") != NULL)
		{
			status = "[PASS]";
			isresult = true;
		}
		else if (strstr(body, " test failed.") != NULL)
		{
			status = "[FAIL]";
			isresult = true;
		}
	}
	if (isresult == true)
	{
		if (strncmp(body, "Passed the ", 11U) == 0)
		{
			body += 11U;
		}
		else if (strncmp(body, "Failed the ", 11U) == 0)
		{
			body += 11U;
		}
		else if (strncmp(body, "Passed ", 7U) == 0 || strncmp(body, "Failed ", 7U) == 0)
		{
			body += 7U;
		}
		/* TLS stage identifiers remain visible and preserve stage numbering. */
		stage = 0U;
		stageparsed = 0;
		qsc_memutils_copy(section, qsctest_section_id, sizeof(section));
		if (strncmp(qsctest_section_id, "06.", 3U) == 0 &&
			strncmp(body, "TLS Stage ", 10U) == 0)
		{
			stageptr = body + 10U;

			if (stageptr[0] >= '1' && stageptr[0] <= '9')
			{
				stage = (unsigned int)(stageptr[0] - '0');
				++stageptr;

				if (stageptr[0] >= '0' && stageptr[0] <= '9')
				{
					stage = (stage * 10U) + (unsigned int)(stageptr[0] - '0');
					++stageptr;
				}

				if ((stageptr[0] == ' ' || stageptr[0] == '\0') && stage <= 37U)
				{
					stageparsed = 1;
				}
			}
		}
		if (stageparsed == 1 && stage >= 1U && stage <= 37U)
		{
			(void)snprintf(section, sizeof(section), "06.%02u", stage);
			++qsctest_tls_stage_count[stage];
			(void)snprintf(message, sizeof(message), "%s %s.%03u  %s",
				status, section, (unsigned int)qsctest_tls_stage_count[stage], body);
		}
		else
		{
			++qsctest_section_test_id;
			(void)snprintf(message, sizeof(message), "%s %s.%03u  %s",
				status, qsctest_section_id, (unsigned int)qsctest_section_test_id, body);
		}
		length = strlen(message);
		if (length >= 7U &&
			(strncmp(message + length - 7U, " : PASS", 7U) == 0 ||
			 strncmp(message + length - 7U, " : FAIL", 7U) == 0))
		{
			message[length - 7U] = '\0';
			length -= 7U;
		}
		while (length != 0U && (message[length - 1U] == ' ' || message[length - 1U] == '\t'))
		{
			message[--length] = '\0';
		}
		qsctest_console_wrapped(message, 10U);
	}
	else
	{
		if (strcmp(qsctest_section_id, "00.02") == 0 && body[0] != '\0' &&
			strncmp(body, "[INFO]", 6U) != 0)
		{
			(void)snprintf(message, sizeof(message), "[INFO] %s", body);
			qsctest_console_wrapped(message, 8U);
		}
		else
		{
			qsctest_console_wrapped(body, 8U);
		}
	}
}

/** \brief Print a qualification section and select its numeric identifier.
 * \param section: Stable section identifier (NN.NN).
 * \param title: Descriptive section name.
 */
void qsctest_print_section(const char* section, const char* title)
{
	char label[QSCTEST_CONSOLE_WIDTH + 1U] = { 0 };

	if (section != NULL && strlen(section) == 5U && section[2] == '.')
	{
		qsc_memutils_copy(qsctest_section_id, section, 5U);
		qsctest_section_id[5] = '\0';
	}
	qsctest_section_test_id = 0U;
	(void)putchar('\n');
	(void)puts("==============================================================================================================");
	(void)snprintf(label, sizeof(label), "  %s | %s", qsctest_section_id, title != NULL ? title : "Qualification");
	qsctest_console_wrapped(label, 8U);
	(void)puts("--------------------------------------------------------------------------------------------------------------");
}

char qsctest_get_char(void)
{
	char line[8] = { 0 };

	fgets(line, sizeof(line), stdin);

	return line[0];
}

char qsctest_get_wait(void)
{
	char res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (char)getwchar();
#else
	res = getchar();
#endif

	return res;
}

void qsctest_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
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

	memset(output, 0, length);

	for (size_t pos = 0; pos < (length * 2U); pos += 2U)
	{
		idx0 = ((uint8_t)hexstr[pos] & 0x1FU) ^ 0x10U;
		idx1 = ((uint8_t)hexstr[pos + 1U] & 0x1FU) ^ 0x10U;
		output[pos / 2U] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	}
}

void qsctest_print_hex(const uint8_t* input, size_t inputlen, size_t linelen)
{
	size_t i;

	while (inputlen >= linelen)
	{
		for (i = 0; i < linelen; ++i)
		{
#if defined(_MSC_VER)
			printf_s("%02X", input[i]);
#else
			printf("%02X", input[i]);
#endif
		}

		input += linelen;
		inputlen -= linelen;
		qsctest_print_safe("\n");
	}

	if (inputlen != 0)
	{
		for (i = 0; i < inputlen; ++i)
		{
#if defined(_MSC_VER)
			printf_s("%02X", input[i]);
#else
			printf("%02X", input[i]);
#endif
		}
	}
}

/** \brief Write console text, formatting complete diagnostic lines. */
void qsctest_print_safe(const char* input)
{
	size_t i;

	if (input != NULL)
	{
		for (i = 0U; input[i] != '\0'; ++i)
		{
			if (input[i] == '\n' || qsctest_output_length >= QSCTEST_CONSOLE_BUFFER - 1U)
			{
				qsctest_output_buffer[qsctest_output_length] = '\0';
				qsctest_console_emit(qsctest_output_buffer);
				qsctest_output_length = 0U;
			}
			if (input[i] != '\n' && input[i] != '\r')
			{
				qsctest_output_buffer[qsctest_output_length++] = input[i];
			}
		}
	}
}

/** \brief Print text followed by a line separator. */
void qsctest_print_line(const char* input)
{
	qsctest_print_safe(input);
	qsctest_print_safe("\n");
}

void qsctest_print_ulong(uint64_t digit)
{
#if defined(_MSC_VER)
	printf_s("%llu", digit);
#else
	printf("%llu", (unsigned long long)digit);
#endif
}

void qsctest_print_double(double digit)
{
#if defined(_MSC_VER)
	printf_s("%.*lf", 3, digit);
#else
	printf("%.*lf", 3, digit);
#endif
}

bool qsctest_test_confirm(const char* message)
{
	char ans;
	bool res;

	qsctest_print_line(message);

	res = false;
	ans = qsctest_get_char();

	if (ans == 'y' || ans == 'Y')
	{
		res = true;
	}

	return res;
}
