#include "encoding.h"

bool qsc_encoding_base64_decode(uint8_t* output, size_t outlen, const char* input, size_t inlen)
{
	const static int DECTBL[] = 
	{
		62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
		59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
		6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
		29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
		43, 44, 45, 46, 47, 48, 49, 50, 51 
	};

	size_t i;
	size_t j;
	int v;
	bool res;

	res = true;

	if (input != NULL && output != NULL)
	{
		if (outlen < qsc_encoding_base64_decoded_size(input, inlen) || inlen % 4 != 0)
		{
			res = false;
		}

		if (res == true)
		{
			for (i = 0; i < inlen; i++)
			{
				if (!qsc_encoding_base64_is_valid_char(input[i]))
				{
					res = false;
					break;
				}
			}

			if (res == true)
			{
				for (i = 0, j = 0; i < inlen; i += 4, j += 3)
				{
					v = DECTBL[input[i] - 43];
					v = (v << 6) | DECTBL[input[i + 1] - 43];
					v = input[i + 2] == '=' ? v << 6 : (v << 6) | DECTBL[input[i + 2] - 43];
					v = input[i + 3] == '=' ? v << 6 : (v << 6) | DECTBL[input[i + 3] - 43];
					output[j] = (v >> 16) & 0xFF;

					if (input[i + 2] != '=')
					{
						output[j + 1] = (v >> 8) & 0xFF;
					}

					if (input[i + 3] != '=')
					{
						output[j + 2] = v & 0xFF;
					}
				}
			}
		}
	}

	return res;
}

size_t qsc_encoding_base64_decoded_size(const char* input, size_t length)
{
	size_t res;
	size_t i;

	res = 0;

	if (input != NULL)
	{
		res = (length / 4) * 3;

		for (i = length; i > 0; --i)
		{
			if (input[i] == '=')
			{
				--res;
				break;
			}
		}
	}

	return res;
}

void qsc_encoding_base64_encode(char* output, size_t outlen, const uint8_t* input, size_t inplen)
{
	const char ENCTBL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	size_t i;
	size_t j;
	size_t v;

	if (input != NULL && inplen != 0 && qsc_encoding_base64_encoded_size(inplen) <= outlen)
	{
		for (i = 0, j = 0; i < inplen; i += 3, j += 4)
		{
			v = input[i];
			v = i + 1 < inplen ? v << 8 | input[i + 1] : v << 8;
			v = i + 2 < inplen ? v << 8 | input[i + 2] : v << 8;

			output[j] = ENCTBL[(v >> 18) & 0x3F];
			output[j + 1] = ENCTBL[(v >> 12) & 0x3F];

			if (i + 1 < inplen)
			{
				output[j + 2] = ENCTBL[(v >> 6) & 0x3F];
			}
			else
			{
				output[j + 2] = '=';
			}

			if (i + 2 < inplen)
			{
				output[j + 3] = ENCTBL[v & 0x3F];
			}
			else
			{
				output[j + 3] = '=';
			}
		}
	}
}

size_t qsc_encoding_base64_encoded_size(size_t length)
{
	size_t ret;

	ret = length;

	if (length % 3 != 0)
	{
		ret += 3 - (length % 3);
	}

	ret /= 3;
	ret *= 4;

	return ret;
}

bool qsc_encoding_base64_is_valid_char(char c)
{
	bool res;

	res = false;

	if (c >= '0' && c <= '9')
	{
		res = true;
	}
	else if (c >= 'A' && c <= 'Z')
	{
		res = true;
	}
	else if (c >= 'a' && c <= 'z')
	{
		res = true;
	}
	else if (c == '+' || c == '/' || c == '=')
	{
		res = true;
	}

	return res;
}

void qsc_encoding_self_test()
{
	//const char *data = "ABC123Test Lets Try this' input and see What \"happens\"";
	//char       *enc;
	//char       *out;
	//size_t      out_len;

	//printf("data:    '%s'\n", data);

	//enc = b64_encode((const unsigned char *)data, strlen(data));
	//printf("encoded: '%s'\n", enc);

	//printf("dec size %s data size\n", b64_decoded_size(enc) == strlen(data) ? "==" : "!=");

	///* +1 for the NULL terminator. */
	//out_len = b64_decoded_size(enc) + 1;
	//out = malloc(out_len);

	//if (!b64_decode(enc, (unsigned char *)out, out_len)) {
	//	printf("Decode Failure\n");
	//	return 1;
	//}
	//out[out_len] = '\0';

	//printf("dec:     '%s'\n", out);
	//printf("data %s dec\n", strcmp(data, out) == 0 ? "==" : "!=");
	//free(out);

	//return 0;
}
