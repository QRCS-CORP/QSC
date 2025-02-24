#include "aesavs_test.h"
#include "../QSC/aes.h"
#include "../QSC/fileutils.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "testutils.h"

static bool aesavs_cbc128_kat(const char* filepath)
{
	FILE* fp;
	const char* CBC_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* CBC_KEY = "KEY = ";
	const char* CBC_PLAINTEXT = "PLAINTEXT = ";
	const char* CBC_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t dec[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pln[QSC_AES_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	errno_t err;
	bool res;

	res = true;
	line = NULL;
	err = 0;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL && err == 0)
	{
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CBC_COUNT, strlen(CBC_COUNT)) == 0)
				{
					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CBC_KEY, strlen(CBC_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_PLAINTEXT, strlen(CBC_PLAINTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CBC_CIPHERTEXT, strlen(CBC_CIPHERTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_CIPHERTEXT), exp, sizeof(exp));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_state state;
					qsc_aes_keyparams kp1 = { key, QSC_AES128_KEY_SIZE, ivc };
					qsc_aes_initialize(&state, &kp1, true, qsc_aes_cipher_128);
					qsc_aes_cbc_encrypt_block(&state, otp, pln);
					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_keyparams kp2 = { key, QSC_AES128_KEY_SIZE, ivc };
					qsc_aes_initialize(&state, &kp2, false, qsc_aes_cipher_128);
					qsc_aes_cbc_decrypt_block(&state, dec, otp);
					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_cbc256_kat(const char* filepath)
{
	FILE* fp;
	const char* CBC_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* CBC_KEY = "KEY = ";
	const char* CBC_PLAINTEXT = "PLAINTEXT = ";
	const char* CBC_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t dec[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pln[QSC_AES_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	bool res;

	res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CBC_COUNT, strlen(CBC_COUNT)) == 0)
				{
					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CBC_KEY, strlen(CBC_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_PLAINTEXT, strlen(CBC_PLAINTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CBC_CIPHERTEXT, strlen(CBC_CIPHERTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_CIPHERTEXT), exp, sizeof(exp));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_state state;
					qsc_aes_keyparams kp1 = { key, QSC_AES256_KEY_SIZE, ivc };
					qsc_aes_initialize(&state, &kp1, true, qsc_aes_cipher_256);
					qsc_aes_cbc_encrypt_block(&state, otp, pln);
					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_keyparams kp2 = { key, QSC_AES256_KEY_SIZE, ivc };
					qsc_aes_initialize(&state, &kp2, false, qsc_aes_cipher_256);
					qsc_aes_cbc_decrypt_block(&state, dec, otp);
					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_ecb128_kat(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t dec[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pln[QSC_AES_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	bool res;

    res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_CIPHERTEXT), exp, sizeof(exp));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_aes_state state;
					qsc_aes_keyparams kp = { key, QSC_AES128_KEY_SIZE };
					qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);
					qsc_aes_ecb_encrypt_block(&state, otp, pln);
					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_128);
					qsc_aes_ecb_decrypt_block(&state, dec, otp);
					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_ecb256_kat(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t dec[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pln[QSC_AES_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	bool res;

    res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_CIPHERTEXT), exp, sizeof(exp));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_aes_state state;
					qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE };
					qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);
					qsc_aes_ecb_encrypt_block(&state, otp, pln);
					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_256);
					qsc_aes_ecb_decrypt_block(&state, dec, otp);
					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_cbc128_mct(const char* filepath)
{
	FILE* fp;
	const char* CBC_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* CBC_KEY = "KEY = ";
	const char* CBC_PLAINTEXT = "PLAINTEXT = ";
	const char* CBC_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t enc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t otpc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pln[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t plnc[QSC_AES_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t count;
	size_t i;
	size_t len;
	bool res;

	count = 0;
    res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CBC_COUNT, strlen(CBC_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CBC_KEY, strlen(CBC_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_PLAINTEXT, strlen(CBC_PLAINTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CBC_CIPHERTEXT, strlen(CBC_CIPHERTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_CIPHERTEXT), exp, sizeof(exp));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}

					if (count <= 100)
					{
						qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);
						qsc_memutils_copy(plnc, pln, QSC_AES_BLOCK_SIZE);

						qsc_aes_state state;
						qsc_aes_keyparams kp = { key, QSC_AES128_KEY_SIZE, ivc };
						qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);

						for (i = 0; i < 1000; ++i)
						{
							if (i != 0)
							{
								qsc_memutils_copy(otpc, otp, QSC_AES_BLOCK_SIZE);
								qsc_aes_cbc_encrypt_block(&state, otp, plnc);
								qsc_memutils_copy(plnc, otpc, QSC_AES_BLOCK_SIZE);
							}
							else
							{
								qsc_aes_cbc_encrypt_block(&state, otp, plnc);
								qsc_memutils_copy(plnc, iv, QSC_AES_BLOCK_SIZE);
							}
						}

						qsc_aes_dispose(&state);

						if (qsc_intutils_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
						{
							res = false;
							break;
						}
					}
					else
					{
						qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);
						qsc_memutils_copy(enc, exp, QSC_AES_BLOCK_SIZE);

						qsc_aes_state state;
						qsc_aes_keyparams kp = { key, QSC_AES128_KEY_SIZE, ivc };
						qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_128);

						for (i = 0; i < 1000; ++i)
						{
							if (i != 0)
							{
								qsc_memutils_copy(otpc, otp, QSC_AES_BLOCK_SIZE);
								qsc_aes_cbc_decrypt_block(&state, otp, enc);
								qsc_memutils_copy(enc, otpc, QSC_AES_BLOCK_SIZE);
							}
							else
							{
								qsc_aes_cbc_decrypt_block(&state, otp, enc);
								qsc_memutils_copy(enc, iv, QSC_AES_BLOCK_SIZE);
							}
						}

						if (qsc_intutils_are_equal8(otp, pln, QSC_AES_BLOCK_SIZE) == false)
						{
							res = false;
							break;
						}
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_cbc256_mct(const char* filepath)
{
	FILE* fp;
	const char* CBC_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* CBC_KEY = "KEY = ";
	const char* CBC_PLAINTEXT = "PLAINTEXT = ";
	const char* CBC_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t enc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t otpc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pln[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t plnc[QSC_AES_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t count;
	size_t i;
	size_t len;
	bool res;

	count = 0;
    res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CBC_COUNT, strlen(CBC_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CBC_KEY, strlen(CBC_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_PLAINTEXT, strlen(CBC_PLAINTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CBC_CIPHERTEXT, strlen(CBC_CIPHERTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_CIPHERTEXT), exp, sizeof(exp));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}

					if (count <= 100)
					{
						qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);
						qsc_memutils_copy(plnc, pln, QSC_AES_BLOCK_SIZE);

						qsc_aes_state state;
						qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE, ivc };
						qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);

						for (i = 0; i < 1000; ++i)
						{
							if (i != 0)
							{
								qsc_memutils_copy(otpc, otp, QSC_AES_BLOCK_SIZE);
								qsc_aes_cbc_encrypt_block(&state, otp, plnc);
								qsc_memutils_copy(plnc, otpc, QSC_AES_BLOCK_SIZE);
							}
							else
							{
								qsc_aes_cbc_encrypt_block(&state, otp, plnc);
								qsc_memutils_copy(plnc, iv, QSC_AES_BLOCK_SIZE);
							}
						}

						qsc_aes_dispose(&state);

						if (qsc_intutils_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
						{
							res = false;
							break;
						}
					}
					else
					{
						qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);
						qsc_memutils_copy(enc, exp, QSC_AES_BLOCK_SIZE);

						qsc_aes_state state;
						qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE, ivc };
						qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_256);

						for (i = 0; i < 1000; ++i)
						{
							if (i != 0)
							{
								qsc_memutils_copy(otpc, otp, QSC_AES_BLOCK_SIZE);
								qsc_aes_cbc_decrypt_block(&state, otp, enc);
								qsc_memutils_copy(enc, otpc, QSC_AES_BLOCK_SIZE);
							}
							else
							{
								qsc_aes_cbc_decrypt_block(&state, otp, enc);
								qsc_memutils_copy(enc, iv, QSC_AES_BLOCK_SIZE);
							}
						}

						if (qsc_intutils_are_equal8(otp, pln, QSC_AES_BLOCK_SIZE) == false)
						{
							res = false;
							break;
						}
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_ecb128_mct(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t dec[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pln[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t plnc[QSC_AES_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	bool res;

    res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_CIPHERTEXT), exp, sizeof(exp));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_aes_state state;
					qsc_aes_keyparams kp = { key, QSC_AES128_KEY_SIZE };
					qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);
					qsc_memutils_copy(plnc, pln, QSC_AES_BLOCK_SIZE);

					for (i = 0; i < 1000; ++i)
					{
						qsc_aes_ecb_encrypt_block(&state, otp, plnc);
						qsc_memutils_copy(plnc, otp, QSC_AES_BLOCK_SIZE);
					}

					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_128);

					for (i = 0; i < 1000; ++i)
					{
						qsc_aes_ecb_decrypt_block(&state, dec, otp);
						qsc_memutils_copy(otp, dec, QSC_AES_BLOCK_SIZE);
					}

					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_ecb256_mct(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t dec[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pln[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t plnc[QSC_AES_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	bool res;

    res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_CIPHERTEXT), exp, sizeof(exp));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_aes_state state;
					qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE };
					qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);
					qsc_memutils_copy(plnc, pln, QSC_AES_BLOCK_SIZE);

					for (i = 0; i < 1000; ++i)
					{
						qsc_aes_ecb_encrypt_block(&state, otp, plnc);
						qsc_memutils_copy(plnc, otp, QSC_AES_BLOCK_SIZE);
					}

					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_256);

					for (i = 0; i < 1000; ++i)
					{
						qsc_aes_ecb_decrypt_block(&state, dec, otp);
						qsc_memutils_copy(otp, dec, QSC_AES_BLOCK_SIZE);
					}

					qsc_aes_dispose(&state);

					if (qsc_intutils_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_cbc128_mmt(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t* dec;
	uint8_t* exp;
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t* otp;
	uint8_t* pln;
	int64_t read;
	size_t count;
	size_t i;
	size_t alen;
	size_t rlen;
	bool res;

	exp = NULL;
	dec = NULL;
	otp = NULL;
	pln = NULL;
    res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		alen = 0;
		count = 0;
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &rlen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &rlen, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)qsc_memutils_malloc(alen);

							if (pln != NULL)
							{
								qsc_memutils_clear(pln, alen);
								qsctest_hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_CIPHERTEXT) + 1)) / 2;
							exp = (uint8_t*)qsc_memutils_malloc(alen);
							dec = (uint8_t*)qsc_memutils_malloc(alen);
							otp = (uint8_t*)qsc_memutils_malloc(alen);

							if (exp != NULL && otp != NULL && dec != NULL)
							{
								qsc_memutils_clear(exp, alen);
								qsc_memutils_clear(dec, alen);
								qsc_memutils_clear(otp, alen);
								qsctest_hex_to_bin(line + strlen(ECB_CIPHERTEXT), exp, alen);
							}
							else
							{
								res = false;
								break;
							}
						}
						else
						{
							res = false;
							break;
						}
					}

					if (res == false)
					{
						break;
					}

					if (count <= 10)
					{
						if (pln != NULL && exp != NULL && dec != NULL && otp != NULL)
						{
							qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);

							qsc_aes_state state;
							qsc_aes_keyparams kp = { key, QSC_AES128_KEY_SIZE, ivc };
							qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);

							for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
							{
								qsc_aes_cbc_encrypt_block(&state, otp + (i * QSC_AES_BLOCK_SIZE), pln + (i * QSC_AES_BLOCK_SIZE));
							}

							qsc_aes_dispose(&state);

							if (qsc_intutils_are_equal8(exp, otp, alen) == false)
							{
								res = false;
								break;
							}

							qsc_memutils_alloc_free(exp);
							qsc_memutils_alloc_free(dec);
							qsc_memutils_alloc_free(pln);
							qsc_memutils_alloc_free(otp);
						}
					}
					else
					{
						if (pln != NULL && exp != NULL && dec != NULL && otp != NULL)
						{
							qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);

							qsc_aes_state state;
							qsc_aes_keyparams kp = { key, QSC_AES128_KEY_SIZE, ivc };
							qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_128);

							for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
							{
								qsc_aes_cbc_decrypt_block(&state, dec + (i * QSC_AES_BLOCK_SIZE), exp + (i * QSC_AES_BLOCK_SIZE));
							}

							qsc_aes_dispose(&state);

							if (qsc_intutils_are_equal8(dec, pln, alen) == false)
							{
								res = false;
								break;
							}

							qsc_memutils_alloc_free(exp);
							qsc_memutils_alloc_free(dec);
							qsc_memutils_alloc_free(pln);
							qsc_memutils_alloc_free(otp);
						}
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_cbc256_mmt(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t* dec;
	uint8_t* exp;
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t* otp;
	uint8_t* pln;
	int64_t read;
	size_t count;
	size_t i;
	size_t alen;
	size_t rlen;
	bool res;

	exp = NULL;
	dec = NULL;
	otp = NULL;
	pln = NULL;
    res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		alen = 0;
		count = 0;
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &rlen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &rlen, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)qsc_memutils_malloc(alen);

							if (pln != NULL)
							{
								qsc_memutils_clear(pln, alen);
								qsctest_hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_CIPHERTEXT) + 1)) / 2;
							exp = (uint8_t*)qsc_memutils_malloc(alen);
							dec = (uint8_t*)qsc_memutils_malloc(alen);
							otp = (uint8_t*)qsc_memutils_malloc(alen);

							if (exp != NULL && dec != NULL && otp != NULL)
							{
								qsc_memutils_clear(exp, alen);
								qsc_memutils_clear(dec, alen);
								qsc_memutils_clear(otp, alen);
								qsctest_hex_to_bin(line + strlen(ECB_CIPHERTEXT), exp, alen);
							}
							else
							{
								res = false;
								break;
							}
						}
						else
						{
							res = false;
							break;
						}
					}

					if (res == false)
					{
						break;
					}

					if (count <= 10)
					{
						if (pln != NULL && exp != NULL && dec != NULL && otp != NULL)
						{
							qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);

							qsc_aes_state state;
							qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE, ivc };
							qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);

							for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
							{
								qsc_aes_cbc_encrypt_block(&state, otp + (i * QSC_AES_BLOCK_SIZE), pln + (i * QSC_AES_BLOCK_SIZE));
							}

							qsc_aes_dispose(&state);

							if (qsc_intutils_are_equal8(exp, otp, alen) == false)
							{
								res = false;
								break;
							}

							qsc_memutils_alloc_free(exp);
							qsc_memutils_alloc_free(dec);
							qsc_memutils_alloc_free(pln);
							qsc_memutils_alloc_free(otp);
						}
					}
					else
					{
						if (pln != NULL && exp != NULL && dec != NULL && otp != NULL)
						{
							qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);

							qsc_aes_state state;
							qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE, ivc };
							qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_256);

							for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
							{
								qsc_aes_cbc_decrypt_block(&state, dec + (i * QSC_AES_BLOCK_SIZE), exp + (i * QSC_AES_BLOCK_SIZE));
							}

							qsc_aes_dispose(&state);

							if (qsc_intutils_are_equal8(dec, pln, alen) == false)
							{
								res = false;
								break;
							}

							qsc_memutils_alloc_free(exp);
							qsc_memutils_alloc_free(dec);
							qsc_memutils_alloc_free(pln);
							qsc_memutils_alloc_free(otp);
						}
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_ecb128_mmt(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t* exp;
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t* otp;
	uint8_t* pln;
	int64_t read;
	size_t i;
	size_t alen;
	size_t rlen;
	bool res;

	exp = NULL;
	otp = NULL;
	pln = NULL;
    res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		alen = 0;
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &rlen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &rlen, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)qsc_memutils_malloc(alen);

							if (pln != NULL)
							{
								qsc_memutils_clear(pln, alen);
								qsctest_hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_CIPHERTEXT) + 1)) / 2;
							exp = (uint8_t*)qsc_memutils_malloc(alen);
							otp = (uint8_t*)qsc_memutils_malloc(alen);

							if (exp != NULL && otp != NULL)
							{
								qsc_memutils_clear(exp, alen);
								qsc_memutils_clear(otp, alen);

								qsctest_hex_to_bin(line + strlen(ECB_CIPHERTEXT), exp, alen);
							}
							else
							{
								res = false;
							}
						}
						else
						{
							res = false;
							break;
						}
					}

					if (res == false)
					{
						break;
					}

					if (pln != NULL && exp != NULL && otp != NULL)
					{
						qsc_aes_state state;
						qsc_aes_keyparams kp = { key, QSC_AES128_KEY_SIZE };
						qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);

						for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
						{
							qsc_aes_ecb_encrypt_block(&state, otp + (i * QSC_AES_BLOCK_SIZE), pln + (i * QSC_AES_BLOCK_SIZE));
						}

						qsc_aes_dispose(&state);

						if (qsc_intutils_are_equal8(exp, otp, alen) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_alloc_free(exp);
						qsc_memutils_alloc_free(pln);
						qsc_memutils_alloc_free(otp);
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool aesavs_ecb256_mmt(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t* exp;
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t* otp;
	uint8_t* pln;
	int64_t read;
	size_t i;
	size_t alen;
	size_t rlen;
	bool res;

	exp = NULL;
	otp = NULL;
	pln = NULL;
    res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		alen = 0;
		read = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &rlen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &rlen, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							qsctest_hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)qsc_memutils_malloc(alen);

							if (pln != NULL)
							{
								qsc_memutils_clear(pln, alen);
								qsctest_hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_CIPHERTEXT) + 1)) / 2;
							exp = (uint8_t*)qsc_memutils_malloc(alen);
							otp = (uint8_t*)qsc_memutils_malloc(alen);

							if (exp != NULL && otp != NULL)
							{
								qsc_memutils_clear(exp, alen);
								qsc_memutils_clear(otp, alen);

								qsctest_hex_to_bin(line + strlen(ECB_CIPHERTEXT), exp, alen);
							}
							else
							{
								res = false;
							}
						}
						else
						{
							res = false;
							break;
						}
					}

					if (res == false)
					{
						break;
					}

					if (pln != NULL && exp != NULL && otp != NULL)
					{
						qsc_aes_state state;
						qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE };
						qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);

						for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
						{
							qsc_aes_ecb_encrypt_block(&state, otp + (i * QSC_AES_BLOCK_SIZE), pln + (i * QSC_AES_BLOCK_SIZE));
						}

						qsc_aes_dispose(&state);

						if (qsc_intutils_are_equal8(exp, otp, alen) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_alloc_free(exp);
						qsc_memutils_alloc_free(pln);
						qsc_memutils_alloc_free(otp);
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

bool aesavs_cbc_kat()
{
	const char* CBC128_VARKEY = "AESAVS/CBC/KAT/CBCVarKey128.rsp";
	const char* CBC128_VARTXT = "AESAVS/CBC/KAT/CBCVarTxt128.rsp";
	const char* CBC256_VARKEY = "AESAVS/CBC/KAT/CBCVarKey256.rsp";
	const char* CBC256_VARTXT = "AESAVS/CBC/KAT/CBCVarTxt256.rsp";
	bool res;

	if (qsc_fileutils_exists(CBC128_VARKEY) && qsc_fileutils_exists(CBC128_VARTXT) && qsc_fileutils_exists(CBC256_VARKEY) && qsc_fileutils_exists(CBC256_VARTXT) == true)
	{
		res = true;

		if (aesavs_cbc128_kat(CBC128_VARKEY) == false)
		{
			qsctest_print_safe("AESAVS failed CBC(AES-128) variable key KAT test. \n");
			res = false;
		}

		if (aesavs_cbc128_kat(CBC128_VARTXT) == false)
		{
			qsctest_print_safe("AESAVS failed CBC(AES-128) variable text KAT test. \n");
			res = false;
		}

		if (aesavs_cbc256_kat(CBC256_VARKEY) == false)
		{
			qsctest_print_safe("AESAVS failed CBC(AES-256) variable key KAT test. \n");
			res = false;
		}

		if (aesavs_cbc256_kat(CBC256_VARTXT) == false)
		{
			qsctest_print_safe("AESAVS failed CBC(AES-256) variable text KAT test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aesavs_ecb_kat()
{
	const char* ECB128_VARKEY = "AESAVS/ECB/KAT/ECBVarKey128.rsp";
	const char* ECB128_VARTXT = "AESAVS/ECB/KAT/ECBVarTxt128.rsp";
	const char* ECB256_VARKEY = "AESAVS/ECB/KAT/ECBVarKey256.rsp";
	const char* ECB256_VARTXT = "AESAVS/ECB/KAT/ECBVarTxt256.rsp";
	bool res;

	if (qsc_fileutils_exists(ECB128_VARKEY) && qsc_fileutils_exists(ECB128_VARTXT) && qsc_fileutils_exists(ECB256_VARKEY) && qsc_fileutils_exists(ECB256_VARTXT) == true)
	{
		res = true;

		if (aesavs_ecb128_kat(ECB128_VARKEY) == false)
		{
			qsctest_print_safe("AESAVS failed ECB(AES-128) variable key KAT test. \n");
			res = false;
		}

		if (aesavs_ecb128_kat(ECB128_VARTXT) == false)
		{
			qsctest_print_safe("AESAVS failed ECB(AES-128) variable text KAT test. \n");
			res = false;
		}

		if (aesavs_ecb256_kat(ECB256_VARKEY) == false)
		{
			qsctest_print_safe("AESAVS failed ECB(AES-256) variable key KAT test. \n");
			res = false;
		}

		if (aesavs_ecb256_kat(ECB256_VARTXT) == false)
		{
			qsctest_print_safe("AESAVS failed ECB(AES-256) variable text KAT test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aesavs_cbc_mct()
{
	const char* CBC128_MCT = "AESAVS/CBC/MCT/CBCMCT128.rsp";
	const char* CBC256_MCT = "AESAVS/CBC/MCT/CBCMCT256.rsp";
	bool res;

	if (qsc_fileutils_exists(CBC128_MCT) && qsc_fileutils_exists(CBC256_MCT) == true)
	{
		res = true;

		if (aesavs_cbc128_mct(CBC128_MCT) == false)
		{
			qsctest_print_safe("AESAVS failed CBC(AES-128) monte carlo test. \n");
			res = false;
		}

		if (aesavs_cbc256_mct(CBC256_MCT) == false)
		{
			qsctest_print_safe("AESAVS failed CBC(AES-256) monte carlo test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aesavs_ecb_mct()
{
	const char* ECB128_MCT = "AESAVS/ECB/MCT/ECBMCT128.rsp";
	const char* ECB256_MCT = "AESAVS/ECB/MCT/ECBMCT256.rsp";
	bool res;

	if (qsc_fileutils_exists(ECB128_MCT) && qsc_fileutils_exists(ECB256_MCT) == true)
	{
		res = true;

		if (aesavs_ecb128_mct(ECB128_MCT) == false)
		{
			qsctest_print_safe("AESAVS failed ECB(AES-128) monte carlo test. \n");
			res = false;
		}

		if (aesavs_ecb256_mct(ECB256_MCT) == false)
		{
			qsctest_print_safe("AESAVS failed ECB(AES-256) monte carlo test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aesavs_cbc_mmt()
{
	const char* CBC128_MMT = "AESAVS/CBC/MMT/CBCMMT128.rsp";
	const char* CBC256_MMT = "AESAVS/CBC/MMT/CBCMMT256.rsp";
	bool res;

	if (qsc_fileutils_exists(CBC128_MMT) && qsc_fileutils_exists(CBC256_MMT) == true)
	{
		res = true;

		if (aesavs_cbc128_mmt(CBC128_MMT) == false)
		{
			qsctest_print_safe("AESAVS failed CBC(AES-128) multi-block message test. \n");
			res = false;
		}

		if (aesavs_cbc256_mmt(CBC256_MMT) == false)
		{
			qsctest_print_safe("AESAVS failed CBC(AES-256) multi-block message test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aesavs_ecb_mmt()
{
	const char* ECB128_MMT = "AESAVS/ECB/MMT/ECBMMT128.rsp";
	const char* ECB256_MMT = "AESAVS/ECB/MMT/ECBMMT256.rsp";
	bool res;

	if (qsc_fileutils_exists(ECB128_MMT) && qsc_fileutils_exists(ECB256_MMT) == true)
	{
		res = true;

		if (aesavs_ecb128_mmt(ECB128_MMT) == false)
		{
			qsctest_print_safe("AESAVS failed ECB(AES-128) multi-block message test. \n");
			res = false;
		}

		if (aesavs_ecb256_mmt(ECB256_MMT) == false)
		{
			qsctest_print_safe("AESAVS failed ECB(AES-256) multi-block message test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

void qsctest_aesavs_run()
{
	if (aesavs_cbc_kat() == true)
	{
		qsctest_print_safe("Success! Passed the AESAVS CBC(AES-128) and CBC(AES-256) KAT tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed AESAVS CBC(AES-128) and CBC(AES-256) KAT tests. \n");
	}

	if (aesavs_ecb_kat() == true)
	{
		qsctest_print_safe("Success! Passed the AESAVS ECB(AES-128) and ECB(AES-256) KAT tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the AESAVS ECB(AES-128) and ECB(AES-256) KAT tests. \n");
	}

	if (aesavs_cbc_mct() == true)
	{
		qsctest_print_safe("Success! Passed the AESAVS CBC(AES-128) and CBC(AES-256) Monte Carlo tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed AESAVS CBC(AES-128) and CBC(AES-256) Monte Carlo tests. \n");
	}

	if (aesavs_ecb_mct() == true)
	{
		qsctest_print_safe("Success! Passed the AESAVS ECB(AES-128) and ECB(AES-256) Monte Carlo tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the AESAVS ECB(AES-128) and ECB(AES-256) Monte Carlo tests. \n");
	}

	if (aesavs_cbc_mmt() == true)
	{
		qsctest_print_safe("Success! Passed the AESAVS CBC(AES-128) and CBC(AES-256) Multi-block Message tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed AESAVS CBC(AES-128) and CBC(AES-256) Multi-block Message tests. \n");
	}

	if (aesavs_ecb_mmt() == true)
	{
		qsctest_print_safe("Success! Passed the AESAVS ECB(AES-128) and ECB(AES-256) Multi-block Message tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the AESAVS ECB(AES-128) and ECB(AES-256) Multi-block Message tests. \n");
	}
}
