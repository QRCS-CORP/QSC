#include "cavp_aes.h"
#include "cavp_utils.h"
#include "aes.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"

#define CTR_MESSAGE_MAX 480
#define GCM_TAG_SIZE 16
static const char* CAVP_AES_AAD = "AAD = ";
static const char* CAVP_AES_COUNT = "COUNT = ";
static const char* CAVP_AES_IV = "IV = ";
static const char* CAVP_AES_KEY = "KEY = ";
static const char* CAVP_AES_PLAINTEXT = "PLAINTEXT = ";
static const char* CAVP_AES_CIPHERTEXT = "CIPHERTEXT = ";
static const char* CAVP_AES_TAG = "TAG = ";

static bool aes_cbc128_kat(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, sizeof(exp));
						}
						else if (memcmp(line, CAVP_AES_IV, strlen(CAVP_AES_IV)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_state state;
					qsc_aes_keyparams kp1 = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
					qsc_aes_initialize(&state, &kp1, true, qsc_aes_cipher_128);
					qsc_aes_cbc_encrypt_block(&state, otp, pln);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_keyparams kp2 = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
					qsc_aes_initialize(&state, &kp2, false, qsc_aes_cipher_128);
					qsc_aes_cbc_decrypt_block(&state, dec, otp);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_cbc256_kat(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, sizeof(exp));
						}
						else if (memcmp(line, CAVP_AES_IV, strlen(CAVP_AES_IV)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_state state;
					qsc_aes_keyparams kp1 = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
					qsc_aes_initialize(&state, &kp1, true, qsc_aes_cipher_256);
					qsc_aes_cbc_encrypt_block(&state, otp, pln);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_keyparams kp2 = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
					qsc_aes_initialize(&state, &kp2, false, qsc_aes_cipher_256);
					qsc_aes_cbc_decrypt_block(&state, dec, otp);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_ctr128_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t dec[CTR_MESSAGE_MAX] = { 0 };
	uint8_t exp[CTR_MESSAGE_MAX] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t otp[CTR_MESSAGE_MAX] = { 0 };
	uint8_t pln[CTR_MESSAGE_MAX] = { 0 };
	int64_t read;
	size_t i;
	size_t slen;
	size_t plen;
	errno_t err;
	bool res;
	res = true;
	line = NULL;
	err = 0;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL && err == 0)
	{
		read = 0;
		plen = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &slen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &slen, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							plen = read - (strlen(CAVP_AES_PLAINTEXT) + 1);
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, plen);
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, plen);
						}
						else if (memcmp(line, CAVP_AES_IV, strlen(CAVP_AES_IV)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}
					
					plen /= 2;

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_state state;
					qsc_aes_keyparams kp1 = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
					qsc_aes_initialize(&state, &kp1, true, qsc_aes_cipher_128);
					qsc_aes_ctrbe_transform(&state, otp, pln, plen);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_keyparams kp2 = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
					qsc_aes_initialize(&state, &kp2, true, qsc_aes_cipher_128);
					qsc_aes_ctrbe_transform(&state, dec, otp, plen);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_ctr256_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t dec[CTR_MESSAGE_MAX] = { 0 };
	uint8_t exp[CTR_MESSAGE_MAX] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t otp[CTR_MESSAGE_MAX] = { 0 };
	uint8_t pln[CTR_MESSAGE_MAX] = { 0 };
	int64_t read;
	size_t i;
	size_t slen;
	size_t plen;
	bool res;

	res = true;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		read = 0;
		plen = 0;

		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &slen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &slen, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							plen = read - (strlen(CAVP_AES_PLAINTEXT) + 1);
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, plen);
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, plen);
						}
						else if (memcmp(line, CAVP_AES_IV, strlen(CAVP_AES_IV)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}
					
					plen /= 2;

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_state state;
					qsc_aes_keyparams kp1 = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
					qsc_aes_initialize(&state, &kp1, true, qsc_aes_cipher_256);
					qsc_aes_ctrbe_transform(&state, otp, pln, plen);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_keyparams kp2 = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
					qsc_aes_initialize(&state, &kp2, true, qsc_aes_cipher_256);
					qsc_aes_ctrbe_transform(&state, dec, otp, plen);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_ecb128_kat(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, sizeof(exp));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_aes_state state;
					qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key) };
					qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);
					qsc_aes_ecb_encrypt_block(&state, otp, pln);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_128);
					qsc_aes_ecb_decrypt_block(&state, dec, otp);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_ecb256_kat(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, sizeof(exp));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_aes_state state;
					qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key) };
					qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);
					qsc_aes_ecb_encrypt_block(&state, otp, pln);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_256);
					qsc_aes_ecb_decrypt_block(&state, dec, otp);
					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_gcm256_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t aad[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t dec[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_AES_BLOCK_SIZE + GCM_TAG_SIZE] = { 0 };
	uint8_t iv[QSC_GCM_NONCE_SIZE] = { 0 };
	uint8_t ivc[QSC_GCM_NONCE_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t otp[QSC_AES_BLOCK_SIZE + GCM_TAG_SIZE] = { 0 };
	uint8_t pln[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t tag[GCM_TAG_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	errno_t err;
	bool res;
	res = true;
	line = NULL;
	err = 0;

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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 6; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_IV, strlen(CAVP_AES_IV)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_IV), iv, sizeof(iv));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CAVP_AES_AAD, strlen(CAVP_AES_AAD)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_AAD), aad, sizeof(aad));
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, sizeof(exp));
						}
						else if (memcmp(line, CAVP_AES_TAG, strlen(CAVP_AES_TAG)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_TAG), tag, sizeof(tag));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));

					qsc_aes_gcm256_state state = { 0 };
					qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc) };

					qsc_aes_gcm256_initialize(&state, &kp, true);
					qsc_aes_gcm256_set_associated(&state, aad, sizeof(aad));
					qsc_aes_gcm256_encrypt(&state, otp, pln, sizeof(pln));
					qsc_aes_gcm256_dispose(&state);

					if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					if (cavp_byte_arrays_are_equal8(tag, otp + QSC_AES_BLOCK_SIZE, GCM_TAG_SIZE) == false)
					{
						res = false;
						break;
					}

					qsc_memutils_copy(ivc, iv, sizeof(iv));
					qsc_aes_gcm256_initialize(&state, &kp, false);
					qsc_aes_gcm256_set_associated(&state, aad, sizeof(aad));
					qsc_aes_gcm256_decrypt(&state, dec, otp, sizeof(otp));
					qsc_aes_gcm256_dispose(&state);

					if (cavp_byte_arrays_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_cbc128_mct(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, sizeof(exp));
						}
						else if (memcmp(line, CAVP_AES_IV, strlen(CAVP_AES_IV)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_IV), iv, sizeof(iv));
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
						qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
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

						if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
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
						qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
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

						if (cavp_byte_arrays_are_equal8(otp, pln, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_cbc256_mct(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, sizeof(exp));
						}
						else if (memcmp(line, CAVP_AES_IV, strlen(CAVP_AES_IV)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_IV), iv, sizeof(iv));
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
						qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
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

						if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
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
						qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
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

						if (cavp_byte_arrays_are_equal8(otp, pln, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_ecb128_mct(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, sizeof(exp));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_aes_state state;
					qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key) };
					qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);
					qsc_memutils_copy(plnc, pln, QSC_AES_BLOCK_SIZE);

					for (i = 0; i < 1000; ++i)
					{
						qsc_aes_ecb_encrypt_block(&state, otp, plnc);
						qsc_memutils_copy(plnc, otp, QSC_AES_BLOCK_SIZE);
					}

					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
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

					if (cavp_byte_arrays_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_ecb256_mct(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &len, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, sizeof(exp));
						}
						else
						{
							res = false;
							break;
						}
					}

					qsc_aes_state state;
					qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key) };
					qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);
					qsc_memutils_copy(plnc, pln, QSC_AES_BLOCK_SIZE);

					for (i = 0; i < 1000; ++i)
					{
						qsc_aes_ecb_encrypt_block(&state, otp, plnc);
						qsc_memutils_copy(plnc, otp, QSC_AES_BLOCK_SIZE);
					}

					qsc_aes_dispose(&state);

					if (cavp_byte_arrays_are_equal8(exp, otp, QSC_AES_BLOCK_SIZE) == false)
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

					if (cavp_byte_arrays_are_equal8(pln, dec, QSC_AES_BLOCK_SIZE) == false)
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

static bool aes_cbc128_mmt(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &rlen, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_IV, strlen(CAVP_AES_IV)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_IV), iv, sizeof(iv));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(CAVP_AES_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)qsc_memutils_malloc(alen);

							if (pln != NULL)
							{
								qsc_memutils_clear(pln, alen);
								cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(CAVP_AES_CIPHERTEXT) + 1)) / 2;
							exp = (uint8_t*)qsc_memutils_malloc(alen);
							dec = (uint8_t*)qsc_memutils_malloc(alen);
							otp = (uint8_t*)qsc_memutils_malloc(alen);

							if (exp != NULL && otp != NULL && dec != NULL)
							{
								qsc_memutils_clear(exp, alen);
								qsc_memutils_clear(dec, alen);
								qsc_memutils_clear(otp, alen);
								cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, alen);
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
							qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
							qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);

							for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
							{
								qsc_aes_cbc_encrypt_block(&state, otp + (i * QSC_AES_BLOCK_SIZE), pln + (i * QSC_AES_BLOCK_SIZE));
							}

							qsc_aes_dispose(&state);

							if (cavp_byte_arrays_are_equal8(exp, otp, alen) == false)
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
							qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
							qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_128);

							for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
							{
								qsc_aes_cbc_decrypt_block(&state, dec + (i * QSC_AES_BLOCK_SIZE), exp + (i * QSC_AES_BLOCK_SIZE));
							}

							qsc_aes_dispose(&state);

							if (cavp_byte_arrays_are_equal8(dec, pln, alen) == false)
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

static bool aes_cbc256_mmt(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = qsc_fileutils_get_line(&line, &rlen, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_IV, strlen(CAVP_AES_IV)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_IV), iv, sizeof(iv));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(CAVP_AES_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)qsc_memutils_malloc(alen);

							if (pln != NULL)
							{
								qsc_memutils_clear(pln, alen);
								cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(CAVP_AES_CIPHERTEXT) + 1)) / 2;
							exp = (uint8_t*)qsc_memutils_malloc(alen);
							dec = (uint8_t*)qsc_memutils_malloc(alen);
							otp = (uint8_t*)qsc_memutils_malloc(alen);

							if (exp != NULL && dec != NULL && otp != NULL)
							{
								qsc_memutils_clear(exp, alen);
								qsc_memutils_clear(dec, alen);
								qsc_memutils_clear(otp, alen);
								cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, alen);
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
							qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
							qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);

							for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
							{
								qsc_aes_cbc_encrypt_block(&state, otp + (i * QSC_AES_BLOCK_SIZE), pln + (i * QSC_AES_BLOCK_SIZE));
							}

							qsc_aes_dispose(&state);

							if (cavp_byte_arrays_are_equal8(exp, otp, alen) == false)
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
							qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = ivc, .noncelen = sizeof(ivc)};
							qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_256);

							for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
							{
								qsc_aes_cbc_decrypt_block(&state, dec + (i * QSC_AES_BLOCK_SIZE), exp + (i * QSC_AES_BLOCK_SIZE));
							}

							qsc_aes_dispose(&state);

							if (cavp_byte_arrays_are_equal8(dec, pln, alen) == false)
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

static bool aes_ecb128_mmt(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &rlen, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(CAVP_AES_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)qsc_memutils_malloc(alen);

							if (pln != NULL)
							{
								qsc_memutils_clear(pln, alen);
								cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(CAVP_AES_CIPHERTEXT) + 1)) / 2;
							exp = (uint8_t*)qsc_memutils_malloc(alen);
							otp = (uint8_t*)qsc_memutils_malloc(alen);

							if (exp != NULL && otp != NULL)
							{
								qsc_memutils_clear(exp, alen);
								qsc_memutils_clear(otp, alen);

								cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, alen);
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
						qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key) };
						qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);

						for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
						{
							qsc_aes_ecb_encrypt_block(&state, otp + (i * QSC_AES_BLOCK_SIZE), pln + (i * QSC_AES_BLOCK_SIZE));
						}

						qsc_aes_dispose(&state);

						if (cavp_byte_arrays_are_equal8(exp, otp, alen) == false)
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

static bool aes_ecb256_mmt(const char* filepath)
{
	FILE* fp;
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
				if (memcmp(line, CAVP_AES_COUNT, strlen(CAVP_AES_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = qsc_fileutils_get_line(&line, &rlen, fp);

						if (memcmp(line, CAVP_AES_KEY, strlen(CAVP_AES_KEY)) == 0)
						{
							cavp_hex_to_bin(line + strlen(CAVP_AES_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CAVP_AES_PLAINTEXT, strlen(CAVP_AES_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(CAVP_AES_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)qsc_memutils_malloc(alen);

							if (pln != NULL)
							{
								qsc_memutils_clear(pln, alen);
								cavp_hex_to_bin(line + strlen(CAVP_AES_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, CAVP_AES_CIPHERTEXT, strlen(CAVP_AES_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(CAVP_AES_CIPHERTEXT) + 1)) / 2;
							exp = (uint8_t*)qsc_memutils_malloc(alen);
							otp = (uint8_t*)qsc_memutils_malloc(alen);

							if (exp != NULL && otp != NULL)
							{
								qsc_memutils_clear(exp, alen);
								qsc_memutils_clear(otp, alen);

								cavp_hex_to_bin(line + strlen(CAVP_AES_CIPHERTEXT), exp, alen);
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
						qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key) };
						qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);

						for (i = 0; i < alen / QSC_AES_BLOCK_SIZE; ++i)
						{
							qsc_aes_ecb_encrypt_block(&state, otp + (i * QSC_AES_BLOCK_SIZE), pln + (i * QSC_AES_BLOCK_SIZE));
						}

						qsc_aes_dispose(&state);

						if (cavp_byte_arrays_are_equal8(exp, otp, alen) == false)
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

static bool aes_cbc_kat()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_CBC128_GFSBOX) && qsc_fileutils_exists(CAVP_CBC256_GFSBOX) && 
		qsc_fileutils_exists(CAVP_CBC128_KEYSBOX) && qsc_fileutils_exists(CAVP_CBC256_KEYSBOX) &&
		qsc_fileutils_exists(CAVP_CBC128_VARKEY) && qsc_fileutils_exists(CAVP_CBC256_VARKEY) && 
		qsc_fileutils_exists(CAVP_CBC128_VARTEXT) && qsc_fileutils_exists(CAVP_CBC256_VARTEXT))
	{
		res = true;

		if (aes_cbc128_kat(CAVP_CBC128_GFSBOX))
		{
			cavp_print_line("AES passed CBC(AES-128) gf-sbox KAT test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-128) gf-sbox KAT test.");
			res = false;
		}

		if (aes_cbc128_kat(CAVP_CBC128_KEYSBOX))
		{
			cavp_print_line("AES passed CBC(AES-128) key-sbox KAT test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-128) key-sbox KAT test.");
			res = false;
		}
		
		if (aes_cbc128_kat(CAVP_CBC128_VARKEY))
		{
			cavp_print_line("AES passed CBC(AES-128) variable-key KAT test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-128) variable-key KAT test.");
			res = false;
		}

		if (aes_cbc128_kat(CAVP_CBC128_VARTEXT))
		{
			cavp_print_line("AES passed CBC(AES-128) variable-text KAT test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-128) variable-text KAT test.");
			res = false;
		}

		if (aes_cbc256_kat(CAVP_CBC256_GFSBOX))
		{
			cavp_print_line("AES passed CBC(AES-256) gf-sbox KAT test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-256) gf-sbox KAT test.");
			res = false;
		}

		if (aes_cbc256_kat(CAVP_CBC256_KEYSBOX))
		{
			cavp_print_line("AES passed CBC(AES-256) key-sbox KAT test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-256) key-sbox KAT test.");
			res = false;
		}
		
		if (aes_cbc256_kat(CAVP_CBC256_VARKEY))
		{
			cavp_print_line("AES passed CBC(AES-256) variable-key KAT test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-256) variable-key KAT test.");
			res = false;
		}
		
		if (aes_cbc256_kat(CAVP_CBC256_VARTEXT))
		{
			cavp_print_line("AES passed CBC(AES-256) variable-text KAT test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-256) variable-text KAT test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

static bool aes_ctr_kat()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_CTR128_VARKEY) && qsc_fileutils_exists(CAVP_CTR256_VARKEY))
	{
		res = true;

		if (aes_ctr128_kat(CAVP_CTR128_VARKEY))
		{
			cavp_print_line("AES passed CTR(AES-128) variable-key KAT test.");
		}
		else
		{
			cavp_print_line("AES failed CTR(AES-128) variable-key KAT test.");
			res = false;
		}

		if (aes_ctr256_kat(CAVP_CTR256_VARKEY))
		{
			cavp_print_line("AES passed CTR(AES-256) variable-key KAT test.");
		}
		else
		{
			cavp_print_line("AES failed CTR(AES-256) variable-key KAT test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

static bool aes_ecb_kat()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_ECB128_GFSBOX) && qsc_fileutils_exists(CAVP_ECB256_GFSBOX) && 
		qsc_fileutils_exists(CAVP_ECB128_KEYSBOX) && qsc_fileutils_exists(CAVP_ECB256_KEYSBOX) &&
		qsc_fileutils_exists(CAVP_ECB128_VARKEY) && qsc_fileutils_exists(CAVP_ECB256_VARKEY) &&
		qsc_fileutils_exists(CAVP_ECB128_VARTEXT) && qsc_fileutils_exists(CAVP_ECB256_VARTEXT))
	{
		res = true;

		if (aes_ecb128_kat(CAVP_ECB128_GFSBOX))
		{
			cavp_print_line("AES passed ECB(AES-128) gf-sbox KAT test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-128) gf-sbox KAT test.");
			res = false;
		}

		if (aes_ecb128_kat(CAVP_ECB128_KEYSBOX))
		{
			cavp_print_line("AES passed ECB(AES-128) key-sbox KAT test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-128) key-sbox KAT test.");
			res = false;
		}
		
		if (aes_ecb128_kat(CAVP_ECB128_VARKEY))
		{
			cavp_print_line("AES passed ECB(AES-128) variable-key KAT test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-128) variable-key KAT test.");
			res = false;
		}

		if (aes_ecb128_kat(CAVP_ECB128_VARTEXT))
		{
			cavp_print_line("AES passed ECB(AES-128) variable-text KAT test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-128) variable-text KAT test.");
			res = false;
		}

		if (aes_ecb256_kat(CAVP_ECB256_GFSBOX))
		{
			cavp_print_line("AES passed ECB(AES-256) gf-sbox KAT test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-256) gf-sbox KAT test.");
			res = false;
		}

		if (aes_ecb256_kat(CAVP_ECB256_KEYSBOX))
		{
			cavp_print_line("AES passed ECB(AES-256) key-sbox KAT test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-256) key-sbox KAT test.");
			res = false;
		}
		
		if (aes_ecb256_kat(CAVP_ECB256_VARKEY))
		{
			cavp_print_line("AES passed ECB(AES-256) variable-key KAT test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-256) variable-key KAT test.");
			res = false;
		}

		if (aes_ecb256_kat(CAVP_ECB256_VARTEXT))
		{
			cavp_print_line("AES passed ECB(AES-256) variable-text KAT test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-256) variable-text KAT test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

static bool aes_gcm_kat()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_GCM256_VARKEY))
	{
		res = true;

		if (aes_gcm256_kat(CAVP_GCM256_VARKEY))
		{
			cavp_print_line("AES passed GCM(AES-256) variable-key KAT test.");
		}
		else
		{
			cavp_print_line("AES failed GCM(AES-256) variable-key KAT test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aes_cbc_mct()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_CBC128_MCT) && qsc_fileutils_exists(CAVP_CBC256_MCT) == true)
	{
		res = true;

		if (aes_cbc128_mct(CAVP_CBC128_MCT))
		{
			cavp_print_line("AES passed CBC(AES-128) monte carlo test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-128) monte carlo test.");
			res = false;
		}

		if (aes_cbc256_mct(CAVP_CBC256_MCT))
		{
			cavp_print_line("AES passed CBC(AES-256) monte carlo test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-256) monte carlo test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aes_ecb_mct()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_ECB128_MCT) && qsc_fileutils_exists(CAVP_ECB256_MCT) == true)
	{
		res = true;

		if (aes_ecb128_mct(CAVP_ECB128_MCT))
		{
			cavp_print_line("AES passed ECB(AES-128) monte carlo test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-128) monte carlo test.");
			res = false;
		}

		if (aes_ecb256_mct(CAVP_ECB256_MCT))
		{
			cavp_print_line("AES passed ECB(AES-256) monte carlo test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-256) monte carlo test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aes_cbc_mmt()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_CBC128_MMT) && qsc_fileutils_exists(CAVP_CBC256_MMT) == true)
	{
		res = true;

		if (aes_cbc128_mmt(CAVP_CBC128_MMT))
		{
			cavp_print_line("AES passed CBC(AES-128) multi-block message test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-128) multi-block message test.");
			res = false;
		}

		if (aes_cbc256_mmt(CAVP_CBC256_MMT))
		{
			cavp_print_line("AES passed CBC(AES-256) multi-block message test.");
		}
		else
		{
			cavp_print_line("AES failed CBC(AES-256) multi-block message test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aes_ecb_mmt()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_ECB128_MMT) && qsc_fileutils_exists(CAVP_ECB256_MMT) == true)
	{
		res = true;

		if (aes_ecb128_mmt(CAVP_ECB128_MMT))
		{
			cavp_print_line("AES passed ECB(AES-128) multi-block message test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-128) multi-block message test.");
			res = false;
		}

		if (aes_ecb256_mmt(CAVP_ECB256_MMT))
		{
			cavp_print_line("AES passed ECB(AES-256) multi-block message test.");
		}
		else
		{
			cavp_print_line("AES failed ECB(AES-256) multi-block message test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

void cavp_aes_run()
{
	cavp_print_line("Running the NIST CAVP AES tests, testing CBC, CTR, ECB, and GCM modes on the 128-bit and 256-bit AES implementations.");
	cavp_print_line("Tests CBC, CTR, GCM, and ECB Known Answer Tests (KAT), CBC and ECB Monte Carlo Tests (MCTs), Multi-Message Tests (MMTs).");
	cavp_print_line("There are four distinct KAT variants:");
	cavp_print_line("- GFSbox: Exercises the substitution box (S-box) with fixed inputs to ensure correct non-linear substitution.");
	cavp_print_line("- KeySbox: Combines key schedule and S-box operations to validate branching between key expansion and substitution.");
	cavp_print_line("- Variable Key: Uses a fixed plaintext but varies the key each test to check key-dependent behavior.");
	cavp_print_line("- Variable Text: Uses a fixed key but varies the plaintext to check plaintext-dependent behavior.");
	cavp_print_line("");

	if (aes_cbc_kat())
	{
		cavp_print_line("Success! Passed the CAVP CBC(AES-128) and CBC(AES-256) KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP CBC(AES-128) and CBC(AES-256) KAT tests.");
	}

	cavp_print_line("");

	if (aes_ecb_kat())
	{
		cavp_print_line("Success! Passed the CAVP ECB(AES-128) and ECB(AES-256) KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP ECB(AES-128) and ECB(AES-256) KAT tests.");
	}
	
	cavp_print_line("");

	if (aes_cbc_mct())
	{
		cavp_print_line("Success! Passed the CAVP CBC(AES-128) and CBC(AES-256) Monte Carlo tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP CBC(AES-128) and CBC(AES-256) Monte Carlo tests.");
	}
	
	cavp_print_line("");

	if (aes_ecb_mct())
	{
		cavp_print_line("Success! Passed the CAVP ECB(AES-128) and ECB(AES-256) Monte Carlo tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP ECB(AES-128) and ECB(AES-256) Monte Carlo tests.");
	}
	
	cavp_print_line("");

	if (aes_cbc_mmt())
	{
		cavp_print_line("Success! Passed the CAVP CBC(AES-128) and CBC(AES-256) Multi-block Message tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP CBC(AES-128) and CBC(AES-256) Multi-block Message tests.");
	}
	
	cavp_print_line("");

	if (aes_ecb_mmt())
	{
		cavp_print_line("Success! Passed the CAVP ECB(AES-128) and ECB(AES-256) Multi-block Message tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP ECB(AES-128) and ECB(AES-256) Multi-block Message tests.");
	}
	
	cavp_print_line("");

	if (aes_ctr_kat())
	{
		cavp_print_line("Success! Passed the CAVP CTR(AES-128) and CTR(AES-256) KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP CTR(AES-128) and CTR(AES-256) KAT tests.");
	}
	
	cavp_print_line("");

	if (aes_gcm_kat())
	{
		cavp_print_line("Success! Passed the CAVP GCM(AES-256) KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP GCM(AES-256) KAT tests.");
	}
}
