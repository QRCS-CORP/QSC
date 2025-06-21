#include "cavp_sha2.h"
#include "cavp_utils.h"
#include "arrayutils.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"

#define SHA2_MESSAGE_INT_SIZE 8
#define SHA2_MESSAGE_MAX 2048
#define HMAC_KEY_MAX 142
#define HMAC_MESSAGE_MAX 128
#define HMAC256_TEST_COUNT 224
#define HMAC512_TEST_COUNT 374

static const char* CAVP_HMAC_COUNT = "Count = ";
static const char* CAVP_HMAC_KEY = "Key = ";
static const char* CAVP_HMAC_KLEN = "Klen = ";
static const char* CAVP_HMAC_MAC = "Mac = ";
static const char* CAVP_HMAC_MSG = "Msg = ";
static const char* CAVP_HMAC_TLEN = "Tlen = ";
static const char* CAVP_SHA2_COUNT = "COUNT = ";
static const char* CAVP_SHA2_LEN = "Len = ";
static const char* CAVP_SHA2_MSG = "Msg = ";
static const char* CAVP_SHA2_MD = "MD = ";
static const char* CAVP_SHA2_SEED = "Seed = ";

static bool hmac_256_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t key[HMAC_KEY_MAX] = { 0 };
	uint8_t exp[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t msg[HMAC_MESSAGE_MAX] = { 0 };
	uint8_t otp[QSC_HMAC_256_MAC_SIZE] = { 0 };
	int64_t read;
	size_t rlen;
	uint32_t klen;
	int32_t tcnt;
	uint32_t tlen;
	errno_t err;
	bool res;

	res = true;
	line = NULL;
	err = 0;
	klen = 0;
	rlen = 0;
	tcnt = 0;
	tlen = 0;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL && err == 0)
	{
		read = 0;
		
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &rlen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CAVP_HMAC_COUNT, strlen(CAVP_HMAC_COUNT)) == 0)
				{
					tcnt = (int32_t)qsc_arrayutils_string_to_uint32(line + strlen(CAVP_HMAC_COUNT), read - (strlen(CAVP_HMAC_COUNT) + 1));

					/* skip zero length (illegal) size inputs */
					if (tcnt >= 0 && tcnt <= HMAC256_TEST_COUNT)
					{
						for (size_t i = 0; i < 5; ++i)
						{
							read = qsc_fileutils_get_line(&line, &rlen, fp);

							if (memcmp(line, CAVP_HMAC_KLEN, strlen(CAVP_HMAC_KLEN)) == 0)
							{
								klen = qsc_arrayutils_string_to_uint32(line + strlen(CAVP_HMAC_KLEN), read - (strlen(CAVP_HMAC_KLEN) + 1));
							}
							else if (memcmp(line, CAVP_HMAC_TLEN, strlen(CAVP_HMAC_TLEN)) == 0)
							{
								tlen = qsc_arrayutils_string_to_uint32(line + strlen(CAVP_HMAC_TLEN), read - (strlen(CAVP_HMAC_TLEN) + 1));
							}
							else if (memcmp(line, CAVP_HMAC_KEY, strlen(CAVP_HMAC_KEY)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_HMAC_KEY), key, klen);
							}
							else if (memcmp(line, CAVP_HMAC_MSG, strlen(CAVP_HMAC_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_HMAC_MSG), msg, sizeof(msg));
							}
							else if (memcmp(line, CAVP_HMAC_MAC, strlen(CAVP_HMAC_MAC)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_HMAC_MAC), exp, tlen);
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_hmac256_compute(otp, msg, sizeof(msg), key, klen);

						if (cavp_byte_arrays_are_equal8(exp, otp, tlen) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_clear(msg, sizeof(msg));
						qsc_memutils_clear(exp, sizeof(exp));
						qsc_memutils_clear(key, klen);
						qsc_memutils_clear(otp, tlen);
						klen = 0;
						tcnt = 0;
						tlen = 0;
					}
					else
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

static bool hmac_512_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t key[HMAC_KEY_MAX] = { 0 };
	uint8_t exp[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t msg[HMAC_MESSAGE_MAX] = { 0 };
	uint8_t otp[QSC_HMAC_512_MAC_SIZE] = { 0 };
	int64_t read;
	size_t rlen;
	uint32_t klen;
	int32_t tcnt;
	uint32_t tlen;
	errno_t err;
	bool res;

	res = true;
	line = NULL;
	err = 0;
	klen = 0;
	rlen = 0;
	tcnt = 0;
	tlen = 0;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL && err == 0)
	{
		read = 0;
		
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &rlen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CAVP_HMAC_COUNT, strlen(CAVP_HMAC_COUNT)) == 0)
				{
					tcnt = (int32_t)qsc_arrayutils_string_to_uint32(line + strlen(CAVP_HMAC_COUNT), read - (strlen(CAVP_HMAC_COUNT) + 1));

					/* skip zero length (illegal) size inputs */
					if (tcnt >= 0 && tcnt <= HMAC512_TEST_COUNT)
					{
						for (size_t i = 0; i < 5; ++i)
						{
							read = qsc_fileutils_get_line(&line, &rlen, fp);

							if (memcmp(line, CAVP_HMAC_KLEN, strlen(CAVP_HMAC_KLEN)) == 0)
							{
								klen = qsc_arrayutils_string_to_uint32(line + strlen(CAVP_HMAC_KLEN), read - (strlen(CAVP_HMAC_KLEN) + 1));
							}
							else if (memcmp(line, CAVP_HMAC_TLEN, strlen(CAVP_HMAC_TLEN)) == 0)
							{
								tlen = qsc_arrayutils_string_to_uint32(line + strlen(CAVP_HMAC_TLEN), read - (strlen(CAVP_HMAC_TLEN) + 1));
							}
							else if (memcmp(line, CAVP_HMAC_KEY, strlen(CAVP_HMAC_KEY)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_HMAC_KEY), key, klen);
							}
							else if (memcmp(line, CAVP_HMAC_MSG, strlen(CAVP_HMAC_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_HMAC_MSG), msg, sizeof(msg));
							}
							else if (memcmp(line, CAVP_HMAC_MAC, strlen(CAVP_HMAC_MAC)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_HMAC_MAC), exp, tlen);
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_hmac512_compute(otp, msg, sizeof(msg), key, klen);

						if (cavp_byte_arrays_are_equal8(exp, otp, tlen) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_clear(msg, sizeof(msg));
						qsc_memutils_clear(exp, sizeof(exp));
						qsc_memutils_clear(key, klen);
						qsc_memutils_clear(otp, tlen);
						klen = 0;
						tcnt = 0;
						tlen = 0;
					}
					else
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

static bool sha2_256_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t msg[SHA2_MESSAGE_MAX] = { 0 };
	uint8_t exp[QSC_SHA2_256_HASH_SIZE] = { 0 };
	uint8_t otp[QSC_SHA2_256_HASH_SIZE] = { 0 };
	char* sln;
	int64_t read;
	size_t i;
	size_t len;
	int32_t mlen;
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
				if (memcmp(line, CAVP_SHA2_LEN, strlen(CAVP_SHA2_LEN)) == 0)
				{
					sln = line + strlen(CAVP_SHA2_LEN);
					mlen = qsc_arrayutils_string_to_uint32(sln, len - (strlen(CAVP_SHA2_LEN) + 1));

					/* skip zero length (illegal) size inputs */
					if (mlen > 0 && mlen <= SHA2_MESSAGE_MAX)
					{
						/* convert from bit-length */
						mlen /= 8;

						for (i = 0; i < 2; ++i)
						{
							read = qsc_fileutils_get_line(&line, &len, fp);

							if (memcmp(line, CAVP_SHA2_MSG, strlen(CAVP_SHA2_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA2_MSG), msg, mlen);
							}
							else if (memcmp(line, CAVP_SHA2_MD, strlen(CAVP_SHA2_MD)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA2_MD), exp, sizeof(exp));
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_sha256_compute(otp, msg, mlen);

						if (cavp_byte_arrays_are_equal8(exp, otp, sizeof(otp)) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_clear(msg, mlen);
						qsc_memutils_clear(exp, sizeof(exp));
						qsc_memutils_clear(otp, sizeof(otp));
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

static bool sha2_384_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t msg[SHA2_MESSAGE_MAX] = { 0 };
	uint8_t exp[QSC_SHA2_384_HASH_SIZE] = { 0 };
	uint8_t otp[QSC_SHA2_384_HASH_SIZE] = { 0 };
	char* sln;
	int64_t read;
	size_t i;
	size_t len;
	int32_t mlen;
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
				if (memcmp(line, CAVP_SHA2_LEN, strlen(CAVP_SHA2_LEN)) == 0)
				{
					sln = line + strlen(CAVP_SHA2_LEN);
					mlen = qsc_arrayutils_string_to_uint32(sln, len - (strlen(CAVP_SHA2_LEN) + 1));

					/* skip zero length (illegal) size inputs */
					if (mlen > 0 && mlen <= SHA2_MESSAGE_MAX)
					{
						/* convert from bit-length */
						mlen /= 8;

						for (i = 0; i < 2; ++i)
						{
							read = qsc_fileutils_get_line(&line, &len, fp);

							if (memcmp(line, CAVP_SHA2_MSG, strlen(CAVP_SHA2_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA2_MSG), msg, mlen);
							}
							else if (memcmp(line, CAVP_SHA2_MD, strlen(CAVP_SHA2_MD)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA2_MD), exp, sizeof(exp));
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_sha384_compute(otp, msg, mlen);

						if (cavp_byte_arrays_are_equal8(exp, otp, sizeof(otp)) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_clear(msg, mlen);
						qsc_memutils_clear(exp, sizeof(exp));
						qsc_memutils_clear(otp, sizeof(otp));
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

static bool sha2_512_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t msg[SHA2_MESSAGE_MAX] = { 0 };
	uint8_t exp[QSC_SHA2_512_HASH_SIZE] = { 0 };
	uint8_t otp[QSC_SHA2_512_HASH_SIZE] = { 0 };
	char* sln;
	int64_t read;
	size_t i;
	size_t len;
	int32_t mlen;
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
				if (memcmp(line, CAVP_SHA2_LEN, strlen(CAVP_SHA2_LEN)) == 0)
				{
					sln = line + strlen(CAVP_SHA2_LEN);
					mlen = qsc_arrayutils_string_to_uint32(sln, len - (strlen(CAVP_SHA2_LEN) + 1));

					/* skip zero length (illegal) size inputs */
					if (mlen > 0 && mlen <= SHA2_MESSAGE_MAX)
					{
						/* convert from bit-length */
						mlen /= 8;

						for (i = 0; i < 2; ++i)
						{
							read = qsc_fileutils_get_line(&line, &len, fp);

							if (memcmp(line, CAVP_SHA2_MSG, strlen(CAVP_SHA2_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA2_MSG), msg, mlen);
							}
							else if (memcmp(line, CAVP_SHA2_MD, strlen(CAVP_SHA2_MD)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA2_MD), exp, sizeof(exp));
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_sha512_compute(otp, msg, mlen);

						if (cavp_byte_arrays_are_equal8(exp, otp, sizeof(otp)) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_clear(msg, mlen);
						qsc_memutils_clear(exp, sizeof(exp));
						qsc_memutils_clear(otp, sizeof(otp));
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

static bool sha2_256_mct(const char* filepath)
{
    QSC_ASSERT(filepath != NULL);

    uint8_t expmd[QSC_SHA2_256_HASH_SIZE] = { 0 };
    uint8_t md0[QSC_SHA2_256_HASH_SIZE] = { 0 };
    uint8_t md1[QSC_SHA2_256_HASH_SIZE] = { 0 };
    uint8_t md2[QSC_SHA2_256_HASH_SIZE] = { 0 };
    uint8_t mdx[QSC_SHA2_256_HASH_SIZE] = { 0 };
    uint8_t msg[3 * QSC_SHA2_256_HASH_SIZE] = { 0 };
	uint8_t seed[QSC_SHA2_256_HASH_SIZE] = { 0 };
    FILE* fp;
    char* line;
    const char* ptr;
    int64_t read;
    size_t len;
    bool res;

	res = true;
	read = 0;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL &&
				memcmp(line, CAVP_SHA2_SEED, strlen(CAVP_SHA2_SEED)) == 0)
			{
				ptr = line + strlen(CAVP_SHA2_SEED);
				cavp_hex_to_bin(ptr, seed, QSC_SHA2_256_HASH_SIZE);
				break;
			}
		}

		for (int count = 0; count < 100; ++count)
		{
			qsc_memutils_copy(md0, seed, QSC_SHA2_256_HASH_SIZE);
			qsc_memutils_copy(md1, seed, QSC_SHA2_256_HASH_SIZE);
			qsc_memutils_copy(md2, seed, QSC_SHA2_256_HASH_SIZE);

			for (int i = 3; i < 1003; ++i)
			{
				qsc_memutils_copy(msg, md0, QSC_SHA2_256_HASH_SIZE);
				qsc_memutils_copy(msg + (1 * QSC_SHA2_256_HASH_SIZE), md1, QSC_SHA2_256_HASH_SIZE);
				qsc_memutils_copy(msg + (2 * QSC_SHA2_256_HASH_SIZE), md2, QSC_SHA2_256_HASH_SIZE);

				qsc_sha256_compute(mdx, msg, sizeof(msg));

				qsc_memutils_copy(md0, md1, QSC_SHA2_256_HASH_SIZE);
				qsc_memutils_copy(md1, md2, QSC_SHA2_256_HASH_SIZE);
				qsc_memutils_copy(md2, mdx, QSC_SHA2_256_HASH_SIZE);
			}

			while (read != -1)
			{
				read = qsc_fileutils_get_line(&line, &len, fp);

				if (read > 0 && line != NULL &&
					memcmp(line, CAVP_SHA2_MD, strlen(CAVP_SHA2_MD)) == 0)
				{
					ptr = line + strlen(CAVP_SHA2_MD);
					cavp_hex_to_bin(ptr, expmd, QSC_SHA2_256_HASH_SIZE);
					break;
				}
			}

			if (cavp_byte_arrays_are_equal8(md2, expmd, QSC_SHA2_256_HASH_SIZE) == false)
			{
				res = false;
				break;
			}

			qsc_memutils_copy(seed, md2, QSC_SHA2_256_HASH_SIZE);
		}

		qsc_fileutils_close(fp);
	}
	else
	{
		res = false;
	}

    if (line != NULL)
    {
        free(line);
    }

    return res;
}

static bool sha2_384_mct(const char* filepath)
{
    QSC_ASSERT(filepath != NULL);

    uint8_t expmd[QSC_SHA2_384_HASH_SIZE] = { 0 };
    uint8_t md0[QSC_SHA2_384_HASH_SIZE] = { 0 };
    uint8_t md1[QSC_SHA2_384_HASH_SIZE] = { 0 };
    uint8_t md2[QSC_SHA2_384_HASH_SIZE] = { 0 };
    uint8_t mdx[QSC_SHA2_384_HASH_SIZE] = { 0 };
    uint8_t msg[3 * QSC_SHA2_384_HASH_SIZE] = { 0 };
	uint8_t seed[QSC_SHA2_384_HASH_SIZE] = { 0 };
    FILE* fp;
    char* line;
    const char* ptr;
    int64_t read;
    size_t len;
    bool res;

	res = true;
	read = 0;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL &&
				memcmp(line, CAVP_SHA2_SEED, strlen(CAVP_SHA2_SEED)) == 0)
			{
				ptr = line + strlen(CAVP_SHA2_SEED);
				cavp_hex_to_bin(ptr, seed, QSC_SHA2_384_HASH_SIZE);
				break;
			}
		}

		for (int count = 0; count < 100; ++count)
		{
			qsc_memutils_copy(md0, seed, QSC_SHA2_384_HASH_SIZE);
			qsc_memutils_copy(md1, seed, QSC_SHA2_384_HASH_SIZE);
			qsc_memutils_copy(md2, seed, QSC_SHA2_384_HASH_SIZE);

			for (int i = 3; i < 1003; ++i)
			{
				qsc_memutils_copy(msg, md0, QSC_SHA2_384_HASH_SIZE);
				qsc_memutils_copy(msg + (1 * QSC_SHA2_384_HASH_SIZE), md1, QSC_SHA2_384_HASH_SIZE);
				qsc_memutils_copy(msg + (2 * QSC_SHA2_384_HASH_SIZE), md2, QSC_SHA2_384_HASH_SIZE);

				qsc_sha384_compute(mdx, msg, sizeof(msg));

				qsc_memutils_copy(md0, md1, QSC_SHA2_384_HASH_SIZE);
				qsc_memutils_copy(md1, md2, QSC_SHA2_384_HASH_SIZE);
				qsc_memutils_copy(md2, mdx, QSC_SHA2_384_HASH_SIZE);
			}

			while (read != -1)
			{
				read = qsc_fileutils_get_line(&line, &len, fp);

				if (read > 0 && line != NULL &&
					memcmp(line, CAVP_SHA2_MD, strlen(CAVP_SHA2_MD)) == 0)
				{
					ptr = line + strlen(CAVP_SHA2_MD);
					cavp_hex_to_bin(ptr, expmd, QSC_SHA2_384_HASH_SIZE);
					break;
				}
			}

			if (cavp_byte_arrays_are_equal8(md2, expmd, QSC_SHA2_384_HASH_SIZE) == false)
			{
				res = false;
				break;
			}

			qsc_memutils_copy(seed, md2, QSC_SHA2_384_HASH_SIZE);
		}

		qsc_fileutils_close(fp);
	}
	else
	{
		res = false;
	}

    if (line != NULL)
    {
        free(line);
    }

    return res;
}

static bool sha2_512_mct(const char* filepath)
{
    QSC_ASSERT(filepath != NULL);

    uint8_t expmd[QSC_SHA2_512_HASH_SIZE] = { 0 };
    uint8_t md0[QSC_SHA2_512_HASH_SIZE] = { 0 };
    uint8_t md1[QSC_SHA2_512_HASH_SIZE] = { 0 };
    uint8_t md2[QSC_SHA2_512_HASH_SIZE] = { 0 };
    uint8_t mdx[QSC_SHA2_512_HASH_SIZE] = { 0 };
    uint8_t msg[3 * QSC_SHA2_512_HASH_SIZE] = { 0 };
	uint8_t seed[QSC_SHA2_512_HASH_SIZE] = { 0 };
    FILE* fp;
    char* line;
    const char* ptr;
    int64_t read;
    size_t len;
    bool res;

	res = true;
	read = 0;
	line = NULL;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			if (read > 0 && line != NULL &&
				memcmp(line, CAVP_SHA2_SEED, strlen(CAVP_SHA2_SEED)) == 0)
			{
				ptr = line + strlen(CAVP_SHA2_SEED);
				cavp_hex_to_bin(ptr, seed, QSC_SHA2_512_HASH_SIZE);
				break;
			}
		}

		for (int count = 0; count < 100; ++count)
		{
			qsc_memutils_copy(md0, seed, QSC_SHA2_512_HASH_SIZE);
			qsc_memutils_copy(md1, seed, QSC_SHA2_512_HASH_SIZE);
			qsc_memutils_copy(md2, seed, QSC_SHA2_512_HASH_SIZE);

			for (int i = 3; i < 1003; ++i)
			{
				qsc_memutils_copy(msg, md0, QSC_SHA2_512_HASH_SIZE);
				qsc_memutils_copy(msg + (1 * QSC_SHA2_512_HASH_SIZE), md1, QSC_SHA2_512_HASH_SIZE);
				qsc_memutils_copy(msg + (2 * QSC_SHA2_512_HASH_SIZE), md2, QSC_SHA2_512_HASH_SIZE);

				qsc_sha512_compute(mdx, msg, sizeof(msg));

				qsc_memutils_copy(md0, md1, QSC_SHA2_512_HASH_SIZE);
				qsc_memutils_copy(md1, md2, QSC_SHA2_512_HASH_SIZE);
				qsc_memutils_copy(md2, mdx, QSC_SHA2_512_HASH_SIZE);
			}

			while (read != -1)
			{
				read = qsc_fileutils_get_line(&line, &len, fp);

				if (read > 0 && line != NULL &&
					memcmp(line, CAVP_SHA2_MD, strlen(CAVP_SHA2_MD)) == 0)
				{
					ptr = line + strlen(CAVP_SHA2_MD);
					cavp_hex_to_bin(ptr, expmd, QSC_SHA2_512_HASH_SIZE);
					break;
				}
			}

			if (cavp_byte_arrays_are_equal8(md2, expmd, QSC_SHA2_512_HASH_SIZE) == false)
			{
				res = false;
				break;
			}

			qsc_memutils_copy(seed, md2, QSC_SHA2_512_HASH_SIZE);
		}

		qsc_fileutils_close(fp);
	}
	else
	{
		res = false;
	}

    if (line != NULL)
    {
        free(line);
    }

    return res;
}

static bool hmac_kat_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_HMAC_SHA256) && qsc_fileutils_exists(CAVP_HMAC_SHA512))
	{
		res = true;

		if (hmac_256_kat(CAVP_HMAC_SHA256))
		{
			cavp_print_line("HMAC-SHA256 passed the keyed-message KAT test.");
		}
		else
		{
			cavp_print_line("HMAC-SHA256 failed the keyed-message KAT test.");
			res = false;
		}

		if (hmac_512_kat(CAVP_HMAC_SHA512))
		{
			cavp_print_line("HMAC-SHA512 passed the keyed-message KAT test.");
		}
		else
		{
			cavp_print_line("HMAC-SHA512 failed the keyed-message KAT test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

static bool sha2_kat_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_SHA256_LONGMSG) && qsc_fileutils_exists(CAVP_SHA384_LONGMSG) && 
		qsc_fileutils_exists(CAVP_SHA512_LONGMSG) && qsc_fileutils_exists(CAVP_SHA256_SHORTMSG) &&
		qsc_fileutils_exists(CAVP_SHA384_SHORTMSG) && qsc_fileutils_exists(CAVP_SHA512_SHORTMSG))
	{
		res = true;

		if (sha2_256_kat(CAVP_SHA256_LONGMSG))
		{
			cavp_print_line("SHA2-256 passed the long-message KAT test.");
		}
		else
		{
			cavp_print_line("SHA2-256 failed the long-message KAT test.");
			res = false;
		}

		if (sha2_256_kat(CAVP_SHA256_SHORTMSG))
		{
			cavp_print_line("SHA2-256 passed the short-message KAT test.");
		}
		else
		{
			cavp_print_line("SHA2-256 failed the short-message KAT test.");
			res = false;
		}
		
		if (sha2_384_kat(CAVP_SHA384_LONGMSG))
		{
			cavp_print_line("SHA2-384 passed the long-message KAT test.");
		}
		else
		{
			cavp_print_line("SHA2-384 failed the long-message KAT test.");
			res = false;
		}

		if (sha2_384_kat(CAVP_SHA384_SHORTMSG))
		{
			cavp_print_line("SHA2-384 passed the short-message KAT test.");
		}
		else
		{
			cavp_print_line("SHA2-384 failed the short-message KAT test.");
			res = false;
		}

		if (sha2_512_kat(CAVP_SHA512_LONGMSG))
		{
			cavp_print_line("SHA2-512 passed the long-message KAT test.");
		}
		else
		{
			cavp_print_line("SHA2-512 failed the long-message KAT test.");
			res = false;
		}

		if (sha2_512_kat(CAVP_SHA512_SHORTMSG))
		{
			cavp_print_line("SHA2-512 passed the short-message KAT test.");
		}
		else
		{
			cavp_print_line("SHA2-512 failed the short-message KAT test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool sha2_mct_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_SHA256_MCT) && qsc_fileutils_exists(CAVP_SHA384_MCT) && qsc_fileutils_exists(CAVP_SHA512_MCT))
	{
		res = true;

		if (sha2_256_mct(CAVP_SHA256_MCT))
		{
			cavp_print_line("SHA256 passed the monte carlo test.");
		}
		else
		{
			cavp_print_line("SHA256 failed the monte carlo test.");
			res = false;
		}

		if (sha2_384_mct(CAVP_SHA384_MCT))
		{
			cavp_print_line("SHA384 passed the monte carlo test.");
		}
		else
		{
			cavp_print_line("SHA384 failed the monte carlo test.");
			res = false;
		}

		if (sha2_512_mct(CAVP_SHA512_MCT))
		{
			cavp_print_line("SHA512 passed the monte carlo test.");
		}
		else
		{
			cavp_print_line("SHA512 failed the monte carlo test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

void cavp_sha2_run()
{
	cavp_print_line("Running the NIST CAVP SHA2 tests, testing known answers and Monte Carlo runs.");
	cavp_print_line("Tests long and short messages against Known Answer Tests (KAT), and Monte Carlo Tests (MCTs).");
	cavp_print_line("There are two distinct KAT variants and a Monte Carlo Test:");
	cavp_print_line("- Long Message: Tests against the known answer of a long message hash.");
	cavp_print_line("- Short Message: Tests against the known answer of a short message hash.");
	cavp_print_line("- Monte Carlo: Tests iterations of hashes where the output is re-hashed.");
	cavp_print_line("Tests the CAVP HMAC known answer tests for HMAC(SHA256) and HMAC(SHA512).");
	cavp_print_line("");

	if (sha2_kat_tests())
	{
		cavp_print_line("Success! Passed the CAVP SHA256, SHA384, and SHA512 Long and Short Message KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP SHA256, SHA384, and SHA512 Long and Short Message KAT tests.");
	}
	
	cavp_print_line("");

	if (sha2_mct_tests())
	{
		cavp_print_line("Success! Passed the CAVP SHA256, SHA384, and SHA512 Monte Carlo KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP SHA256, SHA384, and SHA512 Monte Carlo KAT tests.");
	}
	
	cavp_print_line("");

	if (hmac_kat_tests())
	{
		cavp_print_line("Success! Passed the CAVP HMAC(SHA256) and HMAC(SHA512) KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP HMAC(SHA256) and HMAC(SHA512) KAT tests.");
	}
}
