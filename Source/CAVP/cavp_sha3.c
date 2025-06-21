#include "cavp_sha3.h"
#include "cavp_utils.h"
#include "arrayutils.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

#define SHA3_MESSAGE_INT_SIZE 8
#define SHA3_MESSAGE_MAX 2048
#define SHAKE_EXPECTED_MIN 2
#define SHAKE_EXPECTED_MAX 250
#define SHAKE_MESSAGE_MAX 2048

static const char* CAVP_SHA3_COUNT = "COUNT = ";
static const char* CAVP_SHA3_LEN = "Len = ";
static const char* CAVP_SHA3_MSG = "Msg = ";
static const char* CAVP_SHA3_MD = "MD = ";
static const char* CAVP_SHA3_SEED = "Seed = ";
static const char* CAVP_SHAKE_OUTPUT = "Output = ";
static const char* CAVP_SHAKE_OUTLEN = "Outputlen = ";

static bool sha3_256_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t msg[SHA3_MESSAGE_MAX] = { 0 };
	uint8_t exp[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t otp[QSC_SHA3_256_HASH_SIZE] = { 0 };
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
				if (memcmp(line, CAVP_SHA3_LEN, strlen(CAVP_SHA3_LEN)) == 0)
				{
					sln = line + strlen(CAVP_SHA3_LEN);
					mlen = qsc_arrayutils_string_to_uint32(sln, len - (strlen(CAVP_SHA3_LEN) + 1));

					/* skip zero length (illegal) size inputs */
					if (mlen > 0 && mlen <= SHA3_MESSAGE_MAX)
					{
						/* convert from bit-length */
						mlen /= 8;

						for (i = 0; i < 2; ++i)
						{
							read = qsc_fileutils_get_line(&line, &len, fp);

							if (memcmp(line, CAVP_SHA3_MSG, strlen(CAVP_SHA3_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA3_MSG), msg, mlen);
							}
							else if (memcmp(line, CAVP_SHA3_MD, strlen(CAVP_SHA3_MD)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA3_MD), exp, sizeof(exp));
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_sha3_compute256(otp, msg, mlen);

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

static bool sha3_512_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t msg[SHA3_MESSAGE_MAX] = { 0 };
	uint8_t exp[QSC_SHA3_512_HASH_SIZE] = { 0 };
	uint8_t otp[QSC_SHA3_512_HASH_SIZE] = { 0 };
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
				if (memcmp(line, CAVP_SHA3_LEN, strlen(CAVP_SHA3_LEN)) == 0)
				{
					sln = line + strlen(CAVP_SHA3_LEN);
					mlen = qsc_arrayutils_string_to_uint32(sln, len - (strlen(CAVP_SHA3_LEN) + 1));

					/* skip zero length (illegal) size inputs */
					if (mlen > 0 && mlen <= SHA3_MESSAGE_MAX)
					{
						/* convert from bit-length */
						mlen /= 8;

						for (i = 0; i < 2; ++i)
						{
							read = qsc_fileutils_get_line(&line, &len, fp);

							if (memcmp(line, CAVP_SHA3_MSG, strlen(CAVP_SHA3_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA3_MSG), msg, mlen);
							}
							else if (memcmp(line, CAVP_SHA3_MD, strlen(CAVP_SHA3_MD)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA3_MD), exp, sizeof(exp));
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_sha3_compute512(otp, msg, mlen);

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

static bool sha3_256_mct(const char* filepath)
{
    QSC_ASSERT(filepath != NULL);

	uint8_t seed[QSC_SHA3_256_HASH_SIZE] = { 0 };
    uint8_t mdprev[QSC_SHA3_256_HASH_SIZE] = { 0 };
    uint8_t mdcurr[QSC_SHA3_256_HASH_SIZE] = { 0 };
    uint8_t expmd[QSC_SHA3_256_HASH_SIZE] = { 0 };
    FILE* fp;
    char* line;
    const char* ptr;
    int64_t read;
    size_t len;
    bool res;

	line = NULL;
	read = 0;
	res = true;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			/* get the seed */
			if (line != NULL && memcmp(line, CAVP_SHA3_SEED, strlen(CAVP_SHA3_SEED)) == 0)
			{
				ptr = line + strlen(CAVP_SHA3_SEED);
				cavp_hex_to_bin(ptr, seed, QSC_SHA3_256_HASH_SIZE);
				break;
			}
		}

		/* outer loop, test the 100 kats */
		for (int count = 0; count < 100 && res; ++count)
		{
			/* initialize the chaining buffer */
			qsc_memutils_copy(mdprev, seed, QSC_SHA3_256_HASH_SIZE);

			/* inner loop, 1000 chained hashes of the previous output */
			for (int i = 1; i <= 1000; ++i)
			{
				qsc_sha3_compute256(mdcurr, mdprev, QSC_SHA3_256_HASH_SIZE);
				qsc_memutils_copy(mdprev, mdcurr, QSC_SHA3_256_HASH_SIZE);
			}

			while (read != -1)
			{
				read = qsc_fileutils_get_line(&line, &len, fp);

				if (line != NULL && memcmp(line, CAVP_SHA3_COUNT, strlen(CAVP_SHA3_COUNT)) == 0)
				{
					uint32_t fcount = qsc_arrayutils_string_to_uint32(line + strlen(CAVP_SHA3_COUNT), read - (strlen(CAVP_SHA3_COUNT) + 1));

					if (fcount != count)
					{
						res = false;
					}

					break;
				}
			}

			if (res)
			{
				while (read != -1)
				{
					read = qsc_fileutils_get_line(&line, &len, fp);

					if (line != NULL && memcmp(line, CAVP_SHA3_MD, strlen(CAVP_SHA3_MD)) == 0)
					{
						ptr = line + strlen(CAVP_SHA3_MD);
						cavp_hex_to_bin(ptr, expmd, QSC_SHA3_256_HASH_SIZE);
						break;
					}
				}

				if (cavp_byte_arrays_are_equal8(mdcurr, expmd, QSC_SHA3_256_HASH_SIZE) == false)
				{
					res = false;
				}
			}

			qsc_memutils_copy(seed, mdcurr, QSC_SHA3_256_HASH_SIZE);
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

static bool sha3_512_mct(const char* filepath)
{
    QSC_ASSERT(filepath != NULL);

	uint8_t seed[QSC_SHA3_512_HASH_SIZE] = { 0 };
    uint8_t mdprev[QSC_SHA3_512_HASH_SIZE] = { 0 };
    uint8_t mdcurr[QSC_SHA3_512_HASH_SIZE] = { 0 };
    uint8_t expmd[QSC_SHA3_512_HASH_SIZE] = { 0 };
    FILE* fp;
    char* line;
    const char* ptr;
    int64_t read;
    size_t len;
    bool res;

	line = NULL;
	read = 0;
	res = true;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			/* get the seed */
			if (line != NULL && memcmp(line, CAVP_SHA3_SEED, strlen(CAVP_SHA3_SEED)) == 0)
			{
				ptr = line + strlen(CAVP_SHA3_SEED);
				cavp_hex_to_bin(ptr, seed, QSC_SHA3_512_HASH_SIZE);
				break;
			}
		}

		/* outer loop, test the 100 kats */
		for (int count = 0; count < 100 && res; ++count)
		{
			/* initialize the chaining buffer */
			qsc_memutils_copy(mdprev, seed, QSC_SHA3_512_HASH_SIZE);

			/* inner loop, 1000 chained hashes of the previous output */
			for (int i = 1; i <= 1000; ++i)
			{
				qsc_sha3_compute512(mdcurr, mdprev, QSC_SHA3_512_HASH_SIZE);
				qsc_memutils_copy(mdprev, mdcurr, QSC_SHA3_512_HASH_SIZE);
			}

			while (read != -1)
			{
				read = qsc_fileutils_get_line(&line, &len, fp);

				if (line != NULL && memcmp(line, CAVP_SHA3_COUNT, strlen(CAVP_SHA3_COUNT)) == 0)
				{
					uint32_t fcount = qsc_arrayutils_string_to_uint32(line + strlen(CAVP_SHA3_COUNT), read - (strlen(CAVP_SHA3_COUNT) + 1));

					if (fcount != count)
					{
						res = false;
					}

					break;
				}
			}

			if (res)
			{
				while (read != -1)
				{
					read = qsc_fileutils_get_line(&line, &len, fp);

					if (line != NULL && memcmp(line, CAVP_SHA3_MD, strlen(CAVP_SHA3_MD)) == 0)
					{
						ptr = line + strlen(CAVP_SHA3_MD);
						cavp_hex_to_bin(ptr, expmd, QSC_SHA3_512_HASH_SIZE);
						break;
					}
				}

				if (cavp_byte_arrays_are_equal8(mdcurr, expmd, QSC_SHA3_512_HASH_SIZE) == false)
				{
					res = false;
				}
			}

			qsc_memutils_copy(seed, mdcurr, QSC_SHA3_512_HASH_SIZE);
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

static bool shake_128_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t msg[SHAKE_MESSAGE_MAX] = { 0 };
	uint8_t exp[QSC_SHA3_128_HASH_SIZE] = { 0 };
	uint8_t otp[QSC_SHA3_128_HASH_SIZE] = { 0 };
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
				if (memcmp(line, CAVP_SHA3_LEN, strlen(CAVP_SHA3_LEN)) == 0)
				{
					sln = line + strlen(CAVP_SHA3_LEN);
					mlen = qsc_arrayutils_string_to_uint32(sln, len - (strlen(CAVP_SHA3_LEN) + 1));

					/* skip zero length (illegal) size inputs */
					if (mlen > 0 && mlen <= SHA3_MESSAGE_MAX)
					{
						/* convert from bit-length */
						mlen /= 8;
						
						for (i = 0; i < 2; ++i)
						{
							read = qsc_fileutils_get_line(&line, &len, fp);

							if (memcmp(line, CAVP_SHA3_MSG, strlen(CAVP_SHA3_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA3_MSG), msg, mlen);
							}
							else if (memcmp(line, CAVP_SHAKE_OUTPUT, strlen(CAVP_SHAKE_OUTPUT)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHAKE_OUTPUT), exp, sizeof(exp));
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_shake128_compute(otp, sizeof(otp), msg, mlen);

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

static bool shake_256_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t msg[SHAKE_MESSAGE_MAX] = { 0 };
	uint8_t exp[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t otp[QSC_SHA3_256_HASH_SIZE] = { 0 };
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
				if (memcmp(line, CAVP_SHA3_LEN, strlen(CAVP_SHA3_LEN)) == 0)
				{
					sln = line + strlen(CAVP_SHA3_LEN);
					mlen = qsc_arrayutils_string_to_uint32(sln, len - (strlen(CAVP_SHA3_LEN) + 1));

					/* skip zero length (illegal) size inputs */
					if (mlen > 0 && mlen <= SHA3_MESSAGE_MAX)
					{
						/* convert from bit-length */
						mlen /= 8;
						
						for (i = 0; i < 2; ++i)
						{
							read = qsc_fileutils_get_line(&line, &len, fp);

							if (memcmp(line, CAVP_SHA3_MSG, strlen(CAVP_SHA3_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA3_MSG), msg, mlen);
							}
							else if (memcmp(line, CAVP_SHAKE_OUTPUT, strlen(CAVP_SHAKE_OUTPUT)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHAKE_OUTPUT), exp, sizeof(exp));
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_shake256_compute(otp, sizeof(otp), msg, mlen);

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

static bool shake_128_varkat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t msg[QSC_SHA3_128_HASH_SIZE] = { 0 };
	uint8_t exp[SHAKE_EXPECTED_MAX] = { 0 };
	uint8_t otp[SHAKE_EXPECTED_MAX] = { 0 };
	char* sln;
	int64_t read;
	size_t i;
	size_t len;
	int32_t elen;
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
				if (memcmp(line, CAVP_SHAKE_OUTLEN, strlen(CAVP_SHAKE_OUTLEN)) == 0)
				{
					sln = line + strlen(CAVP_SHAKE_OUTLEN);
					elen = qsc_arrayutils_string_to_uint32(sln, len - (strlen(CAVP_SHAKE_OUTLEN) + 1));

					/* skip zero length (illegal) size inputs */
					if (elen > 0 && elen <= SHA3_MESSAGE_MAX)
					{
						/* convert from bit-length */
						elen /= 8;

						for (i = 0; i < 2; ++i)
						{
							read = qsc_fileutils_get_line(&line, &len, fp);

							if (memcmp(line, CAVP_SHA3_MSG, strlen(CAVP_SHA3_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA3_MSG), msg, QSC_SHA3_128_HASH_SIZE);
							}
							else if (memcmp(line, CAVP_SHAKE_OUTPUT, strlen(CAVP_SHAKE_OUTPUT)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHAKE_OUTPUT), exp, elen);
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_shake128_compute(otp, elen, msg, QSC_SHA3_128_HASH_SIZE);

						if (cavp_byte_arrays_are_equal8(exp, otp, elen) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_clear(msg, QSC_SHA3_128_HASH_SIZE);
						qsc_memutils_clear(exp, elen);
						qsc_memutils_clear(otp, elen);
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

static bool shake_256_varkat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t msg[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t exp[SHAKE_EXPECTED_MAX] = { 0 };
	uint8_t otp[SHAKE_EXPECTED_MAX] = { 0 };
	char* sln;
	int64_t read;
	size_t i;
	size_t len;
	int32_t elen;
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
				if (memcmp(line, CAVP_SHAKE_OUTLEN, strlen(CAVP_SHAKE_OUTLEN)) == 0)
				{
					sln = line + strlen(CAVP_SHAKE_OUTLEN);
					elen = qsc_arrayutils_string_to_uint32(sln, len - (strlen(CAVP_SHAKE_OUTLEN) + 1));

					/* skip zero length (illegal) size inputs */
					if (elen > 0 && elen <= SHA3_MESSAGE_MAX)
					{
						/* convert from bit-length */
						elen /= 8;

						for (i = 0; i < 2; ++i)
						{
							read = qsc_fileutils_get_line(&line, &len, fp);

							if (memcmp(line, CAVP_SHA3_MSG, strlen(CAVP_SHA3_MSG)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHA3_MSG), msg, QSC_SHA3_256_HASH_SIZE);
							}
							else if (memcmp(line, CAVP_SHAKE_OUTPUT, strlen(CAVP_SHAKE_OUTPUT)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SHAKE_OUTPUT), exp, elen);
							}
							else
							{
								res = false;
								break;
							}
						}

						qsc_shake256_compute(otp, elen, msg, QSC_SHA3_256_HASH_SIZE);

						if (cavp_byte_arrays_are_equal8(exp, otp, elen) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_clear(msg, QSC_SHA3_256_HASH_SIZE);
						qsc_memutils_clear(exp, elen);
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

static bool shake_128_mct(const char* filepath)
{
    QSC_ASSERT(filepath != NULL);

	uint8_t seed[SHAKE_EXPECTED_MAX] = { 0 };
    uint8_t mdprev[SHAKE_EXPECTED_MAX] = { 0 };
    uint8_t mdcurr[SHAKE_EXPECTED_MAX] = { 0 };
    uint8_t expmd[SHAKE_EXPECTED_MAX] = { 0 };
	uint8_t mint[SHA3_MESSAGE_INT_SIZE] = { 0 };
    FILE* fp;
    char* line;
    const char* ptr;
    int64_t read;
    size_t len;
	size_t elen;
    bool res;

	line = NULL;
	elen = 0;
	read = 0;
	res = true;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			/* get the seed */
			if (line != NULL && memcmp(line, CAVP_SHA3_MSG, strlen(CAVP_SHA3_MSG)) == 0)
			{
				ptr = line + strlen(CAVP_SHA3_MSG);
				cavp_hex_to_bin(ptr, seed, QSC_SHA3_128_HASH_SIZE);
				break;
			}
		}

		/* outer loop, test the 100 kats */
		for (int count = 0; count < 100 && res; ++count)
		{
			while (read != -1)
			{
				read = qsc_fileutils_get_line(&line, &len, fp);

				if (line != NULL && memcmp(line, CAVP_SHA3_COUNT, strlen(CAVP_SHA3_COUNT)) == 0)
				{
					uint32_t fcount = qsc_arrayutils_string_to_uint32(line + strlen(CAVP_SHA3_COUNT), read - (strlen(CAVP_SHA3_COUNT) + 1));

					if (fcount != count)
					{
						res = false;
						break;
					}
				}
				else if (line != NULL && memcmp(line, CAVP_SHAKE_OUTLEN, strlen(CAVP_SHAKE_OUTLEN)) == 0)
				{
					ptr = line + strlen(CAVP_SHAKE_OUTLEN);
					elen = qsc_arrayutils_string_to_uint32(ptr, read - (strlen(CAVP_SHAKE_OUTLEN) + 1));

					if (elen > 0)
					{
						elen /= 8;
					}
					else
					{
						res = false;
						break;
					}
				}
				else if (line != NULL && memcmp(line, CAVP_SHAKE_OUTPUT, strlen(CAVP_SHAKE_OUTPUT)) == 0)
				{
					ptr = line + strlen(CAVP_SHAKE_OUTPUT);
					cavp_hex_to_bin(ptr, expmd, elen);
					break;
				}
			}

			/* initialize the chaining buffer */
			qsc_memutils_copy(mdprev, seed, QSC_SHA3_128_HASH_SIZE);

			/* inner loop, 1000 chained hashes of the previous output */
			for (int i = 1; i <= 1000; ++i)
			{
				qsc_shake128_compute(mdcurr, elen, mdprev, QSC_SHA3_128_HASH_SIZE);
				qsc_memutils_copy(mdprev, mdcurr, QSC_SHA3_128_HASH_SIZE);
			}

			if (cavp_byte_arrays_are_equal8(mdcurr, expmd, elen) == false)
			{
				res = false;
				break;
			}

			qsc_memutils_copy(seed, mdcurr, elen);
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

static bool shake_256_mct(const char* filepath)
{
    QSC_ASSERT(filepath != NULL);

	uint8_t seed[SHAKE_EXPECTED_MAX] = { 0 };
    uint8_t mdprev[SHAKE_EXPECTED_MAX] = { 0 };
    uint8_t mdcurr[SHAKE_EXPECTED_MAX] = { 0 };
    uint8_t expmd[SHAKE_EXPECTED_MAX] = { 0 };
	uint8_t mint[SHA3_MESSAGE_INT_SIZE] = { 0 };
    FILE* fp;
    char* line;
    const char* ptr;
    int64_t read;
	size_t copylen;
    size_t len;
	size_t elen;
	size_t outlen;
	size_t oldoutlen;
	size_t seedcopy;
	uint32_t fcount;
	uint16_t right16;
    bool res;

	line = NULL;
	elen = 0;
	outlen = SHAKE_EXPECTED_MAX;
	read = 0;
	res = true;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL)
	{
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &len, fp);

			/* get the seed */
			if (line != NULL && memcmp(line, CAVP_SHA3_MSG, strlen(CAVP_SHA3_MSG)) == 0)
			{
				ptr = line + strlen(CAVP_SHA3_MSG);
				cavp_hex_to_bin(ptr, seed, QSC_SHA3_128_HASH_SIZE);
				break;
			}
		}

		/* outer loop, test the 100 kats */
		for (int count = 0; count < 100 && res; ++count)
		{
			while (read != -1)
			{
				read = qsc_fileutils_get_line(&line, &len, fp);

				if (line != NULL && memcmp(line, CAVP_SHA3_COUNT, strlen(CAVP_SHA3_COUNT)) == 0)
				{
					fcount = qsc_arrayutils_string_to_uint32(line + strlen(CAVP_SHA3_COUNT), read - (strlen(CAVP_SHA3_COUNT) + 1));

					if (fcount != count)
					{
						res = false;
						break;
					}
				}
				else if (line != NULL && memcmp(line, CAVP_SHAKE_OUTLEN, strlen(CAVP_SHAKE_OUTLEN)) == 0)
				{
					ptr = line + strlen(CAVP_SHAKE_OUTLEN);
					elen = qsc_arrayutils_string_to_uint32(ptr, read - (strlen(CAVP_SHAKE_OUTLEN) + 1));

					if (elen > 0)
					{
						elen /= 8;
					}
					else
					{
						res = false;
						break;
					}
				}
				else if (line != NULL && memcmp(line, CAVP_SHAKE_OUTPUT, strlen(CAVP_SHAKE_OUTPUT)) == 0)
				{
					ptr = line + strlen(CAVP_SHAKE_OUTPUT);
					cavp_hex_to_bin(ptr, expmd, elen);
					break;
				}
			}

			/* initialize the chaining buffer */
			qsc_memutils_clear(mdprev, sizeof(mdprev));
			qsc_memutils_copy(mdprev, seed, QSC_SHA3_128_HASH_SIZE);

			for (int i = 1; i <= 1000; ++i)
			{
				oldoutlen = outlen;

				qsc_shake256_compute(mdcurr, oldoutlen, mdprev, QSC_SHA3_128_HASH_SIZE);

				right16 = (uint16_t)(mdcurr[oldoutlen - SHAKE_EXPECTED_MIN] << 8) | (uint16_t) mdcurr[oldoutlen - 1];
				outlen = SHAKE_EXPECTED_MIN + (right16 % (SHAKE_EXPECTED_MAX - SHAKE_EXPECTED_MIN + 1));

				copylen = oldoutlen < QSC_SHA3_128_HASH_SIZE ? oldoutlen : QSC_SHA3_128_HASH_SIZE;
				qsc_memutils_clear(mdprev, QSC_SHA3_128_HASH_SIZE);
				qsc_memutils_copy(mdprev, mdcurr, copylen);
			}

			if (cavp_byte_arrays_are_equal8(mdcurr, expmd, elen) == false)
			{
				res = false;
				break;
			}
			
			seedcopy = (elen < QSC_SHA3_128_HASH_SIZE ? elen : QSC_SHA3_128_HASH_SIZE);
			/* zero only the 16-byte seed, not the entire 250-byte array */
			qsc_memutils_clear(seed, QSC_SHA3_128_HASH_SIZE);
			qsc_memutils_copy(seed, mdcurr, seedcopy);
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

static bool sha3_kat_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_SHA3_256_LONGMSG) && qsc_fileutils_exists(CAVP_SHA3_512_LONGMSG) && 
		qsc_fileutils_exists(CAVP_SHA3_256_SHORTMSG) && qsc_fileutils_exists(CAVP_SHA3_512_SHORTMSG))
	{
		res = true;

		if (sha3_256_kat(CAVP_SHA3_256_LONGMSG))
		{
			cavp_print_line("SHA3-256 passed the long-message KAT test.");
		}
		else
		{
			cavp_print_line("SHA3-256 failed the long-message KAT test.");
			res = false;
		}

		if (sha3_256_kat(CAVP_SHA3_256_SHORTMSG))
		{
			cavp_print_line("SHA3-256 passed the short-message KAT test.");
		}
		else
		{
			cavp_print_line("SHA3-256 failed the short-message KAT test.");
			res = false;
		}

		if (sha3_512_kat(CAVP_SHA3_512_LONGMSG))
		{
			cavp_print_line("SHA3-512 passed the long-message KAT test.");
		}
		else
		{
			cavp_print_line("SHA3-512 failed the long-message KAT test.");
			res = false;
		}

		if (sha3_512_kat(CAVP_SHA3_512_SHORTMSG))
		{
			cavp_print_line("SHA3-512 passed the short-message KAT test.");
		}
		else
		{
			cavp_print_line("SHA3-512 failed the short-message KAT test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

static bool sha3_mct_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_SHA3_256_MCT) && qsc_fileutils_exists(CAVP_SHA3_512_MCT))
	{
		res = true;

		if (sha3_256_mct(CAVP_SHA3_256_MCT))
		{
			cavp_print_line("SHA3-256 passed the monte carlo test.");
		}
		else
		{
			cavp_print_line("SHA3-256 failed the monte carlo test.");
			res = false;
		}

		if (sha3_512_mct(CAVP_SHA3_512_MCT))
		{
			cavp_print_line("SHA3-512 passed the monte carlo test.");
		}
		else
		{
			cavp_print_line("SHA3-512 failed the monte carlo test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

static bool shake_kat_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_SHAKE_128_LONGMSG) && qsc_fileutils_exists(CAVP_SHAKE_128_SHORTMSG) && 
		qsc_fileutils_exists(CAVP_SHAKE_128_VAROUT) && qsc_fileutils_exists(CAVP_SHAKE_256_LONGMSG) && 
		qsc_fileutils_exists(CAVP_SHAKE_256_SHORTMSG) && qsc_fileutils_exists(CAVP_SHAKE_256_VAROUT))
	{
		res = true;

		if (shake_128_kat(CAVP_SHAKE_128_LONGMSG))
		{
			cavp_print_line("SHAKE-128 passed the long-message KAT test.");
		}
		else
		{
			cavp_print_line("SHAKE-128 failed the long-message KAT test.");
			res = false;
		}

		if (shake_128_kat(CAVP_SHAKE_128_SHORTMSG))
		{
			cavp_print_line("SHAKE-128 passed the short-message KAT test.");
		}
		else
		{
			cavp_print_line("SHAKE-128 failed the short-message KAT test.");
			res = false;
		}
		
		if (shake_128_varkat(CAVP_SHAKE_128_VAROUT))
		{
			cavp_print_line("SHAKE-128 passed the variable-output KAT test.");
		}
		else
		{
			cavp_print_line("SHAKE-128 failed the variable-output KAT test.");
			res = false;
		}

		if (shake_256_kat(CAVP_SHAKE_256_LONGMSG))
		{
			cavp_print_line("SHAKE-256 passed the long-message KAT test.");
		}
		else
		{
			cavp_print_line("SHAKE-256 failed the long-message KAT test.");
			res = false;
		}

		if (shake_256_kat(CAVP_SHAKE_256_SHORTMSG))
		{
			cavp_print_line("SHAKE-256 passed the short-message KAT test.");
		}
		else
		{
			cavp_print_line("SHAKE-256 failed the short-message KAT test.");
			res = false;
		}
				
		if (shake_256_varkat(CAVP_SHAKE_256_VAROUT))
		{
			cavp_print_line("SHAKE-256 passed the variable-output KAT test.");
		}
		else
		{
			cavp_print_line("SHAKE-256 failed the variable-output KAT test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

static bool shake_mct_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_SHAKE_128_MCT) && qsc_fileutils_exists(CAVP_SHAKE_256_MCT))
	{
		res = true;

		if (shake_128_mct(CAVP_SHAKE_128_MCT))
		{
			cavp_print_line("SHAKE-128 passed the monte carlo test.");
		}
		else
		{
			cavp_print_line("SHAKE-128 failed the monte carlo test.");
			res = false;
		}

		if (shake_256_mct(CAVP_SHAKE_256_MCT))
		{
			cavp_print_line("SHAKE-256 passed the monte carlo test.");
		}
		else
		{
			cavp_print_line("SHAKE-256 failed the monte carlo test.");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

void cavp_sha3_run()
{
	cavp_print_line("Running the NIST CAVP SHA3 tests, testing known answers and Monte Carlo runs.");
	cavp_print_line("Tests long and short messages against Known Answer Tests (KAT), and Monte Carlo Tests (MCTs).");
	cavp_print_line("There are two distinct KAT variants and a Monte Carlo Test:");
	cavp_print_line("- Long Message: Tests against the known answer of a long message hash.");
	cavp_print_line("- Short Message: Tests against the known answer of a short message hash.");
	cavp_print_line("- Monte Carlo: Tests iterations of hashes where the output is re-hashed.");
	cavp_print_line("Tests the CAVP KMAC known answer tests for KMAC-128 and KMAC-256.");
	cavp_print_line("Tests the CAVP SHAKE known answer tests for SHAKE-128 and SHAKE-256.");
	cavp_print_line("Tests the CAVP cSHAKE known answer tests for cSHAKE-128 and cSHAKE-256.");
	cavp_print_line("");

	if (sha3_kat_tests())
	{
		cavp_print_line("Success! Passed the CAVP SHA3-256, and SHA3-512 Long and Short Message KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP SHA3-256, and SHA3-512 Long and Short Message KAT tests.");
	}
	
	cavp_print_line("");

	if (sha3_mct_tests())
	{
		cavp_print_line("Success! Passed the CAVP SHA3-256 and SHA3-512 Monte Carlo KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP SHA3-256 and SHA3-512 Monte Carlo KAT tests.");
	}
	
	cavp_print_line("");

	if (shake_kat_tests())
	{
		cavp_print_line("Success! Passed the CAVP SHAKE-128, and SHAKE-256 Long and Short Message KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP SHAKE-128, and SHAKE-256 Long and Short Message KAT tests.");
	}
	
	cavp_print_line("");

	if (shake_mct_tests())
	{
		cavp_print_line("Success! Passed the CAVP SHAKE-128, and SHAKE-256 and Monte Carlo KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the CAVP SHAKE-128, and SHAKE-256 and Monte Carlo KAT tests.");
	}
}
