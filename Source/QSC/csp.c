#include "csp.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	if defined(QSC_SYSTEM_COMPILER_MSC)
#		pragma comment(lib, "Bcrypt.lib")
#	endif
#  include <Windows.h>
#  include <bcrypt.h>
#elif defined(QSC_SYSTEM_OS_LINUX)
#  include <sys/random.h>
#  include <errno.h>
#  include <unistd.h>
#elif defined(QSC_SYSTEM_OS_BSD) || defined(QSC_SYSTEM_OS_MAC)
#  include <stdlib.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#  include <errno.h>
#endif

bool qsc_csp_generate(uint8_t* output, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);
	QSC_ASSERT(length <= QSC_CSP_SEED_MAX);

	bool res;

	res = false;

	if (output != NULL && length != 0U && length <= QSC_CSP_SEED_MAX)
	{
		res = true;
#if defined(QSC_SYSTEM_OS_WINDOWS)

		ULONG ulen = (ULONG)length;

		if (BCryptGenRandom(NULL, output, ulen, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		{
			res = false;
		}

#elif defined(QSC_SYSTEM_OS_LINUX)

		ssize_t pos;
		size_t  rmd;
		uint8_t* ptr;

		rmd = length;
		ptr = output;

		while (rmd > 0U)
		{
			pos = getrandom(ptr, rmd, 0U);

			if (pos < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}

				res = false;
				break;
			}

			ptr += (size_t)pos;
			rmd -= (size_t)pos;
		}

#elif defined(QSC_SYSTEM_OS_BSD) || defined(QSC_SYSTEM_OS_MAC)

		arc4random_buf(output, length);

#else

		int32_t fd;

		/* fallback: read from /dev/urandom */

		do
		{
			fd = open("/dev/urandom", O_RDONLY);
		} while ((fd < 0) && (errno == EINTR));

		if (fd < 0)
		{
			res = false;
		}
		else
		{
			ssize_t pos;
			size_t rmd;
			uint8_t* ptr;

			rmd = length;
			ptr = output;

			while (rmd > 0U)
			{
				pos = read(fd, ptr, rmd);

				if (pos < 0)
				{
					if (errno == EINTR)
					{
						continue;
					}

					res = false;
					break;
				}
				else if (pos == 0)
				{
					/* zero-length read, treat as failure */
					res = false;
					break;
				}

				ptr += (size_t)pos;
				rmd -= (size_t)pos;
			}

			(void)close(fd);
		}

#endif
	}

	if (res == false)
	{
		qsc_memutils_secure_erase(output, length);
	}

	return res;
}

uint16_t qsc_csp_uint16(void)
{
	uint8_t arr[sizeof(uint16_t)] = { 0U };
	uint16_t num;

	num = 0U;

	if (qsc_csp_generate(arr, sizeof(arr)) == true)
	{
		num = (((uint16_t)arr[1U]) |
			(uint16_t)((uint16_t)arr[0U] << 8U));

		qsc_memutils_secure_erase(arr, sizeof(arr));
	}

	return num;
}

uint32_t qsc_csp_uint32(void)
{
	uint8_t arr[sizeof(uint32_t)] = { 0U };
	uint32_t num;

	num = 0U;

	if (qsc_csp_generate(arr, sizeof(arr)) == true)
	{
		num = (uint32_t)(arr[3U]) |
			(((uint32_t)(arr[2U])) << 8) |
			(((uint32_t)(arr[1U])) << 16) |
			(((uint32_t)(arr[0U])) << 24);

		qsc_memutils_secure_erase(arr, sizeof(arr));
	}

	return num;
}

uint64_t qsc_csp_uint64(void)
{
	uint8_t arr[sizeof(uint64_t)] = { 0U };
	uint64_t num;

	num = 0U;

	if (qsc_csp_generate(arr, sizeof(arr)) == true)
	{
		num = (uint64_t)(arr[7U]) |
			(((uint64_t)(arr[6U])) << 8) |
			(((uint64_t)(arr[5U])) << 16) |
			(((uint64_t)(arr[4U])) << 24) |
			(((uint64_t)(arr[3U])) << 32) |
			(((uint64_t)(arr[2U])) << 40) |
			(((uint64_t)(arr[1U])) << 48) |
			(((uint64_t)(arr[0U])) << 56);

		qsc_memutils_secure_erase(arr, sizeof(arr));
	}

	return num;
}
