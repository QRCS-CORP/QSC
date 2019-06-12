#include "sysrand.h"

#if defined(WINDOWS)
#	include <windows.h>
#	include <wincrypt.h>
#else
#	include <sys/types.h> /* TODO: are all of these really needed? */
#	include <sys/stat.h>
#	include <errno.h>
#	include <fcntl.h>
#	include <stdlib.h>
#	include <stdio.h>
#	include <unistd.h>
#endif

int32_t sysrand_getbytes(uint8_t* buffer, size_t length)
{
	int32_t status = RAND_STATUS_SUCCESS;

#if defined(WINDOWS)

	HCRYPTPROV hProvider = 0;

	if (CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (!CryptGenRandom(hProvider, (DWORD)length, buffer))
		{
			status = RAND_STATUS_FAILURE;
		}
	}
	else
	{
		status = RAND_STATUS_FAILURE;
	}

	if (hProvider != 0)
	{
		CryptReleaseContext(hProvider, 0);
	}

#else

	int32_t fd = open("/dev/urandom", O_RDONLY);

	if (fd <= 0)
	{
		status = RAND_STATUS_FAILURE;
	}
	else
	{
		int32_t r = read(fd, buffer, length);

		if (r != length)
		{
			status = RAND_STATUS_FAILURE;
		}

		close(fd);
	}

#endif

	return status;
}