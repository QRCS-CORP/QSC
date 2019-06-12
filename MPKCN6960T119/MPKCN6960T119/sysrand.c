#include "sysrand.h"

#ifdef MQC_OS_WINDOWS
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

mqc_status sysrand_getbytes(uint8_t* buffer, size_t length)
{
	mqc_status status = MQC_STATUS_SUCCESS;

#ifdef MQC_OS_WINDOWS

	HCRYPTPROV hProvider = 0;

	if (CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (!CryptGenRandom(hProvider, (DWORD)length, buffer))
		{
			status = MQC_ERROR_RANDFAIL;
		}
	}
	else
	{
		status = MQC_ERROR_RANDFAIL;
	}

	if (hProvider != 0)
	{
		CryptReleaseContext(hProvider, 0);
	}

#else

	int32_t fd = open("/dev/urandom", O_RDONLY);

	if (fd <= 0)
	{
		status = MQC_ERROR_RANDFAIL;
	}
	else
	{
		int32_t r = read(fd, buffer, length);

		if (r != length)
		{
			status = MQC_ERROR_RANDFAIL;
		}

		close(fd);
	}

#endif

	return status;
}
