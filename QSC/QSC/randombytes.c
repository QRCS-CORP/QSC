#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "randombytes.h"
#include "fips202.h"

#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include <fcntl.h>
#   include <errno.h>
#   ifdef __linux__
#       define _GNU_SOURCE
#       include <unistd.h>
#       include <sys/syscall.h>
#   else
#       include <unistd.h>
#   endif
#endif

#define SECURE_ZERO(ptr, len)                                       \
    do {                                                            \
        /* Use a volatile pointer to memset so that the call */     \
        /* cannot be optimized out.                           */    \
        void *(* volatile memset_v)(void *, int, size_t) = memset;  \
        memset_v((ptr), 0, (len));                                  \
    } while(0)

int32_t randombytes(uint8_t* out, size_t outlen)
{
    uint8_t* buf;
    int32_t res;
    size_t buflen;
    size_t ctr;
    size_t pos;

    ctr = 0;
    pos = 0;
    res = -1;

    /* allocate 2x the request size for pq equivalent security */
    buflen = outlen * 2;
    ctr = buflen;
    buf = malloc(buflen);

    if (buf != NULL)
    {
        SECURE_ZERO(buf, buflen);

#ifdef _WIN32

        HCRYPTPROV ctx;

        size_t len;

        if (!CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
            abort();
        }

        while (pos < ctr)
        {
            len = (ctr > 1048576) ? 1048576 : ctr;

            if (!CryptGenRandom(ctx, len, (BYTE*)buf + pos))
            {
                abort();
            }

            ctr -= len;
            pos += len;
        }

        if (!CryptReleaseContext(ctx, 0))
        {
            abort();
        }

#elif defined(__linux__) && defined(SYS_getrandom)

        ssize_t ret;

        while (pos < ctr)
        {
            ret = syscall(SYS_getrandom, buf + pos, ctr, 0);

            if (ret == -1 && errno == EINTR)
            {
                continue;
            }

            else if (ret == -1)
            {
                abort();
            }

            ctr -= ret;
            pos += ret;
        }

#else

        static int fd = -1;
        ssize_t ret;

        while (fd == -1)
        {
            fd = open("/dev/urandom", O_RDONLY);

            if (fd == -1 && errno == EINTR)
            {
                continue;
            }
            else if (fd == -1)
            {
                abort();
            }
        }

        while (pos < ctr)
        {
            ret = read(fd, buf + pos, ctr);

            if (ret == -1 && errno == EINTR)
            {
                continue;
            }
            else if (ret == -1)
            {
                abort();
            }

            ctr -= ret;
            pos += ret;
        }

#endif

        shake256(out, outlen, buf, buflen);
        SECURE_ZERO(buf, buflen);
        free(buf);
        res = outlen;
    }
    else
    {
        abort();
    }

    return res;
}

