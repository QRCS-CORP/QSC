/**
* \file sysrand.h
* \brief <b>System random provider</b> \n
* Provides access to either the Windows CryptGenRandom provider or 
* the /dev/urandom pool on posix systems.
*
* \author John Underhill
* \date January 06, 2018
*/

#ifndef SYSRAND_H
#define SYSRAND_H

/* jgu - supressing use of bool warning */
/*lint -e970 */
#include <stdbool.h>
#include <stdint.h>

/**
* \brief Get an array of pseudo-random bytes from the system entropy provider.
*
* \param buffer Pointer to the output byte array
* \param length The number of bytes to copy
* \return Returns true for successful generation, false for failure
*/
bool sysrand_getbytes(uint8_t* buffer, size_t length);

#endif
