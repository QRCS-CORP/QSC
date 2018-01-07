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

#include <stdint.h>

/*! \enum RAND_GENERATION_STATUS
* The random generation success state
*/
enum RAND_GENERATION_STATUS
{
	RAND_STATUS_FAILURE = 0, /*!< signals generator failure */
	RAND_STATUS_SUCCESS = 1  /*!< signals generator success */
};

/**
* \brief Get an array of pseudo-random bytes from the system entropy provider.
*
* \param buffer Pointer to the output byte array
* \param length The number of bytes to copy
* \return Returns one for success, zero for failure
*/
int32_t sysrand_getbytes(uint8_t* buffer, size_t length);

#endif
