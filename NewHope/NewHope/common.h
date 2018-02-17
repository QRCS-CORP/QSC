/**
* \file common.h
* \brief <b>Contains global includes and enumerations</b> \n
* This is an internal class.
*
* \date February 16, 2018
*/

#ifndef NEWHOPE_COMMON_H
#define NEWHOPE_COMMON_H

#if defined(WINDOWS)
#	include <stdint.h>
#else
#	include "inttypes.h"
#endif

/*! \enum newhope_status
* Contains Kyber state and error return codes
*/
typedef enum
{
	NEWHOPE_STATE_FAILURE = 0,	/*!< signals operation failure */
	NEWHOPE_STATE_SUCCESS = 1,	/*!< signals operation success */
	NEWHOPE_ERROR_AUTHFAIL = 2,	/*!< seed authentication failure */
	NEWHOPE_ERROR_RANDFAIL = 3,	/*!< system random failure */
	NEWHOPE_ERROR_INVALID = 4,	/*!< invalid parameter input */
	NEWHOPE_ERROR_INTERNAL = 5,	/*!< anonymous internal failure  */
	NEWHOPE_ERROR_KEYGEN = 6	/*!< key generation failure  */
} newhope_status;

#endif
