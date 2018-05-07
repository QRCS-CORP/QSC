/**
* \file common.h
* \brief <b>Contains global includes and enumerations</b> \n
* This is an internal class.
*
* \date February 16, 2018
*/

#ifndef MQC_COMMON_H
#define MQC_COMMON_H

#include <cstdbool>

#if defined(WINDOWS)
#	include <stdint.h>
#else
#	include "inttypes.h"
#endif

/*! \enum mqc_status
* Contains state and error return codes
*/
typedef enum
{
	MQC_STATUS_FAILURE = 0,		/*!< signals operation failure */
	MQC_STATUS_SUCCESS = 1,		/*!< signals operation success */
	MQC_STATUS_AUTHFAIL = 2,	/*!< seed authentication failure */
	MQC_STATUS_RANDFAIL = 3,	/*!< system random failure */
	MQC_ERROR_INVALID = 4,		/*!< invalid parameter input */
	MQC_ERROR_INTERNAL = 5,		/*!< anonymous internal failure  */
	MQC_ERROR_KEYGEN = 6		/*!< key generation failure  */
} mqc_status;

#endif
