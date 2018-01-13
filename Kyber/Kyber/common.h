/**
* \file common.h
* \brief <b>Contains global includes and enumerations</b> \n
* This is an internal class.
*
* \date January 13, 2018
*/

#ifndef KYBER_COMMON_H
#define KYBER_COMMON_H

#include <stdint.h>

/*! \enum kyber_status
* Contains Kyber state and error return codes
*/
typedef enum
{
	KYBER_STATE_FAILURE = 0,	/*!< signals operation failure */
	KYBER_STATE_SUCCESS = 1,	/*!< signals operation success */
	KYBER_ERROR_AUTHFAIL = 2,	/*!< seed authentication failure */
	KYBER_ERROR_RANDFAIL = 3,	/*!< system random failure */
	KYBER_ERROR_INVALID = 4,	/*!< invalid parameter input */
	KYBER_ERROR_INTERNAL = 5	/*!< anonymous internal failure  */
}
kyber_status;

#endif
