#ifndef QCC_COMMON_H
#define QCC_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*! \enum mqc_status
* Contains state and error return codes
*/
typedef enum
{
	MQC_STATUS_FAILURE = -1,		/*!< signals operation failure */
	MQC_STATUS_SUCCESS = 0,		/*!< signals operation success */
	MQC_STATUS_AUTHFAIL = -2,	/*!< seed authentication failure */
	MQC_STATUS_RANDFAIL = -3,	/*!< system random failure */
	MQC_ERROR_INVALID = -4,		/*!< invalid parameter input */
	MQC_ERROR_INTERNAL = -5,		/*!< anonymous internal failure  */
	MQC_ERROR_KEYGEN = -6		/*!< key generation failure  */
} mqc_status;

#endif
