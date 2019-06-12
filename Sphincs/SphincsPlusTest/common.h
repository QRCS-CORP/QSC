/**
* \file common.h
* \brief <b>Contains global includes and enumerations</b> \n
* This is an internal class.
*
* \date October 25, 2018
*/

#ifndef QCCTEST_COMMON_H
#define QCCTEST_COMMON_H

/*lint -e686 */		/* warns that MS and VS external errors are muted */
/*lint -e766 */		/* bogus unused header, informational */

#include <cstdbool>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WINDOWS)
#	include <stdint.h>
#else
#	include "inttypes.h"
#endif

#endif