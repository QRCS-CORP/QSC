/**
* \file common.h
* \brief <b>Contains global includes and enumerations</b> \n
* This is an internal class.
*
* \date June 05, 2019
*/

#ifndef QSC_COMMON_H
#define QSC_COMMON_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

/* Do not modify values beyond this point */

/*!
\def QSC_STATUS_SUCCESS
* Function return value indicates successful operation
*/
static const int32_t QSC_STATUS_SUCCESS = 0;

/*!
\def QSC_STATUS_FAILURE
* Function return value indicates failed operation
*/
static const int32_t QSC_STATUS_FAILURE = -1;

/*!
\def QSC_ERROR_AUTHENTICATION
* Function return value indicates internal failure
*/
static const int32_t QSC_ERROR_INTERNAL = -2;

/*!
\def QSC_ERROR_AUTHENTICATION
* Function return value indicates authntication failure
*/
static const int32_t QSC_ERROR_AUTHENTICATION = -3;

/*!
\def QSC_ERROR_PROVIDER
* Function return value indicates a random provider failure
*/
static const int32_t QSC_ERROR_PROVIDER = -4;

#endif