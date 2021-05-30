/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Written by John G. Underhill
* Updated on November 11, 2020
* Contact: develop@vtdev.com */

#ifndef QSC_ASYNCRESULT_H
#define QSC_ASYNCRESULT_H

#include "common.h"
#include "ipinfo.h"
#include "socket.h"

/*! \struct qsc_async_result
* \brief Internal Async Results class
*/
typedef struct qsc_async_socket_result
{
	qsc_socket* source;	/*!< A pointer to the parent socket handle */
	uint32_t counter;	/*!< The instance counter */
} qsc_async_socket_result;

#endif