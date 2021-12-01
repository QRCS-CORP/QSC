/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef QSC_SECMEM_H
#define QSC_SECMEM_H

#include "common.h"

/*
* \file secmem.h
* \brief Contains secure memory locking functions
*/

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/**
* \brief Allocate a block of secure memory
*
* \param length: The length in bytes of the allocation request
* \return Returns a pointer to a block of secure memory
*/
QSC_EXPORT_API uint8_t* qsc_secmem_alloc(size_t length);

/**
* \brief Erase a byte length of secure memory
*
* \param block: The pointer to the memory to erase
* \param length: The number of bytes to erase
*/
QSC_EXPORT_API void qsc_secmem_erase(uint8_t* block, size_t length);

/**
* \brief Erase and free a block of secure memory
*
* \param block: The pointer to the memory to be freed
* \param length: The number of bytes in the block
*/
QSC_EXPORT_API void qsc_secmem_free(uint8_t* block, size_t length);

/**
* \brief Returns the internal memory page size.
* Large allocations should be paged on memory boundaries
*
* \return Returns the system memory page boundary size
*/
QSC_EXPORT_API size_t qsc_secmem_page_size();

#endif
