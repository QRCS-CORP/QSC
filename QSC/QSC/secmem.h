/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
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
