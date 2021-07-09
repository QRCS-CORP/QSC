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
*
*
* Implementation Details:
* An implementation of a memory related functions utility class
* Written by John G. Underhill
* Updated on August 20, 2020
* Contact: support@vtdev.com 
*/

/*
* \file memutils.h
* \brief <b>Memory utilities</b> \n
* This file contains common memory functions
* December 20, 2019
*/

#ifndef QSC_MEMUTILS_H
#define QSC_MEMUTILS_H

#include "common.h"

/**
* \brief Prefetch memory to L1 cache
*
* \param address: The array memory address
* \param length: The number of bytes to prefetch
*/
QSC_EXPORT_API void qsc_memutils_prefetch_l1(uint8_t* address, size_t length);

/**
* \brief Prefetch memory to L2 cache
*
* \param address: The array memory address
* \param length: The number of bytes to prefetch
*/
QSC_EXPORT_API void qsc_memutils_prefetch_l2(uint8_t* address, size_t length);

/**
* \brief Prefetch memory to L3 cache
*
* \param address: The array memory address
* \param length: The number of bytes to prefetch
*/
QSC_EXPORT_API void qsc_memutils_prefetch_l3(uint8_t* address, size_t length);

/**
* \brief Allocate an aligned 8-bit integer array
*
* \param align: The memory alignment boundary
* \param length: The length of the requested block
*
* \return Returns the aligned array of bytes, or NULL on failure
*/
QSC_EXPORT_API void* qsc_memutils_aligned_alloc(int32_t align, size_t length);

/**
* \brief Free an aligned memory block created with aligned_alloc
*
* \param block: A pointer to the memory block to release
*/
QSC_EXPORT_API void qsc_memutils_aligned_free(void* block);

/**
* \brief Erase a block of memory
*
* \param output: A pointer to the memory block to erase
* \param length: The number of bytes to erase
*/
QSC_EXPORT_API void qsc_memutils_clear(void* output, size_t length);

/**
* \brief Copy a block of memory
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to copy
*/
QSC_EXPORT_API void qsc_memutils_copy(void* output, const void* input, size_t length);

/**
* \brief Set a block of memory to a value
*
* \param output: A pointer to the destination array
* \param length: The number of bytes to change
* \param value: The value to set each byte
*/
QSC_EXPORT_API void qsc_memutils_setvalue(void* output, size_t length, uint8_t value);

/**
* \brief Bitwise XOR a block of memory
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to XOR
*/
QSC_EXPORT_API void qsc_memutils_xor(uint8_t* output, const uint8_t* input, size_t length);

/**
* \brief Bitwise XOR a block of memory to a byte value
*
* \param output: A pointer to the destination array
* \param input: A byte value
* \param length: The number of bytes to XOR
*/
QSC_EXPORT_API void qsc_memutils_xorv(uint8_t* output, const uint8_t value, size_t length);

#endif
