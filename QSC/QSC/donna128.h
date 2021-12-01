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

#ifndef QSC_DONNA128_H
#define QSC_DONNA128_H

#include "common.h"

/*
* \file donna128.h
* \brief Donna function definitions
*/

/*!
* \struct uint128
* \brief The uint128 state structure
*/
QSC_EXPORT_API typedef struct
{
	uint64_t high;	/*!< The high order bits */
	uint64_t low;	/*!< The low order bits */
} uint128;

/**
* \brief Right shift a 128-bit integer
*
* \param x: [const] The base integer
* \param shift: The shift position
* \return The shifted value
*/
QSC_EXPORT_API uint128 qsc_donna128_shift_right(const uint128* x, size_t shift);

/**
* \brief Left shift a 128-bit integer
*
* \param x: [const] The base integer
* \param shift: The shift position
* \return The shifted value
*/
QSC_EXPORT_API uint128 qsc_donna128_shift_left(const uint128* x, size_t shift);

/**
* \brief Bitwise AND the low part of a 128-bit integer
*
* \param x: [const] The base integer
* \param mask: The AND mask
* \return The AND'd value
*/
QSC_EXPORT_API uint64_t qsc_donna128_andl(const uint128* x, uint64_t mask);

/**
* \brief Bitwise AND the high part of a 128-bit integer
*
* \param x: [const] The base integer
* \param mask: The AND mask
* \return The AND'd value
*/
QSC_EXPORT_API uint64_t qsc_donna128_andh(const uint128* x, uint64_t mask);

/**
* \brief Add two 128-bit integers
*
* \param x: [const] The first value to add
* \param y: [const] The second value to add
* \return The sum value
*/
QSC_EXPORT_API uint128 qsc_donna128_add(const uint128* x, const uint128* y);

/**
* \brief Multiply a 128-bit integer by a 64-bit integer
*
* \param x: [const] The first value to multiply
* \param y: The second value to multiply
* \return The sum value
*/
QSC_EXPORT_API uint128 qsc_donna128_multiply(const uint128* x, uint64_t y);

/**
* \brief Bitwise OR of two 128-bit integers
*
* \param x: [const] The first value to OR
* \param y: The second value to OR
* \return The sum value
*/
QSC_EXPORT_API uint128 qsc_donna128_or(const uint128* x, const uint128* y);

#endif
