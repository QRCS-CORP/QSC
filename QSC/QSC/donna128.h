#ifndef QSC_DONNA128_H
#define QSC_DONNA128_H

#include "common.h"

/*!
* \struct uint128
* \brief The uint128 state structure
*/
QSC_EXPORT_API typedef struct
{
	uint64_t high;
	uint64_t low;
} uint128;

/**
* \brief Right shift a 128-bit integer
*
* \param x: The base integer
* \param shift: The shift position
* \return The shifted value
*/
QSC_EXPORT_API uint128 qsc_donna128_shift_right(const uint128* x, size_t shift);

/**
* \brief Left shift a 128-bit integer
*
* \param x: The base integer
* \param shift: The shift position
* \return The shifted value
*/
QSC_EXPORT_API uint128 qsc_donna128_shift_left(uint128* x, size_t shift);

/**
* \brief Bitwise AND the low part of a 128-bit integer
*
* \param x: The base integer
* \param mask: The AND mask
* \return The AND'd value
*/
QSC_EXPORT_API uint64_t qsc_donna128_andl(uint128* x, uint64_t mask);

/**
* \brief Bitwise AND the high part of a 128-bit integer
*
* \param x: The base integer
* \param mask: The AND mask
* \return The AND'd value
*/
QSC_EXPORT_API uint64_t qsc_donna128_andh(uint128* x, uint64_t mask);

/**
* \brief Add two 128-bit integers
*
* \param x: The first value to add
* \param y: The second value to add
* \return The sum value
*/
QSC_EXPORT_API uint128 qsc_donna128_add(const uint128* x, const uint128* y);

/**
* \brief Multiply a 128-bit integer by a 64-bit integer
*
* \param x: The first value to multiply
* \param y: The second value to multiply
* \return The sum value
*/
QSC_EXPORT_API uint128 qsc_donna128_multiply(uint128* x, uint64_t Y);

/**
* \brief Bitwise OR of two 128-bit integers
*
* \param x: The first value to OR
* \param y: The second value to OR
* \return The sum value
*/
QSC_EXPORT_API uint128 qsc_donna128_or(const uint128 * x, const uint128 * y);

#endif