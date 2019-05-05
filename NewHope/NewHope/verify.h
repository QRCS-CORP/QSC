#ifndef NEWHOPE_VERIFY_H
#define NEWHOPE_VERIFY_H

#include <stdint.h>

/**
* \brief Compare two arrays for equality
*
* \param a The first array
* \param b The second array
* \param len The number of bytes to compare
* \return returns 0 for equal strings, 1 for non-equal strings
*/
int32_t verify(const uint8_t* a, const uint8_t* b, size_t len);

/* b = 1 means mov, b = 0 means don't mov*/
/**
* \brief Conditional move function
*
* \param r The return array
* \param x The source array
* \param len The number of bytes to move
* \param The condition
*/
void cmov(uint8_t* r, const uint8_t* x, size_t len, uint8_t b);

#endif
