#ifndef NEWHOPE_REDUCE_H
#define NEWHOPE_REDUCE_H

#include <stdint.h>

/**
* \brief Montgomery reduction; given a 32-bit integer a, computes
*  16-bit integer congruent to a * R^-1 mod q, 
*  where R=2^18 (see value of rlog)
*
* \param input unsigned integer to be reduced; has to be in {0,...,1073491968}
* \return unsigned integer in {0,...,2^14-1} congruent to a * R^-1 modulo q
*/
uint16_t montgomery_reduce(uint32_t a);

#endif
