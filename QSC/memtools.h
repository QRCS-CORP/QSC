/*
* \file intutils.h
* \brief <b>Integer utilities</b> \n
* This file contains common integer functions
* August 7, 2019
*/

#ifndef QSC_MEMORYTOOLS_H
#define QSC_MEMORYTOOLS_H

#include "common.h"
#include <stdlib.h>
#include <string.h>

#define CACHE_ALIGNMENT 64

void* aligned_malloc(size_t length)
{
	void* mem = malloc(length + CACHE_ALIGNMENT + sizeof(void*));
	void** ptr = (void**)((uintptr_t)((uintptr_t*)mem + CACHE_ALIGNMENT + sizeof(void*)) & ~(CACHE_ALIGNMENT - 1));
	ptr[-1] = mem;

	return ptr;
}

void aligned_free(void* ptr)
{
	free(((void**)ptr)[-1]);
}

#endif

/*
// saved
static void rhx_decrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input)
{
	const size_t RNDCNT = state->rndkeylen - 2;
	uint8x16_t x;
	size_t keyctr;

	keyctr = 0;
	x = vld1q_u8(input);

	while (keyctr != RNDCNT)
	{
		x = vaesimcq_u8(vaesdq_u8(x, state->roundkeys[keyctr]));
		++keyctr;
	}

	x = veorq_u8(vaesdq_u8(x, state->roundkeys[keyctr]), state->roundkeys[keyctr + 1]);
	vst1q_u8(output, x);
}

static void rhx_encrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input)
{
	const size_t RNDCNT = state->rndkeylen - 2;
	uint8x16_t x;
	size_t keyctr;

	keyctr = 0;
	x = vld1q_u8(input);

	while (keyctr != RNDCNT)
	{
		x = vaesmcq_u8(vaeseq_u8(x, state->roundkeys[keyctr]));
		++keyctr;
	}

	x = veorq_u8(vaeseq_u8(x, state->roundkeys[keyctr]), state->roundkeys[keyctr + 1]);
	vst1q_u8(output, x);
}

*/
