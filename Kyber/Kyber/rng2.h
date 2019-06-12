//
//  rng.h
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#ifndef rng2_h
#define rng2_h

#include <stdint.h>
#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct 
{
    uint8_t Key[32];
    uint8_t V[16];
    int reseed_counter;
} AES256_CTR_DRBG_struct2;


void
AES256_CTR_DRBG_Update2(uint8_t *provided_data,
                       uint8_t *Key,
                       uint8_t *V);

void
randombytes2_init(uint8_t *entropy_input,
                 uint8_t *personalization_string,
                 int security_strength);

int
randombytes2(uint8_t *x, unsigned long long xlen);

#endif /* rng_h */
