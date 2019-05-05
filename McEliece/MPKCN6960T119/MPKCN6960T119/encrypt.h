/*
  This file is for Nieddereiter encryption
*/

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "common.h"

/* Nieddereiter encryption with the Berlekamp decoder */
/* output: c, ciphertext */
/* input public key: pk */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
void encrypt(uint8_t* c, const uint8_t* pk, uint8_t* e);

#endif

