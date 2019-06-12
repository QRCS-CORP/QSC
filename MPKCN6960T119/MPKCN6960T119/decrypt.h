/*
  This file is for Nieddereiter decryption
*/

#ifndef DECRYPT_H
#define DECRYPT_H

#include "common.h"

/* Nieddereiter decryption with the Berlekamp decoder */
/* input: sk, secret key */
/* input ciphertext: c */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
int32_t decrypt(uint8_t* e, const uint8_t* sk, const uint8_t* c);

#endif

