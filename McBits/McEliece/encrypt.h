/*
  This file is for Nieddereiter encryption
*/

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "common.h"
#include "params.h"

mqc_status encrypt(uint8_t* s, uint8_t* e, const uint8_t* pk);

#endif
