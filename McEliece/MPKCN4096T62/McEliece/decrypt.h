#ifndef DECRYPT_H
#define DECRYPT_H

#include "common.h"
#include "params.h"

mqc_status decrypt(uint8_t* e, const uint8_t* sk, const uint8_t* s);

#endif
