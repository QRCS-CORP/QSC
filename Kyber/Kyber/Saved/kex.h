#ifndef KEX_H
#define KEX_H

#include <stdint.h>
#include "params.h"
#include "api.h"

#define KYBER_UAKE_SENDABYTES (KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES)
#define KYBER_UAKE_SENDBBYTES (KYBER_CIPHERTEXTBYTES)
#define KYBER_AKE_SENDABYTES (KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES)
#define KYBER_AKE_SENDBBYTES (2*KYBER_CIPHERTEXTBYTES)

void kyber_uake_initA(uint8_t* send, uint8_t* tk, uint8_t* sk, const uint8_t* pkb);

void kyber_uake_sharedB(uint8_t* send, uint8_t* k, const uint8_t* recv, const uint8_t* skb);

void kyber_uake_sharedA(uint8_t* k, const uint8_t* recv, const uint8_t* tk, const uint8_t* sk);

void kyber_ake_initA(uint8_t* send, uint8_t* tk, uint8_t* sk, const uint8_t* pkb);

void kyber_ake_sharedB(uint8_t* send, uint8_t* k, const uint8_t* recv, const uint8_t* skb, const uint8_t* pka);

void kyber_ake_sharedA(uint8_t* k, const uint8_t* recv, const uint8_t* tk, const uint8_t* sk, const uint8_t* ska);

#endif
