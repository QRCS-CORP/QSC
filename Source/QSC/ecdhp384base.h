#ifndef QSC_ECDHP384BASE_H
#define QSC_ECDHP384BASE_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

#define QSC_ECDHP384_PUBLICKEY_SIZE 96U
#define QSC_ECDHP384_PRIVATEKEY_SIZE 48U
#define QSC_ECDHP384_SHAREDSECRET_SIZE 48U
#define QSC_ECDHP384_SEED_SIZE 48U

QSC_EXPORT_API void qsc_p384_public_from_private(uint8_t* publickey, const uint8_t* privatekey);
QSC_EXPORT_API void qsc_p384_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));
QSC_EXPORT_API void qsc_p384_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);
QSC_EXPORT_API bool qsc_p384_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

QSC_CPLUSPLUS_ENABLED_END

#endif
