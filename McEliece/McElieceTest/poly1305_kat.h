#ifndef POLY1305KAT_H
#define POLY1305KAT_H

#include "common.h"
/**
* \file poly1305_kat.h
* \brief <b>Poly1305 Known Answer Tests</b> \n
* ChaChaP20 known answer comparison (KAT) tests. \n
* Test vectors from the official ChaCha implementation. \n
* \author John Underhill \n
* \date April 04, 2018
*/

/**
* \brief Tests the Poly1305 implementation.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* RFC7539: <a href="https://tools.ietf.org/html/rfc7539">7539</a>ChaCha20 and Poly1305 for IETF Protocols.</a>
*/
bool poly1305_kat_test();

#endif