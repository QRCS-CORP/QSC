#ifndef QSCTEST_X509_TEST_HELPER_H
#define QSCTEST_X509_TEST_HELPER_H

#include "qsccommon.h"
#include "asn1.h"

/**
 * \brief Reads a text file into a dynamically allocated buffer.
 *
 * \details
 * This function loads the contents of a text file from disk into a heap-allocated
 * buffer. It is primarily used by X.509 test routines to load PEM-encoded objects
 * such as certificates, CSRs, CRLs, and keys. The returned buffer is null-terminated
 * for convenience when handling textual PEM data.
 *
 * \param path: [const char*] Path to the file on disk.
 * \param len: [size_t*] Receives the length of the file in bytes (excluding any null terminator).
 *
 * \return
 * Pointer to the allocated buffer containing the file contents, or NULL on failure.
 * The caller is responsible for freeing the returned buffer.
 */
char* qsctest_x509_read_text_file(const char* path, size_t* len);

/**
 * \brief Reads a binary file into a dynamically allocated buffer.
 *
 * \details
 * This function loads the contents of a binary file into a heap-allocated buffer.
 * It is used by test routines for DER-encoded objects or other binary test inputs.
 * The buffer contains the raw file data with no modification.
 *
 * \param path: [const char*] Path to the file on disk.
 * \param len: [size_t*] Receives the length of the file in bytes.
 *
 * \return
 * Pointer to the allocated buffer containing the file contents, or NULL on failure.
 * The caller is responsible for freeing the returned buffer.
 */
uint8_t* qsctest_x509_read_binary_file(const char* path, size_t* len);

/**
 * \brief Retrieves the current system time as an ASN.1 time structure.
 *
 * \details
 * This function populates a qsc_asn1_time structure with the current system time.
 * It is used by X.509 verification tests to evaluate certificate validity periods
 * against the current time. The resulting structure is suitable for use with
 * UTCTime or GeneralizedTime comparisons within the ASN.1/X.509 framework.
 *
 * \param t: [qsc_asn1_time*] Pointer to the time structure to be populated.
 */
void qsctest_x509_current_time(qsc_asn1_time* t);

#endif