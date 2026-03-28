OpenSSL-generated Stage 5 signer-wrapper interoperability fixtures.

These fixtures were generated with OpenSSL 3.x using P-256 keys and SHA-256.
They are used as input vectors for the managed signer-wrapper tests:
- root.cert.pem / root.key.pem: OpenSSL-generated issuer CA
- leaf.key.pem: OpenSSL-generated leaf private key used by QSC signer-wrapper CSR and certificate tests
- leaf.openssl.csr.pem: OpenSSL reference CSR built from the leaf key
- leaf.openssl.cert.pem: OpenSSL reference leaf certificate signed by the root CA
- leaf.openssl.ca.cert.pem: OpenSSL CA-database-issued leaf certificate used for CRL revocation reference
- root.openssl.crl.pem: OpenSSL-generated CRL reference issued by the root CA
- trust_roots.pem: trust-anchor bundle for root.cert.pem
