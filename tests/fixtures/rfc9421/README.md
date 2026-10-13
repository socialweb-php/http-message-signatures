# RFC 9421 appendix B.1 keys

The test keys of RFC 9421, appendix B.1, transcribed from the RFC's text. Each PEM file starts with a comment line naming its appendix section, which OpenSSL ignores. The RFC says these keys MUST NOT be used for any purpose other than testing.

| File | Section | Key |
| --- | --- | --- |
| `test-key-rsa.public.pem`, `test-key-rsa.private.pem` | B.1.1 | `test-key-rsa`, 2048-bit RSA in PKCS#1 form |
| `test-key-rsa-pss.public.pem`, `test-key-rsa-pss.private.pem` | B.1.2 | `test-key-rsa-pss`, 2048-bit RSA; the private key is PKCS#8 with the id-RSASSA-PSS algorithm identifier |
| `test-key-ecc-p256.public.pem`, `test-key-ecc-p256.private.pem` | B.1.3 | `test-key-ecc-p256`, P-256 |
| `test-key-ed25519.public.pem`, `test-key-ed25519.private.pem` | B.1.4 | `test-key-ed25519` |
| `test-shared-secret.base64` | B.1.5 | `test-shared-secret`, 64 bytes, Base64 on one line |
