# Copied keys and signed requests

The files in these directories are test keys and signed requests copied from the specifications the package implements and from another implementation's test suite, kept so that the tests check the package against values it did not produce. They are not part of the library, and they are left out of distribution archives.

| Directory | Source | License |
| --- | --- | --- |
| `rfc9421/` | [RFC 9421, HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421), appendix B.1: the test keys, transcribed from the RFC's text. The RFC says these keys MUST NOT be used for any purpose other than testing | [IETF Trust Legal Provisions][tlp] |
| `cavage/` | [draft-cavage-http-signatures-12, Signing HTTP Messages](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12), appendix C: the RSA key pair whose `keyId` is `Test`, transcribed from the Cavage draft's text | [IETF Trust Legal Provisions][tlp] |
| `fedify/` | Signed requests from the test suite of [Fedify](https://github.com/fedify-dev/fedify) at commit `f56118e197798465021d622a2177ec8c017df073`, each with the public key of its signer | MIT License, in `fedify/LICENSE` |

[`manifest.json`](manifest.json) records the rest for each set: the source's URL and title, its copyright line, the license, the date the files were copied, the commit or the appendix sections they come from, and one SHA-256 checksum for the whole set.

None of these sets is a conformance suite, so no license here restricts changes to material used for a conformance claim. The files are kept as they were copied so that the tests check the sources' own values.

## The RFC 9421 keys

Each PEM file starts with a comment line that names its appendix section, which OpenSSL ignores; the rest is the RFC's text.

| File | Section | Key |
| --- | --- | --- |
| `test-key-rsa.public.pem`, `test-key-rsa.private.pem` | B.1.1 | `test-key-rsa`, 2048-bit RSA in PKCS#1 form |
| `test-key-rsa-pss.public.pem`, `test-key-rsa-pss.private.pem` | B.1.2 | `test-key-rsa-pss`, 2048-bit RSA; the private key is PKCS#8 with the id-RSASSA-PSS algorithm identifier |
| `test-key-ecc-p256.public.pem`, `test-key-ecc-p256.private.pem` | B.1.3 | `test-key-ecc-p256`, P-256 |
| `test-key-ed25519.public.pem`, `test-key-ed25519.private.pem` | B.1.4 | `test-key-ed25519` |
| `test-shared-secret.base64` | B.1.5 | `test-shared-secret`, 64 bytes, Base64 on one line |

## The Cavage draft's key pair

`test-key.public.pem` and `test-key.private.pem` are the RSA key pair of the Cavage draft's appendix C. Cavage calls it a 2048-bit key; it is 1024 bits. Each file starts with a comment line that names its source, which OpenSSL ignores. `Cavage\ExamplesTest` holds the appendix's request and its C.1 and C.2 signatures, which verify and which the signer reproduces byte for byte. C.3 is not used: it lists `(created)` and `(expires)` under `rsa-sha256`, which the Cavage draft's section 2.3 forbids, and its signature is over a string without them.

## The Fedify requests

Each JSON file records its `source`, the clock `currentTime` its test verifies at, the `method`, `url`, `headers` in order, and `body` exactly as the source gives them, and the `keyFile` of the signer's public key, which comes from the fixture the source names.

| File | Source | Signature |
| --- | --- | --- |
| `verify-request.json` | `packages/fedify/src/sig/http.test.ts`, lines 84 to 108 | No `algorithm`; a lowercase `sha-256` token in `Digest`; no `Host` field, which the request's URL gives |
| `oeee-cafe-hs2019.json` | `packages/fedify/src/sig/http.test.ts`, lines 260 to 277 | `hs2019` from an RSA key; `created` and `expires` quoted and covered with `Date` |
| `tootik-follow.json` | `packages/fedify/test-vectors/fep-ef61/tootik-v0.25.4/follow/` | `rsa-sha256` as tootik 0.25.4 sent it; a port in `host` |
| `tootik-send.json` | `packages/fedify/test-vectors/fep-ef61/tootik-v0.25.4/send/` | `rsa-sha256` from a 4096-bit key, as Fedify sent it |

## Checking the files

Run this from the root of the repository:

```bash
composer check-fixtures
```

It makes the checksum of each set again and compares it with the one in the manifest. A job in the continuous integration workflow runs the same check on every pull request and push to the main branch.

A checksum that differs from the one in the manifest means that a file has changed since it was copied. If this happens, restore the file from its source. Do not record a new checksum unless a file is being added or corrected on purpose, and say so in the commit.

## How the checksums are made

Each checksum is one SHA-256 value that covers a whole set of files. It changes if the content of any file changes, if a file is renamed, or if a file is added to or removed from the directory.

It is made in four steps:

1. List every file in the set's directory, by its path from that directory, with `./` in front.
2. Sort the paths byte by byte (`LC_ALL=C`), so that the order is the same on every system.
3. Compute the SHA-256 of each file, which gives one line for each file: the value, two spaces, and the path.
4. Compute the SHA-256 of those lines. That value is the checksum.

`bin/check-fixtures.php` does this in PHP. The same checksum can be made without it. For `rfc9421/`:

```bash
(cd resources/rfc9421 && find . -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256)
```

The command prints the checksum, followed by two spaces and a hyphen.

[tlp]: https://trustee.ietf.org/documents/trust-legal-provisions/
