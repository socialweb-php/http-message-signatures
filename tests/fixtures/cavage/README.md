# Fixtures of the draft form

## draft-cavage-http-signatures-12 appendix C

`test-key.public.pem` and `test-key.private.pem` are the RSA key pair of the draft's appendix C, transcribed from its text, with `keyId="Test"`. The draft calls it a 2048-bit key; it is 1024 bits. Each file starts with a comment line naming its source, which OpenSSL ignores. `Cavage\ExamplesTest` holds the appendix's request and its C.1 and C.2 signatures, which verify and which the signer reproduces byte for byte. C.3 is not used: it lists `(created)` and `(expires)` under `rsa-sha256`, which the draft's section 2.3 forbids, and its signature is over a string without them.

## Fedify

The files under `fedify/` are signed requests from the test suite of Fedify, https://github.com/fedify-dev/fedify, at commit `f56118e197798465021d622a2177ec8c017df073`, distributed under the MIT license in `fedify/LICENSE`. Each JSON file records its `source`, the clock `currentTime` its test verifies at, the `method`, `url`, `headers` in order, and `body` exactly as the source gives them, and the `keyFile` of the signer's public key, which comes from the fixture the source names.

| File | Source | Signature |
| --- | --- | --- |
| `verify-request.json` | `packages/fedify/src/sig/http.test.ts`, lines 84 to 108 | No `algorithm`; a lowercase `sha-256` token in `Digest`; no `Host` field, which the request's URL gives |
| `oeee-cafe-hs2019.json` | `packages/fedify/src/sig/http.test.ts`, lines 260 to 277 | `hs2019` from an RSA key; `created` and `expires` quoted and covered with `Date` |
| `tootik-follow.json` | `packages/fedify/test-vectors/fep-ef61/tootik-v0.25.4/follow/` | `rsa-sha256` as tootik 0.25.4 sent it; a port in `host` |
| `tootik-send.json` | `packages/fedify/test-vectors/fep-ef61/tootik-v0.25.4/send/` | `rsa-sha256` from a 4096-bit key, as Fedify sent it |
