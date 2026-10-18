# socialweb/http-message-signatures Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - TBD

### Added

- `Signer` and `Verifier`, which sign and verify HTTP requests and responses as HTTP Message Signatures of RFC 9421 and in the form of draft-cavage-http-signatures-12. The verifier tells the two forms apart, never throws because of what a message contains, and tries a draft-form `(request-target)` once more without its query string.
- `SigningOptions`, `VerifierOptions`, and `TimePolicy`, which choose what a signature covers and what a verifier requires and accepts, and the enum `Form`.
- `SigningKey` and `VerificationKey`, built from PEM or a shared secret, with the enums `KeyType` and `Algorithm`: RSASSA-PKCS1-v1_5 with SHA-256, RSASSA-PSS with SHA-512, ECDSA on P-256 and P-384, Ed25519, and HMAC with SHA-256.
- `KeyResolver`, the interface through which the verifier gets the key a signature names, and refreshes it once after a failure a rotated key could explain.
- `VerificationResult`, with a `FailureReason` case and a detail for every failure, and what a replay store needs.
- The `Content-Digest` field of RFC 9530 and the `Digest` field of RFC 3230, computed when signing and checked when verifying, with the enum `DigestAlgorithm`.
- Exceptions under `SocialWeb\Http\MessageSignatures\Exception`, every one implementing the `MessageSignaturesException` marker interface: `InvalidArgument` and `SigningFailed`.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- Nothing.
