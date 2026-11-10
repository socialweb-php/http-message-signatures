# socialweb/http-message-signatures Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `VerificationResult::$maxSignaturesExceeded`, which is `true` when a message has more RFC 9421 labels than the verifier's `maxSignatures`. The labels beyond the limit are not tried, as before; the result now says so, whether or not a signature within the limit verified.
- `HashAlgorithm::Sha384` and `HashAlgorithm::isDigestFieldAlgorithm()`. The registries of the `Content-Digest` and `Digest` fields have no SHA-384, so `SigningOptions` refuses `Sha384` among its `digestAlgorithms`, `HashAlgorithm::rfc3230Token()` throws `InvalidArgument` for it, and a `sha-384` entry of a digest field is not read.
- `SigningFailedReason`, a pure enum with the cases `OpenSslError` and `SignatureDoesNotFitCurve`, and `SigningFailed::$reason`, which holds the case for the failure.
- `KeyLookup` and `VerificationResult` accept any `DateTimeInterface` for `created` and `expires`, and keep a `DateTimeImmutable` copy.

### Changed

- `Verifier` takes its settings as named constructor parameters after the resolver and the clock: `forms`, `clockSkew`, `defaultLifetime`, `maximumLifetime`, `requireTarget`, `requireCreationTime`, `requireContentDigest`, `requiredComponents`, `requireNonce`, `retryWithRefreshedKey`, `acceptRequestTargetWithoutQuery`, and `maxSignatures`, each with the default it had in `VerifierOptions` or `TimePolicy`. `new Verifier($resolver, $clock, new VerifierOptions(requireNonce: true))` becomes `new Verifier($resolver, $clock, requireNonce: true)`.
- `DigestAlgorithm` is `HashAlgorithm`, with the cases and values the other socialweb packages give the enum of that name.
- `KeyType` is `SigningKeyType`, so that it is not taken for the `kty` member of a JSON Web Key.
- `Form` is a pure enum. `Form::Cavage->value` and `Form::from()` are gone, and exception messages and result details name a form by its case, `Cavage` or `Rfc9421`.
- `SigningOptions::$form` defaults to `Form::Rfc9421`, so `new SigningOptions()` signs in the RFC 9421 form.
- The `SigningFailed` constructor takes a `SigningFailedReason` first, then the message, then an optional previous throwable. It took a message, a code, and an optional previous throwable, so code that constructs the exception itself must pass a reason.
- `InvalidArgument` messages put a covered component identifier, an EC curve name, and a field name in double quotes, and name a digest algorithm by its case, as in `Digest algorithm Sha256 appears more than once`.

### Removed

- `VerifierOptions` and `TimePolicy`. Their settings are parameters of the `Verifier` constructor.

### Fixed

- The package empties the OpenSSL error queue before each call it makes to OpenSSL, so an error message reports the errors of the call that failed and none that an earlier call left behind.

## [0.2.1] - 2026-11-01

### Fixed

- `VerificationKey::fromJwk()` refuses an empty list of permitted algorithms, or a list that names the key's `alg` more than once, as `fromPem()` and `fromSharedSecret()` refuse them.

## [0.2.0] - 2026-11-01

### Added

- `VerificationKey::fromJwk()`, which builds a verification key from a JSON Web Key of RFC 7517 read by the `socialweb/jwk` package, now a suggested dependency. An `RSA`, `EC`, or `OKP` key becomes a public key and an `oct` key a shared secret; a key with `alg` permits that algorithm alone; a key with private members, or one whose `use` or `key_ops` excludes verifying, is refused.

## [0.1.0] - 2026-10-24

### Added

- `Signer` and `Verifier`, which sign and verify HTTP requests and responses as HTTP Message Signatures of RFC 9421 and in the form of draft-cavage-http-signatures-12. The verifier tells the two forms apart, never throws because of what a message contains, and tries a draft-form `(request-target)` once more without its query string.
- `SigningOptions`, `VerifierOptions`, and `TimePolicy`, which choose what a signature covers and what a verifier requires and accepts, and the enum `Form`.
- `SigningKey` and `VerificationKey`, built from PEM or a shared secret, with the enums `KeyType` and `Algorithm`: RSASSA-PKCS1-v1_5 with SHA-256, RSASSA-PSS with SHA-512, ECDSA on P-256 and P-384, Ed25519, and HMAC with SHA-256. A verification key may name its owner, the identity the resolver says it belongs to.
- `KeyResolver`, the interface through which the verifier gets the key a signature names, and refreshes it once after a failure a rotated key could explain. The resolver receives a `KeyLookup`.
- `KeyLookup`, what the verifier hands the resolver: the message, the request it answers, the form, the key identifier, and the parameters of the signature that the verifier reads.
- `VerificationResult`, with a `FailureReason` case and a detail for every failure, what a replay store needs, and `keyOwner`, the owner of the key that verified the signature.
- The `Content-Digest` field of RFC 9530 and the `Digest` field of RFC 3230, computed when signing and checked when verifying, with the enum `DigestAlgorithm`.
- Exceptions under `SocialWeb\Http\MessageSignatures\Exception`, every one implementing the `MessageSignaturesException` marker interface: `InvalidArgument` and `SigningFailed`.

[unreleased]: https://github.com/socialweb-php/http-message-signatures/compare/0.2.1...HEAD
[0.2.1]: https://github.com/socialweb-php/http-message-signatures/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/socialweb-php/http-message-signatures/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/socialweb-php/http-message-signatures/commits/0.1.0/
