<h1 align="center">socialweb/http-message-signatures</h1>

<p align="center">
    <a href="https://github.com/socialweb-php/http-message-signatures"><img src="https://img.shields.io/badge/source-socialweb/http--message--signatures-blue.svg?style=flat-square" alt="Source Code"></a>
    <a href="https://packagist.org/packages/socialweb/http-message-signatures"><img src="https://img.shields.io/packagist/v/socialweb/http-message-signatures.svg?style=flat-square&label=release" alt="Download Package"></a>
    <a href="https://php.net"><img src="https://img.shields.io/packagist/php-v/socialweb/http-message-signatures.svg?style=flat-square&colorB=%238892BF" alt="PHP Programming Language"></a>
    <a href="https://github.com/socialweb-php/http-message-signatures/blob/main/COPYING.LESSER"><img src="https://img.shields.io/packagist/l/socialweb/http-message-signatures.svg?style=flat-square&colorB=darkcyan" alt="Read License"></a>
    <a href="https://github.com/socialweb-php/http-message-signatures/actions/workflows/continuous-integration.yml"><img src="https://img.shields.io/github/actions/workflow/status/socialweb-php/http-message-signatures/continuous-integration.yml?branch=main&style=flat-square&logo=github" alt="Build Status"></a>
    <a href="https://codecov.io/gh/socialweb-php/http-message-signatures"><img src="https://img.shields.io/codecov/c/gh/socialweb-php/http-message-signatures?label=codecov&logo=codecov&style=flat-square" alt="Codecov Code Coverage"></a>
</p>

## About

socialweb/http-message-signatures signs and verifies HTTP messages in two
forms behind one interface:

- HTTP Message Signatures as published in [RFC 9421][rfc9421], and
- the form of the expired Internet-Draft
  [draft-cavage-http-signatures-12][cavage], which many implementations still
  send and accept.

It signs and verifies requests and responses, computes and checks the body
digest fields that bind a signature to the content, `Content-Digest` of
[RFC 9530][rfc9530] and `Digest` of [RFC 3230][rfc3230], and supports every
algorithm of the RFC 9421 registry: RSASSA-PKCS1-v1_5 and RSASSA-PSS, ECDSA on
P-256 and P-384, Ed25519, and HMAC with SHA-256. It works on any
[PSR-7][psr-7] message, takes the time from a [PSR-20][psr-20] clock, and never
sends or fetches anything: keys come from a resolver that you write.

The verifier tells the two forms apart from the fields of the message. It
never throws because of what a message contains, only for a body it cannot
rewind; it returns a result that says whether the signature verified and, when
it did not, a reason and a detail. It does bounded work on untrusted input,
compares signatures and digests in constant time, and looks up a key only after
everything that needs no key has passed.

Not included: the `Accept-Signature` field, replay protection, fetching and
caching keys, sending requests, trailer fields, the JSON Web Signature
algorithms, signing into the `Authorization` field, signing a draft-form
`(request-target)` without its query string, the `Want-Digest`,
`Want-Content-Digest`, and `Repr-Digest` fields, and middleware for any
framework.

This project adheres to a [code of conduct](CODE_OF_CONDUCT.md).
By participating in this project and its community, you are expected to
uphold this code.

## Installation

Install this package as a dependency using [Composer](https://getcomposer.org).

``` bash
composer require socialweb/http-message-signatures
```

## Usage

The examples use [nyholm/psr7][nyholm] for the messages; any PSR-7
implementation works. Each needs a PSR-20 clock, which can be as small as this:

``` php
use Psr\Clock\ClockInterface;

$clock = new class implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
};
```

### Signing a request in both forms with one key

`Signer::sign()` returns the message it was given, with the signature fields
of the chosen form added, a `Date` field added when the message has none, and
the digest field added when the message has content. Signing is a pure
function of its arguments and the clock, so the same request can be signed in
each form, for a receiver that accepts only one of them.

``` php
use Nyholm\Psr7\Request;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\Signer;
use SocialWeb\Http\MessageSignatures\SigningKey;
use SocialWeb\Http\MessageSignatures\SigningOptions;

$key = SigningKey::fromPem('https://example.com/keys/1', $privateKeyPem);
$signer = new Signer($clock);

$request = new Request(
    'POST',
    'https://example.org/inbox',
    ['Content-Type' => 'application/json'],
    '{"hello": "world"}',
);

$signed = $signer->sign($request, $key, new SigningOptions(form: Form::Rfc9421));
$legacy = $signer->sign($request, $key, new SigningOptions(form: Form::Cavage));

echo $signed->getHeaderLine('Signature-Input'), "\n";
echo $legacy->getHeaderLine('Signature'), "\n";
```

With an RSA key, this prints a `Signature-Input` field and a draft-form
`Signature` field like these, with the creation time and the signature of the
moment:

``` text
sig1=("@method" "@target-uri" "host" "date" "content-digest");created=1792108800;alg="rsa-v1_5-sha256";keyid="https://example.com/keys/1"
keyId="https://example.com/keys/1",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="..."
```

`SigningOptions` chooses the covered components, the algorithm, the RFC 9421
label, the expiry, the nonce and tag of RFC 9421, and the digest algorithms;
each has a default. The key's algorithm is the first one it permits that has
a name in the form, so an RSA key signs with RSASSA-PKCS1-v1_5 and SHA-256 by
default.

### Verifying with a resolver that holds keys in an array

`Verifier` asks a `KeyResolver` for the key that a signature names. The
resolver is where key policy belongs: it may refuse keys below a size, keys
from an origin it does not trust, or keys that have been revoked, by returning
`null` or throwing. Anything it throws passes through `verify()` unchanged.

``` php
use SocialWeb\Http\MessageSignatures\KeyResolver;
use SocialWeb\Http\MessageSignatures\VerificationKey;
use SocialWeb\Http\MessageSignatures\Verifier;

final class ArrayKeyResolver implements KeyResolver
{
    /**
     * @param array<string, VerificationKey> $keys
     */
    public function __construct(private readonly array $keys)
    {
    }

    public function resolve(string $keyId): ?VerificationKey
    {
        return $this->keys[$keyId] ?? null;
    }

    public function refresh(string $keyId): ?VerificationKey
    {
        return $this->resolve($keyId);
    }
}

$resolver = new ArrayKeyResolver([
    'https://example.com/keys/1' => VerificationKey::fromPem($publicKeyPem),
]);

$result = (new Verifier($resolver, $clock))->verify($incomingRequest);

if ($result->verified) {
    echo "Signed by {$result->keyId} in the form {$result->form?->value}\n";
} else {
    echo "Not verified: {$result->reason?->name}, {$result->detail}\n";
}
```

`refresh()` is called once, after a failure that a rotated key could explain,
so a resolver that caches keys can fetch the key again there. A resolver with
no cache gives the same answer as `resolve()`.

`VerifierOptions` sets the forms the verifier accepts and what a signature
must cover. By default a request's signature must cover its target, the
signature must have a creation time, a message with content must cover its
digest field, and the times are judged with a clock skew of one hour, a
default lifetime of five minutes, and a maximum lifetime of twelve hours.
Under the draft form, a signature over a `(request-target)` without the query
string is accepted when the one with it fails, since some implementations
leave the query string out; the result's `requestTargetVerifiedWithoutQuery`
says when that happened. When it is `true`, the query string was not signed,
so treat it as input from anyone. Also under the draft form, the `created` and
`expires` parameters count only when `(created)` and `(expires)` are covered,
since only then are they signed; otherwise the covered `Date` field is the
creation time.

The result also has what a replay store needs: the key identifier, the
creation and expiry times, the nonce, and the signature bytes.

### Signing a response that covers request components

Under RFC 9421, a response's signature can cover components of the request it
answers, with the `req` parameter. Give the request as the last argument when
signing, and again when verifying.

``` php
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\SigningOptions;

$signedResponse = $signer->sign(
    $response,
    $key,
    new SigningOptions(
        form: Form::Rfc9421,
        coveredComponents: ['@status', '@method;req', '@target-uri;req', 'content-digest'],
    ),
    $request,
);

$result = $verifier->verify($signedResponse, $request);
```

### Behind a proxy

`@target-uri`, `@authority`, and `@scheme` are taken from the request's URI,
so they are only as true as the URI that your server's request factory
builds. A server behind a proxy that terminates TLS must build the request
with the scheme and the authority that the signer saw, as RFC 9421 section
7.4.3 says. The package cannot check this.

## Contributing

Contributions are welcome! To contribute, please familiarize yourself with
[CONTRIBUTING.md](CONTRIBUTING.md).

## Coordinated Disclosure

Keeping user information safe and secure is a top priority, and we welcome the
contribution of external security researchers. If you believe you've found a
security issue in software that is maintained in this repository, please read
[SECURITY.md](SECURITY.md) for instructions on submitting a vulnerability report.

## Copyright and License

socialweb/http-message-signatures is copyright © socialweb/http-message-signatures
Contributors and licensed for use under the terms of the GNU Lesser General
Public License (LGPL-3.0-or-later) as published by the Free Software Foundation.
Please see [COPYING.LESSER](COPYING.LESSER), [COPYING](COPYING), and
[NOTICE](NOTICE) for more information.

[rfc9421]: https://www.rfc-editor.org/rfc/rfc9421
[cavage]: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12
[rfc9530]: https://www.rfc-editor.org/rfc/rfc9530
[rfc3230]: https://www.rfc-editor.org/rfc/rfc3230
[psr-7]: https://www.php-fig.org/psr/psr-7/
[psr-20]: https://www.php-fig.org/psr/psr-20/
[nyholm]: https://github.com/Nyholm/psr7
