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
use DateTimeImmutable;
use Psr\Clock\ClockInterface;

$clock = new class implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
};
```

### Sending a request

`Signer::sign()` returns the message it was given, with the signature fields
of the chosen form added. A signature covers the parts of the message it signs,
its components, such as the method, the target URI, and chosen fields;
changing a covered part breaks the signature, while any other part can change
without it. When the signature covers `date` and the message has no `Date`
field, one is added; when it covers a digest field, that field is computed and
set. The default components cover `date` and cover the digest field when the
message has content.

``` php
use Nyholm\Psr7\Request;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\Signer;
use SocialWeb\Http\MessageSignatures\SigningKey;
use SocialWeb\Http\MessageSignatures\SigningOptions;

use function file_get_contents;

$privateKeyPem = file_get_contents('/path/to/private-key.pem');
$key = SigningKey::fromPem('https://example.com/keys/1', $privateKeyPem);
$signer = new Signer($clock);

$request = new Request(
    'POST',
    'https://example.org/inbox',
    ['Content-Type' => 'application/json'],
    '{"hello": "world"}',
);

$signedRequest = $signer->sign($request, $key, new SigningOptions(form: Form::Rfc9421));
$legacySignedRequest = $signer->sign($request, $key, new SigningOptions(form: Form::Cavage));

echo $signedRequest->getHeaderLine('Signature-Input'), "\n";
echo $legacySignedRequest->getHeaderLine('Signature'), "\n";
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

A receiver that accepts only one form refuses the other. A sender that does
not know which form a receiver accepts signs the request once in each form,
as above, sends the RFC 9421 form, and sends the draft form when the receiver
refuses it. Signing is a pure function of its arguments and the clock, so the
two calls sign the same request without rebuilding it, and the second
signature is the only added cost.

The response that comes back can be signed over the request it answers, as
"Sending a response" below shows. The client is the one holding the request
it sent, so it verifies the response with that request as the second
argument, and with a resolver that holds the server's key; the next section
says what a resolver is. `$httpClient` is any PSR-18 (PHP Standards
Recommendation 18) HTTP client.

``` php
use SocialWeb\Http\MessageSignatures\Verifier;

$signedResponse = $httpClient->sendRequest($signedRequest);

$verifier = new Verifier($resolver, $clock);
$result = $verifier->verify($signedResponse, $signedRequest);
```

### Receiving a request

`Verifier` asks a `KeyResolver` for the key that a signature names. Write the
resolver for where your keys come from. This one holds them in an array, each
with the identity it belongs to:

``` php
use SocialWeb\Http\MessageSignatures\KeyLookup;
use SocialWeb\Http\MessageSignatures\KeyResolver;
use SocialWeb\Http\MessageSignatures\VerificationKey;

final class ArrayKeyResolver implements KeyResolver
{
    /**
     * @param array<string, VerificationKey> $keys by key identifier
     */
    public function __construct(private readonly array $keys)
    {
    }

    public function resolve(KeyLookup $lookup): ?VerificationKey
    {
        return $this->keys[$lookup->keyId] ?? null;
    }

    public function refresh(KeyLookup $lookup): ?VerificationKey
    {
        return $this->resolve($lookup);
    }
}

$resolver = new ArrayKeyResolver([
    'https://example.com/keys/1' => VerificationKey::fromPem(
        $publicKeyPem,
        owner: 'https://example.com/users/alice',
    ),
]);
```

The resolver receives a `KeyLookup`: the message, the form, the key
identifier as the message gave it, the related request when a response is
verified, and these parameters of the signature: the label, the algorithm,
the creation and expiry times, the nonce, the tag, and the covered
components. The verifier calls it only after every check that needs no key
has passed: the fields parse, the policy is met, the signature base was built,
and every covered digest matches the content. The signature bytes have not
been verified at that point, so everything the resolver reads from the
message is a claim, good for finding a key and for nothing else. The resolver
is where key policy belongs: it may refuse keys below a size, keys from an
origin it does not trust, or keys that have been revoked, by returning `null`
or throwing. Anything it throws passes through `verify()` unchanged.

`refresh()` is called once, with the same `KeyLookup`, after a failure that a
rotated key could explain, so a resolver that caches keys fetches the key
again there. A resolver with no cache gives the same answer as `resolve()`.
When the fetch fails, return `null` and keep the cached key; the original
failure stands.

Build the verifier with the options that state your policy, and act on the
result. `keyOwner` is the owner the resolver gave the key that verified the
signature, and `null` when that key had none or the signature did not verify.
Compare it with whoever the message claims to be from before you trust the
message; the package does not know who that is. `$claimedSender` is the
identity the message claims to be from, read from the message itself.

``` php
use SocialWeb\Http\MessageSignatures\Verifier;
use SocialWeb\Http\MessageSignatures\VerifierOptions;

$verifier = new Verifier($resolver, $clock, new VerifierOptions());
$result = $verifier->verify($incomingRequest);

if (!$result->verified) {
    echo "Not verified: {$result->reason?->name}, {$result->detail}\n";
} elseif ($result->keyOwner === null || $result->keyOwner !== $claimedSender) {
    echo "Signed by {$result->keyId}, which is not a key of {$claimedSender}\n";
} else {
    echo "Signed by {$result->keyOwner} in the form {$result->form?->value}\n";
}
```

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

`@target-uri`, `@authority`, and `@scheme` are taken from the request's URI,
so they are only as true as the URI that your server's request factory
builds. A server behind a proxy that terminates TLS must build the request
with the scheme and the authority that the signer saw, as RFC 9421 section
7.4.3 says. The package cannot check this.

### Sending a response

Under RFC 9421, a response's signature can cover components of the request it
answers, with the `req` parameter. Give the request as the last argument when
signing; the client verifies the response with the same request, as "Sending
a request" above shows.

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
```

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
