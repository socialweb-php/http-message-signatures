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

socialweb/http-message-signatures signs and verifies HTTP requests and responses with HTTP Message Signatures, as published in [RFC 9421][rfc9421].

TLS protects a message over a single connection. When a message passes through a gateway or proxy that ends one TLS connection and opens another, TLS can no longer show that the message came from its sender unchanged. An HTTP message signature is part of the message itself: the sender signs the parts that matter to the application, such as the method, the target URI, chosen fields, and a digest of the body, and the receiver checks those parts with the sender's key, however many connections lie between them. Because only chosen parts are signed, the signature survives the changes that proxies and frameworks make to the rest of the message.

The package also signs and verifies the form of [draft-cavage-http-signatures-12][cavage], the Cavage draft that came before RFC 9421 and that many implementations still use; the verifier tells the two forms apart on its own. It supports every algorithm of the RFC 9421 registry, computes and checks the `Content-Digest` ([RFC 9530][rfc9530]) and `Digest` ([RFC 3230][rfc3230]) fields, and works with any [PSR-7][psr-7] message and [PSR-20][psr-20] clock. It never sends or fetches anything; your application sends the messages and supplies the keys.

The verifier never throws because of what a message contains. It returns a result that says whether the signature verified and, when it did not, why.

This project adheres to a [code of conduct](CODE_OF_CONDUCT.md). By participating in this project and its community, you are expected to uphold this code.

## Installation

Install this package as a dependency using [Composer](https://getcomposer.org).

```bash
composer require socialweb/http-message-signatures
```

## Usage

The examples use [nyholm/psr7][nyholm] for the messages; any PSR-7 implementation works. Each needs a PSR-20 clock, which can be as small as this:

```php
use Psr\Clock\ClockInterface;

$clock = new class implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
};
```

The client and server sections below sign with a key and verify with a resolver; "Keys" and "Resolvers" at the end of this section show how to build them.

### As a client

#### Signing a request

`Signer::sign()` returns the message it was given, with the signature fields of the chosen form added. A signature covers the parts of the message it signs, its components, such as the method, the target URI, and chosen fields; changing a covered part breaks the signature, while any other part can change without breaking it. When the signature covers `date` and the message has no `Date` field, one is added; when it covers a digest field, that field is computed and set. The default components cover `date` and cover the digest field when the message has content.

The example signs with `$key`, a `SigningKey` built as "Keys" below shows.

```php
use Nyholm\Psr7\Request;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\Signer;
use SocialWeb\Http\MessageSignatures\SigningOptions;

$signer = new Signer($clock);

$request = new Request(
    'POST',
    'https://example.com/inbox',
    ['Content-Type' => 'application/json'],
    '{"sender": "https://example.com/users/amara", "text": "The troll is asleep."}',
);

$signedRequest = $signer->sign($request, $key, new SigningOptions(form: Form::Rfc9421));
$legacySignedRequest = $signer->sign($request, $key, new SigningOptions(form: Form::Cavage));

echo $signedRequest->getHeaderLine('Signature-Input'), "\n";
echo $legacySignedRequest->getHeaderLine('Signature'), "\n";
```

With an RSA key, this prints an RFC 9421 `Signature-Input` field and a Cavage draft-form `Signature` field like these:

```text
sig1=("@method" "@target-uri" "host" "date" "content-digest");created=1792108800;alg="rsa-v1_5-sha256";keyid="https://example.com/keys/1"
keyId="https://example.com/keys/1",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="..."
```

`SigningOptions` chooses the covered components, the algorithm, the RFC 9421 label, the expiry, the nonce and tag of RFC 9421, and the digest algorithms; each has a default.

The signed request is an ordinary PSR-7 request. Send it with any [PSR-18][psr-18] HTTP client, and the receiver verifies the signature from its fields. In the example below, `$httpClient` is that client.

> [!NOTE]
> To sign a message in both RFC 9421 and Cavage draft forms with the same key, use an RSA key. The draft form has no name for the ECDSA and RSASSA-PSS algorithms, and its receivers do not all accept Ed25519.

RFC 9421 was published in 2024, after many services had implemented draft-cavage-http-signatures-12, and some of them still accept only the draft form. There is no standard response specified to indicate the receiver refused the signature. If a receiver cannot verify a signature for any reason, it usually responds with `401 Unauthorized`, and some respond with `400 Bad Request` or `403 Forbidden`. A sender that does not know which form a receiver accepts signs the request once in each form, as above, and sends the RFC 9421 form first. Check the status code of the response, and when the receiver responds with 400, 401, or 403, send the Cavage draft form once. If the draft form is refused, too, the form was not the problem; do not try again. Remember which form each receiver accepted so that the next request to it is sent once.

```php
$sentRequest = $signedRequest;
$signedResponse = $httpClient->sendRequest($sentRequest);

if (in_array($signedResponse->getStatusCode(), [400, 401, 403], true)) {
    $sentRequest = $legacySignedRequest;
    $signedResponse = $httpClient->sendRequest($sentRequest);
}
```

#### Verifying a response

A server may sign its response, over the response alone or bound to the request it answers, as "Signing a response" below shows. Verify it with the request the client sent as the second argument, and with `$resolver`, a resolver that has the server's key, as "Resolvers" below shows.

```php
use SocialWeb\Http\MessageSignatures\Verifier;

$verifier = new Verifier($resolver, $clock);
$result = $verifier->verify($signedResponse, $sentRequest);
```

The result says whether the signature verified, and `keyOwner` names whose key verified it, as the resolver gave it; "Resolvers" below says more. Here the resolver gives the server's key the owner `https://example.com`, where the request was sent. A server that does not sign its responses gives a result with the reason `NoSignature`; whether to accept such a response is up to you.

```php
if (!$result->verified) {
    echo "Not verified: {$result->reason?->name}, {$result->detail}\n";
} elseif ($result->keyOwner !== 'https://example.com') {
    echo "Signed by {$result->keyId}, which is not a key of example.com\n";
} else {
    echo "The response came from example.com\n";
}
```

When the server signed its response with the key the resolver has, this prints:

```text
The response came from example.com
```

### As a server

#### Verifying a request

Build the verifier with `$resolver`, a resolver built as "Resolvers" below shows, and with the settings that state your policy, and act on the result. Compare `keyOwner` with whoever the message claims to be from before you trust the message; the package does not know who that is. `$claimedSender` is the identity the message claims to be from. Your application reads it from a part of the message the signature covers; here it is the `sender` field of a JSON body, which the digest covers. Where to find it depends on your protocol. `$incomingRequest` is the request your server received, usually the `ServerRequestInterface` your framework builds; `verify()` accepts any PSR-7 message, request or response.

```php
use SocialWeb\Http\MessageSignatures\Verifier;

$verifier = new Verifier($resolver, $clock);
$result = $verifier->verify($incomingRequest);

$body = json_decode((string) $incomingRequest->getBody(), true);
$claimedSender = $body['sender'] ?? null;

if (!$result->verified) {
    echo "Not verified: {$result->reason?->name}, {$result->detail}\n";
} elseif ($result->keyOwner === null || $result->keyOwner !== $claimedSender) {
    echo "Signed by {$result->keyId}, which is not a key of {$claimedSender}\n";
} else {
    echo "Signed by {$result->keyOwner} in the form {$result->form?->name}\n";
}
```

For the request signed in "Signing a request" above, with a resolver that gives its key the owner `https://example.com/users/amara`, this prints:

```text
Signed by https://example.com/users/amara in the form Rfc9421
```

The verifier's settings are named parameters of its constructor, after the resolver and the clock. They set the forms the verifier accepts and what a signature must cover. By default a request's signature must cover its target, the signature must have a creation time, a message with content must cover its digest field, and the times are judged with a clock skew of one hour, a default lifetime of five minutes, and a maximum lifetime of twelve hours. Name the ones you want to change:

```php
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\Verifier;

$strictVerifier = new Verifier(
    $resolver,
    $clock,
    forms: [Form::Rfc9421],
    clockSkew: new DateInterval('PT5M'),
    requireNonce: true,
);
```

An RFC 9421 message may have several signatures, each under its own label. The verifier tries them in the order the message lists them until one verifies, up to `maxSignatures` of them, which is 3 by default. When a message has more labels than that, the rest are not tried, and the result's `maxSignaturesExceeded` is `true`, whether or not a signature within the limit verified.

> [!WARNING]
> Some Cavage draft implementations sign the request target without its query string, so by default the verifier accepts such a signature when the one with the query string fails. When it does, the result's `requestTargetVerifiedWithoutQuery` is `true`, and the query string was not signed: treat it as input from anyone. To refuse such signatures, build the verifier with `acceptRequestTargetWithoutQuery: false`.

The result also has what a replay store needs: the key identifier, the creation and expiry times, the nonce, and the signature bytes.

The verifier reads `@target-uri`, `@authority`, and `@scheme` from the request's URI, and the `host` field from its `Host` header. Behind a reverse proxy or load balancer that terminates TLS, the request your server receives can have a different scheme, host, or port from the one the client signed, and every signature that covers them fails with `SignatureInvalid`. Before verifying, set the URI to the public address you configure, as RFC 9421 section 7.4.3 suggests, not to forwarding fields such as `X-Forwarded-Host`, which anyone can send unless your proxy replaces them:

```php
$publicUri = $incomingRequest->getUri()
    ->withScheme('https')
    ->withHost('example.com')
    ->withPort(null);

$result = $verifier->verify($incomingRequest->withUri($publicUri));
```

`withUri()` also sets the `Host` field to the new host. The package cannot tell whether the URI is the one the client saw; that is up to your server.

#### Signing a response

A server can sign its response whether or not the request was signed. Under RFC 9421, a response's signature can also include parts of the request it answers, such as the request's method and target URI. That ties the response to that one request, so the client can tell that the response answers the request it sent and not some other request. Name those parts with `;req`, as in `@method;req`, and give the request as the last argument when signing; the client verifies the response with the same request, as "Verifying a response" above shows. The example signs with `$key`, a `SigningKey` built as "Keys" below shows. `$request` is the request your server received, and `$response` is the response it is about to send.

> [!NOTE]
> The Cavage draft signs only the response's own fields, so it cannot tie a response to its request.

```php
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\Signer;
use SocialWeb\Http\MessageSignatures\SigningOptions;

$signer = new Signer($clock);

$signedResponse = $signer->sign(
    $response,
    $key,
    new SigningOptions(
        form: Form::Rfc9421,
        coveredComponents: ['@status', '@method;req', '@target-uri;req', 'content-digest'],
    ),
    $request,
);

echo $signedResponse->getHeaderLine('Signature-Input'), "\n";
```

With an RSA key, this prints a `Signature-Input` field like this one:

```text
sig1=("@status" "@method";req "@target-uri";req "content-digest");created=1792108800;alg="rsa-v1_5-sha256";keyid="https://example.com/keys/1"
```

### Keys

A `SigningKey` is built from the text of a PEM private key and the key identifier that the receiver finds the key by:

```php
use SocialWeb\Http\MessageSignatures\SigningKey;

$privateKeyPem = file_get_contents('/path/to/private-key.pem');
$key = SigningKey::fromPem('https://example.com/keys/1', $privateKeyPem);
```

A `VerificationKey` is built the same way from the text of a PEM public key, and may name its owner, the identity the key belongs to, as "Resolvers" below shows. Both classes also have `fromSharedSecret()`, for HMAC.

A `VerificationKey` may also be built from a JSON Web Key ([RFC 7517][rfc7517]) with `fromJwk()`, which takes a key read by [socialweb/jwk][jwk]. That package is a suggested dependency; install it to use the method:

```bash
composer require socialweb/jwk
```

```php
use SocialWeb\Http\MessageSignatures\VerificationKey;
use SocialWeb\Jwk\Jwk;

$jwkJson = file_get_contents('/path/to/public-key.json');
$jwk = Jwk::fromJson($jwkJson, publicOnly: true);
$key = VerificationKey::fromJwk($jwk, owner: 'https://example.com/users/amara');
```

An `RSA`, `EC`, or `OKP` key becomes a public key, and an `oct` key becomes a shared secret. A key with `alg` permits that algorithm alone. A key with private members is refused, and so is a key whose `use` is not `sig` or whose `key_ops` lacks `verify`.

### Resolvers

`Verifier` asks a `KeyResolver` for the key that a signature names. Write the resolver for where your keys come from. This one holds them in an array, each with the identity it belongs to. `$publicKeyPem` is the text of the sender's PEM public key.

```php
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
        owner: 'https://example.com/users/amara',
    ),
]);
```

The resolver receives a `KeyLookup` with what the verifier knows about the signature:

- the message, its form, and the key identifier it names;
- the request it answers, when the message is a response; and
- the signature's label, algorithm, creation and expiry times, nonce, tag, and covered components.

Before it asks for a key, the verifier checks everything it can without one: that the signature fields parse, that the signature covers what your verifier requires, that it has not expired, and that the body matches its digest. A message that fails any of these never reaches the resolver, so a resolver that fetches keys does not fetch one for a message that would fail anyway. The signature itself has not been checked yet, so treat everything in the lookup as a claim: use it to find a key, and for nothing else.

The resolver is also where key policy belongs: it may refuse a key that is too small, comes from an origin you do not trust, or has been revoked. Return `null` to refuse a key, and `verify()` returns a failed result with the reason `KeyNotFound`. If the resolver throws instead, `verify()` does not catch the exception, so it reaches the code that called `verify()`.

`refresh()` is called once, with the same `KeyLookup`, after a failure that a rotated key could explain, so a resolver that caches keys fetches the key again there. A resolver with no cache gives the same answer as `resolve()`. When the fetch fails, return `null` and keep the cached key; the original failure stands.

`keyOwner` on a result is the owner the resolver gave the key that verified the signature, and `null` when that key had none or the signature did not verify.

## Contributing

Contributions are welcome! To contribute, please familiarize yourself with [CONTRIBUTING.md](CONTRIBUTING.md).

## Coordinated vulnerability disclosure policy

Keeping user information safe and secure is a top priority, and we welcome the contribution of external security researchers. If you believe you've found a security issue in software that is maintained in this repository, please read [SECURITY.md](SECURITY.md) for instructions on submitting a vulnerability report.

## Copyright and license

socialweb/http-message-signatures is copyright © socialweb/http-message-signatures Contributors and licensed for use under the terms of the GNU Lesser General Public License (LGPL-3.0-or-later) as published by the Free Software Foundation. Please see [COPYING.LESSER](COPYING.LESSER), [COPYING](COPYING), and [NOTICE](NOTICE) for more information.

[rfc9421]: https://www.rfc-editor.org/rfc/rfc9421
[cavage]: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12
[rfc9530]: https://www.rfc-editor.org/rfc/rfc9530
[rfc3230]: https://www.rfc-editor.org/rfc/rfc3230
[psr-7]: https://www.php-fig.org/psr/psr-7/
[psr-18]: https://www.php-fig.org/psr/psr-18/
[psr-20]: https://www.php-fig.org/psr/psr-20/
[rfc7517]: https://www.rfc-editor.org/rfc/rfc7517
[jwk]: https://github.com/socialweb-php/jwk
[nyholm]: https://github.com/Nyholm/psr7
