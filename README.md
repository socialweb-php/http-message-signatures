<h1 align="center">socialweb/http-message-signatures</h1>

<p align="center">
    <a href="https://github.com/socialweb-php/http-message-signatures"><img src="https://img.shields.io/badge/source-socialweb/http--message--signatures-blue.svg" alt="Source Code"></a>
    <a href="https://packagist.org/packages/socialweb/http-message-signatures"><img src="https://img.shields.io/packagist/v/socialweb/http-message-signatures.svg?label=release" alt="Download Package"></a>
    <a href="https://php.net"><img src="https://img.shields.io/packagist/php-v/socialweb/http-message-signatures.svg?colorB=%238892BF" alt="PHP Programming Language"></a>
    <a href="https://github.com/socialweb-php/http-message-signatures/blob/main/COPYING.LESSER"><img src="https://img.shields.io/packagist/l/socialweb/http-message-signatures.svg?colorB=darkcyan" alt="Read License"></a>
    <a href="https://github.com/socialweb-php/http-message-signatures/actions/workflows/continuous-integration.yml"><img src="https://img.shields.io/github/actions/workflow/status/socialweb-php/http-message-signatures/continuous-integration.yml?branch=main&logo=github" alt="Build Status"></a>
    <a href="https://codecov.io/gh/socialweb-php/http-message-signatures"><img src="https://img.shields.io/codecov/c/gh/socialweb-php/http-message-signatures?label=codecov&logo=codecov" alt="Codecov Code Coverage"></a>
</p>

## About

socialweb/http-message-signatures signs and verifies HTTP requests and responses with HTTP Message Signatures, as published in [RFC 9421][rfc9421].

TLS encryption protects a message over a single connection. When a message passes through a gateway or proxy that ends one TLS connection and opens another, TLS can no longer show that the message came from its sender unchanged. An HTTP message signature is part of the message itself: the sender signs the parts that matter to the application, such as the method, the target URI, chosen fields, and a digest of the body, and the receiver checks those parts with the sender's key, however many connections lie between them. Because only chosen parts are signed, the signature survives the changes that proxies and frameworks make to the rest of the message.

This package also signs and verifies the form of [draft-cavage-http-signatures-12][cavage], the Cavage draft that came before RFC 9421 and that many implementations still use; the verifier detects which form a message uses. This package supports every algorithm of the RFC 9421 registry, computes and checks the `Content-Digest` ([RFC 9530][rfc9530]) and `Digest` ([RFC 3230][rfc3230]) fields, and works with any [PSR-7][psr-7] message and [PSR-20][psr-20] clock. It never sends or fetches anything; your application sends the messages and supplies the keys.

The verifier never throws because of what a message contains. It returns a result that says whether the signature verified and, when it did not, why, so a malformed or hostile message cannot crash the code that handles it.

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

The client and server sections below sign with a key and verify with a resolver. A resolver is code you write that finds the sender's public key from the key identifier in a signature; "Loading your keys" and "Finding the sender's key" at the end of this section show how to build both.

### As a client

#### Signing a request

`Signer::sign()` returns a copy of the message with the signature fields of the chosen form added. A signature protects only the parts of the message it covers, called its components, such as the method, the target URI, and chosen fields. Changing a covered component breaks the signature; any other part can change freely. When the signature covers `date` and the message has no `Date` field, one is added; when it covers a digest field, that field is computed and set. By default, the signature covers `date`, and also the digest field when the message has content.

This example signs with `$key`, which is a `SigningKey` built as "Loading your keys" below shows.

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

echo $signedRequest->getHeaderLine('Signature-Input') . "\n";
echo $signedRequest->getHeaderLine('Signature') . "\n";
echo $legacySignedRequest->getHeaderLine('Signature') . "\n";
```

With an RSA key, this prints the RFC 9421 `Signature-Input` and `Signature` fields and a Cavage `Signature` field like these:

```text
sig1=("@method" "@target-uri" "host" "date" "content-digest");created=1792108800;alg="rsa-v1_5-sha256";keyid="https://example.com/keys/1"
sig1=:...:
keyId="https://example.com/keys/1",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="..."
```

RFC 9421 puts the signature in its own `Signature` field, under the same label as its `Signature-Input`; the Cavage form puts everything in one `Signature` field.

`SigningOptions` chooses the covered components, the algorithm, the RFC 9421 label, the expiry, the nonce and tag of RFC 9421, and the digest algorithms; each has a default. "Choosing what a signature covers" below lists the components you can name.

The signed request is an ordinary PSR-7 request. Send it with any [PSR-18][psr-18] HTTP client, and the receiver verifies the signature from its fields. In the example below, `$httpClient` is that client.

> [!NOTE]
> To sign a message in both RFC 9421 and Cavage draft forms with the same key, use an RSA key. The Cavage form has no name for the ECDSA and RSASSA-PSS algorithms, and its receivers do not all accept Ed25519.

RFC 9421 was published in 2024, after many services had implemented draft-cavage-http-signatures-12, and some of them still accept only the Cavage form. No standard defines how a receiver reports a refused signature. If a receiver cannot verify a signature for any reason, it usually responds with `401 Unauthorized`, and some respond with `400 Bad Request` or `403 Forbidden`.

A sender that does not know which form a receiver accepts signs the request once in each form, as above, and sends the RFC 9421 form first. Check the status code of the response, and when the receiver responds with 400, 401, or 403, send the Cavage form once. If the Cavage form is refused, too, the form was not the problem; do not try again. Remember which form each receiver accepted so that the next request to it is sent once.

```php
$sentRequest = $signedRequest;
$signedResponse = $httpClient->sendRequest($sentRequest);

if (in_array($signedResponse->getStatusCode(), [400, 401, 403], true)) {
    $sentRequest = $legacySignedRequest;
    $signedResponse = $httpClient->sendRequest($sentRequest);
}
```

`$sentRequest` holds whichever request was sent, since verifying a signed response needs it, as "Verifying a response" below shows.

#### Verifying a response

A server may sign its response, over the response alone or bound to the request it responds to, as "Signing a response" below shows. Verify it with the request the client sent as the second argument, and with `$resolver`, which is a resolver that has the server's key, as "Finding the sender's key" below shows.

```php
use SocialWeb\Http\MessageSignatures\Verifier;

$verifier = new Verifier($resolver, $clock);
$result = $verifier->verify($signedResponse, $sentRequest);
```

The result says whether the signature verified, and `keyOwner` is the owner of the key that verified it, which your resolver sets when it builds the key; "Finding the sender's key" below says more. Here the resolver sets the server's key's owner to `https://example.com`, where the request was sent. A server that does not sign its responses gives a result with the reason `NoSignature`; whether to accept such a response is up to you.

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

Build the verifier with `$resolver`, which is a resolver built as "Finding the sender's key" below shows, and with the settings that state your policy, and act on the result. A valid signature proves only that whoever holds the key signed the message. It doesn't prove that the key belongs to the sender the message names, so compare `keyOwner` with that sender before you trust the message; this package doesn't know who the sender is.

`$claimedSender` is the identity the message claims to be from. Your application reads it from a part of the message the signature covers; here it is the `sender` field of a JSON body, which the digest covers. Where to find it depends on your protocol. `$incomingRequest` is the request your server received, usually the `ServerRequestInterface` your framework builds; `verify()` accepts any PSR-7 message, request or response.

> [!TIP]
> In [ActivityPub][activitypub], the claimed sender is the activity's `actor`, the URL of the account that sent it. Your resolver reads the key's owner from the actor document that publishes the key, so `keyOwner` and `actor` should be the same URL. A webhook usually names the sending account in a header or in the body. Make sure the signature covers that header, or the body's digest, so the claim is signed too.

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

The verifier's settings are named parameters of its constructor, after the resolver and the clock. They set the forms the verifier accepts and what a signature must cover. By default, a request's signature must cover its target, the signature must have a creation time, a message with content must cover its digest field, and the times are checked with a clock skew of one hour, a default lifetime of five minutes, and a maximum lifetime of twelve hours. A signature without an expiry time stays valid for the default lifetime after it was created. Name the ones you want to change:

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

An RFC 9421 message may have several signatures, each under its own label. The verifier checks them in the order they appear in the message and stops at the first one that verifies. It checks at most `maxSignatures` of them, which is 3 by default. When a message has more labels than that, the rest are not checked, and the result's `maxSignaturesExceeded` is `true`, whether or not a signature within the limit verified.

> [!WARNING]
> Some Cavage draft implementations sign the request target without its query string, so, by default, the verifier accepts such a signature when the one with the query string fails. When it does, the result's `requestTargetVerifiedWithoutQuery` is `true`, and the query string was not signed, so treat it as input from anyone. To refuse such signatures, build the verifier with `acceptRequestTargetWithoutQuery: false`.

An attacker who copies a signed message can send it again. To refuse such a replay, your application can remember the signatures it has accepted; the result has what it needs for that: the key identifier, the creation and expiry times, the nonce, and the signature bytes.

The verifier reads `@target-uri`, `@authority`, and `@scheme` from the request's URI, and the `host` field from its `Host` header. Behind a reverse proxy or load balancer that ends the TLS connection, the request your server receives can have a different scheme, host, or port from the one the client signed, and every signature that covers them fails with `SignatureInvalid`. Before verifying, set the URI to the public address you configure, as RFC 9421 section 7.4.3 suggests, not to forwarding fields such as `X-Forwarded-Host`, which anyone can send unless your proxy replaces them:

```php
$publicUri = $incomingRequest->getUri()
    ->withScheme('https')
    ->withHost('example.com')
    ->withPort(null);

$result = $verifier->verify($incomingRequest->withUri($publicUri));
```

`withUri()` also sets the `Host` field to the new host. This package cannot tell whether the URI is the one the client saw; that is up to your server.

#### Signing a response

A server can sign its response whether or not the request was signed. Under RFC 9421, a response's signature can also include parts of the request it responds to, such as the request's method and target URI. That ties the response to that one request, so the client can tell that the response is for the request it sent and not some other request. Name those parts with `;req`, as in `@method;req`, and give the request as the last argument when signing; the client verifies the response with the same request, as "Verifying a response" above shows. This example signs with `$key`, which is a `SigningKey` built as "Loading your keys" below shows. `$request` is the request your server received, and `$response` is the response it is about to send.

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

echo $signedResponse->getHeaderLine('Signature-Input') . "\n";
```

With an RSA key, this prints a `Signature-Input` field like this one:

```text
sig1=("@status" "@method";req "@target-uri";req "content-digest");created=1792108800;alg="rsa-v1_5-sha256";keyid="https://example.com/keys/1"
```

### Loading your keys

A `SigningKey` is built from the text of a PEM private key and the key identifier, which receivers use to find your public key, often the URL where it's published:

```php
use SocialWeb\Http\MessageSignatures\SigningKey;

$privateKeyPem = file_get_contents('/path/to/private-key.pem');
$key = SigningKey::fromPem('https://example.com/keys/1', $privateKeyPem);
```

A `VerificationKey` is built the same way from the text of a PEM public key, and may name its owner, the identity the key belongs to, as "Finding the sender's key" below shows. Both classes also have `fromSharedSecret()`, for HMAC, where both sides share one secret.

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

### Finding the sender's key

`Verifier` asks a `KeyResolver` for the key that a signature names. Write the resolver for where your keys come from. The resolver below holds them in an array, each with the identity it belongs to. `$publicKeyPem` is the text of the sender's PEM public key.

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
- the request it responds to, when the message is a response; and
- the signature's label, algorithm, creation and expiry times, nonce, tag, and covered components.

Before it asks for a key, the verifier checks everything it can without one: that the signature fields parse, that the signature covers what your verifier requires, that it has not expired, and that the body matches its digest. A message that fails any of these never reaches the resolver, so a resolver that fetches keys does not fetch one for a message that would fail anyway. The signature itself has not been checked yet, so treat everything in the lookup as a claim: use it to find a key, and for nothing else.

The resolver is also where key policy belongs: it may refuse a key that is too small, comes from an origin you do not trust, or has been revoked. Return `null` to refuse a key, and `verify()` returns a failed result with the reason `KeyNotFound`. If the resolver throws instead, `verify()` does not catch the exception, so the code that called `verify()` receives it and must catch it.

Senders replace their keys from time to time, sometimes under the same key identifier. A resolver that caches keys may then still hold the old key, and a valid signature fails to verify with it. So when a signature fails with `SignatureInvalid` or `AlgorithmNotPermitted`, the verifier calls the resolver's `refresh()` once, with the same `KeyLookup`, and checks the signature again with the key it returns. In `refresh()`, a resolver that caches keys fetches the key again and replaces its cached copy; a resolver with no cache returns the same key as `resolve()`. If the fetch fails, return `null` and keep the cached key, so a server that is down for a moment does not cost you a key that still works; the verifier then reports the original failure. To turn this off, build the verifier with `retryWithRefreshedKey: false`.

`keyOwner` on a result is the owner of the key that verified the signature, as your resolver set it, and `null` when that key had none or the signature did not verify.

### Choosing what a signature covers

A signature protects only the components it covers, so the list you give `SigningOptions` as `coveredComponents`, and the list a verifier requires as `requiredComponents`, decide which parts of a message a receiver can trust. [RFC 9421][rfc9421] section 2 defines two kinds of component: HTTP fields and derived components.

An HTTP field is named in lowercase, such as `content-type` or `date`, and any field the message has may be covered. A parameter after the name changes what is signed:

| Component | What it signs |
| --- | --- |
| `content-type` | The field's value, with its lines joined by commas |
| `content-digest;sf` | The field written again in its Structured Field form |
| `content-digest;key="sha-256"` | One member of a Dictionary field |
| `x-custom;bs` | Each line of the field, as bytes |
| `content-type;req` | A field of the request, in the signature of a response |

`;sf` and `;key` apply to fields defined as [Structured Fields][rfc8941], a common syntax for HTTP field values. This package reads them for the Dictionary fields it knows: `Content-Digest`, `Signature`, `Signature-Input`, and `Accept-Signature`. It does not implement trailer fields, so it refuses `;tr`.

A derived component is computed from the message instead of read from a field:

| Component | What it signs |
| --- | --- |
| `@method` | The method, such as `POST` |
| `@target-uri` | The full target URI, such as `https://example.com/inbox?page=2` |
| `@authority` | The host, and the port when it is not the scheme's default |
| `@scheme` | The scheme, `http` or `https` |
| `@request-target` | The target as the request line sends it, usually the path and the query |
| `@path` | The path, such as `/inbox` |
| `@query` | The query with its leading `?`, such as `?page=2` |
| `@query-param;name="page"` | The value of one query parameter, such as `2` |
| `@status` | The status code of a response, such as `200` |

Every derived component except `@status` describes a request. In the signature of a response, add `;req` to sign the request's value, as "Signing a response" above shows.

The Cavage form names a component by a field name, in any case, or by one of three names in parentheses: `(request-target)`, the method and the target together, and `(created)` and `(expires)`, the signature's creation and expiry times.

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
[rfc8941]: https://www.rfc-editor.org/rfc/rfc8941
[psr-7]: https://www.php-fig.org/psr/psr-7/
[psr-18]: https://www.php-fig.org/psr/psr-18/
[psr-20]: https://www.php-fig.org/psr/psr-20/
[rfc7517]: https://www.rfc-editor.org/rfc/rfc7517
[jwk]: https://github.com/socialweb-php/jwk
[nyholm]: https://github.com/Nyholm/psr7
[activitypub]: https://activitypub.rocks
