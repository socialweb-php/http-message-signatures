<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use DateTimeImmutable;
use Ergebnis\Clock\FrozenClock;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\Stream;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\MessageInterface;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\Signer;
use SocialWeb\Http\MessageSignatures\SigningKey;
use SocialWeb\Http\MessageSignatures\SigningOptions;
use SocialWeb\Http\MessageSignatures\VerificationKey;
use SocialWeb\Http\MessageSignatures\VerificationResult;
use SocialWeb\Http\MessageSignatures\Verifier;
use SocialWeb\Http\MessageSignatures\VerifierOptions;

use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function sprintf;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_ED25519;

/**
 * Signs and then verifies under every algorithm, on requests and responses,
 * with and without content, and proves the negative cases
 */
class RoundTripTest extends TestCase
{
    private const int NOW = 1618884473;

    /**
     * @var array<string, array{SigningKey, VerificationKey}>
     */
    private static array $keys = [];

    /**
     * @return array{SigningKey, VerificationKey}
     */
    private static function keyPair(Algorithm $algorithm): array
    {
        $name = $algorithm->name;

        if (isset(self::$keys[$name])) {
            return self::$keys[$name];
        }

        self::$keys[$name] = match ($algorithm) {
            Algorithm::RsaV15Sha256 => [
                SigningKey::fromPem($name, self::rfc9421Key('test-key-rsa.private.pem')),
                VerificationKey::fromPem(self::rfc9421Key('test-key-rsa.public.pem')),
            ],
            Algorithm::RsaPssSha512 => [
                SigningKey::fromPem($name, self::rfc9421Key('test-key-rsa-pss.private.pem')),
                VerificationKey::fromPem(self::rfc9421Key('test-key-rsa-pss.public.pem'), [Algorithm::RsaPssSha512]),
            ],
            Algorithm::Ed25519 => [
                SigningKey::fromPem($name, self::rfc9421Key('test-key-ed25519.private.pem')),
                VerificationKey::fromPem(self::rfc9421Key('test-key-ed25519.public.pem')),
            ],
            Algorithm::EcdsaP256Sha256 => [
                SigningKey::fromPem($name, self::rfc9421Key('test-key-ecc-p256.private.pem')),
                VerificationKey::fromPem(self::rfc9421Key('test-key-ecc-p256.public.pem')),
            ],
            Algorithm::EcdsaP384Sha384 => self::generatedP384Pair($name),
            Algorithm::HmacSha256 => [
                SigningKey::fromSharedSecret($name, self::rfc9421SharedSecret()),
                VerificationKey::fromSharedSecret(self::rfc9421SharedSecret()),
            ],
        };

        return self::$keys[$name];
    }

    /**
     * @return array{SigningKey, VerificationKey}
     */
    private static function generatedP384Pair(string $name): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
        self::assertNotFalse($key);
        $private = '';
        openssl_pkey_export($key, $private);
        self::assertIsString($private);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsString($details['key']);

        return [SigningKey::fromPem($name, $private), VerificationKey::fromPem($details['key'])];
    }

    /**
     * @return iterable<string, array{Algorithm, MessageInterface}>
     */
    public static function casesProvider(): iterable
    {
        $messages = [
            'a request without content' => new Request('GET', 'https://example.com/foo?param=Value&Pet=dog', [
                'Host' => 'example.com',
            ]),
            'a request with content' => new Request('POST', 'https://example.com/foo', [
                'Host' => 'example.com',
                'Content-Type' => 'application/json',
            ], '{"hello": "world"}'),
            'a response without content' => new Response(204),
            'a response with content' => new Response(
                200,
                ['Content-Type' => 'application/json'],
                '{"message": "good dog"}',
            ),
        ];

        foreach (Algorithm::cases() as $algorithm) {
            foreach ($messages as $description => $message) {
                yield sprintf('%s on %s', $algorithm->rfc9421Name(), $description) => [$algorithm, $message];
            }
        }
    }

    #[DataProvider('casesProvider')]
    public function testWhatTheSignerProducesTheVerifierAccepts(Algorithm $algorithm, MessageInterface $message): void
    {
        [$signingKey, $verificationKey] = self::keyPair($algorithm);
        $clock = new FrozenClock(new DateTimeImmutable('@' . self::NOW));

        $signed = (new Signer($clock))->sign($message, $signingKey, new SigningOptions(form: Form::Rfc9421));
        $result = (new Verifier(new ArrayKeyResolver([$algorithm->name => $verificationKey]), $clock))->verify($signed);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame($algorithm, $result->algorithm);
        $this->assertSame($algorithm->name, $result->keyId);
    }

    private static function signedRequest(): Request
    {
        [$signingKey] = self::keyPair(Algorithm::Ed25519);
        $request = new Request('POST', 'https://example.com/foo', [
            'Host' => 'example.com',
            'Content-Type' => 'application/json',
        ], '{"hello": "world"}');

        return (new Signer(new FrozenClock(new DateTimeImmutable('@' . self::NOW))))->sign(
            $request,
            $signingKey,
            new SigningOptions(
                form: Form::Rfc9421,
                coveredComponents: ['@method', '@target-uri', 'content-type', 'content-digest'],
            ),
        );
    }

    private static function verify(
        MessageInterface $message,
        ?VerificationKey $key = null,
        int $clockOffset = 0,
    ): VerificationResult {
        $key ??= self::keyPair(Algorithm::Ed25519)[1];
        $verifier = new Verifier(
            new ArrayKeyResolver([Algorithm::Ed25519->name => $key]),
            new FrozenClock(new DateTimeImmutable('@' . (self::NOW + $clockOffset))),
            new VerifierOptions(retryWithRefreshedKey: false),
        );

        return $verifier->verify($message);
    }

    public function testTheSignedRequestVerifies(): void
    {
        $this->assertTrue(self::verify(self::signedRequest())->verified);
    }

    public function testAChangedBodyFails(): void
    {
        $this->assertSame(
            FailureReason::DigestMismatch,
            self::verify(self::signedRequest()->withBody(Stream::create('{"hello": "there"}')))->reason,
        );
    }

    public function testAChangedCoveredFieldFails(): void
    {
        $this->assertSame(
            FailureReason::SignatureInvalid,
            self::verify(self::signedRequest()->withHeader('Content-Type', 'text/plain'))->reason,
        );
    }

    public function testAChangedUncoveredFieldDoesNotMatter(): void
    {
        $this->assertTrue(self::verify(self::signedRequest()->withHeader('Accept', 'text/plain'))->verified);
    }

    public function testACreationTimeOutsideThePolicyFails(): void
    {
        $this->assertSame(FailureReason::Expired, self::verify(self::signedRequest(), clockOffset: 86400)->reason);
        $this->assertSame(FailureReason::NotYetValid, self::verify(self::signedRequest(), clockOffset: -86400)->reason);
    }

    public function testAKeySwappedForAnotherOfTheSameTypeFails(): void
    {
        $other = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_ED25519]);
        $this->assertNotFalse($other);
        $details = openssl_pkey_get_details($other);
        $this->assertIsArray($details);
        $this->assertIsString($details['key']);

        $this->assertSame(
            FailureReason::SignatureInvalid,
            self::verify(self::signedRequest(), VerificationKey::fromPem($details['key']))->reason,
        );
    }

    public function testALabelMissingFromOneFieldFails(): void
    {
        $this->assertSame(
            FailureReason::MalformedSignature,
            self::verify(self::signedRequest()->withHeader('Signature', 'other=:AQ==:'))->reason,
        );
    }

    public function testASecondSignatureAppendedStillVerifies(): void
    {
        [$rsaKey] = self::keyPair(Algorithm::RsaV15Sha256);
        $twice = (new Signer(new FrozenClock(new DateTimeImmutable('@' . self::NOW))))->sign(
            self::signedRequest(),
            $rsaKey,
            new SigningOptions(form: Form::Rfc9421, label: 'sig2'),
        );

        $this->assertTrue(self::verify($twice)->verified);
    }
}
