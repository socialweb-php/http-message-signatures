<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Ergebnis\Clock\FrozenClock;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\Stream;
use Psr\Http\Message\RequestInterface;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Component\ComponentFailure;
use SocialWeb\Http\MessageSignatures\DigestAlgorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\Signer;
use SocialWeb\Http\MessageSignatures\SigningKey;
use SocialWeb\Http\MessageSignatures\SigningOptions;
use SocialWeb\Http\MessageSignatures\VerificationKey;

use function base64_decode;
use function fopen;
use function strlen;
use function strpos;
use function strtolower;
use function substr;
use function trim;

/**
 * Pins what `Signer` writes: the fields, the default covered components, the
 * digest and `Date` fields it adds, and the parameters in the RFC's order
 *
 * The deterministic algorithms sign to known bytes at the primitive level in
 * `Rfc9421AppendixBTest`; here the signature is checked against the key.
 */
class SignerTest extends TestCase
{
    private const int NOW = 1618884473;
    private const string SHA256 = 'X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=';
    private const string SHA512 = 'WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJ'
        . 'wew==';

    private static function signer(): Signer
    {
        // A clock in another time zone, to show the Date field is written in
        // GMT.
        return new Signer(new FrozenClock(
            (new DateTimeImmutable('@' . self::NOW))->setTimezone(new DateTimeZone('America/Chicago')),
        ));
    }

    private static function key(string $name = 'test-key-ed25519'): SigningKey
    {
        return SigningKey::fromPem($name, self::rfc9421Key($name . '.private.pem'));
    }

    private static function request(string $body = ''): Request
    {
        return new Request('POST', 'https://example.com/foo?param=Value&Pet=dog', [
            'Host' => 'example.com',
            'Content-Type' => 'application/json',
        ], $body);
    }

    private static function signatureBytes(Request | Response $signed, string $label = 'sig1'): string
    {
        $value = $signed->getHeaderLine('Signature');
        $start = strpos($value, $label . '=:');
        self::assertNotFalse($start);
        $start += strlen($label) + 2;
        $end = strpos($value, ':', $start);
        self::assertNotFalse($end);

        return (string) base64_decode(substr($value, $start, $end - $start), true);
    }

    public function testSignsARequestWithTheDefaultComponentsAndAddsADateField(): void
    {
        $signed = self::signer()->sign(self::request(), self::key(), new SigningOptions(form: Form::Rfc9421));

        $this->assertSame(
            'sig1=("@method" "@target-uri" "host" "date");created=1618884473;alg="ed25519";keyid="test-key-ed25519"',
            $signed->getHeaderLine('Signature-Input'),
        );
        $this->assertSame('Tue, 20 Apr 2021 02:07:53 GMT', $signed->getHeaderLine('Date'));
        $this->assertFalse($signed->hasHeader('Content-Digest'));
        $this->assertSame(64, strlen(self::signatureBytes($signed)));
    }

    public function testSignsARequestWithContentAndAddsItsDigest(): void
    {
        $signed = self::signer()->sign(
            self::request('{"hello": "world"}'),
            self::key(),
            new SigningOptions(form: Form::Rfc9421),
        );

        $this->assertSame(
            'sig1=("@method" "@target-uri" "host" "date" "content-digest");created=1618884473;alg="ed25519"'
            . ';keyid="test-key-ed25519"',
            $signed->getHeaderLine('Signature-Input'),
        );
        $this->assertSame('sha-256=:' . self::SHA256 . ':', $signed->getHeaderLine('Content-Digest'));
        $this->assertSame('{"hello": "world"}', (string) $signed->getBody());
    }

    public function testSignsAResponseWithTheDefaultComponents(): void
    {
        $signed = self::signer()->sign(
            new Response(200, [], '{"message": "good dog"}'),
            self::key(),
            new SigningOptions(form: Form::Rfc9421),
        );

        $this->assertSame(
            'sig1=("@status" "date" "content-digest");created=1618884473;alg="ed25519";keyid="test-key-ed25519"',
            $signed->getHeaderLine('Signature-Input'),
        );
        $this->assertSame('Tue, 20 Apr 2021 02:07:53 GMT', $signed->getHeaderLine('Date'));
    }

    public function testKeepsAnExistingDateField(): void
    {
        $signed = self::signer()->sign(
            self::request()->withHeader('Date', 'Tue, 20 Apr 2021 02:07:55 GMT'),
            self::key(),
            new SigningOptions(form: Form::Rfc9421),
        );

        $this->assertSame('Tue, 20 Apr 2021 02:07:55 GMT', $signed->getHeaderLine('Date'));
    }

    public function testDoesNotAddADateFieldWhenDateIsNotCovered(): void
    {
        $signed = self::signer()->sign(
            self::request(),
            self::key(),
            new SigningOptions(form: Form::Rfc9421, coveredComponents: ['@method', '@target-uri']),
        );

        $this->assertFalse($signed->hasHeader('Date'));
        $this->assertSame(
            'sig1=("@method" "@target-uri");created=1618884473;alg="ed25519";keyid="test-key-ed25519"',
            $signed->getHeaderLine('Signature-Input'),
        );
    }

    public function testReplacesAnExistingDigestFieldAndComputesEveryAlgorithmAsked(): void
    {
        $signed = self::signer()->sign(
            self::request('{"hello": "world"}')->withHeader('Content-Digest', 'sha-256=:stale:'),
            self::key(),
            new SigningOptions(
                form: Form::Rfc9421,
                coveredComponents: ['@method', '@target-uri', 'content-digest'],
                digestAlgorithms: [DigestAlgorithm::Sha512, DigestAlgorithm::Sha256],
            ),
        );

        $this->assertSame(
            'sha-512=:' . self::SHA512 . ':, sha-256=:' . self::SHA256 . ':',
            $signed->getHeaderLine('Content-Digest'),
        );
    }

    public function testWritesTheRfc3230DigestFieldWhenItIsListed(): void
    {
        $signed = self::signer()->sign(
            self::request('{"hello": "world"}'),
            self::key(),
            new SigningOptions(form: Form::Rfc9421, coveredComponents: ['@method', '@target-uri', 'digest']),
        );

        $this->assertSame('SHA-256=' . self::SHA256, $signed->getHeaderLine('Digest'));
        $this->assertFalse($signed->hasHeader('Content-Digest'));
    }

    public function testListingTheDigestFieldOnAMessageWithoutContentSignsTheDigestOfEmptyContent(): void
    {
        $signed = self::signer()->sign(
            self::request(),
            self::key(),
            new SigningOptions(form: Form::Rfc9421, coveredComponents: ['@method', '@target-uri', 'content-digest']),
        );

        $this->assertSame(
            'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
            $signed->getHeaderLine('Content-Digest'),
        );
    }

    public function testDoesNotComputeADigestForTheRelatedRequest(): void
    {
        $request = self::request('{"hello": "world"}')->withHeader('Content-Digest', 'sha-256=:' . self::SHA256 . ':');
        $signed = self::signer()->sign(
            new Response(200),
            self::key(),
            new SigningOptions(form: Form::Rfc9421, coveredComponents: ['@status', 'content-digest;req']),
            $request,
        );

        $this->assertFalse($signed->hasHeader('Content-Digest'));
        $this->assertSame(
            'sig1=("@status" "content-digest";req);created=1618884473;alg="ed25519";keyid="test-key-ed25519"',
            $signed->getHeaderLine('Signature-Input'),
        );
    }

    public function testWritesTheParametersInTheRfcsOrder(): void
    {
        $signed = self::signer()->sign(
            self::request(),
            self::key(),
            new SigningOptions(
                form: Form::Rfc9421,
                coveredComponents: ['@method', '@query-param;name="Pet"'],
                label: 'sig-b22',
                expires: new DateInterval('PT5M'),
                nonce: 'b3k2pp5k7z-50gnwp.yemd',
                tag: 'header-example',
            ),
        );

        $this->assertSame(
            'sig-b22=("@method" "@query-param";name="Pet");created=1618884473;expires=1618884773'
            . ';nonce="b3k2pp5k7z-50gnwp.yemd";alg="ed25519";keyid="test-key-ed25519";tag="header-example"',
            $signed->getHeaderLine('Signature-Input'),
        );
    }

    public function testLeavesTheCreationTimeOutWhenAsked(): void
    {
        $signed = self::signer()->sign(
            self::request(),
            self::key(),
            new SigningOptions(form: Form::Rfc9421, created: false, expires: new DateInterval('PT5M')),
        );

        $this->assertSame(
            'sig1=("@method" "@target-uri" "host" "date");expires=1618884773;alg="ed25519";keyid="test-key-ed25519"',
            $signed->getHeaderLine('Signature-Input'),
        );
    }

    public function testUsesTheKeysFirstPermittedAlgorithmByDefault(): void
    {
        $options = new SigningOptions(form: Form::Rfc9421);
        $rsa = self::signer()->sign(self::request(), self::key('test-key-rsa'), $options);
        $pss = self::signer()->sign(self::request(), self::key('test-key-rsa-pss'), $options);

        $this->assertStringContainsString(
            ';alg="rsa-v1_5-sha256";keyid="test-key-rsa"',
            $rsa->getHeaderLine('Signature-Input'),
        );
        $this->assertStringContainsString(
            ';alg="rsa-pss-sha512";keyid="test-key-rsa-pss"',
            $pss->getHeaderLine('Signature-Input'),
        );
    }

    public function testUsesTheAlgorithmTheOptionsName(): void
    {
        $signed = self::signer()->sign(
            self::request(),
            self::key('test-key-rsa'),
            new SigningOptions(form: Form::Rfc9421, algorithm: Algorithm::RsaPssSha512),
        );

        $this->assertStringContainsString(';alg="rsa-pss-sha512";', $signed->getHeaderLine('Signature-Input'));
        $this->assertTrue(VerificationKey::fromPem(self::rfc9421Key('test-key-rsa.public.pem'))->verify(
            Algorithm::RsaPssSha512,
            "\"@method\": POST\n\"@target-uri\": https://example.com/foo?param=Value&Pet=dog\n\"host\": example.com\n"
            . "\"date\": Tue, 20 Apr 2021 02:07:53 GMT\n"
            . '"@signature-params": ("@method" "@target-uri" "host" "date");created=1618884473;alg="rsa-pss-sha512"'
            . ';keyid="test-key-rsa"',
            self::signatureBytes($signed),
        ));
    }

    public function testRefusesAnAlgorithmTheKeyDoesNotPermit(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('Algorithm RsaV15Sha256 is not permitted for this key');

        self::signer()->sign(
            self::request(),
            self::key('test-key-rsa-pss'),
            new SigningOptions(form: Form::Rfc9421, algorithm: Algorithm::RsaV15Sha256),
        );
    }

    public function testAppendsASecondSignatureUnderAnotherLabel(): void
    {
        $once = self::signer()->sign(self::request(), self::key(), new SigningOptions(form: Form::Rfc9421));
        $twice = self::signer()->sign(
            $once,
            self::key('test-key-rsa'),
            new SigningOptions(form: Form::Rfc9421, label: 'sig2'),
        );

        $this->assertSame(
            'sig1=("@method" "@target-uri" "host" "date");created=1618884473;alg="ed25519";keyid="test-key-ed25519"'
            . ', sig2=("@method" "@target-uri" "host" "date");created=1618884473;alg="rsa-v1_5-sha256"'
            . ';keyid="test-key-rsa"',
            $twice->getHeaderLine('Signature-Input'),
        );
        $this->assertSame(self::signatureBytes($once), self::signatureBytes($twice));
        $this->assertSame(256, strlen(self::signatureBytes($twice, 'sig2')));
    }

    public function testRefusesALabelTheMessageAlreadyHas(): void
    {
        $once = self::signer()->sign(self::request(), self::key(), new SigningOptions(form: Form::Rfc9421));

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The message already has a signature with the label "sig1"');

        self::signer()->sign($once, self::key('test-key-rsa'), new SigningOptions(form: Form::Rfc9421));
    }

    public function testRefusesAnExistingSignatureInputFieldWithALineBreak(): void
    {
        $request = self::request();
        $message = $this->createStub(RequestInterface::class);
        $message->method('getBody')->willReturn($request->getBody());
        $message->method('getMethod')->willReturn($request->getMethod());
        $message->method('getUri')->willReturn($request->getUri());
        $message->method('hasHeader')->willReturnCallback(
            static fn (string $field): bool => strtolower($field) === 'signature-input' || $request->hasHeader($field),
        );
        $message->method('getHeader')->willReturnCallback(
            static fn (string $field): array => strtolower($field) === 'signature-input'
                ? ["sig0=();created=1\r\nx"]
                : $request->getHeader($field),
        );

        try {
            self::signer()->sign(
                $message,
                self::key(),
                new SigningOptions(form: Form::Rfc9421, coveredComponents: ['@method', '@target-uri']),
            );
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertSame(
                'Cannot sign the message: the value of signature-input holds a line break, which a component value'
                . ' cannot',
                $exception->getMessage(),
            );
            $this->assertSame(0, $exception->getCode());
            $this->assertInstanceOf(Failure::class, $exception->getPrevious());
        }
    }

    public function testRefusesTheDraftFormUntilItIsImplemented(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The draft form is not implemented');

        self::signer()->sign(self::request(), self::key(), new SigningOptions(form: Form::Cavage));
    }

    public function testRefusesAComponentTheMessageLacks(): void
    {
        try {
            self::signer()->sign(
                self::request(),
                self::key(),
                new SigningOptions(form: Form::Rfc9421, coveredComponents: ['@method', 'x-absent']),
            );
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertSame(
                'Cannot sign the message: the field "x-absent" is not in the message',
                $exception->getMessage(),
            );
            $this->assertInstanceOf(ComponentFailure::class, $exception->getPrevious());
            $this->assertSame(0, $exception->getCode());
        }
    }

    public function testRefusesAReqComponentWithoutTheRelatedRequest(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage(
            'Cannot sign the message: a component with the req parameter needs the related request, which was not'
            . ' given',
        );

        self::signer()->sign(
            new Response(200),
            self::key(),
            new SigningOptions(form: Form::Rfc9421, coveredComponents: ['@status', '@method;req']),
        );
    }

    public function testRefusesABodyThatCannotBeRewound(): void
    {
        $pipe = fopen('php://stdin', 'r');
        $this->assertNotFalse($pipe);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The message body must be seekable');

        self::signer()->sign(
            self::request()->withBody(Stream::create($pipe)),
            self::key(),
            new SigningOptions(form: Form::Rfc9421),
        );
    }

    public function testSignsTheAppendixB26ComponentsToTheAppendixBytesExceptForTheAlgParameter(): void
    {
        // The signer always emits `alg`, so the `@signature-params` line
        // differs from the appendix's and the bytes cannot match; the base it
        // signed, with `alg`, verifies against the appendix key.
        $signed = (new Signer(new FrozenClock(new DateTimeImmutable('@1618884473'))))->sign(
            self::request('{"hello": "world"}')
                ->withHeader('Date', 'Tue, 20 Apr 2021 02:07:55 GMT')
                ->withHeader('Content-Length', '18'),
            self::key(),
            new SigningOptions(
                form: Form::Rfc9421,
                coveredComponents: ['date', '@method', '@path', '@authority', 'content-type', 'content-length'],
                label: 'sig-b26',
            ),
        );

        $this->assertSame(
            'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473'
            . ';alg="ed25519";keyid="test-key-ed25519"',
            $signed->getHeaderLine('Signature-Input'),
        );
        $this->assertNotSame(
            'wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==',
            trim(substr($signed->getHeaderLine('Signature'), 8), ':'),
        );
        $this->assertTrue(VerificationKey::fromPem(self::rfc9421Key('test-key-ed25519.public.pem'))->verify(
            Algorithm::Ed25519,
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@authority\": example.com\n"
            . "\"content-type\": application/json\n\"content-length\": 18\n"
            . '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length")'
            . ';created=1618884473;alg="ed25519";keyid="test-key-ed25519"',
            self::signatureBytes($signed, 'sig-b26'),
        ));
    }
}
