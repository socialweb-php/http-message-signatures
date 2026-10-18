<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Cavage;

use DateTimeImmutable;
use Ergebnis\Clock\FrozenClock;
use Nyholm\Psr7\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\KeyResolver;
use SocialWeb\Http\MessageSignatures\Signer;
use SocialWeb\Http\MessageSignatures\SigningKey;
use SocialWeb\Http\MessageSignatures\SigningOptions;
use SocialWeb\Http\MessageSignatures\VerificationKey;
use SocialWeb\Http\MessageSignatures\VerificationResult;
use SocialWeb\Http\MessageSignatures\Verifier;
use SocialWeb\Http\MessageSignatures\VerifierOptions;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function json_decode;
use function preg_replace_callback;

use const JSON_THROW_ON_ERROR;

/**
 * Verifies the draft form's own test values and signatures that other
 * implementations produced, and signs the test values to the same bytes
 *
 * Appendix C of draft-cavage-http-signatures-12 is used where it holds: C.1,
 * the default `date` signing, and C.2, the basic signing string. Its C.3
 * lists `(created)` and `(expires)` under `rsa-sha256`, which the draft's
 * section 2.3 forbids, and its signature is over a string without them. The
 * other signatures are Fedify's, under `tests/fixtures/cavage/fedify/`, each
 * recording its source; see the README beside them.
 */
class ExamplesTest extends TestCase
{
    /**
     * The `Date` field of the appendix C request, Sun, 05 Jan 2014 21:31:40
     * GMT
     */
    private const int APPENDIX_C_NOW = 1388957500;

    private const string C1_SIGNATURE = 'SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGK'
        . 'KCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM=';

    private const string C2_SIGNATURE = 'qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7'
        . 'ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=';

    /**
     * The request of appendix C
     */
    private static function appendixCRequest(): Request
    {
        return new Request(
            'POST',
            'https://example.com/foo?param=value&pet=dog',
            [
                'Host' => 'example.com',
                'Date' => 'Sun, 05 Jan 2014 21:31:40 GMT',
                'Content-Type' => 'application/json',
                'Digest' => 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
                'Content-Length' => '18',
            ],
            '{"hello": "world"}',
        );
    }

    /**
     * The request a Fedify fixture records, with its clock and key
     *
     * @return array{RequestInterface, int, string}
     */
    private static function fedifyRequest(string $name): array
    {
        /**
         * @var array{
         *     source: string,
         *     currentTime: int,
         *     method: string,
         *     url: string,
         *     headers: list<array{string, string}>,
         *     body: string,
         *     keyFile: string,
         * } $fixture
         */
        $fixture = json_decode(self::cavageFixture('fedify/' . $name . '.json'), true, 4, JSON_THROW_ON_ERROR);
        $request = new Request($fixture['method'], $fixture['url'], [], $fixture['body']);

        foreach ($fixture['headers'] as [$field, $value]) {
            $request = $request->withHeader($field, $value);
        }

        return [$request, $fixture['currentTime'], self::cavageFixture('fedify/' . $fixture['keyFile'])];
    }

    /**
     * @return iterable<string, array{RequestInterface, int, string, VerifierOptions, list<string>}>
     */
    public static function signaturesProvider(): iterable
    {
        // C.1 and C.2 cover neither the request target nor the digest, and
        // C.1 signs `date` alone.
        $appendixOptions = new VerifierOptions(requireTarget: false, requireContentDigest: false);
        $appendixKey = self::cavageFixture('test-key.public.pem');

        yield 'appendix C.1, the Signature field' => [
            self::appendixCRequest()->withHeader(
                'Signature',
                'keyId="Test",algorithm="rsa-sha256",signature="' . self::C1_SIGNATURE . '"',
            ),
            self::APPENDIX_C_NOW,
            $appendixKey,
            $appendixOptions,
            ['date'],
        ];
        yield 'appendix C.1, the Authorization field' => [
            self::appendixCRequest()->withHeader(
                'Authorization',
                'Signature keyId="Test",algorithm="rsa-sha256",signature="' . self::C1_SIGNATURE . '"',
            ),
            self::APPENDIX_C_NOW,
            $appendixKey,
            $appendixOptions,
            ['date'],
        ];
        yield 'appendix C.2, the Authorization field' => [
            self::appendixCRequest()->withHeader(
                'Authorization',
                'Signature keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date",'
                    . 'signature="' . self::C2_SIGNATURE . '"',
            ),
            self::APPENDIX_C_NOW,
            $appendixKey,
            $appendixOptions,
            ['(request-target)', 'host', 'date'],
        ];

        $fedify = [
            'verify-request' => ['(request-target)', 'accept', 'content-type', 'date', 'digest', 'host'],
            'oeee-cafe-hs2019' => [
                '(request-target)',
                '(created)',
                '(expires)',
                'content-type',
                'date',
                'digest',
                'host',
            ],
            'tootik-follow' => ['(request-target)', 'host', 'date', 'content-type', 'digest'],
            'tootik-send' => ['(request-target)', 'content-type', 'date', 'digest', 'host'],
        ];

        foreach ($fedify as $name => $covered) {
            [$request, $now, $key] = self::fedifyRequest($name);

            yield 'Fedify, ' . $name => [$request, $now, $key, new VerifierOptions(), $covered];
        }
    }

    /**
     * @param list<string> $covered
     */
    #[DataProvider('signaturesProvider')]
    public function testVerifies(
        RequestInterface $request,
        int $now,
        string $key,
        VerifierOptions $options,
        array $covered,
    ): void {
        $result = self::verify($request, $now, $key, $options);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame(Form::Cavage, $result->form);
        $this->assertSame(Algorithm::RsaV15Sha256, $result->algorithm);
        $this->assertSame($covered, $result->coveredComponents);
        $this->assertFalse($result->requestTargetVerifiedWithoutQuery);
    }

    /**
     * @param list<string> $covered
     */
    #[DataProvider('signaturesProvider')]
    public function testChangingAnyCoveredComponentFails(
        RequestInterface $request,
        int $now,
        string $key,
        VerifierOptions $options,
        array $covered,
    ): void {
        foreach ($covered as $name) {
            // Each change keeps the message well formed up to the signature
            // check, except the digest, which is checked before the key.
            [$changed, $reason] = match ($name) {
                '(request-target)' => [
                    $request->withRequestTarget($request->getRequestTarget() . 'x'),
                    FailureReason::SignatureInvalid,
                ],
                '(created)', '(expires)' => [
                    self::withParameterIncremented($request, $name === '(created)' ? 'created' : 'expires'),
                    FailureReason::SignatureInvalid,
                ],
                'date' => [
                    $request->withHeader('date', self::oneSecondLater($request->getHeaderLine('date'))),
                    FailureReason::SignatureInvalid,
                ],
                'digest' => [
                    $request->withHeader('digest', $request->getHeaderLine('digest') . 'x'),
                    FailureReason::DigestMismatch,
                ],
                default => [
                    $request->withHeader($name, $request->getHeaderLine($name) . 'x'),
                    FailureReason::SignatureInvalid,
                ],
            };

            $result = self::verify($changed, $now, $key, $options);

            $this->assertFalse($result->verified, $name);
            $this->assertSame($reason, $result->reason, $name);
        }
    }

    public function testSignsTheStringsOfAppendixCToTheSameBytes(): void
    {
        $signer = new Signer(new FrozenClock(new DateTimeImmutable('@' . self::APPENDIX_C_NOW)));
        $key = SigningKey::fromPem('Test', self::cavageFixture('test-key.private.pem'));

        $c1 = $signer->sign(
            self::appendixCRequest(),
            $key,
            new SigningOptions(form: Form::Cavage, coveredComponents: ['date']),
        );
        $c2 = $signer->sign(
            self::appendixCRequest(),
            $key,
            new SigningOptions(form: Form::Cavage, coveredComponents: ['(request-target)', 'host', 'date']),
        );

        $this->assertSame(
            'keyId="Test",algorithm="rsa-sha256",headers="date",signature="' . self::C1_SIGNATURE . '"',
            $c1->getHeaderLine('Signature'),
        );
        $this->assertSame(
            'keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date",signature="'
                . self::C2_SIGNATURE . '"',
            $c2->getHeaderLine('Signature'),
        );
    }

    private static function verify(
        RequestInterface $request,
        int $now,
        string $key,
        VerifierOptions $options,
    ): VerificationResult {
        $resolver = new class (VerificationKey::fromPem($key)) implements KeyResolver {
            public function __construct(private readonly VerificationKey $key)
            {
            }

            public function resolve(string $keyId): VerificationKey
            {
                return $this->key;
            }

            public function refresh(string $keyId): ?VerificationKey
            {
                return null;
            }
        };

        return (new Verifier($resolver, new FrozenClock(new DateTimeImmutable('@' . $now)), $options))
            ->verify($request);
    }

    private static function oneSecondLater(string $date): string
    {
        return (new DateTimeImmutable($date))->modify('+1 second')->format('D, d M Y H:i:s \G\M\T');
    }

    private static function withParameterIncremented(RequestInterface $request, string $parameter): RequestInterface
    {
        $field = $request->hasHeader('Signature') ? 'Signature' : 'Authorization';
        $value = (string) preg_replace_callback(
            '/(' . $parameter . '="?)([0-9]+)/',
            static fn (array $matches): string => $matches[1] . ((int) $matches[2] + 1),
            $request->getHeaderLine($field),
        );

        return $request->withHeader($field, $value);
    }
}
