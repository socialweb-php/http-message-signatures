<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use DateInterval;
use DateTimeImmutable;
use Ergebnis\Clock\FrozenClock;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
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

use function base64_encode;
use function str_replace;
use function strlen;
use function strtolower;

/**
 * Reaches every `FailureReason` of the draft form through `verify()`
 *
 * Several cases are those of the draft-form tests of Mastodon's
 * `spec/requests/signature_verification_spec.rb`, rebuilt with this package's
 * keys: a query string left out of `(request-target)`, a changed query, path,
 * or method, a `Date` field that is not a date or is too old, a digest that is
 * not signed, and a changed body.
 */
class VerifierCavageTest extends TestCase
{
    private const int NOW = 1618884473;

    /**
     * The string the draft form signs for `request()` under its defaults with
     * no content
     */
    private const string BASE = "(request-target): post /foo?param=Value&Pet=dog\nhost: example.com\n"
        . 'date: Tue, 20 Apr 2021 02:07:55 GMT';

    private static function clock(int $offset = 0): FrozenClock
    {
        return new FrozenClock(new DateTimeImmutable('@' . (self::NOW + $offset)));
    }

    private static function signingKey(string $name = 'test-key-rsa'): SigningKey
    {
        return SigningKey::fromPem($name, self::rfc9421Key($name . '.private.pem'));
    }

    private static function resolver(): ArrayKeyResolver
    {
        return new ArrayKeyResolver([
            'test-key-ed25519' => VerificationKey::fromPem(self::rfc9421Key('test-key-ed25519.public.pem')),
            'test-key-rsa' => VerificationKey::fromPem(self::rfc9421Key('test-key-rsa.public.pem')),
            'test-key-ecc-p256' => VerificationKey::fromPem(self::rfc9421Key('test-key-ecc-p256.public.pem')),
        ]);
    }

    private static function request(string $body = '', string $target = '/foo?param=Value&Pet=dog'): Request
    {
        return new Request('POST', 'https://example.com' . $target, [
            'Host' => 'example.com',
            'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
            'Content-Type' => 'application/json',
        ], $body);
    }

    /**
     * @param T $message
     * @param list<string> | null $covered
     *
     * @return T
     *
     * @template T of MessageInterface
     */
    private static function signed(
        MessageInterface $message,
        ?array $covered = null,
        string $keyName = 'test-key-rsa',
        ?DateInterval $expires = null,
    ): MessageInterface {
        return (new Signer(self::clock()))->sign(
            $message,
            self::signingKey($keyName),
            new SigningOptions(form: Form::Cavage, coveredComponents: $covered, expires: $expires),
        );
    }

    /**
     * Signs the string as given, for a signature this package's signer would
     * not write
     *
     * @param T $message
     *
     * @return T
     *
     * @template T of MessageInterface
     */
    private static function signedByHand(
        MessageInterface $message,
        string $parameters,
        string $base,
        string $keyName = 'test-key-rsa',
        Algorithm $algorithm = Algorithm::RsaV15Sha256,
    ): MessageInterface {
        $signature = base64_encode(self::signingKey($keyName)->sign($algorithm, $base));

        return $message->withHeader('Signature', $parameters . ',signature="' . $signature . '"');
    }

    private static function verify(
        MessageInterface $message,
        ?VerifierOptions $options = null,
        ?ArrayKeyResolver $resolver = null,
        int $clockOffset = 0,
    ): VerificationResult {
        $verifier = new Verifier(
            $resolver ?? self::resolver(),
            self::clock($clockOffset),
            $options ?? new VerifierOptions(),
        );

        return $verifier->verify($message);
    }

    public function testVerifiesASignedRequestAndReportsEverything(): void
    {
        $result = self::verify(self::signed(self::request('{"hello": "world"}')));

        $this->assertTrue($result->verified, $result->detail);
        $this->assertNull($result->reason);
        $this->assertSame('', $result->detail);
        $this->assertSame(Form::Cavage, $result->form);
        $this->assertSame(Algorithm::RsaV15Sha256, $result->algorithm);
        $this->assertSame('test-key-rsa', $result->keyId);
        $this->assertNull($result->label);
        $this->assertSame(['(request-target)', 'host', 'date', 'digest'], $result->coveredComponents);
        $this->assertSame(self::NOW + 2, $result->created?->getTimestamp());
        $this->assertNull($result->expires);
        $this->assertNull($result->nonce);
        $this->assertSame(256, strlen((string) $result->signature));
        $this->assertFalse($result->keyRefreshed);
        $this->assertFalse($result->requestTargetVerifiedWithoutQuery);
    }

    public function testVerifiesHs2019WithItsTimes(): void
    {
        $message = self::signed(
            self::request(),
            ['(request-target)', '(created)', '(expires)', 'host'],
            'test-key-ed25519',
            new DateInterval('PT5M'),
        );

        $result = self::verify($message);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame(Algorithm::Ed25519, $result->algorithm);
        $this->assertSame(self::NOW, $result->created?->getTimestamp());
        $this->assertSame(self::NOW + 300, $result->expires?->getTimestamp());
    }

    public function testHs2019FromAnRsaKeyIsRsaSha256(): void
    {
        $message = self::signedByHand(
            self::request(),
            'keyId="test-key-rsa",algorithm="hs2019",headers="(request-target) host date"',
            self::BASE,
        );

        $result = self::verify($message);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame(Algorithm::RsaV15Sha256, $result->algorithm);
    }

    public function testVerifiesASignedResponse(): void
    {
        $message = self::signed(new Response(200, ['Date' => 'Tue, 20 Apr 2021 02:07:55 GMT'], '{"ok": true}'));

        $result = self::verify($message);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame(['date', 'digest'], $result->coveredComponents);
    }

    public function testVerifiesTheAuthorizationField(): void
    {
        $signed = self::signed(self::request());
        $message = $signed->withoutHeader('Signature')
            ->withHeader('Authorization', 'Signature ' . $signed->getHeaderLine('Signature'));

        $this->assertTrue(self::verify($message)->verified);
    }

    public function testAcceptsARequestTargetWithoutItsQuery(): void
    {
        $message = self::signedByHand(
            self::request(),
            'keyId="test-key-rsa",algorithm="rsa-sha256",headers="(request-target) host date"',
            "(request-target): post /foo\nhost: example.com\ndate: Tue, 20 Apr 2021 02:07:55 GMT",
        );

        $result = self::verify($message);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertTrue($result->requestTargetVerifiedWithoutQuery);

        $refused = self::verify($message, new VerifierOptions(acceptRequestTargetWithoutQuery: false));

        $this->assertSame(FailureReason::SignatureInvalid, $refused->reason);
        $this->assertSame('the signature does not verify under rsa-sha256', $refused->detail);
        $this->assertFalse($refused->requestTargetVerifiedWithoutQuery);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function changedTargetProvider(): iterable
    {
        yield 'another query' => ['POST', '/foo?param=Value&Pet=cat'];
        yield 'another path' => ['POST', '/bar?param=Value&Pet=dog'];
        yield 'another method' => ['PUT', '/foo?param=Value&Pet=dog'];
    }

    #[DataProvider('changedTargetProvider')]
    public function testAChangedRequestTargetIsSignatureInvalid(string $method, string $target): void
    {
        $signed = self::signed(self::request());
        $changed = new Request($method, 'https://example.com' . $target, $signed->getHeaders());

        $result = self::verify($changed);

        $this->assertSame(FailureReason::SignatureInvalid, $result->reason);
        $this->assertFalse($result->requestTargetVerifiedWithoutQuery);
    }

    public function testADateFieldThatIsNotADateGivesNoCreationTime(): void
    {
        $message = self::signed(self::request()->withHeader('Date', 'wrong date'));

        $result = self::verify($message);

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame(
            'the signature does not cover (created) and its date field is not an HTTP date',
            $result->detail,
        );
        $this->assertNull($result->created);
    }

    public function testTheDateFieldIsReadWithItsOuterWhitespaceRemoved(): void
    {
        $signed = self::signed(self::request());
        $message = $this->withField($signed, 'Date', "\t" . $signed->getHeaderLine('Date') . ' ');

        $result = self::verify($message);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame(self::NOW + 2, $result->created?->getTimestamp());
    }

    public function testACoveredDateFieldTheMessageLacksGivesNoCreationTime(): void
    {
        $message = self::signedByHand(
            self::request()->withoutHeader('Date'),
            'keyId="test-key-rsa",algorithm="rsa-sha256",headers="(request-target) host date"',
            self::BASE,
        );

        $result = self::verify($message);

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the signature covers date and the message has no Date field', $result->detail);
    }

    public function testTheCreationTimeRule(): void
    {
        $message = self::signed(self::request(), ['(request-target)', 'host']);

        $result = self::verify($message);

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the signature covers neither (created) nor date', $result->detail);
        $this->assertTrue(self::verify($message, new VerifierOptions(requireCreationTime: false))->verified);
    }

    public function testACreatedParameterCountsOnlyWhenCreatedIsCovered(): void
    {
        $signed = self::signed(self::request());
        $replayed = $signed->withHeader(
            'Signature',
            'created=' . (self::NOW + 3903) . ',' . $signed->getHeaderLine('Signature'),
        );

        $result = self::verify($replayed, clockOffset: 3903);

        $this->assertSame(FailureReason::Expired, $result->reason);
        $this->assertSame(self::NOW + 2, $result->created?->getTimestamp());

        $uncovered = self::signedByHand(
            self::request(),
            'keyId="test-key-ed25519",algorithm="hs2019",created=' . self::NOW . ',headers="(request-target) host"',
            "(request-target): post /foo?param=Value&Pet=dog\nhost: example.com",
            'test-key-ed25519',
            Algorithm::Ed25519,
        );

        $result = self::verify($uncovered);

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the signature covers neither (created) nor date', $result->detail);
    }

    public function testAnExpiresParameterCountsOnlyWhenExpiresIsCovered(): void
    {
        $signed = self::signed(self::request(), ['(request-target)', '(created)', 'host'], 'test-key-ed25519');
        $shortened = $signed->withHeader(
            'Signature',
            'expires=' . (self::NOW + 1) . ',' . $signed->getHeaderLine('Signature'),
        );

        $result = self::verify($shortened, clockOffset: 3602);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertNull($result->expires);
    }

    public function testACreatedOfFifteenDigitsIsNotYetValid(): void
    {
        $message = self::signedByHand(
            self::request(),
            'keyId="test-key-ed25519",algorithm="hs2019",created=999999999999999,'
                . 'headers="(request-target) (created) host"',
            "(request-target): post /foo?param=Value&Pet=dog\n(created): 999999999999999\nhost: example.com",
            'test-key-ed25519',
            Algorithm::Ed25519,
        );

        $result = self::verify($message);

        $this->assertSame(FailureReason::NotYetValid, $result->reason);
        $this->assertSame(999999999999999, $result->created?->getTimestamp());
    }

    public function testTheTimePolicyJudgesTheDateField(): void
    {
        $message = self::signed(self::request());

        $this->assertSame(FailureReason::Expired, self::verify($message, clockOffset: 3600 + 300 + 3)->reason);
        $this->assertTrue(self::verify($message, clockOffset: 3600 + 300 + 2)->verified);
        $this->assertSame(FailureReason::NotYetValid, self::verify($message, clockOffset: -3600 - 1)->reason);
    }

    public function testTheTargetRule(): void
    {
        $message = self::signed(self::request(), ['host', 'date']);

        $result = self::verify($message);

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the signature does not cover (request-target)', $result->detail);
        $this->assertFalse($result->keyRefreshed);
        $this->assertFalse($result->requestTargetVerifiedWithoutQuery);
        $this->assertTrue(self::verify($message, new VerifierOptions(requireTarget: false))->verified);
    }

    public function testTheContentDigestRule(): void
    {
        $message = self::signed(self::request('Hello world'), ['(request-target)', 'host', 'date']);

        $result = self::verify($message);

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame(
            'the message has content and the signature does not cover its digest field',
            $result->detail,
        );
    }

    public function testAChangedBodyIsADigestMismatchBeforeTheKeyIsLookedUp(): void
    {
        $signed = self::signed(self::request('Hello world'));
        $resolver = self::resolver();

        $result = self::verify($signed->withBody(self::request('Hello world!')->getBody()), resolver: $resolver);

        $this->assertSame(FailureReason::DigestMismatch, $result->reason);
        $this->assertSame([], $resolver->resolved);
    }

    public function testTheRequiredComponentsThatApplyToTheDraft(): void
    {
        $message = self::signed(self::request());

        $this->assertTrue(
            self::verify($message, new VerifierOptions(requiredComponents: ['(request-target)', '@method']))->verified,
        );

        $result = self::verify($message, new VerifierOptions(requiredComponents: ['@method', 'content-type']));

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the required component content-type is not covered', $result->detail);
    }

    public function testRequiredFieldNamesAreMetByTheFieldsADraftSignatureCovers(): void
    {
        $message = self::signed(self::request('{"hello": "world"}'));
        $options = new VerifierOptions(requiredComponents: ['Host', 'date', '(request-target)', 'digest']);

        $result = self::verify($message, $options);

        $this->assertTrue($result->verified, $result->detail);
    }

    public function testTheNonceRuleDoesNotApplyToTheDraft(): void
    {
        $result = self::verify(self::signed(self::request()), new VerifierOptions(requireNonce: true));

        $this->assertTrue($result->verified);
    }

    public function testAMalformedFieldIsReportedWithTheForm(): void
    {
        $result = self::verify(self::request()->withHeader('Signature', 'keyId="k"'));

        $this->assertSame(FailureReason::MalformedSignature, $result->reason);
        $this->assertSame('the signature parameter is absent or empty', $result->detail);
        $this->assertSame(Form::Cavage, $result->form);
        $this->assertNull($result->keyId);
    }

    public function testAnAlgorithmThePackageDoesNotKnowIsUnsupportedBeforeTheKeyIsLookedUp(): void
    {
        $resolver = self::resolver();
        $message = self::signedByHand(
            self::request(),
            'keyId="test-key-rsa",algorithm="rsa-sha1",headers="(request-target) host date"',
            self::BASE,
        );

        $result = self::verify($message, resolver: $resolver);

        $this->assertSame(FailureReason::UnsupportedSignature, $result->reason);
        $this->assertSame('the algorithm "rsa-sha1" is not one the package knows', $result->detail);
        $this->assertSame('test-key-rsa', $result->keyId);
        $this->assertSame([], $resolver->resolved);
    }

    public function testAComponentTheMessageLacksIsMissingBeforeTheKeyIsLookedUp(): void
    {
        $resolver = self::resolver();
        $message = self::signedByHand(
            self::request(),
            'keyId="test-key-rsa",algorithm="rsa-sha256",headers="(request-target) date x-absent"',
            self::BASE,
        );

        $result = self::verify($message, resolver: $resolver);

        $this->assertSame(FailureReason::MissingComponent, $result->reason);
        $this->assertSame('the field "x-absent" is not in the message', $result->detail);
        $this->assertSame([], $resolver->resolved);
    }

    public function testTheTimesUnderANamedAlgorithmAreMalformed(): void
    {
        $message = self::signedByHand(
            self::request(),
            'keyId="test-key-rsa",algorithm="rsa-sha256",created=1618884473,headers="(request-target) (created)"',
            "(request-target): post /foo?param=Value&Pet=dog\n(created): 1618884473",
        );

        $result = self::verify($message);

        $this->assertSame(FailureReason::MalformedSignature, $result->reason);
        $this->assertSame('(created) cannot be covered under the algorithm rsa-sha256', $result->detail);
    }

    public function testACoveredCreatedWithoutItsParameterIsReportedByThePolicyFirst(): void
    {
        $signed = self::signed(
            self::request(),
            ['(request-target)', '(created)', 'host', 'date'],
            'test-key-ed25519',
        );
        $message = $signed->withHeader(
            'Signature',
            str_replace('created=' . self::NOW . ',', '', $signed->getHeaderLine('Signature')),
        );

        $result = self::verify($message);

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('(created) is covered and the created parameter is absent', $result->detail);
        $this->assertSame(
            FailureReason::MalformedSignature,
            self::verify($message, new VerifierOptions(requireCreationTime: false))->reason,
        );
    }

    public function testAKeyTheResolverDoesNotHaveIsNotFound(): void
    {
        $message = self::signedByHand(
            self::request(),
            'keyId="unknown",algorithm="rsa-sha256",headers="(request-target) host date"',
            self::BASE,
        );

        $result = self::verify($message);

        $this->assertSame(FailureReason::KeyNotFound, $result->reason);
        $this->assertSame('the resolver has no key "unknown"', $result->detail);
        $this->assertFalse($result->keyRefreshed);
        $this->assertFalse($result->requestTargetVerifiedWithoutQuery);
    }

    public function testANamedAlgorithmTheKeyDoesNotPermitIsRefused(): void
    {
        $message = self::signedByHand(
            self::request(),
            'keyId="test-key-ed25519",algorithm="rsa-sha256",headers="(request-target) host date"',
            self::BASE,
        );

        $result = self::verify($message);

        $this->assertSame(FailureReason::AlgorithmNotPermitted, $result->reason);
        $this->assertSame('the key does not permit rsa-sha256', $result->detail);
        $this->assertTrue($result->keyRefreshed);
    }

    public function testAKeyWithNoAlgorithmInTheDraftFormIsRefused(): void
    {
        $message = self::signedByHand(
            self::request(),
            'keyId="test-key-ecc-p256",algorithm="hs2019",headers="(request-target) host date"',
            self::BASE,
        );

        $result = self::verify($message);

        $this->assertSame(FailureReason::AlgorithmNotPermitted, $result->reason);
        $this->assertSame(
            'the key permits no algorithm that has a name in the form draft-cavage-http-signatures-12',
            $result->detail,
        );
        $this->assertNull($result->algorithm);
    }

    /**
     * A PSR-7 implementation that, unlike nyholm/psr7, keeps the whitespace
     * around a field value: the request as given, with one field set to the
     * value
     */
    private function withField(Request $request, string $name, string $value): RequestInterface
    {
        $message = $this->createStub(RequestInterface::class);
        $message->method('getBody')->willReturn($request->getBody());
        $message->method('getMethod')->willReturn($request->getMethod());
        $message->method('getUri')->willReturn($request->getUri());
        $message->method('getRequestTarget')->willReturn($request->getRequestTarget());
        $message->method('hasHeader')->willReturnCallback(
            static fn (string $field): bool => strtolower($field) === strtolower($name) || $request->hasHeader($field),
        );
        $message->method('getHeader')->willReturnCallback(
            static fn (string $field): array => strtolower($field) === strtolower($name)
                ? [$value]
                : $request->getHeader($field),
        );
        $message->method('getHeaderLine')->willReturnCallback(
            static fn (string $field): string => strtolower($field) === strtolower($name)
                ? $value
                : $request->getHeaderLine($field),
        );

        return $message;
    }

    public function testARefreshThatReturnsTheRightKeyVerifies(): void
    {
        $resolver = new ArrayKeyResolver(
            ['test-key-rsa' => VerificationKey::fromPem(self::rfc9421Key('test-key-rsa-pss.public.pem'), [
                Algorithm::RsaV15Sha256,
            ]),
            ],
            ['test-key-rsa' => VerificationKey::fromPem(self::rfc9421Key('test-key-rsa.public.pem'))],
        );

        $result = self::verify(self::signed(self::request()), resolver: $resolver);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertTrue($result->keyRefreshed);
        $this->assertSame(['test-key-rsa'], $resolver->refreshed);
    }
}
