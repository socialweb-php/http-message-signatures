<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use DateInterval;
use DateTimeImmutable;
use Ergebnis\Clock\FrozenClock;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\Stream;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use RuntimeException;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\KeyResolver;
use SocialWeb\Http\MessageSignatures\Signer;
use SocialWeb\Http\MessageSignatures\SigningKey;
use SocialWeb\Http\MessageSignatures\SigningOptions;
use SocialWeb\Http\MessageSignatures\TimePolicy;
use SocialWeb\Http\MessageSignatures\VerificationKey;
use SocialWeb\Http\MessageSignatures\VerificationResult;
use SocialWeb\Http\MessageSignatures\Verifier;
use SocialWeb\Http\MessageSignatures\VerifierOptions;

use function fopen;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function strlen;
use function strtolower;

use const OPENSSL_KEYTYPE_EC;

/**
 * Reaches every `FailureReason` through `verify()`, and proves the order of
 * the checks, the per-label loop, and the retry with a refreshed key
 *
 * The messages are signed by `Signer`, whose own tests pin what it writes;
 * `Rfc9421\ExamplesTest` proves the verifier against the RFC's own
 * signatures.
 */
class VerifierTest extends TestCase
{
    private const int NOW = 1618884473;

    private static function clock(int $offset = 0): FrozenClock
    {
        return new FrozenClock(new DateTimeImmutable('@' . (self::NOW + $offset)));
    }

    private static function signingKey(string $name = 'test-key-ed25519'): SigningKey
    {
        return $name === 'test-shared-secret'
            ? SigningKey::fromSharedSecret($name, self::rfc9421SharedSecret())
            : SigningKey::fromPem($name, self::rfc9421Key($name . '.private.pem'));
    }

    /**
     * @param list<Algorithm> | null $permitted
     */
    private static function verificationKey(
        string $name = 'test-key-ed25519',
        ?array $permitted = null,
    ): VerificationKey {
        return $name === 'test-shared-secret'
            ? VerificationKey::fromSharedSecret(self::rfc9421SharedSecret(), $permitted)
            : VerificationKey::fromPem(self::rfc9421Key($name . '.public.pem'), $permitted);
    }

    private static function resolver(): ArrayKeyResolver
    {
        return new ArrayKeyResolver([
            'test-key-ed25519' => self::verificationKey(),
            'test-key-rsa' => self::verificationKey('test-key-rsa'),
            'test-key-ecc-p256' => self::verificationKey('test-key-ecc-p256'),
            'test-shared-secret' => self::verificationKey('test-shared-secret'),
        ]);
    }

    private static function request(string $body = ''): Request
    {
        return new Request('POST', 'https://example.com/foo?param=Value&Pet=dog', [
            'Host' => 'example.com',
            'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
            'Content-Type' => 'application/json',
            'X-Custom' => 'custom',
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
        string $keyName = 'test-key-ed25519',
        int $clockOffset = 0,
        ?Algorithm $algorithm = null,
        bool $created = true,
        ?DateInterval $expires = null,
        ?string $nonce = null,
        string $label = 'sig1',
        ?Request $relatedRequest = null,
    ): MessageInterface {
        return (new Signer(self::clock($clockOffset)))->sign(
            $message,
            self::signingKey($keyName),
            new SigningOptions(
                form: Form::Rfc9421,
                coveredComponents: $covered,
                algorithm: $algorithm,
                label: $label,
                created: $created,
                expires: $expires,
                nonce: $nonce,
            ),
            $relatedRequest,
        );
    }

    private static function verify(
        MessageInterface $message,
        ?VerifierOptions $options = null,
        ?KeyResolver $resolver = null,
        int $clockOffset = 0,
        ?Request $relatedRequest = null,
    ): VerificationResult {
        $verifier = new Verifier(
            $resolver ?? self::resolver(),
            self::clock($clockOffset),
            $options ?? new VerifierOptions(),
        );

        return $verifier->verify($message, $relatedRequest);
    }

    public function testVerifiesASignedRequestAndReportsEverything(): void
    {
        $message = self::signed(
            self::request('{"hello": "world"}'),
            expires: new DateInterval('PT5M'),
            nonce: 'n1',
        );

        $result = self::verify($message);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertNull($result->reason);
        $this->assertSame('', $result->detail);
        $this->assertSame(Form::Rfc9421, $result->form);
        $this->assertSame(Algorithm::Ed25519, $result->algorithm);
        $this->assertSame('test-key-ed25519', $result->keyId);
        $this->assertSame('sig1', $result->label);
        $this->assertSame(['@method', '@target-uri', 'host', 'date', 'content-digest'], $result->coveredComponents);
        $this->assertSame(self::NOW, $result->created?->getTimestamp());
        $this->assertSame(self::NOW + 300, $result->expires?->getTimestamp());
        $this->assertSame('n1', $result->nonce);
        $this->assertSame(64, strlen((string) $result->signature));
        $this->assertFalse($result->keyRefreshed);
        $this->assertFalse($result->requestTargetVerifiedWithoutQuery);
    }

    public function testVerifiesASignedResponseWithItsRequest(): void
    {
        $request = self::request('{"hello": "world"}');
        $response = self::signed(
            new Response(200, ['Date' => 'Tue, 20 Apr 2021 02:07:56 GMT'], '{"message": "good dog"}'),
            ['@status', '@method;req', '@target-uri;req', 'content-digest'],
            relatedRequest: $request,
        );

        $this->assertTrue(self::verify($response, relatedRequest: $request)->verified);

        $withoutTheRequest = self::verify($response);

        $this->assertSame(FailureReason::MissingComponent, $withoutTheRequest->reason);
    }

    public function testAMessageWithNeitherFieldHasNoSignature(): void
    {
        $result = self::verify(self::request());

        $this->assertFalse($result->verified);
        $this->assertSame(FailureReason::NoSignature, $result->reason);
        $this->assertSame('the message has neither Signature-Input nor Signature', $result->detail);
        $this->assertNull($result->form);
        $this->assertNull($result->keyId);
    }

    public function testAnAuthorizationFieldOfAnotherSchemeIsNoSignature(): void
    {
        $this->assertSame(
            FailureReason::NoSignature,
            self::verify(self::request()->withHeader('Authorization', 'Bearer token'))->reason,
        );
        // The scheme is the first word only.
        $this->assertSame(
            FailureReason::NoSignature,
            self::verify(self::request()->withHeader('Authorization', 'Bearer signature token'))->reason,
        );
    }

    public function testAnAuthorizationFieldOfTheSignatureSchemeWithALineBreakIsTheDraftForm(): void
    {
        $message = $this->withField(self::request(), 'Authorization', "Signature a\r\nb");

        $result = self::verify($message);

        $this->assertFalse($result->verified);
        $this->assertSame(FailureReason::UnsupportedSignature, $result->reason);
        $this->assertSame('the draft form is not implemented', $result->detail);
        $this->assertSame(Form::Cavage, $result->form);
    }

    public function testAnAuthorizationFieldOfAnotherSchemeWithALineBreakIsNoSignature(): void
    {
        $message = $this->withField(self::request(), 'Authorization', "Bearer x\r\ny");

        $result = self::verify($message);

        $this->assertFalse($result->verified);
        $this->assertSame(FailureReason::NoSignature, $result->reason);
        $this->assertSame('the message has neither Signature-Input nor Signature', $result->detail);
        $this->assertNull($result->form);
    }

    /**
     * @return iterable<string, array{Request}>
     */
    public static function draftFormProvider(): iterable
    {
        yield 'a Signature field' => [self::request()->withHeader('Signature', 'keyId="k",signature="AQ=="')];
        yield 'an Authorization field with the Signature scheme' => [
            self::request()->withHeader('Authorization', 'Signature keyId="k",signature="AQ=="'),
        ];
        yield 'the scheme in another case' => [
            self::request()->withHeader('Authorization', 'signature keyId="k",signature="AQ=="'),
        ];
    }

    #[DataProvider('draftFormProvider')]
    public function testTheDraftFormIsDetectedAndNotImplementedYet(Request $request): void
    {
        $result = self::verify($request);

        $this->assertFalse($result->verified);
        $this->assertSame(FailureReason::UnsupportedSignature, $result->reason);
        $this->assertSame('the draft form is not implemented', $result->detail);
        $this->assertSame(Form::Cavage, $result->form);
    }

    public function testSignatureInputDecidesTheFormWhenBothFieldsArePresent(): void
    {
        $result = self::verify(self::signed(self::request())->withHeader('Authorization', 'Signature keyId="k"'));

        $this->assertTrue($result->verified);
        $this->assertSame(Form::Rfc9421, $result->form);
    }

    public function testAFormTheOptionsExcludeIsUnsupported(): void
    {
        $result = self::verify(self::signed(self::request()), new VerifierOptions(forms: [Form::Cavage]));

        $this->assertSame(FailureReason::UnsupportedSignature, $result->reason);
        $this->assertSame('the form rfc9421 is not accepted', $result->detail);
        $this->assertSame(Form::Rfc9421, $result->form);

        $draft = self::verify(
            self::request()->withHeader('Signature', 'keyId="k"'),
            new VerifierOptions(forms: [Form::Rfc9421]),
        );

        $this->assertSame('the form draft-cavage-http-signatures-12 is not accepted', $draft->detail);
        $this->assertSame(Form::Cavage, $draft->form);
    }

    public function testTwoEmptySignatureFieldsAreMalformed(): void
    {
        $result = self::verify(self::request()->withHeader('Signature-Input', '')->withHeader('Signature', ''));

        $this->assertSame(FailureReason::MalformedSignature, $result->reason);
        $this->assertSame('the Signature-Input field has no members', $result->detail);
        $this->assertSame(Form::Rfc9421, $result->form);
    }

    public function testAMalformedFieldIsReportedWithTheFormAndNoLabel(): void
    {
        $result = self::verify(self::signed(self::request())->withoutHeader('Signature'));

        $this->assertSame(FailureReason::MalformedSignature, $result->reason);
        $this->assertSame('the message has a signature-input field and no signature field', $result->detail);
        $this->assertSame(Form::Rfc9421, $result->form);
        $this->assertNull($result->label);
        $this->assertNull($result->keyId);
    }

    public function testAnAlgorithmThePackageDoesNotKnowIsUnsupportedBeforeTheKeyIsLookedUp(): void
    {
        $resolver = self::resolver();
        $message = self::request()
            ->withHeader(
                'Signature-Input',
                'sig1=("@method" "@target-uri");created=1618884473;alg="rsa-sha256";keyid="test-key-rsa"',
            )
            ->withHeader('Signature', 'sig1=:AQ==:');

        $result = self::verify($message, resolver: $resolver);

        $this->assertSame(FailureReason::UnsupportedSignature, $result->reason);
        $this->assertSame('the algorithm "rsa-sha256" is not one the package knows', $result->detail);
        $this->assertSame('sig1', $result->label);
        $this->assertSame('test-key-rsa', $result->keyId);
        $this->assertSame([], $resolver->resolved);
    }

    /**
     * @return iterable<string, array{list<string>, bool}>
     */
    public static function targetRuleProvider(): iterable
    {
        yield '@method with @target-uri' => [['@method', '@target-uri'], true];
        yield '@method with @authority and @path' => [['@method', '@authority', '@path'], true];
        yield '@method with @authority and @request-target' => [['@method', '@authority', '@request-target'], true];
        yield '@target-uri without @method' => [['@target-uri', '@authority', '@path'], false];
        yield '@method with @authority only' => [['@method', '@authority'], false];
        yield '@method with @path only' => [['@method', '@path'], false];
        yield 'nothing' => [[], false];
    }

    /**
     * @param list<string> $covered
     */
    #[DataProvider('targetRuleProvider')]
    public function testTheTargetRuleForARequest(array $covered, bool $satisfied): void
    {
        $result = self::verify(self::signed(self::request(), $covered));

        $this->assertSame($satisfied, $result->verified, $result->detail);

        if (!$satisfied) {
            $this->assertSame(FailureReason::PolicyViolation, $result->reason);
            $this->assertSame('the signature does not cover the request target', $result->detail);
        }
    }

    public function testTheTargetRuleForAResponseIsStatus(): void
    {
        $response = new Response(200, ['Date' => 'Tue, 20 Apr 2021 02:07:56 GMT']);

        $this->assertTrue(self::verify(self::signed($response, ['@status']))->verified);

        $result = self::verify(self::signed($response, ['date']));

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the signature does not cover @status', $result->detail);
    }

    public function testTheTargetRuleCanBeTurnedOff(): void
    {
        $result = self::verify(self::signed(self::request(), ['date']), new VerifierOptions(requireTarget: false));

        $this->assertTrue($result->verified, $result->detail);
    }

    public function testAComponentWithTheReqParameterDoesNotSatisfyTheTargetRule(): void
    {
        $response = self::signed(
            new Response(200),
            ['@method;req', '@target-uri;req'],
            relatedRequest: self::request(),
        );

        $result = self::verify($response, new VerifierOptions(requireTarget: false), relatedRequest: self::request());
        $this->assertTrue($result->verified, $result->detail);

        $result = self::verify($response, relatedRequest: self::request());
        $this->assertSame('the signature does not cover @status', $result->detail);
    }

    public function testTheCreationTimeRule(): void
    {
        $message = self::signed(self::request(), created: false);

        $result = self::verify($message);

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the signature has no created parameter', $result->detail);
        $this->assertNull($result->created);

        $this->assertTrue(self::verify($message, new VerifierOptions(requireCreationTime: false))->verified);
    }

    public function testExpiresAloneIsJudgedWhenTheCreationTimeIsNotRequired(): void
    {
        $message = self::signed(self::request(), created: false, expires: new DateInterval('PT5M'));
        $options = new VerifierOptions(requireCreationTime: false);

        $this->assertTrue(self::verify($message, $options)->verified);

        $result = self::verify($message, $options, clockOffset: 300 + 3600 + 1);

        $this->assertSame(FailureReason::Expired, $result->reason);
        $this->assertSame('the effective expiry has passed', $result->detail);
        $this->assertNull($result->created);
        $this->assertSame(self::NOW + 300, $result->expires?->getTimestamp());
    }

    public function testTheContentDigestRule(): void
    {
        $message = self::signed(self::request('{"hello": "world"}'), ['@method', '@target-uri']);

        $result = self::verify($message);

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the message has content and the signature does not cover its digest field', $result->detail);

        $this->assertTrue(self::verify($message, new VerifierOptions(requireContentDigest: false))->verified);
        $this->assertTrue(self::verify(self::signed(self::request(), ['@method', '@target-uri']))->verified);
    }

    public function testTheContentDigestRuleAcceptsEitherDigestFieldOfTheMessageItself(): void
    {
        $body = '{"hello": "world"}';

        $this->assertTrue(
            self::verify(self::signed(self::request($body), ['@method', '@target-uri', 'digest']))->verified,
        );
        $this->assertTrue(
            self::verify(self::signed(self::request($body), ['@method', '@target-uri', 'content-digest;sf']))->verified,
        );

        $request = self::signed(self::request($body));
        $response = self::signed(
            new Response(200, [], 'content'),
            ['@status', 'content-digest;req'],
            relatedRequest: $request,
        );

        $result = self::verify($response, relatedRequest: $request);

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the message has content and the signature does not cover its digest field', $result->detail);
    }

    public function testTheNonceRule(): void
    {
        $result = self::verify(self::signed(self::request()), new VerifierOptions(requireNonce: true));

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the signature has no nonce parameter', $result->detail);

        $this->assertTrue(
            self::verify(self::signed(self::request(), nonce: 'n'), new VerifierOptions(requireNonce: true))->verified,
        );
    }

    public function testTheRequiredComponentsRule(): void
    {
        $message = self::signed(self::request(), ['@method', '@target-uri', '@query-param;name="Pet"']);

        $result = self::verify($message, new VerifierOptions(requiredComponents: ['@method', 'date']));

        $this->assertSame(FailureReason::PolicyViolation, $result->reason);
        $this->assertSame('the required component date is not covered', $result->detail);

        $this->assertTrue(self::verify(
            $message,
            new VerifierOptions(requiredComponents: ['@query-param;name="Pet"', '@method']),
        )->verified);

        $result = self::verify($message, new VerifierOptions(requiredComponents: ['@query-param;name="pet"']));

        $this->assertSame('the required component @query-param;name="pet" is not covered', $result->detail);
    }

    public function testTheTimePolicy(): void
    {
        $message = self::signed(self::request());

        $notYetValid = self::verify($message, clockOffset: -3601);

        $this->assertSame(FailureReason::NotYetValid, $notYetValid->reason);
        $this->assertSame('the created parameter is beyond the clock skew', $notYetValid->detail);

        $expired = self::verify($message, clockOffset: 300 + 3600 + 1);

        $this->assertSame(FailureReason::Expired, $expired->reason);
        $this->assertSame('the effective expiry has passed', $expired->detail);

        $lenient = new VerifierOptions(timePolicy: new TimePolicy(defaultLifetime: new DateInterval('PT1H')));

        $this->assertTrue(self::verify($message, $lenient, clockOffset: 300 + 3600 + 1)->verified);
    }

    public function testAMissingComponentIsReportedBeforeTheKeyIsLookedUp(): void
    {
        $resolver = self::resolver();
        $message = self::signed(self::request(), ['@method', '@target-uri', 'x-custom'])->withoutHeader('X-Custom');

        $result = self::verify($message, resolver: $resolver);

        $this->assertSame(FailureReason::MissingComponent, $result->reason);
        $this->assertSame('the field "x-custom" is not in the message', $result->detail);
        $this->assertSame([], $resolver->resolved);
    }

    public function testADigestMismatchIsReportedBeforeTheKeyIsLookedUp(): void
    {
        $resolver = self::resolver();
        $message = self::signed(self::request('{"hello": "world"}'))->withBody(Stream::create('{"hello": "there"}'));

        $result = self::verify($message, resolver: $resolver);

        $this->assertSame(FailureReason::DigestMismatch, $result->reason);
        $this->assertSame('the sha-256 digest in content-digest does not match the content', $result->detail);
        $this->assertSame([], $resolver->resolved);
    }

    public function testACoveredDigestFieldWithALineBreakIsAResult(): void
    {
        $resolver = self::resolver();
        $signed = self::signed(self::request('{"hello": "world"}'), ['@method', '@target-uri', 'content-digest;bs']);
        $message = $this->withField($signed, 'Content-Digest', $signed->getHeaderLine('Content-Digest') . "\r\nx");

        $result = self::verify($message, resolver: $resolver);

        $this->assertFalse($result->verified);
        $this->assertSame(FailureReason::MissingComponent, $result->reason);
        $this->assertSame(
            'the value of content-digest holds a line break, which a component value cannot',
            $result->detail,
        );
        $this->assertSame('sig1', $result->label);
        $this->assertSame([], $resolver->resolved);
    }

    public function testAKeyTheResolverDoesNotHaveIsNotFound(): void
    {
        $resolver = new ArrayKeyResolver([]);

        $result = self::verify(self::signed(self::request()), resolver: $resolver);

        $this->assertSame(FailureReason::KeyNotFound, $result->reason);
        $this->assertSame('the resolver has no key "test-key-ed25519"', $result->detail);
        $this->assertSame(['test-key-ed25519'], $resolver->resolved);
        $this->assertSame([], $resolver->refreshed);
        $this->assertFalse($result->keyRefreshed);
    }

    public function testWhatTheResolverThrowsPassesThrough(): void
    {
        $resolver = new class implements KeyResolver {
            public function resolve(string $keyId): ?VerificationKey
            {
                throw new RuntimeException('the key server is down');
            }

            public function refresh(string $keyId): ?VerificationKey
            {
                return null;
            }
        };

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('the key server is down');

        self::verify(self::signed(self::request()), resolver: $resolver);
    }

    public function testAnAlgorithmTheKeyDoesNotPermitIsRefused(): void
    {
        $message = self::signed(self::request(), keyName: 'test-key-rsa', algorithm: Algorithm::RsaV15Sha256);
        $resolver = new ArrayKeyResolver([
            'test-key-rsa' => self::verificationKey('test-key-rsa', [Algorithm::RsaPssSha512]),
        ]);

        $result = self::verify($message, new VerifierOptions(retryWithRefreshedKey: false), $resolver);

        $this->assertSame(FailureReason::AlgorithmNotPermitted, $result->reason);
        $this->assertSame('the key does not permit rsa-v1_5-sha256', $result->detail);
        $this->assertSame(Algorithm::RsaV15Sha256, $result->algorithm);
        $this->assertSame([], $resolver->refreshed);
    }

    public function testARefreshedKeyThatPermitsTheAlgorithmVerifies(): void
    {
        $message = self::signed(self::request(), keyName: 'test-key-rsa', algorithm: Algorithm::RsaV15Sha256);
        $resolver = new ArrayKeyResolver(
            ['test-key-rsa' => self::verificationKey('test-key-rsa', [Algorithm::RsaPssSha512])],
            ['test-key-rsa' => self::verificationKey('test-key-rsa')],
        );

        $result = self::verify($message, resolver: $resolver);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertTrue($result->keyRefreshed);
        $this->assertSame(['test-key-rsa'], $resolver->refreshed);
    }

    public function testAWrongKeyOfTheSameTypeIsSignatureInvalid(): void
    {
        $message = self::signed(self::request(), keyName: 'test-key-ecc-p256');
        $other = self::generatedP256Key();
        $resolver = new ArrayKeyResolver(['test-key-ecc-p256' => $other]);

        $result = self::verify($message, new VerifierOptions(retryWithRefreshedKey: false), $resolver);

        $this->assertSame(FailureReason::SignatureInvalid, $result->reason);
        $this->assertSame('the signature "sig1" does not verify under ecdsa-p256-sha256', $result->detail);
        $this->assertSame(Algorithm::EcdsaP256Sha256, $result->algorithm);
        $this->assertFalse($result->keyRefreshed);
        $this->assertSame([], $resolver->refreshed);
    }

    public function testARefreshThatReturnsTheRightKeyVerifies(): void
    {
        $message = self::signed(self::request(), keyName: 'test-key-ecc-p256');
        $resolver = new ArrayKeyResolver(
            ['test-key-ecc-p256' => self::generatedP256Key()],
            ['test-key-ecc-p256' => self::verificationKey('test-key-ecc-p256')],
        );

        $result = self::verify($message, resolver: $resolver);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertTrue($result->keyRefreshed);
        $this->assertSame(['test-key-ecc-p256'], $resolver->resolved);
        $this->assertSame(['test-key-ecc-p256'], $resolver->refreshed);
    }

    public function testARefreshThatReturnsNullLeavesTheReasonStanding(): void
    {
        $message = self::signed(self::request(), keyName: 'test-key-ecc-p256');
        $resolver = new class (self::generatedP256Key()) implements KeyResolver {
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

        $result = self::verify($message, resolver: $resolver);

        $this->assertSame(FailureReason::SignatureInvalid, $result->reason);
        $this->assertTrue($result->keyRefreshed);
    }

    public function testARefreshThatReturnsAnotherWrongKeyFailsOnce(): void
    {
        $message = self::signed(self::request(), keyName: 'test-key-ecc-p256');
        $resolver = new ArrayKeyResolver(
            ['test-key-ecc-p256' => self::generatedP256Key()],
            ['test-key-ecc-p256' => self::generatedP256Key()],
        );

        $result = self::verify($message, resolver: $resolver);

        $this->assertSame(FailureReason::SignatureInvalid, $result->reason);
        $this->assertTrue($result->keyRefreshed);
        $this->assertSame(['test-key-ecc-p256'], $resolver->refreshed);
    }

    public function testTriesTheLabelsInOrderUntilOneVerifies(): void
    {
        $message = self::signed(
            self::signed(self::request(), keyName: 'test-key-rsa', label: 'first'),
            label: 'second',
        );
        $resolver = new ArrayKeyResolver(['test-key-ed25519' => self::verificationKey()]);

        $result = self::verify($message, resolver: $resolver);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame('second', $result->label);
        $this->assertSame(['test-key-rsa', 'test-key-ed25519'], $resolver->resolved);
    }

    public function testReportsTheLastLabelTriedWhenNoneVerifies(): void
    {
        $message = self::signed(
            self::signed(self::request(), keyName: 'test-key-rsa', label: 'first'),
            label: 'second',
        );
        $resolver = new ArrayKeyResolver([]);

        $result = self::verify($message, resolver: $resolver);

        $this->assertSame(FailureReason::KeyNotFound, $result->reason);
        $this->assertSame('second', $result->label);
        $this->assertSame('the resolver has no key "test-key-ed25519"', $result->detail);
    }

    public function testStopsAtTheSignatureLimit(): void
    {
        $message = self::signed(
            self::signed(self::request(), keyName: 'test-key-rsa', label: 'first'),
            label: 'second',
        );
        $resolver = new ArrayKeyResolver(['test-key-ed25519' => self::verificationKey()]);

        $result = self::verify($message, new VerifierOptions(maxSignatures: 1), $resolver);

        $this->assertSame(FailureReason::KeyNotFound, $result->reason);
        $this->assertSame('first', $result->label);
        $this->assertSame(['test-key-rsa'], $resolver->resolved);
    }

    public function testStopsAtTheFirstLabelThatVerifies(): void
    {
        $message = self::signed(
            self::signed(self::request(), label: 'first'),
            keyName: 'test-key-rsa',
            label: 'second',
        );
        $resolver = self::resolver();

        $result = self::verify($message, resolver: $resolver);

        $this->assertTrue($result->verified);
        $this->assertSame('first', $result->label);
        $this->assertSame(['test-key-ed25519'], $resolver->resolved);
    }

    public function testTheKeyDecidesTheAlgorithmWhenAlgIsAbsent(): void
    {
        // The covered components, parameters, and signature of appendix B.2.5.
        $message = self::request()
            ->withHeader(
                'Signature-Input',
                'sig1=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
            )
            ->withHeader('Signature', 'sig1=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:');

        $result = self::verify($message, new VerifierOptions(requireTarget: false));

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame(Algorithm::HmacSha256, $result->algorithm);
    }

    public function testARefreshedKeyChoosesItsOwnAlgorithmWhenAlgIsAbsent(): void
    {
        $message = self::request()
            ->withHeader(
                'Signature-Input',
                'sig1=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
            )
            ->withHeader('Signature', 'sig1=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:');
        $resolver = new ArrayKeyResolver(
            ['test-shared-secret' => self::verificationKey()],
            ['test-shared-secret' => self::verificationKey('test-shared-secret')],
        );

        $result = self::verify($message, new VerifierOptions(requireTarget: false), $resolver);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame(Algorithm::HmacSha256, $result->algorithm);
        $this->assertTrue($result->keyRefreshed);
    }

    public function testRefusesABodyThatCannotBeRewoundBeforeAnythingElse(): void
    {
        $pipe = fopen('php://stdin', 'r');
        $this->assertNotFalse($pipe);
        $resolver = self::resolver();
        $message = self::signed(self::request())->withBody(Stream::create($pipe));

        try {
            self::verify($message, resolver: $resolver);
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertStringStartsWith('The message body must be seekable', $exception->getMessage());
            $this->assertSame([], $resolver->resolved);
        }
    }

    /**
     * A PSR-7 implementation that, unlike nyholm/psr7, lets a line break into
     * a field value: the request as given, with one field set to the value
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

    private static function generatedP256Key(): VerificationKey
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsString($details['key']);

        return VerificationKey::fromPem($details['key']);
    }
}
