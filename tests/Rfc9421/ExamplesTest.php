<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Rfc9421;

use DateInterval;
use DateTimeImmutable;
use Ergebnis\Clock\FrozenClock;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\MessageInterface;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\TimePolicy;
use SocialWeb\Http\MessageSignatures\VerificationKey;
use SocialWeb\Http\MessageSignatures\Verifier;
use SocialWeb\Http\MessageSignatures\VerifierOptions;
use SocialWeb\Test\Http\MessageSignatures\ArrayKeyResolver;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function base64_decode;
use function substr;
use function trim;

/**
 * Verifies the example messages of RFC 9421 as whole messages: sections 2.4,
 * 3.2, and 4.3, and appendices B.2, B.3, and B.4
 *
 * The examples give no `alg` parameter except the proxy's in section 4.3,
 * since "the verifier is known by the application to use the RSA-PSS
 * algorithm based on the identified key", so the resolver's keys permit the
 * algorithm the appendix used. The examples cover what they cover, not what
 * the verifier requires by default, so the target and content-digest rules
 * are off here, and the clock is set a few seconds after the signatures were
 * created.
 */
class ExamplesTest extends TestCase
{
    private const string REQUEST_DIGEST = 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNy'
        . 'ealdVLvRwEmTHWXvJwew==:';
    private const string RESPONSE_DIGEST = 'sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdX'
        . 'ymyU0rjJuahq4l5aGgfLQ==:';
    private const string BUSY_DIGEST = 'sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwnHJDbkkWWQz6PhhU9kxsTbARtY2'
        . 'PTBOzq24uJFpHsMuAg==:';
    private const string CLIENT_CERT = ':MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNh'
        . 'dGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJD'
        . 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcG'
        . 'zkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAw'
        . 'EwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6'
        . 'G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:';

    private const string SIG_B21 = ':d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it'
        . '++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJ'
        . 'zsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0g'
        . 'Cw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:';
    private const string SIG_B22 = ':LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CD'
        . 'fKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTl'
        . 'aqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErO'
        . 's0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:';
    private const string SIG_B23 = ':bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFke'
        . 'Gt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/'
        . 'aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VB'
        . 'rohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:';
    private const string SIG_B24 = ':wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+'
        . '32oiasw==:';
    private const string SIG_B25 = ':pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:';
    private const string SIG_B26 = ':wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WP'
        . 'pBKRCw==:';
    private const string SIG_32 = ':HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/'
        . 'J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPu'
        . 'BCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNu'
        . 'ZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:';
    private const string SIG_24_RESPONSE = ':dMT/A/76ehrdBTD/2Xx8QuKV6FoyzEP/I9hdzKN8LQJLNgzU4W767HK05rx1i8meNQQgQPgQp'
        . '8wq2ive3tV5Ag==:';
    private const string SIG_24_REQUEST = ':e8UJ5wMiRaonlth5ERtE8GIiEH7Akcr493nQ07VPNo6y3qvjdKt0fo8VHO8xXDjmtYoatGYBG'
        . 'JVlMfIp06eVMEyNW2I4vN7XDAz7m5v1108vGzaDljrd0H8+SJ28g7bzn6h2xeL/8q+qUwahWA/JmC8aOC9iVnwbOKCc0WSrLgWQwTY6V'
        . 'Lp42Qt7jjhYT5W7/wCvfK9A1VmHH1lJXsV873Z6hpxesd50PSmO+xaNeYvDLvVdZlhtw5PCtUYzKjHqwmaQ6DEuM8udRjYsoNqp2xZKc'
        . 'uCO1nKc0V3RjpqMZLuuyVbHDAbCzr0pg2d2VM/OC33JAU7meEjjaNz+d7LWPg==:';
    private const string SIG_24_SIGNED_RESPONSE = ':C73J41GVKc+TYXbSobvZf0CmNcptRiWN+NY1Or0A36ISg6ymdRN6ZgR2QfrtopFNz'
        . 'qAyv+CeWrMsNbcV2Ojsgg==:';
    private const string SIG_43_CLIENT = ':X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNal'
        . 'zA8ESSaHD3A==:';
    private const string SIG_43_PROXY = ':S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iH'
        . 'gxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7'
        . 'LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJv'
        . 'ye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:';
    private const string SIG_B3 = ':xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOg'
        . 'mizw==:';
    private const string SIG_B4 = ':ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj'
        . '3NDA==:';

    /**
     * The `test-request` message of appendix B.2
     */
    private static function testRequest(): Request
    {
        return new Request('POST', 'https://example.com/foo?param=Value&Pet=dog', [
            'Host' => 'example.com',
            'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
            'Content-Type' => 'application/json',
            'Content-Digest' => self::REQUEST_DIGEST,
            'Content-Length' => '18',
        ], '{"hello": "world"}');
    }

    /**
     * The `test-response` message of appendix B.2
     */
    private static function testResponse(): Response
    {
        return new Response(200, [
            'Date' => 'Tue, 20 Apr 2021 02:07:56 GMT',
            'Content-Type' => 'application/json',
            'Content-Digest' => self::RESPONSE_DIGEST,
            'Content-Length' => '23',
        ], '{"message": "good dog"}');
    }

    /**
     * The 503 response of section 2.4
     */
    private static function busyResponse(): Response
    {
        return new Response(503, [
            'Date' => 'Tue, 20 Apr 2021 02:07:56 GMT',
            'Content-Type' => 'application/json',
            'Content-Length' => '62',
            'Content-Digest' => self::BUSY_DIGEST,
        ], '{"busy": true, "message": "Your call is very important to us"}');
    }

    private static function resolver(): ArrayKeyResolver
    {
        return new ArrayKeyResolver([
            'test-key-rsa' => VerificationKey::fromPem(self::rfc9421Key('test-key-rsa.public.pem')),
            'test-key-rsa-pss' => VerificationKey::fromPem(
                self::rfc9421Key('test-key-rsa-pss.public.pem'),
                [Algorithm::RsaPssSha512],
            ),
            'test-key-ecc-p256' => VerificationKey::fromPem(self::rfc9421Key('test-key-ecc-p256.public.pem')),
            'test-key-ed25519' => VerificationKey::fromPem(self::rfc9421Key('test-key-ed25519.public.pem')),
            'test-shared-secret' => VerificationKey::fromSharedSecret(self::rfc9421SharedSecret()),
        ]);
    }

    private static function verifier(?ArrayKeyResolver $resolver = null, int $maxSignatures = 3): Verifier
    {
        return new Verifier(
            $resolver ?? self::resolver(),
            new FrozenClock(new DateTimeImmutable('@1618884480')),
            new VerifierOptions(
                timePolicy: new TimePolicy(defaultLifetime: new DateInterval('PT1M')),
                requireTarget: false,
                requireContentDigest: false,
                maxSignatures: $maxSignatures,
            ),
        );
    }

    /**
     * @return iterable<string, array{MessageInterface, string, string, string, Algorithm}>
     */
    public static function appendixB2Provider(): iterable
    {
        yield 'B.2.1 minimal signature using rsa-pss-sha512' => [
            self::testRequest(),
            'sig-b21',
            '();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
            self::SIG_B21,
            Algorithm::RsaPssSha512,
        ];
        yield 'B.2.2 selective covered components using rsa-pss-sha512' => [
            self::testRequest(),
            'sig-b22',
            '("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss"'
            . ';tag="header-example"',
            self::SIG_B22,
            Algorithm::RsaPssSha512,
        ];
        yield 'B.2.3 full coverage using rsa-pss-sha512' => [
            self::testRequest(),
            'sig-b23',
            '("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length")'
            . ';created=1618884473;keyid="test-key-rsa-pss"',
            self::SIG_B23,
            Algorithm::RsaPssSha512,
        ];
        yield 'B.2.4 signing a response using ecdsa-p256-sha256' => [
            self::testResponse(),
            'sig-b24',
            '("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
            self::SIG_B24,
            Algorithm::EcdsaP256Sha256,
        ];
        yield 'B.2.5 signing a request using hmac-sha256' => [
            self::testRequest(),
            'sig-b25',
            '("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
            self::SIG_B25,
            Algorithm::HmacSha256,
        ];
        yield 'B.2.6 signing a request using ed25519' => [
            self::testRequest(),
            'sig-b26',
            '("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473'
            . ';keyid="test-key-ed25519"',
            self::SIG_B26,
            Algorithm::Ed25519,
        ];
        yield '3.2 the verification example' => [
            self::testRequest(),
            'sig1',
            '("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473'
            . ';keyid="test-key-rsa-pss"',
            self::SIG_32,
            Algorithm::RsaPssSha512,
        ];
        yield 'B.3 the TLS-terminating proxy' => [
            new Request('POST', 'https://service.internal.example/foo?param=Value&Pet=dog', [
                'Host' => 'service.internal.example',
                'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
                'Content-Type' => 'application/json',
                'Content-Length' => '18',
                'Client-Cert' => self::CLIENT_CERT,
            ], '{"hello": "world"}'),
            'ttrp',
            '("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"',
            self::SIG_B3,
            Algorithm::EcdsaP256Sha256,
        ];
    }

    #[DataProvider('appendixB2Provider')]
    public function testTheExampleMessageVerifies(
        MessageInterface $message,
        string $label,
        string $signatureInput,
        string $signature,
        Algorithm $algorithm,
    ): void {
        $message = $message
            ->withHeader('Signature-Input', $label . '=' . $signatureInput)
            ->withHeader('Signature', $label . '=' . $signature);

        $result = self::verifier()->verify($message);

        $this->assertTrue($result->verified, $result->detail);
        $this->assertNull($result->reason);
        $this->assertSame(Form::Rfc9421, $result->form);
        $this->assertSame($label, $result->label);
        $this->assertSame($algorithm, $result->algorithm);
        $this->assertSame(1618884473, $result->created?->getTimestamp());
        $this->assertFalse($result->keyRefreshed);
    }

    #[DataProvider('appendixB2Provider')]
    public function testTheExampleMessageFailsWithAChangedSignature(
        MessageInterface $message,
        string $label,
        string $signatureInput,
        string $signature,
        Algorithm $algorithm,
    ): void {
        $changed = ':' . ($signature[1] === 'A' ? 'B' : 'A') . substr($signature, 2);
        $message = $message
            ->withHeader('Signature-Input', $label . '=' . $signatureInput)
            ->withHeader('Signature', $label . '=' . $changed);

        $result = self::verifier()->verify($message);

        $this->assertFalse($result->verified);
        $this->assertSame(FailureReason::SignatureInvalid, $result->reason);
        $this->assertSame($algorithm, $result->algorithm);
        $this->assertTrue($result->keyRefreshed);
    }

    public function testTheMinimalSignatureOfB21ReportsItsNonceAndNoCoveredComponents(): void
    {
        $message = self::testRequest()
            ->withHeader(
                'Signature-Input',
                'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
            )
            ->withHeader('Signature', 'sig-b21=' . self::SIG_B21);

        $result = self::verifier()->verify($message);

        $this->assertTrue($result->verified);
        $this->assertSame([], $result->coveredComponents);
        $this->assertSame('b3k2pp5k7z-50gnwp.yemd', $result->nonce);
        $this->assertSame('test-key-rsa-pss', $result->keyId);
        $this->assertNull($result->expires);
        $this->assertSame(base64_decode(trim(self::SIG_B21, ':'), true), $result->signature);
    }

    public function testTheSection24ResponseCoversTheRequestItAnswers(): void
    {
        $response = self::busyResponse()
            ->withHeader(
                'Signature-Input',
                'reqres=("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req'
                . ' "content-digest";req);created=1618884479;keyid="test-key-ecc-p256"',
            )
            ->withHeader('Signature', 'reqres=' . self::SIG_24_RESPONSE);

        $result = self::verifier()->verify($response, self::testRequest());

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame(
            [
                '@status',
                'content-digest',
                'content-type',
                '@authority;req',
                '@method;req',
                '@path;req',
                'content-digest;req',
            ],
            $result->coveredComponents,
        );

        $withoutTheRequest = self::verifier()->verify($response);

        $this->assertFalse($withoutTheRequest->verified);
        $this->assertSame(FailureReason::MissingComponent, $withoutTheRequest->reason);
        $this->assertSame(
            'a component with the req parameter needs the related request, which was not given',
            $withoutTheRequest->detail,
        );
    }

    public function testTheSection24ResponseToASignedRequestCoversTheRequestsComponents(): void
    {
        $request = self::testRequest()
            ->withHeader(
                'Signature-Input',
                'sig1=("@method" "@authority" "@path" "@query" "content-digest" "content-type" "content-length")'
                . ';created=1618884475;keyid="test-key-rsa-pss"',
            )
            ->withHeader('Signature', 'sig1=' . self::SIG_24_REQUEST);
        $response = self::busyResponse()
            ->withHeader(
                'Signature-Input',
                'reqres=("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req'
                . ' "@query";req "content-digest";req "content-type";req "content-length";req);created=1618884479'
                . ';keyid="test-key-ecc-p256"',
            )
            ->withHeader('Signature', 'reqres=' . self::SIG_24_SIGNED_RESPONSE);

        $this->assertTrue(self::verifier()->verify($request)->verified);
        $this->assertTrue(self::verifier()->verify($response, $request)->verified);
    }

    public function testTheSection43ClientSignatureVerifiesBeforeTheProxyChangesTheMessage(): void
    {
        $request = self::testRequest()
            ->withHeader(
                'Signature-Input',
                'sig1=("@method" "@authority" "@path" "content-digest" "content-type" "content-length")'
                . ';created=1618884475;keyid="test-key-ecc-p256"',
            )
            ->withHeader('Signature', 'sig1=' . self::SIG_43_CLIENT);

        $this->assertTrue(self::verifier()->verify($request)->verified);
    }

    private static function section43ForwardedRequest(): Request
    {
        return new Request('POST', 'https://origin.host.internal.example/foo?param=Value&Pet=dog', [
            'Host' => 'origin.host.internal.example',
            'Date' => 'Tue, 20 Apr 2021 02:07:56 GMT',
            'Content-Type' => 'application/json',
            'Content-Length' => '18',
            'Forwarded' => 'for=192.0.2.123;host=example.com;proto=https',
            'Content-Digest' => self::REQUEST_DIGEST,
            'Signature-Input' => 'sig1=("@method" "@authority" "@path" "content-digest" "content-type"'
                . ' "content-length");created=1618884475;keyid="test-key-ecc-p256", proxy_sig=("@method" "@authority"'
                . ' "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480'
                . ';keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540',
            'Signature' => 'sig1=' . self::SIG_43_CLIENT . ', proxy_sig=' . self::SIG_43_PROXY,
        ], '{"hello": "world"}');
    }

    public function testTheSection43ProxySignatureVerifiesAfterTheClientsFails(): void
    {
        $resolver = self::resolver();

        $result = self::verifier($resolver)->verify(self::section43ForwardedRequest());

        $this->assertTrue($result->verified, $result->detail);
        $this->assertSame('proxy_sig', $result->label);
        $this->assertSame('test-key-rsa', $result->keyId);
        $this->assertSame(Algorithm::RsaV15Sha256, $result->algorithm);
        $this->assertSame(1618884480, $result->created?->getTimestamp());
        $this->assertSame(1618884540, $result->expires?->getTimestamp());
        $this->assertFalse($result->keyRefreshed);
        // The client's signature was tried first, failed on the changed
        // authority, and was retried once with a refreshed key.
        $this->assertSame(['test-key-ecc-p256', 'test-key-rsa'], $resolver->resolved);
        $this->assertSame(['test-key-ecc-p256'], $resolver->refreshed);
    }

    public function testTheSection43ProxySignatureIsNotReadWhenTheLimitIsOne(): void
    {
        $resolver = self::resolver();

        $result = self::verifier($resolver, 1)->verify(self::section43ForwardedRequest());

        $this->assertFalse($result->verified);
        $this->assertSame(FailureReason::SignatureInvalid, $result->reason);
        $this->assertSame('sig1', $result->label);
        $this->assertSame('the signature "sig1" does not verify under ecdsa-p256-sha256', $result->detail);
        $this->assertSame(['test-key-ecc-p256'], $resolver->resolved);
    }

    private static function appendixB4Request(): Request
    {
        return new Request('GET', 'https://example.org/demo?name1=Value1&Name2=value2', [
            'Host' => 'example.org',
            'Date' => 'Fri, 15 Jul 2022 14:24:55 GMT',
            'Accept' => ['application/json', '*/*'],
            'Signature-Input' => 'transform=("@method" "@path" "@authority" "accept");created=1618884473'
                . ';keyid="test-key-ed25519"',
            'Signature' => 'transform=' . self::SIG_B4,
        ]);
    }

    /**
     * @return iterable<string, array{Request, bool}>
     */
    public static function appendixB4Provider(): iterable
    {
        $original = self::appendixB4Request();

        yield 'the original message' => [$original, true];
        yield 'a header field and a query parameter added' => [
            $original
                ->withUri($original->getUri()->withQuery('name1=Value1&Name2=value2&param=added'))
                ->withHeader('Accept-Language', 'en-US,en;q=0.5'),
            true,
        ];
        yield 'Date removed, Referer added, and Accept collapsed into one line' => [
            $original
                ->withoutHeader('Date')
                ->withHeader('Referer', 'https://developer.example.org/demo')
                ->withHeader('Accept', 'application/json, */*'),
            true,
        ];
        yield 'the fields reordered' => [
            new Request('GET', 'https://example.org/demo?name1=Value1&Name2=value2', [
                'Accept' => ['application/json', '*/*'],
                'Date' => 'Fri, 15 Jul 2022 14:24:55 GMT',
                'Host' => 'example.org',
                'Signature-Input' => $original->getHeaderLine('Signature-Input'),
                'Signature' => $original->getHeaderLine('Signature'),
            ]),
            true,
        ];
        yield 'the method and authority changed' => [
            $original
                ->withMethod('POST')
                ->withUri($original->getUri()->withHost('example.com'))
                ->withHeader('Host', 'example.com'),
            false,
        ];
        yield 'the two Accept lines swapped' => [
            $original->withHeader('Accept', ['*/*', 'application/json']),
            false,
        ];
    }

    #[DataProvider('appendixB4Provider')]
    public function testTheSignatureSurvivesTheTransformationsOfAppendixB4(Request $request, bool $expected): void
    {
        $result = self::verifier()->verify($request);

        $this->assertSame($expected, $result->verified, $result->detail);

        if (!$expected) {
            $this->assertSame(FailureReason::SignatureInvalid, $result->reason);
        }
    }
}
