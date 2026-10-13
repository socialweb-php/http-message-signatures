<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\SigningKey;
use SocialWeb\Http\MessageSignatures\VerificationKey;

use function base64_decode;
use function base64_encode;
use function substr;

/**
 * Proves the algorithms with the example signatures of RFC 9421 appendix B.2
 *
 * Each example's signature base is transcribed from the appendix; the
 * `@signature-params` line is the last line and no newline follows it. The
 * deterministic algorithms, `hmac-sha256` and `ed25519`, sign to the exact
 * example bytes. `rsa-pss-sha512` and ECDSA produce a different signature on
 * every run, so for them the appendix's signature verifies and a fresh
 * signature verifies, which is the test section 7.3.5 allows.
 */
class Rfc9421AppendixBTest extends TestCase
{
    private const string CONTENT_DIGEST = 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu'
        . '7BNNyealdVLvRwEmTHWXvJwew==:';

    /**
     * @return iterable<string, array{Algorithm, string, string, string, string}>
     */
    public static function examplesProvider(): iterable
    {
        yield 'B.2.1 minimal signature using rsa-pss-sha512' => [
            Algorithm::RsaPssSha512,
            'test-key-rsa-pss',
            '"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
            'd2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7z'
            . 'FZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4'
            . 'DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV'
            . '5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==',
            '',
        ];

        yield 'B.2.2 selective covered components using rsa-pss-sha512' => [
            Algorithm::RsaPssSha512,
            'test-key-rsa-pss',
            "\"@authority\": example.com\n"
            . '"content-digest": ' . self::CONTENT_DIGEST . "\n"
            . "\"@query-param\";name=\"Pet\": dog\n"
            . '"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet")'
            . ';created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
            'LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCM'
            . 'kSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4'
            . 'UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQo'
            . 'sMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==',
            '',
        ];

        yield 'B.2.3 full coverage using rsa-pss-sha512' => [
            Algorithm::RsaPssSha512,
            'test-key-rsa-pss',
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n"
            . "\"@method\": POST\n"
            . "\"@path\": /foo\n"
            . "\"@query\": ?param=Value&Pet=dog\n"
            . "\"@authority\": example.com\n"
            . "\"content-type\": application/json\n"
            . '"content-digest": ' . self::CONTENT_DIGEST . "\n"
            . "\"content-length\": 18\n"
            . '"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest"'
            . ' "content-length");created=1618884473;keyid="test-key-rsa-pss"',
            'bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp'
            . '768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmI'
            . 'koQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyM'
            . 'UJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==',
            '',
        ];

        yield 'B.2.4 signing a response using ecdsa-p256-sha256' => [
            Algorithm::EcdsaP256Sha256,
            'test-key-ecc-p256',
            "\"@status\": 200\n"
            . "\"content-type\": application/json\n"
            . '"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rj'
            . "Juahq4l5aGgfLQ==:\n"
            . "\"content-length\": 23\n"
            . '"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473'
            . ';keyid="test-key-ecc-p256"',
            'wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==',
            '',
        ];

        yield 'B.2.5 signing a request using hmac-sha256' => [
            Algorithm::HmacSha256,
            'test-shared-secret',
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n"
            . "\"@authority\": example.com\n"
            . "\"content-type\": application/json\n"
            . '"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
            'pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=',
            'deterministic',
        ];

        yield 'B.2.6 signing a request using ed25519' => [
            Algorithm::Ed25519,
            'test-key-ed25519',
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n"
            . "\"@method\": POST\n"
            . "\"@path\": /foo\n"
            . "\"@authority\": example.com\n"
            . "\"content-type\": application/json\n"
            . "\"content-length\": 18\n"
            . '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length")'
            . ';created=1618884473;keyid="test-key-ed25519"',
            'wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==',
            'deterministic',
        ];
    }

    #[DataProvider('examplesProvider')]
    public function testTheExampleSignatureVerifies(
        Algorithm $algorithm,
        string $keyName,
        string $signatureBase,
        string $signatureBase64,
        string $determinism,
    ): void {
        $this->assertContains($determinism, ['', 'deterministic']);

        $signature = (string) base64_decode($signatureBase64, true);
        $key = self::verificationKey($keyName);

        $this->assertTrue($key->verify($algorithm, $signatureBase, $signature));
        $this->assertFalse($key->verify($algorithm, $signatureBase . "\n", $signature));
        $this->assertFalse($key->verify($algorithm, $signatureBase, "\x00" . substr($signature, 1)));
    }

    #[DataProvider('examplesProvider')]
    public function testAFreshSignatureVerifies(
        Algorithm $algorithm,
        string $keyName,
        string $signatureBase,
        string $signatureBase64,
        string $determinism,
    ): void {
        $signature = self::signingKey($keyName)->sign($algorithm, $signatureBase);

        $this->assertTrue(self::verificationKey($keyName)->verify($algorithm, $signatureBase, $signature));

        if ($determinism === 'deterministic') {
            $this->assertSame($signatureBase64, base64_encode($signature));
        } else {
            $this->assertNotSame($signatureBase64, base64_encode($signature));
        }
    }

    public function testTheOtherKeysRejectTheExampleSignatures(): void
    {
        $base = '"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"';
        $signature = self::signingKey('test-key-rsa-pss')->sign(Algorithm::RsaPssSha512, $base);

        $this->assertFalse(self::verificationKey('test-key-rsa')->verify(Algorithm::RsaPssSha512, $base, $signature));
        $this->assertFalse(
            self::verificationKey('test-key-rsa-pss')->verify(Algorithm::RsaV15Sha256, $base, $signature),
        );
    }

    private static function verificationKey(string $name): VerificationKey
    {
        return $name === 'test-shared-secret'
            ? VerificationKey::fromSharedSecret(self::rfc9421SharedSecret())
            : VerificationKey::fromPem(self::rfc9421Key($name . '.public.pem'));
    }

    private static function signingKey(string $name): SigningKey
    {
        return $name === 'test-shared-secret'
            ? SigningKey::fromSharedSecret($name, self::rfc9421SharedSecret())
            : SigningKey::fromPem($name, self::rfc9421Key($name . '.private.pem'));
    }
}
