<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\SigningKeyType;

/**
 * Checks the default algorithms of each key type and the algorithms a type
 * accepts
 */
final class SigningKeyTypeTest extends TestCase
{
    /**
     * @return iterable<string, array{SigningKeyType, non-empty-list<Algorithm>}>
     */
    public static function defaults(): iterable
    {
        yield 'RSA' => [SigningKeyType::Rsa, [Algorithm::RsaV15Sha256, Algorithm::RsaPssSha512]];
        yield 'RSA for RSASSA-PSS' => [SigningKeyType::RsaPss, [Algorithm::RsaPssSha512]];
        yield 'P-256' => [SigningKeyType::EcP256, [Algorithm::EcdsaP256Sha256]];
        yield 'P-384' => [SigningKeyType::EcP384, [Algorithm::EcdsaP384Sha384]];
        yield 'Ed25519' => [SigningKeyType::Ed25519, [Algorithm::Ed25519]];
        yield 'shared secret' => [SigningKeyType::SharedSecret, [Algorithm::HmacSha256]];
    }

    /**
     * @param non-empty-list<Algorithm> $expected
     */
    #[DataProvider('defaults')]
    public function testHasTheDocumentedDefaultAlgorithmsInOrder(SigningKeyType $type, array $expected): void
    {
        $this->assertSame($expected, $type->defaultAlgorithms());

        foreach ($expected as $algorithm) {
            $this->assertTrue($type->accepts($algorithm));
        }
    }

    public function testAnRsaKeyNeverAcceptsHmac(): void
    {
        $this->assertFalse(SigningKeyType::Rsa->accepts(Algorithm::HmacSha256));
        $this->assertFalse(SigningKeyType::SharedSecret->accepts(Algorithm::RsaV15Sha256));
    }

    public function testAKeyEncodedForRsassaPssNeverAcceptsPkcs1V15(): void
    {
        $this->assertFalse(SigningKeyType::RsaPss->accepts(Algorithm::RsaV15Sha256));
        $this->assertTrue(SigningKeyType::RsaPss->accepts(Algorithm::RsaPssSha512));
        $this->assertTrue(SigningKeyType::Rsa->accepts(Algorithm::RsaPssSha512));
    }
}
