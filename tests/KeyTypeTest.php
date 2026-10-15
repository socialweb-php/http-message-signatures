<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\KeyType;

class KeyTypeTest extends TestCase
{
    /**
     * @return iterable<string, array{KeyType, non-empty-list<Algorithm>}>
     */
    public static function defaultsProvider(): iterable
    {
        yield 'RSA' => [KeyType::Rsa, [Algorithm::RsaV15Sha256, Algorithm::RsaPssSha512]];
        yield 'RSA for RSASSA-PSS' => [KeyType::RsaPss, [Algorithm::RsaPssSha512]];
        yield 'P-256' => [KeyType::EcP256, [Algorithm::EcdsaP256Sha256]];
        yield 'P-384' => [KeyType::EcP384, [Algorithm::EcdsaP384Sha384]];
        yield 'Ed25519' => [KeyType::Ed25519, [Algorithm::Ed25519]];
        yield 'shared secret' => [KeyType::SharedSecret, [Algorithm::HmacSha256]];
    }

    /**
     * @param non-empty-list<Algorithm> $expected
     */
    #[DataProvider('defaultsProvider')]
    public function testHasTheDocumentedDefaultAlgorithmsInOrder(KeyType $type, array $expected): void
    {
        $this->assertSame($expected, $type->defaultAlgorithms());

        foreach ($expected as $algorithm) {
            $this->assertTrue($type->accepts($algorithm));
        }
    }

    public function testAnRsaKeyNeverAcceptsHmac(): void
    {
        $this->assertFalse(KeyType::Rsa->accepts(Algorithm::HmacSha256));
        $this->assertFalse(KeyType::SharedSecret->accepts(Algorithm::RsaV15Sha256));
    }

    public function testAKeyEncodedForRsassaPssNeverAcceptsPkcs1V15(): void
    {
        $this->assertFalse(KeyType::RsaPss->accepts(Algorithm::RsaV15Sha256));
        $this->assertTrue(KeyType::RsaPss->accepts(Algorithm::RsaPssSha512));
        $this->assertTrue(KeyType::Rsa->accepts(Algorithm::RsaPssSha512));
    }
}
