<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\KeyType;

class AlgorithmTest extends TestCase
{
    public function testHasTheSixAlgorithmsOfTheRegistry(): void
    {
        $this->assertCount(6, Algorithm::cases());
    }

    /**
     * @return iterable<string, array{Algorithm, string | null, string}>
     */
    public static function namesProvider(): iterable
    {
        yield 'RSA v1.5' => [Algorithm::RsaV15Sha256, 'rsa-sha256', 'rsa-v1_5-sha256'];
        yield 'RSA PSS' => [Algorithm::RsaPssSha512, null, 'rsa-pss-sha512'];
        yield 'Ed25519' => [Algorithm::Ed25519, 'hs2019', 'ed25519'];
        yield 'ECDSA P-256' => [Algorithm::EcdsaP256Sha256, null, 'ecdsa-p256-sha256'];
        yield 'ECDSA P-384' => [Algorithm::EcdsaP384Sha384, null, 'ecdsa-p384-sha384'];
        yield 'HMAC' => [Algorithm::HmacSha256, 'hmac-sha256', 'hmac-sha256'];
    }

    #[DataProvider('namesProvider')]
    public function testNamesTheAlgorithmInEachForm(Algorithm $algorithm, ?string $cavage, string $rfc9421): void
    {
        $this->assertSame($cavage, $algorithm->name(Form::Cavage));
        $this->assertSame($rfc9421, $algorithm->name(Form::Rfc9421));
    }

    /**
     * @return iterable<string, array{Algorithm, KeyType}>
     */
    public static function keyTypesProvider(): iterable
    {
        yield 'RSA v1.5' => [Algorithm::RsaV15Sha256, KeyType::Rsa];
        yield 'RSA PSS' => [Algorithm::RsaPssSha512, KeyType::Rsa];
        yield 'Ed25519' => [Algorithm::Ed25519, KeyType::Ed25519];
        yield 'ECDSA P-256' => [Algorithm::EcdsaP256Sha256, KeyType::EcP256];
        yield 'ECDSA P-384' => [Algorithm::EcdsaP384Sha384, KeyType::EcP384];
        yield 'HMAC' => [Algorithm::HmacSha256, KeyType::SharedSecret];
    }

    #[DataProvider('keyTypesProvider')]
    public function testFitsExactlyOneKeyType(Algorithm $algorithm, KeyType $expected): void
    {
        $this->assertSame($expected, $algorithm->keyType());

        foreach (KeyType::cases() as $type) {
            $this->assertSame($type === $expected, $type->accepts($algorithm));
        }
    }
}
