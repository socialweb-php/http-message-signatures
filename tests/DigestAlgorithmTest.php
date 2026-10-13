<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\DigestAlgorithm;

use function hash;
use function strlen;

class DigestAlgorithmTest extends TestCase
{
    public function testUsesTheRfc9530AlgorithmKeysAsValues(): void
    {
        $this->assertSame('sha-256', DigestAlgorithm::Sha256->value);
        $this->assertSame('sha-512', DigestAlgorithm::Sha512->value);
        $this->assertCount(2, DigestAlgorithm::cases());
    }

    /**
     * @return iterable<string, array{DigestAlgorithm, string, int, string}>
     */
    public static function algorithmsProvider(): iterable
    {
        yield 'SHA-256' => [DigestAlgorithm::Sha256, 'sha256', 32, 'SHA-256'];
        yield 'SHA-512' => [DigestAlgorithm::Sha512, 'sha512', 64, 'SHA-512'];
    }

    #[DataProvider('algorithmsProvider')]
    public function testDescribesTheHash(DigestAlgorithm $algorithm, string $hashName, int $length, string $token): void
    {
        $this->assertSame($hashName, $algorithm->hashName());
        $this->assertSame($length, $algorithm->digestLength());
        $this->assertSame($length, strlen(hash($algorithm->hashName(), '', true)));
        $this->assertSame($token, $algorithm->rfc3230Token());
    }

    /**
     * @return iterable<string, array{string, DigestAlgorithm | null}>
     */
    public static function tokensProvider(): iterable
    {
        yield 'RFC 5843 spelling' => ['SHA-256', DigestAlgorithm::Sha256];
        yield 'lowercase' => ['sha-512', DigestAlgorithm::Sha512];
        yield 'mixed case' => ['Sha-256', DigestAlgorithm::Sha256];
        yield 'MD5 is refused' => ['MD5', null];
        yield 'SHA-1 is refused' => ['SHA', null];
        yield 'the RFC 9530 deprecated entries are refused' => ['unixsum', null];
        yield 'a hash the package does not offer' => ['sha-384', null];
        yield 'empty' => ['', null];
    }

    #[DataProvider('tokensProvider')]
    public function testReadsTheRfc3230TokenCaseInsensitively(string $token, ?DigestAlgorithm $expected): void
    {
        $this->assertSame($expected, DigestAlgorithm::tryFromRfc3230Token($token));
    }
}
