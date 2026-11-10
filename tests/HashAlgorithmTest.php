<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\HashAlgorithm;

use function hash;
use function strlen;

/**
 * Checks the values, the hash names, and the digest field tokens of the hash
 * algorithms
 */
final class HashAlgorithmTest extends TestCase
{
    public function testHasTheThreeCasesTheSocialwebPackagesShare(): void
    {
        $this->assertSame('sha-256', HashAlgorithm::Sha256->value);
        $this->assertSame('sha-384', HashAlgorithm::Sha384->value);
        $this->assertSame('sha-512', HashAlgorithm::Sha512->value);
        $this->assertCount(3, HashAlgorithm::cases());
    }

    /**
     * @return iterable<string, array{HashAlgorithm, string, int}>
     */
    public static function algorithms(): iterable
    {
        yield 'SHA-256' => [HashAlgorithm::Sha256, 'sha256', 32];
        yield 'SHA-384' => [HashAlgorithm::Sha384, 'sha384', 48];
        yield 'SHA-512' => [HashAlgorithm::Sha512, 'sha512', 64];
    }

    #[DataProvider('algorithms')]
    public function testDescribesTheHash(HashAlgorithm $algorithm, string $hashName, int $length): void
    {
        $this->assertSame($hashName, $algorithm->hashName());
        $this->assertSame($length, $algorithm->digestLength());
        $this->assertSame($length, strlen(hash($algorithm->hashName(), '', true)));
    }

    public function testTheDigestFieldsHaveSha256AndSha512Only(): void
    {
        $this->assertTrue(HashAlgorithm::Sha256->isDigestFieldAlgorithm());
        $this->assertFalse(HashAlgorithm::Sha384->isDigestFieldAlgorithm());
        $this->assertTrue(HashAlgorithm::Sha512->isDigestFieldAlgorithm());
    }

    public function testNamesTheRfc3230TokenOfAnAlgorithmTheDigestFieldsHave(): void
    {
        $this->assertSame('SHA-256', HashAlgorithm::Sha256->rfc3230Token());
        $this->assertSame('SHA-512', HashAlgorithm::Sha512->rfc3230Token());
    }

    public function testSha384HasNoRfc3230Token(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('Hash algorithm Sha384 has no token in the Digest field');

        HashAlgorithm::Sha384->rfc3230Token();
    }

    /**
     * @return iterable<string, array{string, HashAlgorithm | null}>
     */
    public static function tokens(): iterable
    {
        yield 'RFC 5843 spelling' => ['SHA-256', HashAlgorithm::Sha256];
        yield 'lowercase' => ['sha-512', HashAlgorithm::Sha512];
        yield 'mixed case' => ['Sha-256', HashAlgorithm::Sha256];
        yield 'MD5 is refused' => ['MD5', null];
        yield 'SHA-1 is refused' => ['SHA', null];
        yield 'the RFC 9530 deprecated entries are refused' => ['unixsum', null];
        yield 'SHA-384, which RFC 5843 does not register' => ['sha-384', null];
        yield 'empty' => ['', null];
    }

    #[DataProvider('tokens')]
    public function testReadsTheRfc3230TokenCaseInsensitively(string $token, ?HashAlgorithm $expected): void
    {
        $this->assertSame($expected, HashAlgorithm::tryFromRfc3230Token($token));
    }
}
