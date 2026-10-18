<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Cavage;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Cavage\ParsedSignature;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

class ParsedSignatureTest extends TestCase
{
    private static function signature(?string $algorithm, ?string $created, ?string $expires): ParsedSignature
    {
        return new ParsedSignature(
            keyId: 'a',
            algorithm: $algorithm,
            created: $created,
            expires: $expires,
            coveredComponents: [
                ComponentIdentifier::fromCavageName('(request-target)'),
                ComponentIdentifier::fromCavageName('host'),
            ],
            signature: 'bytes',
        );
    }

    /**
     * @return iterable<string, array{string | null, bool}>
     */
    public static function algorithmsProvider(): iterable
    {
        yield 'absent' => [null, true];
        yield 'hs2019' => ['hs2019', true];
        yield 'hs2019 in another case' => ['HS2019', false];
        yield 'rsa-sha256' => ['rsa-sha256', false];
    }

    #[DataProvider('algorithmsProvider')]
    public function testTheKeyDecidesUnderHs2019OrNoAlgorithm(?string $algorithm, bool $keyDecides): void
    {
        $this->assertSame($keyDecides, self::signature($algorithm, null, null)->keyDecidesAlgorithm());
    }

    public function testGivesTheTimes(): void
    {
        $signature = self::signature('hs2019', '1402170695', '1402170699.75');

        $this->assertSame(1402170695, $signature->createdTime()?->getTimestamp());
        $this->assertSame(1402170699, $signature->expiresTime()?->getTimestamp());
        $this->assertSame(1402170699, self::signature(null, null, '1402170699')->expiresTime()?->getTimestamp());
    }

    public function testHasNoTimesWithoutTheParameters(): void
    {
        $signature = self::signature(null, null, null);

        $this->assertNull($signature->createdTime());
        $this->assertNull($signature->expiresTime());
    }

    public function testNamesTheCoveredComponents(): void
    {
        $this->assertSame(['(request-target)', 'host'], self::signature(null, null, null)->coveredComponentNames());
    }
}
