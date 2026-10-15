<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use DateInterval;
use DateTimeImmutable;
use Ergebnis\Clock\FrozenClock;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\TimePolicy;

use function sprintf;

class TimePolicyTest extends TestCase
{
    public function testHasTheDocumentedDefaults(): void
    {
        $policy = new TimePolicy();
        $epoch = new DateTimeImmutable('@0');

        $this->assertSame(3600, $epoch->add($policy->clockSkew)->getTimestamp());
        $this->assertSame(300, $epoch->add($policy->defaultLifetime)->getTimestamp());
        $this->assertSame(43200, $epoch->add($policy->maximumLifetime)->getTimestamp());
    }

    public function testAcceptsExplicitIntervalsIncludingZero(): void
    {
        $policy = new TimePolicy(
            clockSkew: new DateInterval('PT0S'),
            defaultLifetime: new DateInterval('PT1M'),
            maximumLifetime: new DateInterval('P1D'),
        );
        $epoch = new DateTimeImmutable('@0');

        $this->assertSame(0, $epoch->add($policy->clockSkew)->getTimestamp());
        $this->assertSame(60, $epoch->add($policy->defaultLifetime)->getTimestamp());
        $this->assertSame(86400, $epoch->add($policy->maximumLifetime)->getTimestamp());
    }

    /**
     * @return iterable<string, array{string, DateInterval}>
     */
    public static function negativeIntervalsProvider(): iterable
    {
        $inverted = new DateInterval('PT5M');
        $inverted->invert = 1;

        yield 'an inverted clock skew' => ['clockSkew', $inverted];
        yield 'a negative default lifetime' => ['defaultLifetime', DateInterval::createFromDateString('-5 minutes')];
        yield 'a negative maximum lifetime' => ['maximumLifetime', DateInterval::createFromDateString('-1 day')];
    }

    #[DataProvider('negativeIntervalsProvider')]
    public function testRejectsANegativeInterval(string $name, DateInterval $interval): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage($name . ' must not be negative');

        new TimePolicy(...[$name => $interval]);
    }

    /**
     * Times are seconds relative to the creation time; the policy under test
     * has a skew of 60 seconds, a default lifetime of 300, and a maximum of
     * 600.
     *
     * @return iterable<string, array{int, int | null, FailureReason | null}>
     */
    public static function evaluationsProvider(): iterable
    {
        yield 'created now' => [0, null, null];
        yield 'created in the future within the skew' => [-60, null, null];
        yield 'created one second beyond the skew' => [-61, null, FailureReason::NotYetValid];
        yield 'at the default expiry plus the skew' => [360, null, null];
        yield 'one second after the default expiry plus the skew' => [361, null, FailureReason::Expired];
        yield 'an explicit expiry stretches the lifetime' => [500, 500, null];
        yield 'at the explicit expiry plus the skew' => [560, 500, null];
        yield 'one second after the explicit expiry plus the skew' => [561, 500, FailureReason::Expired];
        yield 'an explicit expiry is clamped to the maximum' => [661, 3600, FailureReason::Expired];
        yield 'at the maximum plus the skew' => [660, 3600, null];
        yield 'an explicit expiry shorter than the default' => [121, 60, FailureReason::Expired];
        yield 'an explicit expiry before the creation time' => [0, -1, null];
        yield 'an explicit expiry before the creation time, past it and the skew' => [60, -1, FailureReason::Expired];
    }

    #[DataProvider('evaluationsProvider')]
    public function testEvaluatesAtEachBoundary(int $nowOffset, ?int $expiresOffset, ?FailureReason $expected): void
    {
        $policy = new TimePolicy(
            clockSkew: new DateInterval('PT60S'),
            defaultLifetime: new DateInterval('PT300S'),
            maximumLifetime: new DateInterval('PT600S'),
        );
        $created = new DateTimeImmutable('@1618884473');
        $clock = new FrozenClock($created->modify(sprintf('%+d seconds', $nowOffset)));
        $expires = $expiresOffset === null ? null : $created->modify(sprintf('%+d seconds', $expiresOffset));

        $this->assertSame($expected, $policy->evaluate($clock->now(), $created, $expires));
    }

    /**
     * Without a creation time, which the verifier allows only when its option
     * `requireCreationTime` is off, `expires` alone decides, with no clamping.
     *
     * @return iterable<string, array{int, int | null, FailureReason | null}>
     */
    public static function evaluationsWithoutACreationTimeProvider(): iterable
    {
        yield 'no expiry either' => [0, null, null];
        yield 'far in the future with no expiry' => [-864000, null, null];
        yield 'far in the past with no expiry' => [864000, null, null];
        yield 'at the expiry plus the skew' => [60, 0, null];
        yield 'one second after the expiry plus the skew' => [61, 0, FailureReason::Expired];
        yield 'an expiry beyond the maximum lifetime is not clamped' => [3600, 7200, null];
    }

    #[DataProvider('evaluationsWithoutACreationTimeProvider')]
    public function testEvaluatesExpiresAloneWithoutACreationTime(
        int $nowOffset,
        ?int $expiresOffset,
        ?FailureReason $expected,
    ): void {
        $policy = new TimePolicy(
            clockSkew: new DateInterval('PT60S'),
            defaultLifetime: new DateInterval('PT300S'),
            maximumLifetime: new DateInterval('PT600S'),
        );
        $reference = new DateTimeImmutable('@1618884473');
        $now = $reference->modify(sprintf('%+d seconds', $nowOffset));
        $expires = $expiresOffset === null ? null : $reference->modify(sprintf('%+d seconds', $expiresOffset));

        $this->assertSame($expected, $policy->evaluate($now, null, $expires));
    }

    public function testAZeroSkewAcceptsACreationTimeEqualToNow(): void
    {
        $policy = new TimePolicy(clockSkew: new DateInterval('PT0S'));
        $now = new DateTimeImmutable('@1618884473');

        $this->assertNull($policy->evaluate($now, $now, null));
        $this->assertSame(FailureReason::NotYetValid, $policy->evaluate($now, $now->modify('+1 second'), null));
    }
}
