<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use DateInterval;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Intervals;

class IntervalsTest extends TestCase
{
    /**
     * @return iterable<string, array{DateInterval}>
     */
    public static function negativeIntervalsProvider(): iterable
    {
        $inverted = new DateInterval('PT5M');
        $inverted->invert = 1;

        yield 'inverted' => [$inverted];
        yield 'negative years' => [self::withComponent('y', -1)];
        yield 'negative months' => [self::withComponent('m', -1)];
        yield 'negative days' => [self::withComponent('d', -1)];
        yield 'negative hours' => [self::withComponent('h', -1)];
        yield 'negative minutes' => [DateInterval::createFromDateString('-5 minutes')];
        yield 'negative seconds' => [self::withComponent('s', -1)];
        yield 'negative microseconds' => [self::withComponent('f', -0.5)];
        yield 'one negative component among positive ones' => [self::withComponent('d', -1, 'P1Y2MT3H4M5S')];
    }

    #[DataProvider('negativeIntervalsProvider')]
    public function testSeesANegativeInterval(DateInterval $interval): void
    {
        $this->assertTrue(Intervals::isNegative($interval));
    }

    /**
     * @return iterable<string, array{DateInterval}>
     */
    public static function nonNegativeIntervalsProvider(): iterable
    {
        yield 'zero' => [new DateInterval('PT0S')];
        yield 'every component set' => [new DateInterval('P1Y2M3DT4H5M6S')];
        yield 'microseconds' => [self::withComponent('f', 0.5)];
        yield 'from a date string' => [DateInterval::createFromDateString('5 minutes')];
    }

    #[DataProvider('nonNegativeIntervalsProvider')]
    public function testAcceptsANonNegativeInterval(DateInterval $interval): void
    {
        $this->assertFalse(Intervals::isNegative($interval));
    }

    private static function withComponent(string $component, int | float $value, string $base = 'PT0S'): DateInterval
    {
        $interval = new DateInterval($base);
        $interval->{$component} = $value;

        return $interval;
    }
}
