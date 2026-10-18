<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Cavage;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Cavage\HttpDate;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

class HttpDateTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function datesProvider(): iterable
    {
        // The three examples of RFC 9110 section 5.6.7.
        yield 'an IMF-fixdate' => ['Sun, 06 Nov 1994 08:49:37 GMT', '2026-10-16', '1994-11-06T08:49:37+00:00'];
        yield 'an RFC 850 date' => ['Sunday, 06-Nov-94 08:49:37 GMT', '2026-10-16', '1994-11-06T08:49:37+00:00'];
        yield 'an asctime date' => ['Sun Nov  6 08:49:37 1994', '2026-10-16', '1994-11-06T08:49:37+00:00'];
        yield 'an asctime date with a two-digit day' => [
            'Wed Nov 16 08:49:37 1994',
            '2026-10-16',
            '1994-11-16T08:49:37+00:00',
        ];
        yield 'an RFC 850 date at most 50 years ahead' => [
            'Monday, 06-Nov-76 08:49:37 GMT',
            '2026-10-16',
            '2076-11-06T08:49:37+00:00',
        ];
        yield 'an RFC 850 date more than 50 years ahead' => [
            'Monday, 06-Nov-77 08:49:37 GMT',
            '2026-10-16',
            '1977-11-06T08:49:37+00:00',
        ];
        yield 'a leap day' => ['Tue, 29 Feb 2000 23:59:59 GMT', '2026-10-16', '2000-02-29T23:59:59+00:00'];
        yield 'an IMF-fixdate in the year 100' => [
            'Sat, 06 Nov 0100 08:49:37 GMT',
            '2026-10-16',
            '0100-11-06T08:49:37+00:00',
        ];
        yield 'an IMF-fixdate in the year 26' => [
            'Sat, 06 Nov 0026 08:49:37 GMT',
            '2026-10-16',
            '0026-11-06T08:49:37+00:00',
        ];
        yield 'an asctime date in the year 26' => [
            'Sat Nov  6 08:49:37 0026',
            '2026-10-16',
            '0026-11-06T08:49:37+00:00',
        ];
        yield 'an RFC 850 date read in the year 2000' => [
            'Saturday, 06-Nov-10 08:49:37 GMT',
            '2000-06-01',
            '2010-11-06T08:49:37+00:00',
        ];
        yield 'an RFC 850 date read in the year 2099' => [
            'Saturday, 06-Nov-10 08:49:37 GMT',
            '2099-06-01',
            '2010-11-06T08:49:37+00:00',
        ];
    }

    #[DataProvider('datesProvider')]
    public function testReadsAnHttpDate(string $value, string $now, string $expected): void
    {
        $this->assertSame($expected, HttpDate::parse($value, new DateTimeImmutable($now))?->format('c'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedProvider(): iterable
    {
        yield 'not a date' => ['wrong date'];
        yield 'the year 0' => ['Sun, 06 Nov 0000 08:49:37 GMT'];
        yield 'empty' => [''];
        yield 'another time zone' => ['Sun, 06 Nov 1994 08:49:37 UTC'];
        yield 'a lowercase month' => ['Sun, 06 nov 1994 08:49:37 GMT'];
        yield 'a day that does not exist' => ['Fri, 31 Nov 1994 08:49:37 GMT'];
        yield 'a February 29 outside a leap year' => ['Tue, 29 Feb 1900 08:49:37 GMT'];
        yield 'hour 24' => ['Sun, 06 Nov 1994 24:00:00 GMT'];
        yield 'minute 60' => ['Sun, 06 Nov 1994 08:60:00 GMT'];
        yield 'second 61' => ['Sun, 06 Nov 1994 08:49:61 GMT'];
        yield 'a trailing space' => ['Sun, 06 Nov 1994 08:49:37 GMT '];
        yield 'two dates joined' => ['Sun, 06 Nov 1994 08:49:37 GMT, Sun, 06 Nov 1994 08:49:38 GMT'];
    }

    #[DataProvider('rejectedProvider')]
    public function testRefusesWhatIsNotAnHttpDate(string $value): void
    {
        $this->assertNull(HttpDate::parse($value, new DateTimeImmutable('2026-10-16')));
    }

    public function testAcceptsALeapSecond(): void
    {
        $this->assertSame(
            '1998-12-31T23:59:59+00:00',
            HttpDate::parse('Thu, 31 Dec 1998 23:59:60 GMT', new DateTimeImmutable('2026-10-16'))
                ?->modify('-1 second')
                ->format('c'),
        );
    }
}
