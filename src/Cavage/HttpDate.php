<?php

/**
 * This file is part of socialweb/http-message-signatures
 *
 * socialweb/http-message-signatures is free software: you can redistribute it
 * and/or modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * socialweb/http-message-signatures is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with socialweb/http-message-signatures. If not, see
 * <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

declare(strict_types=1);

namespace SocialWeb\Http\MessageSignatures\Cavage;

use DateTimeImmutable;
use DateTimeZone;

use function checkdate;
use function intdiv;
use function preg_match;

/**
 * Reads the `Date` field that the draft form takes as the creation time when
 * the `created` parameter is absent
 *
 * RFC 9110 section 5.6.7 says a recipient must accept all three formats of an
 * HTTP date: the IMF-fixdate, and the obsolete RFC 850 and asctime formats.
 * A two-digit year that would be more than 50 years in the future is taken
 * as the most recent year in the past with the same last two digits, as that
 * section says.
 *
 * @internal
 */
final class HttpDate
{
    private const array MONTHS = [
        'Jan' => 1,
        'Feb' => 2,
        'Mar' => 3,
        'Apr' => 4,
        'May' => 5,
        'Jun' => 6,
        'Jul' => 7,
        'Aug' => 8,
        'Sep' => 9,
        'Oct' => 10,
        'Nov' => 11,
        'Dec' => 12,
    ];

    private const string MONTH = '(?<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)';

    private const string TIME = '(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})';

    private const string IMF_FIXDATE = '/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (?<day>[0-9]{2}) ' . self::MONTH
        . ' (?<year>[0-9]{4}) ' . self::TIME . ' GMT\z/';

    private const string RFC850_DATE = '/^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), '
        . '(?<day>[0-9]{2})-' . self::MONTH . '-(?<year>[0-9]{2}) ' . self::TIME . ' GMT\z/';

    private const string ASCTIME_DATE = '/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) ' . self::MONTH
        . ' (?<day>[ 0-9][0-9]) ' . self::TIME . ' (?<year>[0-9]{4})\z/';

    /**
     * Returns the time the value names, or `null` when it is not an HTTP date
     *
     * @param DateTimeImmutable $now the verifier's clock, against which a
     *     two-digit year is placed
     */
    public static function parse(string $value, DateTimeImmutable $now): ?DateTimeImmutable
    {
        if (
            preg_match(self::IMF_FIXDATE, $value, $matches) !== 1
            && preg_match(self::ASCTIME_DATE, $value, $matches) !== 1
            && preg_match(self::RFC850_DATE, $value, $matches) !== 1
        ) {
            return null;
        }

        $year = (int) $matches['year'];

        if ($year < 100) {
            $thisYear = (int) $now->setTimezone(new DateTimeZone('UTC'))->format('Y');
            $year += intdiv($thisYear, 100) * 100;

            if ($year > $thisYear + 50) {
                $year -= 100;
            }
        }

        $month = self::MONTHS[$matches['month']];
        $day = (int) $matches['day'];
        $hour = (int) $matches['hour'];
        $minute = (int) $matches['minute'];
        $second = (int) $matches['second'];

        if (!checkdate($month, $day, $year) || $hour > 23 || $minute > 59 || $second > 60) {
            return null;
        }

        return (new DateTimeImmutable('@0'))->setDate($year, $month, $day)->setTime($hour, $minute, $second);
    }
}
