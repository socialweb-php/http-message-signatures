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

namespace SocialWeb\Http\MessageSignatures;

use DateInterval;

/**
 * Checks on `DateInterval` values shared by the options and the time policy
 *
 * @internal
 */
final class Intervals
{
    /**
     * Returns whether the interval runs backward
     *
     * A `DateInterval` from the constructor is never negative, but one from
     * `DateInterval::createFromDateString()` or a date difference can have
     * the inverted flag or a negative component.
     */
    public static function isNegative(DateInterval $interval): bool
    {
        return $interval->invert === 1
            || $interval->y < 0
            || $interval->m < 0
            || $interval->d < 0
            || $interval->h < 0
            || $interval->i < 0
            || $interval->s < 0
            || $interval->f < 0;
    }
}
