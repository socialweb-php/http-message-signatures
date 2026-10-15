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
use DateTimeImmutable;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;

use function min;

/**
 * How far a signature's times may stray from the verifier's clock
 *
 * The creation time is the `created` parameter, or in the draft form without
 * one, the covered `Date` field. The effective expiry is the `expires`
 * parameter when present and the creation time plus `defaultLifetime` when
 * not, clamped to the creation time plus `maximumLifetime` either way. The
 * defaults are what the largest implementation enforces; RFC 9421 section
 * 3.2.1 leaves the values to the application.
 */
final readonly class TimePolicy
{
    /**
     * @param DateInterval $clockSkew how far the signer's clock may differ from
     *     the injected clock, in either direction
     * @param DateInterval $defaultLifetime how long a signature without
     *     `expires` is valid after its creation time
     * @param DateInterval $maximumLifetime an `expires` further from the
     *     creation time than this is clamped to it
     *
     * @throws InvalidArgument when an interval is negative
     */
    public function __construct(
        public DateInterval $clockSkew = new DateInterval('PT1H'),
        public DateInterval $defaultLifetime = new DateInterval('PT5M'),
        public DateInterval $maximumLifetime = new DateInterval('PT12H'),
    ) {
        if (Intervals::isNegative($clockSkew)) {
            throw new InvalidArgument('clockSkew must not be negative');
        }

        if (Intervals::isNegative($defaultLifetime)) {
            throw new InvalidArgument('defaultLifetime must not be negative');
        }

        if (Intervals::isNegative($maximumLifetime)) {
            throw new InvalidArgument('maximumLifetime must not be negative');
        }
    }

    /**
     * Applies the policy to a signature's times and returns why it fails, or
     * `null` when it passes
     *
     * A creation time after now plus the clock skew is `NotYetValid`. Now
     * after the effective expiry plus the clock skew is `Expired`. A
     * signature with no creation time, which the verifier allows only when
     * its option `requireCreationTime` is off, is judged by `expires` alone,
     * with no clamping, and passes when that is absent too.
     *
     * @param DateTimeImmutable $now the injected clock's current time
     * @param DateTimeImmutable | null $created the signature's creation time
     * @param DateTimeImmutable | null $expires the signature's `expires`
     *     parameter, as sent
     */
    public function evaluate(
        DateTimeImmutable $now,
        ?DateTimeImmutable $created,
        ?DateTimeImmutable $expires,
    ): ?FailureReason {
        if ($created === null) {
            $effectiveExpiry = $expires;
        } else {
            if ($created > $now->add($this->clockSkew)) {
                return FailureReason::NotYetValid;
            }

            $effectiveExpiry = min(
                $expires ?? $created->add($this->defaultLifetime),
                $created->add($this->maximumLifetime),
            );
        }

        if ($effectiveExpiry !== null && $now > $effectiveExpiry->add($this->clockSkew)) {
            return FailureReason::Expired;
        }

        return null;
    }
}
