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
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;

use function array_map;
use function strstr;

/**
 * The signature of a message in the draft form, as its `Signature` or
 * `Authorization` field gave it
 *
 * @internal
 */
final readonly class ParsedSignature
{
    /**
     * The `algorithm` value of draft-cavage-http-signatures-12 appendix E.2
     * that defers to the key
     */
    public const string HS2019 = 'hs2019';

    /**
     * @param string $keyId the `keyId` parameter
     * @param string | null $algorithm the `algorithm` parameter, as sent
     * @param string | null $created the `created` parameter, as sent: an
     *     integer
     * @param string | null $expires the `expires` parameter, as sent: an
     *     integer, or a decimal number as the draft's section 2.1.5 allows
     * @param list<ComponentIdentifier> $coveredComponents the `headers`
     *     parameter in order, or its default when it is absent
     * @param string $signature the raw signature bytes
     */
    public function __construct(
        public string $keyId,
        public ?string $algorithm,
        public ?string $created,
        public ?string $expires,
        public array $coveredComponents,
        public string $signature,
    ) {
    }

    /**
     * Returns whether the key chooses the algorithm: the `algorithm`
     * parameter is absent or `hs2019`
     */
    public function keyDecidesAlgorithm(): bool
    {
        return $this->algorithm === null || $this->algorithm === self::HS2019;
    }

    /**
     * Returns the `created` parameter as a time
     */
    public function createdTime(): ?DateTimeImmutable
    {
        return $this->created === null ? null : new DateTimeImmutable('@' . $this->created);
    }

    /**
     * Returns the `expires` parameter as a time, any fraction of a second
     * dropped
     */
    public function expiresTime(): ?DateTimeImmutable
    {
        if ($this->expires === null) {
            return null;
        }

        $seconds = strstr($this->expires, '.', true);

        return new DateTimeImmutable('@' . ($seconds === false ? $this->expires : $seconds));
    }

    /**
     * Returns the covered components as the `headers` parameter names them,
     * for the result
     *
     * @return list<string>
     */
    public function coveredComponentNames(): array
    {
        return array_map(
            static fn (ComponentIdentifier $identifier): string => $identifier->toString(),
            $this->coveredComponents,
        );
    }
}
