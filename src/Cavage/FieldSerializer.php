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

use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;

use function addcslashes;
use function array_map;
use function base64_encode;
use function implode;
use function preg_match;

/**
 * Serializes the `Signature` field of draft-cavage-http-signatures-12
 * section 4.1
 *
 * The parameters are written in the order of the draft's examples, `keyId`,
 * `algorithm`, `created`, `expires`, `headers`, and `signature`, separated by
 * a comma with no space; `created` and `expires` are bare integers and the
 * others quoted-strings.
 *
 * @internal
 */
final class FieldSerializer
{
    /**
     * @param string $keyId the `keyId` parameter
     * @param string $algorithm the `algorithm` parameter
     * @param int | null $created the `created` parameter, when emitted
     * @param int | null $expires the `expires` parameter, when emitted
     * @param list<ComponentIdentifier> $coveredComponents the `headers`
     *     parameter, in order
     * @param string $signature the raw signature bytes
     *
     * @throws InvalidArgument when the key identifier holds a character
     *     outside printable ASCII, which a quoted-string can hold only as
     *     obsolete text
     */
    public static function serialize(
        string $keyId,
        string $algorithm,
        ?int $created,
        ?int $expires,
        array $coveredComponents,
        string $signature,
    ): string {
        if (preg_match('/^[\x20-\x7e]*\z/', $keyId) !== 1) {
            throw new InvalidArgument(
                'Under the draft form the key identifier must hold only printable ASCII characters',
            );
        }

        $parameters = ['keyId="' . addcslashes($keyId, '"\\') . '"', 'algorithm="' . $algorithm . '"'];

        if ($created !== null) {
            $parameters[] = 'created=' . $created;
        }

        if ($expires !== null) {
            $parameters[] = 'expires=' . $expires;
        }

        $names = array_map(
            static fn (ComponentIdentifier $identifier): string => $identifier->name,
            $coveredComponents,
        );
        $parameters[] = 'headers="' . implode(' ', $names) . '"';
        $parameters[] = 'signature="' . base64_encode($signature) . '"';

        return implode(',', $parameters);
    }
}
