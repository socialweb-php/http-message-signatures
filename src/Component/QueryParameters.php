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

namespace SocialWeb\Http\MessageSignatures\Component;

use function explode;
use function strtr;
use function urldecode;
use function urlencode;

/**
 * The `application/x-www-form-urlencoded` parsing and serializing that
 * `@query-param` needs, as RFC 9421 section 2.2.8 cites them from the WHATWG
 * URL standard
 *
 * @internal
 */
final class QueryParameters
{
    /**
     * Parses a query string into its name and value pairs, each re-encoded
     * with the percent-encode-after-encoding process, in the order they occur
     *
     * The parser splits on `&`, skips empty sequences, splits each at its
     * first `=`, turns `+` into a space, and percent-decodes. An absent `=`
     * gives an empty value.
     *
     * @return list<array{string, string}>
     */
    public static function parse(string $query): array
    {
        $pairs = [];

        foreach (explode('&', $query) as $sequence) {
            if ($sequence === '') {
                continue;
            }

            $parts = explode('=', $sequence, 2);
            $pairs[] = [self::encode(urldecode($parts[0])), self::encode(urldecode($parts[1] ?? ''))];
        }

        return $pairs;
    }

    /**
     * Percent-encodes a decoded name or value with the
     * `application/x-www-form-urlencoded` percent-encode set, which leaves
     * only ASCII letters and digits, `*`, `-`, `.`, and `_` as they are, and
     * writes a space as `%20`
     */
    public static function encode(string $decoded): string
    {
        return strtr(urlencode($decoded), ['+' => '%20', '%2A' => '*']);
    }
}
