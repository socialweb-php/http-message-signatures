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

use Bakame\Http\StructuredFields\Dictionary;
use Bakame\Http\StructuredFields\Ietf;
use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\OuterList;
use Bakame\Http\StructuredFields\Parameters;
use Bakame\Http\StructuredFields\SyntaxError;

use function restore_error_handler;
use function set_error_handler;

/**
 * Parses and serializes Structured Fields through the library in its RFC 8941
 * mode, the edition RFC 9421 cites
 *
 * The library's parser raises a PHP warning before it throws `SyntaxError` for
 * a member or parameter whose value is empty, such as `a=`. A verifier runs on
 * untrusted input, so the warning is held back for the length of the parse and
 * the `SyntaxError` is what the caller sees.
 *
 * @internal
 */
final class StructuredFields
{
    /**
     * @throws SyntaxError when the value is not a Dictionary
     */
    public static function parseDictionary(string $value): Dictionary
    {
        set_error_handler(static fn (): bool => true);

        try {
            return Dictionary::fromHttpValue($value, Ietf::Rfc8941);
        } finally {
            restore_error_handler();
        }
    }

    /**
     * @param string $value the parameters, starting with a semicolon
     *
     * @throws SyntaxError when the value is not a list of parameters
     */
    public static function parseParameters(string $value): Parameters
    {
        set_error_handler(static fn (): bool => true);

        try {
            return Parameters::fromHttpValue($value, Ietf::Rfc8941);
        } finally {
            restore_error_handler();
        }
    }

    public static function serialize(Dictionary | OuterList | InnerList | Item | Parameters $value): string
    {
        return $value->toHttpValue(Ietf::Rfc8941);
    }
}
