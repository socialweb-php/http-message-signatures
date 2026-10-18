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
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\FailureReason;

use function implode;
use function preg_match;
use function sprintf;

/**
 * Builds the signature string of draft-cavage-http-signatures-12 section 2.3
 *
 * One line per covered component, in the order of the `headers` parameter:
 * the lowercased name, a colon, a space, and the value, the lines joined by a
 * newline with none after the last. `(request-target)` is the lowercased
 * method, a space, and the request target; `(created)` and `(expires)` are the
 * integer values of the parameters of the same name; a field's value is its
 * lines with leading and trailing whitespace removed, joined with a comma and a
 * space, as `MessageContext` gives it.
 *
 * @internal
 */
final class SignatureBase
{
    /**
     * The algorithms under which section 2.3 refuses `(created)` and
     * `(expires)`: those whose name begins with `rsa`, `hmac`, or `ecdsa`
     */
    private const string NAMED_ALGORITHM_PATTERN = '/^(?:rsa|hmac|ecdsa)/';

    /**
     * @param list<ComponentIdentifier> $coveredComponents in signing order
     * @param string | null $algorithm the `algorithm` parameter, as sent or
     *     emitted
     * @param string | null $created the `created` parameter, as sent or
     *     emitted
     * @param string | null $expires the `expires` parameter, as sent or
     *     emitted
     * @param bool $includeQuery whether `(request-target)` has the query
     *     string; `false` only for the verifier's second try
     *
     * @throws Failure `MalformedSignature` for `(created)` or `(expires)`
     *     under a named algorithm, or covered without an integer parameter;
     *     `UnsupportedSignature` for `(request-target)` of a response; and
     *     `MissingComponent` for a field the message lacks or a value with a
     *     line break
     */
    public static function build(
        MessageContext $context,
        array $coveredComponents,
        ?string $algorithm,
        ?string $created,
        ?string $expires,
        bool $includeQuery = true,
    ): string {
        $lines = [];

        foreach ($coveredComponents as $identifier) {
            $value = match ($identifier->name) {
                '(request-target)' => $context->cavageRequestTarget($includeQuery),
                '(created)' => self::parameter('created', $created, $algorithm),
                '(expires)' => self::parameter('expires', $expires, $algorithm),
                default => $context->field($identifier->name),
            };

            $lines[] = $identifier->name . ': ' . $value;
        }

        return implode("\n", $lines);
    }

    /**
     * @throws Failure `MalformedSignature`
     */
    private static function parameter(string $name, ?string $value, ?string $algorithm): string
    {
        if ($algorithm !== null && preg_match(self::NAMED_ALGORITHM_PATTERN, $algorithm) === 1) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('(%s) cannot be covered under the algorithm %s', $name, $algorithm),
            );
        }

        if ($value === null) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('(%s) is covered and the %s parameter is absent', $name, $name),
            );
        }

        if (preg_match('/^[0-9]+\z/', $value) !== 1) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('(%s) is covered and the %s parameter is not an integer', $name, $name),
            );
        }

        return $value;
    }
}
