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

use function base64_decode;
use function base64_encode;
use function explode;
use function preg_match;
use function preg_replace;
use function sprintf;
use function strlen;
use function strspn;
use function strtolower;
use function substr;

use const PREG_UNMATCHED_AS_NULL;

/**
 * Parses the signature fields of draft-cavage-http-signatures-12 sections 3.1
 * and 4.1
 *
 * The `Signature` field is read, and when it is absent, the `Authorization`
 * field with the `Signature` scheme. The value is a comma-separated list of
 * auth-params as RFC 7235 section 2.1 defines them, `token "=" ( token /
 * quoted-string )`, whose names are matched case-insensitively. A duplicated
 * parameter is malformed, as the draft's section 2.2 says, and a parameter the
 * draft does not define is ignored.
 *
 * @internal
 */
final class FieldParser
{
    private const string SIGNATURE = 'signature';
    private const string AUTHORIZATION = 'authorization';

    /**
     * One auth-param: a token, `=` with optional whitespace around it, and a
     * token or a quoted-string of RFC 9110 section 5.6.4
     */
    private const string PARAMETER_PATTERN = "/\\G(?<name>[!#$%&'*+.^_`|~0-9A-Za-z-]+)[ \\t]*=[ \\t]*"
        . "(?:(?<token>[!#$%&'*+.^_`|~0-9A-Za-z-]+)"
        . '|"(?<quoted>(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\\\[\t \x21-\x7e\x80-\xff])*)")/';

    /**
     * An integer number of seconds, at most 15 digits, the range of an RFC
     * 8941 Integer that the RFC 9421 form uses for the same parameters
     */
    private const string CREATED_PATTERN = '/^[0-9]{1,15}\z/';

    /**
     * An integer number of seconds, or a decimal one as the draft's section
     * 2.1.5 allows for `expires`
     */
    private const string EXPIRES_PATTERN = '/^[0-9]{1,15}(?:\.[0-9]{1,15})?\z/';

    /**
     * Parses the message's signature
     *
     * When `headers` is absent, the default is `(created)` when `algorithm`
     * is absent or `hs2019`, and `date` otherwise. The draft's section 2.1.6
     * gives `(created)` as the default and its section 2.3 refuses
     * `(created)` under an algorithm that begins with `rsa`, `hmac`, or
     * `ecdsa`; its appendix C.1 signs `date` by default under `rsa-sha256`.
     *
     * @throws Failure `NoSignature` when the message has neither field;
     *     `MalformedSignature` when the field is not a list of auth-params, a
     *     parameter appears twice, `keyId` or `signature` is absent or empty,
     *     the signature is not strict Base64, `created` or `expires` is not a
     *     number of seconds, or `headers` is empty or has an empty name; and
     *     `UnsupportedSignature` for a name in parentheses that the draft
     *     does not define
     */
    public static function parse(MessageContext $context): ParsedSignature
    {
        [$field, $value] = self::fieldValue($context);
        $parameters = self::parameters($field, $value);

        $keyId = $parameters['keyid'] ?? '';

        if ($keyId === '') {
            throw new Failure(FailureReason::MalformedSignature, 'the keyId parameter is absent or empty');
        }

        $encoded = $parameters['signature'] ?? '';

        if ($encoded === '') {
            throw new Failure(FailureReason::MalformedSignature, 'the signature parameter is absent or empty');
        }

        $signature = base64_decode($encoded, true);

        if ($signature === false || base64_encode($signature) !== $encoded) {
            throw new Failure(FailureReason::MalformedSignature, 'the signature parameter is not strict Base64');
        }

        $created = $parameters['created'] ?? null;

        if ($created !== null && preg_match(self::CREATED_PATTERN, $created) !== 1) {
            throw new Failure(FailureReason::MalformedSignature, 'the created parameter is not an integer');
        }

        $expires = $parameters['expires'] ?? null;

        if ($expires !== null && preg_match(self::EXPIRES_PATTERN, $expires) !== 1) {
            throw new Failure(FailureReason::MalformedSignature, 'the expires parameter is not a number of seconds');
        }

        $algorithm = $parameters['algorithm'] ?? null;

        return new ParsedSignature(
            keyId: $keyId,
            algorithm: $algorithm,
            created: $created,
            expires: $expires,
            coveredComponents: self::coveredComponents($parameters['headers'] ?? null, $algorithm),
            signature: $signature,
        );
    }

    /**
     * @return array{string, string} the field's name and its value
     *
     * @throws Failure `NoSignature` or `MalformedSignature`
     */
    private static function fieldValue(MessageContext $context): array
    {
        if (!$context->hasField(self::SIGNATURE) && !$context->hasField(self::AUTHORIZATION)) {
            throw new Failure(
                FailureReason::NoSignature,
                'the message has neither a Signature field nor an Authorization field',
            );
        }

        try {
            if ($context->hasField(self::SIGNATURE)) {
                return [self::SIGNATURE, $context->field(self::SIGNATURE)];
            }

            $value = $context->field(self::AUTHORIZATION);
        } catch (Failure $failure) {
            throw new Failure(FailureReason::MalformedSignature, $failure->detail, $failure);
        }

        if (preg_match('/^signature[ \t]+/i', $value, $matches) !== 1) {
            throw new Failure(
                FailureReason::MalformedSignature,
                'the Authorization field does not have the Signature scheme',
            );
        }

        return [self::AUTHORIZATION, substr($value, strlen($matches[0]))];
    }

    /**
     * @return array<string, string> the parameters by lowercased name, with
     *     a quoted-string's quoted-pairs undone
     *
     * @throws Failure `MalformedSignature`
     */
    private static function parameters(string $field, string $value): array
    {
        $parameters = [];
        $offset = 0;
        $length = strlen($value);

        while (true) {
            // Optional whitespace, and the empty list elements RFC 9110
            // section 5.6.1.2 tells a recipient to ignore.
            $offset += strspn($value, " \t,", $offset);

            if ($offset === $length) {
                return $parameters;
            }

            if (preg_match(self::PARAMETER_PATTERN, $value, $matches, PREG_UNMATCHED_AS_NULL, $offset) !== 1) {
                throw new Failure(
                    FailureReason::MalformedSignature,
                    sprintf('the %s field is not a list of auth-params', $field),
                );
            }

            $offset += strlen($matches[0]);
            $name = strtolower($matches['name']);

            if (isset($parameters[$name])) {
                throw new Failure(
                    FailureReason::MalformedSignature,
                    sprintf('the parameter %s appears more than once', $name),
                );
            }

            $parameters[$name] = $matches['token'] ?? self::unquote((string) $matches['quoted']);
            $offset += strspn($value, " \t", $offset);

            if ($offset !== $length && $value[$offset] !== ',') {
                throw new Failure(
                    FailureReason::MalformedSignature,
                    sprintf('the %s field is not a list of auth-params', $field),
                );
            }
        }
    }

    /**
     * Undoes the quoted-pairs of a quoted-string's content
     */
    private static function unquote(string $quoted): string
    {
        return (string) preg_replace('/\\\\(.)/s', '$1', $quoted);
    }

    /**
     * @return list<ComponentIdentifier>
     *
     * @throws Failure
     */
    private static function coveredComponents(?string $headers, ?string $algorithm): array
    {
        if ($headers === null) {
            $default = $algorithm === null || $algorithm === ParsedSignature::HS2019 ? '(created)' : 'date';

            return [ComponentIdentifier::fromCavageName($default)];
        }

        if ($headers === '') {
            throw new Failure(FailureReason::MalformedSignature, 'the headers parameter is empty');
        }

        $identifiers = [];

        foreach (explode(' ', strtolower($headers)) as $name) {
            if ($name === '') {
                throw new Failure(FailureReason::MalformedSignature, 'the headers parameter has an empty name');
            }

            $identifiers[] = ComponentIdentifier::fromCavageName($name);
        }

        return $identifiers;
    }
}
