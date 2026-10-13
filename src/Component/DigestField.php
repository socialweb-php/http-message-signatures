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

use Bakame\Http\StructuredFields\Bytes;
use Bakame\Http\StructuredFields\Dictionary;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\SyntaxError;
use SocialWeb\Http\MessageSignatures\DigestAlgorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\StructuredFields;

use function array_map;
use function base64_decode;
use function base64_encode;
use function count;
use function explode;
use function hash_equals;
use function implode;
use function in_array;
use function is_array;
use function sprintf;
use function strlen;
use function trim;

/**
 * The two digest fields: `Content-Digest` of RFC 9530 and `Digest` of RFC 3230
 *
 * `Content-Digest` is a Dictionary of algorithm key to Byte Sequence, parsed
 * and serialized through the Structured Fields library. `Digest` is a
 * comma-separated list of `token=value`, where the token is compared
 * case-insensitively, as RFC 3230 section 4.1.1 says, and emitted as `SHA-256`
 * or `SHA-512`, the spelling of RFC 5843, and the value is strict Base64.
 *
 * @internal
 */
final class DigestField
{
    public const string CONTENT_DIGEST = 'content-digest';
    public const string DIGEST = 'digest';

    /**
     * Returns whether a lowercased field name is one of the two digest fields
     */
    public static function isDigestField(string $fieldName): bool
    {
        return $fieldName === self::CONTENT_DIGEST || $fieldName === self::DIGEST;
    }

    /**
     * Serializes digests, keyed by RFC 9530 algorithm key with raw bytes as
     * values, as the value of the named field
     *
     * @param array<string, string> $digests as `Content::digests()` returns
     *     them
     *
     * @throws InvalidArgument for a field name that is not a digest field, an
     *     empty list of digests, or a key that is not an algorithm the package
     *     knows
     */
    public static function serialize(string $fieldName, array $digests): string
    {
        if ($digests === []) {
            throw new InvalidArgument('There are no digests to serialize');
        }

        $entries = [];

        foreach ($digests as $key => $bytes) {
            $algorithm = DigestAlgorithm::tryFrom($key);

            if ($algorithm === null) {
                throw new InvalidArgument(sprintf('"%s" is not a digest algorithm the package knows', $key));
            }

            $entries[] = [$algorithm, $bytes];
        }

        return match ($fieldName) {
            self::CONTENT_DIGEST => StructuredFields::serialize(Dictionary::fromPairs(array_map(
                static fn (array $entry): array => [$entry[0]->value, Item::fromDecodedBytes($entry[1])],
                $entries,
            ))),
            self::DIGEST => implode(', ', array_map(
                static fn (array $entry): string => $entry[0]->rfc3230Token() . '=' . base64_encode($entry[1]),
                $entries,
            )),
            default => throw new InvalidArgument(sprintf('"%s" is not a digest field', $fieldName)),
        };
    }

    /**
     * Recomputes every digest in the field value whose algorithm the package
     * knows and compares it with the content
     *
     * @return string | null `null` when every known digest matches; otherwise
     *     the detail for `DigestMismatch`: what did not match, what did not
     *     parse, or what the field offered when it names no known algorithm
     *
     * @throws InvalidArgument for a field name that is not a digest field
     */
    public static function check(string $fieldName, string $fieldValue, Content $content): ?string
    {
        $claims = match ($fieldName) {
            self::CONTENT_DIGEST => self::parseContentDigest($fieldValue),
            self::DIGEST => self::parseDigest($fieldValue),
            default => throw new InvalidArgument(sprintf('"%s" is not a digest field', $fieldName)),
        };

        if (!is_array($claims)) {
            return $claims;
        }

        $algorithms = [];

        foreach ($claims as [$algorithm]) {
            if (!in_array($algorithm, $algorithms, true)) {
                $algorithms[] = $algorithm;
            }
        }

        $digests = $content->digests($algorithms);

        foreach ($claims as [$algorithm, $bytes]) {
            if (!hash_equals($digests[$algorithm->value], $bytes)) {
                return sprintf('the %s digest in %s does not match the content', $algorithm->value, $fieldName);
            }
        }

        return null;
    }

    /**
     * @return non-empty-list<array{DigestAlgorithm, string}> | string the
     *     known digests, or the detail of why there are none
     */
    private static function parseContentDigest(string $fieldValue): array | string
    {
        try {
            $dictionary = StructuredFields::parseDictionary($fieldValue);
        } catch (SyntaxError $error) {
            return sprintf('%s does not parse as a Dictionary: %s', self::CONTENT_DIGEST, $error->getMessage());
        }

        $claims = [];
        $offered = [];

        foreach ($dictionary as [$key, $member]) {
            $offered[] = $key;
            $algorithm = DigestAlgorithm::tryFrom($key);

            if ($algorithm === null) {
                continue;
            }

            $value = $member instanceof Item ? $member->value() : null;

            if (!$value instanceof Bytes) {
                return sprintf('the %s member of %s is not a Byte Sequence', $key, self::CONTENT_DIGEST);
            }

            $claims[] = [$algorithm, $value->decoded()];
        }

        return $claims === [] ? self::noKnownAlgorithm(self::CONTENT_DIGEST, $offered) : $claims;
    }

    /**
     * @return non-empty-list<array{DigestAlgorithm, string}> | string the
     *     known digests, or the detail of why there are none
     */
    private static function parseDigest(string $fieldValue): array | string
    {
        $claims = [];
        $offered = [];

        foreach (explode(',', $fieldValue) as $entry) {
            $entry = trim($entry, " \t");

            if ($entry === '') {
                continue;
            }

            $parts = explode('=', $entry, 2);

            if (count($parts) !== 2 || $parts[0] === '') {
                return sprintf('%s is not a list of token=value entries', self::DIGEST);
            }

            $offered[] = $parts[0];
            $algorithm = DigestAlgorithm::tryFromRfc3230Token($parts[0]);

            if ($algorithm === null) {
                continue;
            }

            $bytes = base64_decode($parts[1], true);

            if ($bytes === false) {
                return sprintf('the %s value in %s is not valid Base64', $parts[0], self::DIGEST);
            }

            if (strlen($bytes) !== $algorithm->digestLength()) {
                return sprintf('the %s value in %s has the wrong length', $parts[0], self::DIGEST);
            }

            $claims[] = [$algorithm, $bytes];
        }

        return $claims === [] ? self::noKnownAlgorithm(self::DIGEST, $offered) : $claims;
    }

    /**
     * @param list<string> $offered
     */
    private static function noKnownAlgorithm(string $fieldName, array $offered): string
    {
        return sprintf('%s names no algorithm the package knows; it offered: %s', $fieldName, implode(', ', $offered));
    }
}
