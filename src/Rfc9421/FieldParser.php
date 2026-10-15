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

namespace SocialWeb\Http\MessageSignatures\Rfc9421;

use Bakame\Http\StructuredFields\Bytes;
use Bakame\Http\StructuredFields\Dictionary;
use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\Parameters;
use Bakame\Http\StructuredFields\SyntaxError;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\StructuredFields;

use function array_slice;
use function is_int;
use function is_string;
use function sprintf;

/**
 * Reads the `Signature-Input` and `Signature` fields of RFC 9421 section 4
 *
 * Both fields are Dictionaries. Each label must be in both, with an Inner List
 * of Strings in the one and a Byte Sequence in the other, and the six
 * parameters of section 2.3 are read with their types; anything else is
 * `MalformedSignature`. A parameter the package does not know stays in the
 * Inner List for the `@signature-params` line and is otherwise ignored, since
 * the registry of section 6.3 allows more. The `keyid` parameter is required,
 * because the resolver needs it.
 *
 * @internal
 */
final class FieldParser
{
    public const string SIGNATURE_INPUT = 'signature-input';
    public const string SIGNATURE = 'signature';

    /**
     * Returns the first signatures of the message, in the order of
     * `Signature-Input`, up to the limit; an empty list when both fields are
     * present and empty
     *
     * @param int $maxSignatures how many labels to read
     *
     * @return list<ParsedSignature>
     *
     * @throws Failure `MalformedSignature` when a field does not parse or has
     *     a label the other lacks, or when a signature does not have the
     *     shape section 4 gives it
     */
    public static function parse(MessageContext $context, int $maxSignatures): array
    {
        $inputs = self::dictionary($context, self::SIGNATURE_INPUT);
        $signatures = self::dictionary($context, self::SIGNATURE);

        foreach ($inputs->keys() as $label) {
            if (!$signatures->hasKeys($label)) {
                throw new Failure(
                    FailureReason::MalformedSignature,
                    sprintf('the label "%s" is in Signature-Input and not in Signature', $label),
                );
            }
        }

        foreach ($signatures->keys() as $label) {
            if (!$inputs->hasKeys($label)) {
                throw new Failure(
                    FailureReason::MalformedSignature,
                    sprintf('the label "%s" is in Signature and not in Signature-Input', $label),
                );
            }
        }

        $parsed = [];

        foreach (array_slice($inputs->keys(), 0, $maxSignatures) as $label) {
            $parsed[] = self::parseOne($label, $inputs->getByKey($label), $signatures->getByKey($label));
        }

        return $parsed;
    }

    private static function parseOne(
        string $label,
        Item | InnerList $input,
        Item | InnerList $signature,
    ): ParsedSignature {
        if (!$input instanceof InnerList) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('the Signature-Input member "%s" is not an Inner List', $label),
            );
        }

        $bytes = $signature instanceof Item ? $signature->value() : null;

        if (!$bytes instanceof Bytes) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('the Signature member "%s" is not a Byte Sequence', $label),
            );
        }

        $covered = [];

        foreach ($input as $item) {
            /** @var Item $item */
            $covered[] = ComponentIdentifier::fromItem($item);
        }

        $parameters = $input->parameters();
        $keyId = self::string($parameters, 'keyid', $label);

        if ($keyId === null) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('the signature "%s" has no keyid parameter', $label),
            );
        }

        return new ParsedSignature(
            label: $label,
            coveredComponents: $covered,
            signatureParams: $input,
            keyId: $keyId,
            created: self::integer($parameters, 'created', $label),
            expires: self::integer($parameters, 'expires', $label),
            nonce: self::string($parameters, 'nonce', $label),
            algorithm: self::string($parameters, 'alg', $label),
            tag: self::string($parameters, 'tag', $label),
            signature: $bytes->decoded(),
        );
    }

    private static function dictionary(MessageContext $context, string $field): Dictionary
    {
        if (!$context->hasField($field)) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('the message has a %s field and no %s field', self::other($field), $field),
            );
        }

        try {
            return StructuredFields::parseDictionary($context->field($field));
        } catch (SyntaxError $error) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('the %s field does not parse as a Dictionary', $field),
                $error,
            );
        }
    }

    private static function other(string $field): string
    {
        return $field === self::SIGNATURE ? self::SIGNATURE_INPUT : self::SIGNATURE;
    }

    private static function integer(Parameters $parameters, string $key, string $label): ?int
    {
        if (!$parameters->hasKeys($key)) {
            return null;
        }

        $value = $parameters->getByKey($key)->value();

        if (!is_int($value)) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('the %s parameter of "%s" is not an Integer', $key, $label),
            );
        }

        return $value;
    }

    private static function string(Parameters $parameters, string $key, string $label): ?string
    {
        if (!$parameters->hasKeys($key)) {
            return null;
        }

        $value = $parameters->getByKey($key)->value();

        if (!is_string($value)) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('the %s parameter of "%s" is not a String', $key, $label),
            );
        }

        return $value;
    }
}
