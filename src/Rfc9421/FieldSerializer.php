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

use Bakame\Http\StructuredFields\Dictionary;
use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\SyntaxError;
use Psr\Http\Message\MessageInterface;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\StructuredFields;

use function array_map;
use function sprintf;

/**
 * Writes the `Signature-Input` and `Signature` fields of RFC 9421 section 4
 *
 * A message that already has the two fields gets the new label appended to
 * each; a label already present is `InvalidArgument`.
 *
 * @internal
 */
final class FieldSerializer
{
    /**
     * Builds the value of a `Signature-Input` member: the covered component
     * identifiers as an Inner List, with the signature parameters in the
     * order given
     *
     * @param list<ComponentIdentifier> $coveredComponents
     * @param array<string, int | string> $parameters the signature
     *     parameters in the order they are to be serialized
     */
    public static function signatureParams(array $coveredComponents, array $parameters): InnerList
    {
        $items = array_map(
            static fn (ComponentIdentifier $identifier): Item => $identifier->toItem(),
            $coveredComponents,
        );

        return InnerList::fromAssociative($items, $parameters);
    }

    /**
     * Returns the message with the signature added to both fields under the
     * label
     *
     * @param T $message
     *
     * @return T
     *
     * @throws InvalidArgument when the message already has a signature with
     *     the label, or when one of its two fields does not parse or holds a
     *     line break
     *
     * @template T of MessageInterface
     */
    public static function append(
        MessageInterface $message,
        string $label,
        InnerList $signatureParams,
        string $signature,
    ): MessageInterface {
        $inputs = self::existing($message, FieldParser::SIGNATURE_INPUT);
        $signatures = self::existing($message, FieldParser::SIGNATURE);

        if ($inputs->hasKeys($label) || $signatures->hasKeys($label)) {
            throw new InvalidArgument(sprintf('The message already has a signature with the label "%s"', $label));
        }

        /** @var T */
        return $message
            ->withHeader('Signature-Input', StructuredFields::serialize($inputs->add($label, $signatureParams)))
            ->withHeader('Signature', StructuredFields::serialize(
                $signatures->add($label, Item::fromDecodedBytes($signature)),
            ));
    }

    private static function existing(MessageInterface $message, string $field): Dictionary
    {
        if (!$message->hasHeader($field)) {
            return Dictionary::new();
        }

        try {
            return StructuredFields::parseDictionary((new MessageContext($message))->field($field));
        } catch (SyntaxError $error) {
            throw new InvalidArgument(
                sprintf('The %s field of the message does not parse as a Dictionary', $field),
                0,
                $error,
            );
        } catch (Failure $failure) {
            throw new InvalidArgument('Cannot sign the message: ' . $failure->detail, 0, $failure);
        }
    }
}
