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

use Bakame\Http\StructuredFields\InnerList;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\StructuredFields;

use function implode;
use function in_array;
use function is_string;
use function preg_match;
use function sprintf;

/**
 * Builds the signature base of RFC 9421 section 2.5
 *
 * One line per covered component, the serialized identifier, a colon, a
 * space, and the value, joined by a newline, and the `@signature-params` line
 * last. Each error case of the section has a reason: a component identifier
 * that appears twice, `@signature-params` among the covered components, or
 * parameters that cannot be combined is `MalformedSignature`; a parameter or
 * derived component the package does not implement is
 * `UnsupportedSignature`; a component the message lacks, or whose value
 * cannot go into the base, is `MissingComponent`.
 *
 * @internal
 */
final class SignatureBase
{
    public const string SIGNATURE_PARAMS = '@signature-params';

    /**
     * The field and derived component parameters of RFC 9421 section 6.5
     */
    private const array KNOWN_PARAMETERS = ['sf', 'key', 'bs', 'req', 'tr', 'name'];

    /**
     * @param list<ComponentIdentifier> $coveredComponents in signing order
     * @param InnerList $signatureParams the value of the `@signature-params`
     *     line
     *
     * @throws Failure with the reason the section's error case maps to
     */
    public static function build(MessageContext $context, array $coveredComponents, InnerList $signatureParams): string
    {
        $lines = [];
        $seen = [];

        foreach ($coveredComponents as $identifier) {
            $serialized = $identifier->serialize();

            if ($identifier->name === self::SIGNATURE_PARAMS) {
                throw new Failure(
                    FailureReason::MalformedSignature,
                    '@signature-params must not be among the covered components',
                );
            }

            if (in_array($serialized, $seen, true)) {
                throw new Failure(
                    FailureReason::MalformedSignature,
                    sprintf('the component identifier %s appears more than once', $serialized),
                );
            }

            $seen[] = $serialized;
            $lines[] = $serialized . ': ' . self::value($context, $identifier, $serialized);
        }

        $lines[] = '"' . self::SIGNATURE_PARAMS . '": ' . StructuredFields::serialize($signatureParams);

        return implode("\n", $lines);
    }

    /**
     * Step 2.5 of the section: the value for one component identifier
     */
    private static function value(MessageContext $context, ComponentIdentifier $identifier, string $serialized): string
    {
        $parameters = $identifier->parameters;

        foreach ($parameters->keys() as $key) {
            if (!in_array($key, self::KNOWN_PARAMETERS, true)) {
                throw new Failure(
                    FailureReason::UnsupportedSignature,
                    sprintf('the parameter "%s" of %s is not one the package knows', $key, $serialized),
                );
            }
        }

        if ($parameters->hasKeys('req')) {
            $context = $context->forRelatedRequest();
        }

        $value = $identifier->isDerived()
            ? self::derivedValue($context, $identifier, $serialized)
            : self::fieldValue($context, $identifier, $serialized);

        if (preg_match('/[^\x00-\x7f]/', $value) === 1) {
            throw new Failure(
                FailureReason::MissingComponent,
                sprintf(
                    'the value of %s holds a byte outside ASCII, which the signature base cannot hold',
                    $serialized,
                ),
            );
        }

        return $value;
    }

    private static function derivedValue(
        MessageContext $context,
        ComponentIdentifier $identifier,
        string $serialized,
    ): string {
        foreach (['sf', 'key', 'bs', 'tr'] as $key) {
            if ($identifier->hasParameter($key)) {
                throw new Failure(
                    FailureReason::UnsupportedSignature,
                    sprintf('the parameter "%s" does not apply to the derived component %s', $key, $serialized),
                );
            }
        }

        if ($identifier->name === '@query-param') {
            if (!$identifier->hasParameter('name')) {
                throw new Failure(FailureReason::UnsupportedSignature, '@query-param needs a name parameter');
            }

            $name = $identifier->parameters->getByKey('name')->value();

            if (!is_string($name)) {
                throw new Failure(
                    FailureReason::MalformedSignature,
                    sprintf('the name parameter of %s is not a String', $serialized),
                );
            }

            return $context->queryParameter($name);
        }

        if ($identifier->hasParameter('name')) {
            throw new Failure(
                FailureReason::UnsupportedSignature,
                sprintf('the name parameter applies to @query-param only, not to %s', $serialized),
            );
        }

        return $context->derived($identifier->name);
    }

    private static function fieldValue(
        MessageContext $context,
        ComponentIdentifier $identifier,
        string $serialized,
    ): string {
        if ($identifier->hasParameter('name')) {
            throw new Failure(
                FailureReason::UnsupportedSignature,
                sprintf('the name parameter applies to @query-param only, not to %s', $serialized),
            );
        }

        if ($identifier->hasParameter('tr')) {
            throw new Failure(
                FailureReason::UnsupportedSignature,
                sprintf('trailer fields are not implemented, so %s cannot be covered', $serialized),
            );
        }

        if ($identifier->hasParameter('bs') && ($identifier->hasParameter('sf') || $identifier->hasParameter('key'))) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('the bs parameter of %s cannot be combined with sf or key', $serialized),
            );
        }

        if ($identifier->hasParameter('key')) {
            $key = $identifier->parameters->getByKey('key')->value();

            if (!is_string($key)) {
                throw new Failure(
                    FailureReason::MalformedSignature,
                    sprintf('the key parameter of %s is not a String', $serialized),
                );
            }

            return $context->dictionaryMember($identifier->name, $key);
        }

        if ($identifier->hasParameter('sf')) {
            return $context->fieldStructured($identifier->name);
        }

        if ($identifier->hasParameter('bs')) {
            return $context->fieldBinaryWrapped($identifier->name);
        }

        return $context->field($identifier->name);
    }
}
