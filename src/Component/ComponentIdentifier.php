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

use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\Parameters;
use Bakame\Http\StructuredFields\SyntaxError;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\StructuredFields;

use function in_array;
use function is_string;
use function preg_match;
use function sprintf;
use function str_starts_with;
use function strpos;
use function strtolower;
use function substr;

/**
 * A component identifier: under RFC 9421, a component name and its
 * parameters, as section 2 defines them; under the draft form, a name from the
 * `headers` parameter, with nothing after it
 *
 * The options write an identifier as the name followed by its parameters in
 * the syntax of RFC 8941, as in `@query-param;name="Pet"` or
 * `content-digest;req`. The signature base writes it with the name in double
 * quotes, as in `"@query-param";name="Pet"`. A field name is lowercased on
 * the way in; a derived component name is lowercase by the registry. Under
 * the draft form a name is a field name or one of the draft's three names in
 * parentheses, such as `(request-target)`.
 *
 * @internal
 */
final class ComponentIdentifier
{
    /**
     * The names of draft-cavage-http-signatures-12 section 2.3 that are not
     * fields
     */
    public const array CAVAGE_PSEUDO_HEADERS = ['(request-target)', '(created)', '(expires)'];

    /**
     * A derived component name of RFC 9421 section 6.4.1
     */
    private const string DERIVED_NAME_PATTERN = '/^@[a-z0-9-]+\z/';

    /**
     * A field name, in any case: the `tchar` characters of RFC 9110
     */
    private const string FIELD_NAME_PATTERN = "/^[!#$%&'*+.^_`|~0-9a-z-]+\\z/i";

    private function __construct(
        public readonly string $name,
        public readonly Parameters $parameters,
    ) {
    }

    /**
     * Parses an identifier as the options write it
     *
     * @throws InvalidArgument when the identifier has no name, a name that is
     *     not a component name, or parameters that do not parse
     */
    public static function parse(string $identifier): self
    {
        $semicolon = strpos($identifier, ';');
        $name = $semicolon === false ? $identifier : substr($identifier, 0, $semicolon);

        if ($name === '') {
            throw new InvalidArgument('A component identifier must not be empty');
        }

        if (!self::isComponentName($name)) {
            throw new InvalidArgument(sprintf('"%s" is not a component name', $name));
        }

        try {
            $parameters = $semicolon === false
                ? Parameters::new()
                : StructuredFields::parseParameters(substr($identifier, $semicolon));
        } catch (SyntaxError $error) {
            throw new InvalidArgument(
                sprintf('The parameters of the component identifier "%s" do not parse', $identifier),
                0,
                $error,
            );
        }

        return new self(strtolower($name), $parameters);
    }

    /**
     * Parses a name of the draft form as the options write it: a field name
     * or one of the draft's three names in parentheses, in any case
     *
     * @throws InvalidArgument when the name is empty or is neither
     */
    public static function parseCavage(string $name): self
    {
        if ($name === '') {
            throw new InvalidArgument('A component identifier must not be empty');
        }

        $lowercase = strtolower($name);
        $isPseudoHeader = in_array($lowercase, self::CAVAGE_PSEUDO_HEADERS, true);

        if (!$isPseudoHeader && preg_match(self::FIELD_NAME_PATTERN, $name) !== 1) {
            throw new InvalidArgument(sprintf('"%s" is not a component name of the draft form', $name));
        }

        return new self($lowercase, Parameters::new());
    }

    /**
     * Parses an identifier that may be written in either form: a name in
     * parentheses as the draft form writes it, and anything else as RFC 9421
     * writes it
     *
     * @throws InvalidArgument when the identifier does not parse in the form
     *     it is written in
     */
    public static function parseInEitherForm(string $identifier): self
    {
        return str_starts_with($identifier, '(') ? self::parseCavage($identifier) : self::parse($identifier);
    }

    /**
     * Builds an identifier from a name of the draft form's `headers`
     * parameter, which the parser has lowercased
     *
     * @throws Failure `UnsupportedSignature` for a name in parentheses that
     *     the draft does not define, and `MalformedSignature` for a name that
     *     is not a field name
     */
    public static function fromCavageName(string $name): self
    {
        if (in_array($name, self::CAVAGE_PSEUDO_HEADERS, true)) {
            return new self($name, Parameters::new());
        }

        if (preg_match('/^\(.*\)\z/', $name) === 1) {
            throw new Failure(
                FailureReason::UnsupportedSignature,
                sprintf('%s is not a name the draft form defines', $name),
            );
        }

        if (preg_match(self::FIELD_NAME_PATTERN, $name) !== 1) {
            throw new Failure(FailureReason::MalformedSignature, sprintf('"%s" is not a field name', $name));
        }

        return new self($name, Parameters::new());
    }

    /**
     * Builds an identifier from a member of a parsed `Signature-Input` Inner
     * List
     *
     * @throws Failure `MalformedSignature` when the member is not a String or
     *     its value is not a component name
     */
    public static function fromItem(Item $item): self
    {
        $name = $item->value();

        if (!is_string($name)) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('a covered component identifier must be a String, not %s', $item->type()->name),
            );
        }

        if (!self::isComponentName($name) || $name !== strtolower($name)) {
            throw new Failure(
                FailureReason::MalformedSignature,
                sprintf('"%s" is not a component name', $name),
            );
        }

        return new self($name, $item->parameters());
    }

    /**
     * Returns whether this is a derived component, whose name starts with `@`
     */
    public function isDerived(): bool
    {
        return str_starts_with($this->name, '@');
    }

    /**
     * Returns whether this is one of the draft form's names in parentheses
     */
    public function isPseudoHeader(): bool
    {
        return str_starts_with($this->name, '(');
    }

    /**
     * Returns whether the identifier has the parameter
     */
    public function hasParameter(string $key): bool
    {
        return $this->parameters->hasKeys($key);
    }

    /**
     * Returns whether this is the named component with no parameters
     */
    public function isPlain(string $name): bool
    {
        return $this->name === $name && $this->parameters->isEmpty();
    }

    /**
     * Returns whether the two identifiers serialize the same
     */
    public function equals(self $other): bool
    {
        return $this->serialize() === $other->serialize();
    }

    /**
     * Returns the identifier as a String Item with its parameters, for the
     * `Signature-Input` Inner List
     */
    public function toItem(): Item
    {
        return Item::fromAssociative($this->name, $this->parameters);
    }

    /**
     * Returns the identifier as the signature base writes it: the name in
     * double quotes, then the parameters
     */
    public function serialize(): string
    {
        return StructuredFields::serialize($this->toItem());
    }

    /**
     * Returns the identifier as the options write it: the name, then the
     * parameters
     */
    public function toString(): string
    {
        return $this->name . StructuredFields::serialize($this->parameters);
    }

    private static function isComponentName(string $name): bool
    {
        return preg_match(self::DERIVED_NAME_PATTERN, $name) === 1 || preg_match(self::FIELD_NAME_PATTERN, $name) === 1;
    }
}
