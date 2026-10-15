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

use DateInterval;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;

use function in_array;
use function preg_match;
use function sprintf;

/**
 * What `Signer::sign()` produces
 *
 * The default covered components are what the implementations accept. Under
 * the draft form: `(request-target)`, `host`, `date`, and `digest` when the
 * message has content. Under RFC 9421: `@method`, `@target-uri`, `host`,
 * `date`, and `content-digest` when the message has content. For a response,
 * `(request-target)`, `@method`, and `@target-uri` are replaced by `@status`
 * under RFC 9421 and dropped under the draft. A caller who names the
 * components gets exactly what was named: the digest field is then included
 * only if listed, and listing it on a message without content signs the digest
 * of empty content, which RFC 9530 allows.
 */
final readonly class SigningOptions
{
    /**
     * A Dictionary key of RFC 8941 section 3.1.2
     */
    private const string LABEL_PATTERN = '/^[a-z*][a-z0-9_.*-]*\z/';

    /**
     * The characters an RFC 8941 String may hold
     */
    private const string STRING_PATTERN = '/^[\x20-\x7e]*\z/';

    /**
     * Component identifiers in signing order, or `null` for the form's default
     *
     * @var list<string> | null
     */
    public ?array $coveredComponents;

    /**
     * @var list<ComponentIdentifier> | null
     */
    private ?array $coveredComponentIdentifiers;

    /**
     * Which digests to compute for the digest field
     *
     * @var non-empty-list<DigestAlgorithm>
     */
    public array $digestAlgorithms;

    /**
     * @param Form $form which form to produce
     * @param list<string> | null $coveredComponents component identifiers in
     *     signing order, each a component name followed by its parameters in
     *     the syntax of RFC 8941, as in `@query-param;name="Pet"` or
     *     `content-digest;req`; `null` means the form's default
     * @param Algorithm | null $algorithm `null` means the first algorithm the
     *     key permits that has a name in the form
     * @param string $label the signature label; RFC 9421 only
     * @param bool $created whether to emit the creation time
     * @param DateInterval | null $expires emit an expiry this long after the
     *     creation time
     * @param string | null $nonce RFC 9421 only
     * @param string | null $tag RFC 9421 only
     * @param list<DigestAlgorithm> $digestAlgorithms which digests to compute
     *     for the digest field; must not be empty
     *
     * @throws InvalidArgument for an option that does not fit the form: an
     *     algorithm with no name in the form, or a `nonce`, `tag`, or `label`
     *     other than the default under the draft; and for a value that fits
     *     no form: a component identifier that is empty, does not parse,
     *     appears twice, or names `@signature-params`, a label that is not a
     *     valid Dictionary key, a negative expiry, a nonce or tag outside
     *     printable ASCII, or a digest list that is empty or holds a duplicate
     */
    public function __construct(
        public Form $form,
        ?array $coveredComponents = null,
        public ?Algorithm $algorithm = null,
        public string $label = 'sig1',
        public bool $created = true,
        public ?DateInterval $expires = null,
        public ?string $nonce = null,
        public ?string $tag = null,
        array $digestAlgorithms = [DigestAlgorithm::Sha256],
    ) {
        $identifiers = $coveredComponents === null ? null : self::parseIdentifiers($coveredComponents);

        if ($algorithm !== null && $algorithm->name($form) === null) {
            throw new InvalidArgument(
                sprintf('Algorithm %s has no name in the form %s', $algorithm->name, $form->value),
            );
        }

        if (preg_match(self::LABEL_PATTERN, $label) !== 1) {
            throw new InvalidArgument(sprintf('The label "%s" is not a valid Dictionary key', $label));
        }

        if ($expires !== null && Intervals::isNegative($expires)) {
            throw new InvalidArgument('expires must not be negative');
        }

        if ($nonce !== null && preg_match(self::STRING_PATTERN, $nonce) !== 1) {
            throw new InvalidArgument('The nonce must hold only printable ASCII characters');
        }

        if ($tag !== null && preg_match(self::STRING_PATTERN, $tag) !== 1) {
            throw new InvalidArgument('The tag must hold only printable ASCII characters');
        }

        if ($form === Form::Cavage) {
            if ($label !== 'sig1') {
                throw new InvalidArgument('The draft form has no signature labels; leave label at its default');
            }

            if ($nonce !== null) {
                throw new InvalidArgument('The draft form has no nonce parameter');
            }

            if ($tag !== null) {
                throw new InvalidArgument('The draft form has no tag parameter');
            }
        }

        if ($digestAlgorithms === []) {
            throw new InvalidArgument('The list of digest algorithms must not be empty');
        }

        $seen = [];

        foreach ($digestAlgorithms as $digestAlgorithm) {
            if (in_array($digestAlgorithm, $seen, true)) {
                throw new InvalidArgument(
                    sprintf('Digest algorithm %s appears more than once', $digestAlgorithm->value),
                );
            }

            $seen[] = $digestAlgorithm;
        }

        $this->coveredComponents = $coveredComponents;
        $this->coveredComponentIdentifiers = $identifiers;
        $this->digestAlgorithms = $seen;
    }

    /**
     * Returns the covered components as parsed, or `null` for the form's
     * default
     *
     * @internal
     *
     * @return list<ComponentIdentifier> | null
     */
    public function coveredComponentIdentifiers(): ?array
    {
        return $this->coveredComponentIdentifiers;
    }

    /**
     * @param list<string> $components
     *
     * @return list<ComponentIdentifier>
     *
     * @throws InvalidArgument
     */
    private static function parseIdentifiers(array $components): array
    {
        $identifiers = [];

        foreach ($components as $component) {
            $identifier = ComponentIdentifier::parse($component);

            if ($identifier->name === '@signature-params') {
                throw new InvalidArgument('@signature-params cannot be a covered component');
            }

            foreach ($identifiers as $earlier) {
                if ($earlier->equals($identifier)) {
                    throw new InvalidArgument(
                        sprintf('The covered component %s appears more than once', $identifier->toString()),
                    );
                }
            }

            $identifiers[] = $identifier;
        }

        return $identifiers;
    }
}
