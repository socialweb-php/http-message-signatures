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

use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;

use function in_array;
use function sprintf;

/**
 * What `Verifier::verify()` accepts
 *
 * The target rule is a rule and not a literal list, so that the ways the
 * specifications allow all satisfy it. Under the draft, a request satisfies it
 * when `(request-target)` is covered. Under RFC 9421, a request satisfies it
 * when `@method` is covered together with `@target-uri`, with `@authority` and
 * `@path`, or with `@authority` and `@request-target`. A response satisfies it
 * when `@status` is covered under RFC 9421, and always under the draft, which
 * has no response target. The creation-time rule is satisfied by a `created`
 * parameter in either form, or by a covered `date` field under the draft,
 * which is where the implementations put it when `created` is absent.
 */
final readonly class VerifierOptions
{
    /**
     * Forms the verifier accepts; a message in another form is
     * `UnsupportedSignature`
     *
     * @var non-empty-list<Form>
     */
    public array $forms;

    /**
     * Component identifiers that must be covered, in addition to the rules
     * above
     *
     * @var list<string>
     */
    public array $requiredComponents;

    /**
     * @var list<ComponentIdentifier>
     */
    private array $requiredComponentIdentifiers;

    /**
     * @param non-empty-list<Form> $forms forms the verifier accepts; must not
     *     be empty
     * @param TimePolicy $timePolicy how far a signature's times may stray
     * @param bool $requireTarget the signature must cover the request target
     * @param bool $requireCreationTime the signature must have a creation time
     * @param bool $requireContentDigest a message with content must cover its
     *     digest field
     * @param list<string> $requiredComponents component identifiers that must
     *     be covered, each a component name followed by its parameters in
     *     the syntax of RFC 8941, as in `content-digest;req`
     * @param bool $requireNonce the `nonce` parameter must be present; RFC
     *     9421 only
     * @param bool $retryWithRefreshedKey call the resolver's `refresh()` once
     *     after a failure a rotated key could explain
     * @param bool $acceptRequestTargetWithoutQuery under the draft, try the
     *     signature base once more with the query string removed from
     *     `(request-target)` after a failure
     * @param int $maxSignatures how many RFC 9421 labels are tried before
     *     giving up; at least 1
     *
     * @throws InvalidArgument when the list of forms is empty or holds a
     *     duplicate, when a required component identifier is empty or does
     *     not parse, or when `maxSignatures` is below 1
     */
    public function __construct(
        array $forms = [Form::Cavage, Form::Rfc9421],
        public TimePolicy $timePolicy = new TimePolicy(),
        public bool $requireTarget = true,
        public bool $requireCreationTime = true,
        public bool $requireContentDigest = true,
        array $requiredComponents = [],
        public bool $requireNonce = false,
        public bool $retryWithRefreshedKey = true,
        public bool $acceptRequestTargetWithoutQuery = true,
        public int $maxSignatures = 3,
    ) {
        if ($forms === []) {
            throw new InvalidArgument('The list of forms must not be empty');
        }

        $seen = [];

        foreach ($forms as $form) {
            if (in_array($form, $seen, true)) {
                throw new InvalidArgument(sprintf('The form %s appears more than once', $form->value));
            }

            $seen[] = $form;
        }

        $identifiers = [];

        foreach ($requiredComponents as $component) {
            $identifiers[] = ComponentIdentifier::parse($component);
        }

        if ($maxSignatures < 1) {
            throw new InvalidArgument(sprintf('maxSignatures must be at least 1; %d given', $maxSignatures));
        }

        $this->forms = $seen;
        $this->requiredComponents = $requiredComponents;
        $this->requiredComponentIdentifiers = $identifiers;
    }

    /**
     * Returns the required components as parsed
     *
     * @internal
     *
     * @return list<ComponentIdentifier>
     */
    public function requiredComponentIdentifiers(): array
    {
        return $this->requiredComponentIdentifiers;
    }

    /**
     * Returns whether the verifier accepts the form
     */
    public function accepts(Form $form): bool
    {
        return in_array($form, $this->forms, true);
    }
}
