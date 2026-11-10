<?php

/**
 * This file is part of socialweb/http-message-signatures
 *
 * Copyright © socialweb/http-message-signatures Contributors
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

use DateTimeImmutable;
use DateTimeInterface;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;

/**
 * What the verifier hands the resolver when it asks for a key
 *
 * It holds the message, the form, and the parameters of the signature that the
 * verifier reads, so that a resolver reads what its protocol needs without the
 * verifier deciding for it. The verifier is the one producer, and a test of a
 * resolver is the other: the constructor takes the message, the form, and the
 * key identifier and defaults the rest, and it validates nothing beyond its
 * types.
 */
final readonly class KeyLookup
{
    /**
     * The creation time the time policy judged, as the result reports it
     */
    public ?DateTimeImmutable $created;

    /**
     * The expiry as sent, before clamping, as the result reports it
     */
    public ?DateTimeImmutable $expires;

    /**
     * @param MessageInterface $message the request or response being
     *     verified
     * @param Form $form the form detected
     * @param string $keyId the `keyid` or `keyId` parameter, as the message
     *     gave it; the package never parses it as a URL
     * @param RequestInterface | null $relatedRequest the request a response
     *     answers, as given to `Verifier::verify()`
     * @param string | null $label the signature label; RFC 9421 only
     * @param Algorithm | null $algorithm the algorithm the signature names,
     *     resolved, or `null` when the key decides: an absent `alg` under
     *     RFC 9421, or an absent or `hs2019` `algorithm` under the draft
     * @param DateTimeInterface | null $created the creation time the time
     *     policy judged, as the result reports it
     * @param DateTimeInterface | null $expires the expiry as sent, before
     *     clamping, as the result reports it
     * @param string | null $nonce the `nonce` parameter; RFC 9421 only
     * @param string | null $tag the `tag` parameter; RFC 9421 only
     * @param list<string> $coveredComponents the covered component
     *     identifiers, written as the result and the options write them, in
     *     the order the signature named them
     */
    public function __construct(
        public MessageInterface $message,
        public Form $form,
        public string $keyId,
        public ?RequestInterface $relatedRequest = null,
        public ?string $label = null,
        public ?Algorithm $algorithm = null,
        ?DateTimeInterface $created = null,
        ?DateTimeInterface $expires = null,
        public ?string $nonce = null,
        public ?string $tag = null,
        public array $coveredComponents = [],
    ) {
        $this->created = $created === null ? null : DateTimeImmutable::createFromInterface($created);
        $this->expires = $expires === null ? null : DateTimeImmutable::createFromInterface($expires);
    }
}
