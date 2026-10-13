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

use DateTimeImmutable;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;

/**
 * What `Verifier::verify()` found
 *
 * Everything a replay store needs is here: the key identifier, the times, the
 * nonce, and the signature bytes.
 */
final readonly class VerificationResult
{
    /**
     * @param bool $verified whether the signature verified
     * @param FailureReason | null $reason why it did not; `null` on success
     * @param string $detail for logs: the label, the component, the parameter,
     *     or the algorithm the failure concerns; empty on success
     * @param Form | null $form the form detected; `null` only for
     *     `NoSignature`
     * @param Algorithm | null $algorithm set once the algorithm is resolved
     * @param string | null $keyId set once the fields are parsed
     * @param string | null $label the signature label; RFC 9421 only
     * @param list<string> $coveredComponents as the signature named them
     * @param DateTimeImmutable | null $created the creation time
     * @param DateTimeImmutable | null $expires the expiry as sent, before
     *     clamping
     * @param string | null $nonce the nonce parameter
     * @param string | null $signature the raw signature bytes
     * @param bool $keyRefreshed whether the resolver's `refresh()` was called
     * @param bool $requestTargetVerifiedWithoutQuery whether the draft form's
     *     retry without the query string is what verified
     *
     * @throws InvalidArgument when a verified result has a reason or a
     *     detail, when a failed result has no reason, or when the form is
     *     absent for a reason other than `NoSignature` or present for it
     */
    public function __construct(
        public bool $verified,
        public ?FailureReason $reason = null,
        public string $detail = '',
        public ?Form $form = null,
        public ?Algorithm $algorithm = null,
        public ?string $keyId = null,
        public ?string $label = null,
        public array $coveredComponents = [],
        public ?DateTimeImmutable $created = null,
        public ?DateTimeImmutable $expires = null,
        public ?string $nonce = null,
        public ?string $signature = null,
        public bool $keyRefreshed = false,
        public bool $requestTargetVerifiedWithoutQuery = false,
    ) {
        if ($verified && $reason !== null) {
            throw new InvalidArgument('A verified result cannot have a failure reason');
        }

        if ($verified && $detail !== '') {
            throw new InvalidArgument('A verified result cannot have a detail');
        }

        if (!$verified && $reason === null) {
            throw new InvalidArgument('A failed result must have a failure reason');
        }

        if (($form === null) !== ($reason === FailureReason::NoSignature)) {
            throw new InvalidArgument('The form is absent exactly when the reason is NoSignature');
        }
    }
}
