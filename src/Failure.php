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

use RuntimeException;
use SocialWeb\Http\MessageSignatures\Exception\MessageSignaturesException;
use Throwable;

/**
 * Raised inside the package when a message cannot be verified, with the
 * reason the result reports; `Verifier` turns it into a result and `Signer`
 * into `InvalidArgument`
 *
 * @internal
 */
class Failure extends RuntimeException implements MessageSignaturesException
{
    public function __construct(
        public readonly FailureReason $reason,
        public readonly string $detail,
        ?Throwable $previous = null,
    ) {
        parent::__construct($reason->name . ': ' . $detail, 0, $previous);
    }
}
