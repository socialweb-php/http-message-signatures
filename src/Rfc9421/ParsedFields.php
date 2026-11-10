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

namespace SocialWeb\Http\MessageSignatures\Rfc9421;

/**
 * What `FieldParser` read from the `Signature-Input` and `Signature` fields:
 * the signatures, up to the limit it was given, and whether the fields have
 * labels beyond that limit
 *
 * @internal
 */
final readonly class ParsedFields
{
    /**
     * @param list<ParsedSignature> $signatures the signatures read, in the
     *     order of `Signature-Input`
     * @param bool $labelsLeftUnread whether the fields have more labels than
     *     the limit, so that some were not read
     */
    public function __construct(
        public array $signatures,
        public bool $labelsLeftUnread,
    ) {
    }
}
