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

/**
 * Finds the key a signature names
 *
 * The key identifier is the parameter value as the message gave it, an opaque
 * string: the package never parses it as a URL, never fetches, and never
 * caches. Anything a resolver throws passes through `Verifier::verify()`
 * untouched, so a caller can tell a key that does not exist from a key that
 * could not be fetched. The resolver is the one place for key policy: a
 * resolver that refuses keys below a size, keys from a blocked origin, or
 * revoked keys returns `null` or throws, and the package does not second-guess
 * it.
 */
interface KeyResolver
{
    /**
     * Returns the key, or `null` when there is no such key, which the
     * verifier reports as `KeyNotFound`
     */
    public function resolve(string $keyId): ?VerificationKey;

    /**
     * Returns the key again after a failure a rotated key could explain,
     * fetching it afresh when the resolver caches; a resolver with no cache
     * returns what `resolve()` returns
     *
     * The verifier calls this once per signature, and only when its option
     * `retryWithRefreshedKey` is on.
     */
    public function refresh(string $keyId): ?VerificationKey;
}
