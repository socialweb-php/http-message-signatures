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
 * The verifier calls the resolver once per signature, with a `KeyLookup` that
 * holds the message, the form, and the parameters of the signature that the
 * verifier reads, after every check that needs no key has passed. By then the
 * verifier has established that the form is one the options accept and the
 * fields parse; that the algorithm named, if any, is one the package
 * implements; that the policy that needs no key is met, that is, the target,
 * the creation time, the digest, the nonce, and the required components; that
 * the time policy is met; that the signature base was built, so every covered
 * component is present in the message or the related request and has a value;
 * and that every covered digest field of the message matches its content. It
 * has not verified the signature bytes. Everything the resolver reads from the
 * message is therefore a claim until `Verifier::verify()` returns a verified
 * result: the resolver may use it to find a key, and nothing else, and a
 * resolver that fetches applies its own limits to what the message makes it
 * fetch.
 *
 * The key identifier is the parameter value as the message gave it, an opaque
 * string: the package never parses it as a URL, never fetches, and never
 * caches. Anything a resolver throws passes through `Verifier::verify()`
 * untouched, so a caller can tell a key that does not exist from a key that
 * could not be fetched. The resolver is the one place for key policy: a
 * resolver that refuses keys below a size, keys from a blocked origin, or
 * revoked keys returns `null` or throws, and the package does not second-guess
 * it. The `owner` of the key it returns is its claim about whose key that is,
 * which the verifier reports only on a verified result.
 */
interface KeyResolver
{
    /**
     * Returns the key, or `null` when there is no such key, which the
     * verifier reports as `KeyNotFound`
     */
    public function resolve(KeyLookup $lookup): ?VerificationKey;

    /**
     * Returns the key again after a failure a rotated key could explain,
     * fetching it afresh when the resolver caches; a resolver with no cache
     * returns what `resolve()` returns
     *
     * The verifier calls this once per signature, with the same `KeyLookup`
     * it passed to `resolve()`, and only when its option
     * `retryWithRefreshedKey` is on. A fetch that fails here must not discard
     * a cached key: the resolver returns `null`, and the original failure
     * reason stands.
     */
    public function refresh(KeyLookup $lookup): ?VerificationKey;
}
