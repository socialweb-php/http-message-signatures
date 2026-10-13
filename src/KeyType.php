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
 * The kind of key material a key holds, detected from the material
 */
enum KeyType
{
    /**
     * An RSA key of any size
     */
    case Rsa;

    /**
     * An EC key on the curve P-256, which OpenSSL names `prime256v1`
     */
    case EcP256;

    /**
     * An EC key on the curve P-384, which OpenSSL names `secp384r1`
     */
    case EcP384;

    /**
     * An Ed25519 key
     */
    case Ed25519;

    /**
     * A byte string shared by the signer and the verifier
     */
    case SharedSecret;

    /**
     * Returns the algorithms a key of this type permits by default, in order
     * of preference
     *
     * @return non-empty-list<Algorithm>
     */
    public function defaultAlgorithms(): array
    {
        return match ($this) {
            self::Rsa => [Algorithm::RsaV15Sha256, Algorithm::RsaPssSha512],
            self::EcP256 => [Algorithm::EcdsaP256Sha256],
            self::EcP384 => [Algorithm::EcdsaP384Sha384],
            self::Ed25519 => [Algorithm::Ed25519],
            self::SharedSecret => [Algorithm::HmacSha256],
        };
    }

    /**
     * Returns whether a key of this type can run the algorithm
     *
     * An RSA key can never run HMAC, so the downgrade of RFC 9421 section
     * 7.3.6, an HMAC keyed with a public key, cannot happen.
     */
    public function accepts(Algorithm $algorithm): bool
    {
        return $algorithm->keyType() === $this;
    }
}
