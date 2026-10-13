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

use function strtolower;

/**
 * A hash algorithm for the `Content-Digest` and `Digest` fields
 *
 * These are the two entries the RFC 9530 registry marks Active. The value of
 * each case is the RFC 9530 algorithm key, which is also the `Content-Digest`
 * Dictionary key. The deprecated entries of that registry, and the MD5 and
 * SHA-1 of RFC 3230, are refused on both sides, because RFC 9530 section 5
 * forbids a deprecated algorithm where the digest is signed.
 */
enum DigestAlgorithm: string
{
    case Sha256 = 'sha-256';
    case Sha512 = 'sha-512';

    /**
     * Returns the name `hash_init()` takes for this algorithm
     */
    public function hashName(): string
    {
        return match ($this) {
            self::Sha256 => 'sha256',
            self::Sha512 => 'sha512',
        };
    }

    /**
     * Returns the length in bytes of a digest this algorithm produces
     */
    public function digestLength(): int
    {
        return match ($this) {
            self::Sha256 => 32,
            self::Sha512 => 64,
        };
    }

    /**
     * Returns the token RFC 5843 registers for this algorithm in the RFC 3230
     * `Digest` field
     *
     * The token is compared case-insensitively on the way in, as RFC 3230
     * section 4.1.1 says, and emitted in this spelling on the way out.
     */
    public function rfc3230Token(): string
    {
        return match ($this) {
            self::Sha256 => 'SHA-256',
            self::Sha512 => 'SHA-512',
        };
    }

    /**
     * Returns the algorithm an RFC 3230 token names, compared
     * case-insensitively, or `null` for a token the package refuses
     */
    public static function tryFromRfc3230Token(string $token): ?self
    {
        return match (strtolower($token)) {
            'sha-256' => self::Sha256,
            'sha-512' => self::Sha512,
            default => null,
        };
    }
}
