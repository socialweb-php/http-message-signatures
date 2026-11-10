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

use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;

use function sprintf;
use function strtolower;

/**
 * A hash function, with the names the `Content-Digest` and `Digest` fields
 * give it
 *
 * The cases and their values are the ones every socialweb package uses. The
 * value of `Sha256` and of `Sha512` is also the algorithm key of RFC 9530,
 * which is the `Content-Digest` Dictionary key: they are the two entries the
 * RFC 9530 registry marks Active, and the two RFC 5843 registers for the
 * `Digest` field of RFC 3230. `Sha384` is in neither registry, so the package
 * refuses it where a digest field is written and does not read a `sha-384`
 * entry of a digest field. The deprecated entries of the RFC 9530 registry,
 * and the MD5 and SHA-1 of RFC 3230, are refused on both sides, because RFC
 * 9530 section 5 forbids a deprecated algorithm where the digest is signed.
 *
 * @link https://www.rfc-editor.org/rfc/rfc9530#section-5 Hash Algorithm Considerations and Registration
 */
enum HashAlgorithm: string
{
    case Sha256 = 'sha-256';
    case Sha384 = 'sha-384';
    case Sha512 = 'sha-512';

    /**
     * Returns the name `hash_init()` takes for this algorithm
     */
    public function hashName(): string
    {
        return match ($this) {
            self::Sha256 => 'sha256',
            self::Sha384 => 'sha384',
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
            self::Sha384 => 48,
            self::Sha512 => 64,
        };
    }

    /**
     * Returns whether the registries of the two digest fields have this
     * algorithm, which is so for `Sha256` and `Sha512`
     */
    public function isDigestFieldAlgorithm(): bool
    {
        return $this !== self::Sha384;
    }

    /**
     * Returns the token RFC 5843 registers for this algorithm in the RFC 3230
     * `Digest` field
     *
     * The token is compared case-insensitively on the way in, as RFC 3230
     * section 4.1.1 says, and emitted in this spelling on the way out.
     *
     * @throws InvalidArgument for `Sha384`, which has no token
     */
    public function rfc3230Token(): string
    {
        return match ($this) {
            self::Sha256 => 'SHA-256',
            self::Sha512 => 'SHA-512',
            self::Sha384 => throw new InvalidArgument(
                sprintf('Hash algorithm %s has no token in the Digest field', $this->name),
            ),
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
