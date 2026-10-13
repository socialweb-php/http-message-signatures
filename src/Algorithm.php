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
 * A signature algorithm, independent of the form that uses it
 *
 * These are the six algorithms of the RFC 9421 "HTTP Signature Algorithms"
 * registry. The draft form names three of them, and puts Ed25519 under
 * `hs2019`, the draft's placeholder that defers to the key.
 */
enum Algorithm
{
    /**
     * RSASSA-PKCS1-v1_5 with SHA-256
     */
    case RsaV15Sha256;

    /**
     * RSASSA-PSS with SHA-512
     */
    case RsaPssSha512;

    /**
     * Ed25519 as RFC 8032 defines it
     */
    case Ed25519;

    /**
     * ECDSA on P-256 with SHA-256
     */
    case EcdsaP256Sha256;

    /**
     * ECDSA on P-384 with SHA-384
     */
    case EcdsaP384Sha384;

    /**
     * HMAC with SHA-256
     */
    case HmacSha256;

    /**
     * Returns the name this algorithm has on the wire in the given form, or
     * `null` when the form has no name for it
     *
     * Under the draft form, Ed25519 is sent as `hs2019`: the draft has no
     * name of its own for it. The RSASSA-PSS and ECDSA algorithms have no draft
     * name at all.
     */
    public function name(Form $form): ?string
    {
        return match ($form) {
            Form::Cavage => match ($this) {
                self::RsaV15Sha256 => 'rsa-sha256',
                self::Ed25519 => 'hs2019',
                self::HmacSha256 => 'hmac-sha256',
                self::RsaPssSha512, self::EcdsaP256Sha256, self::EcdsaP384Sha384 => null,
            },
            Form::Rfc9421 => match ($this) {
                self::RsaV15Sha256 => 'rsa-v1_5-sha256',
                self::RsaPssSha512 => 'rsa-pss-sha512',
                self::Ed25519 => 'ed25519',
                self::EcdsaP256Sha256 => 'ecdsa-p256-sha256',
                self::EcdsaP384Sha384 => 'ecdsa-p384-sha384',
                self::HmacSha256 => 'hmac-sha256',
            },
        };
    }

    /**
     * Returns the one key type this algorithm fits
     */
    public function keyType(): KeyType
    {
        return match ($this) {
            self::RsaV15Sha256, self::RsaPssSha512 => KeyType::Rsa,
            self::Ed25519 => KeyType::Ed25519,
            self::EcdsaP256Sha256 => KeyType::EcP256,
            self::EcdsaP384Sha384 => KeyType::EcP384,
            self::HmacSha256 => KeyType::SharedSecret,
        };
    }
}
