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

use OpenSSLAsymmetricKey;
use SensitiveParameter;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Exception\SigningFailed;

use function array_search;
use function hash_equals;
use function hash_hmac;
use function implode;
use function in_array;
use function is_string;
use function openssl_error_string;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;
use function sprintf;
use function str_contains;
use function str_starts_with;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_ED25519;
use const OPENSSL_KEYTYPE_RSA;
use const OPENSSL_PKCS1_PSS_PADDING;

/**
 * The material of a key, its detected type, and the signature primitives over
 * it
 *
 * This is the one place that calls OpenSSL. RSA and ECDSA go through
 * `openssl_sign()` and `openssl_verify()` with the digest name, RSASSA-PSS
 * with the padding argument as well, and Ed25519 with the algorithm argument
 * `0`, which OpenSSL signs without a prehash. HMAC goes through `hash_hmac()`
 * and `hash_equals()`.
 *
 * @internal
 */
final readonly class KeyMaterial
{
    private function __construct(
        public KeyType $type,
        #[SensitiveParameter]
        private OpenSSLAsymmetricKey | string $material,
    ) {
    }

    /**
     * Loads a public key from a PEM in SubjectPublicKeyInfo or PKCS#1 form
     *
     * @throws InvalidArgument when the string is a file path, when OpenSSL
     *     cannot read the PEM, or when the key is of a type the package does
     *     not implement
     */
    public static function fromPublicPem(string $pem): self
    {
        self::refuseFilePath($pem);
        self::clearOpenSslErrors();
        $key = openssl_pkey_get_public($pem);

        if ($key === false) {
            throw new InvalidArgument('OpenSSL cannot read the public key: ' . self::openSslErrors());
        }

        return new self(self::detectType($key, $pem), $key);
    }

    /**
     * Loads a private key from a PEM, decrypting it with the passphrase when
     * one is given
     *
     * @throws InvalidArgument when the string is a file path, when OpenSSL
     *     cannot read the PEM, or when the key is of a type the package does
     *     not implement
     */
    public static function fromPrivatePem(
        #[SensitiveParameter]
        string $pem,
        #[SensitiveParameter]
        ?string $passphrase,
    ): self {
        self::refuseFilePath($pem);
        self::clearOpenSslErrors();
        $key = openssl_pkey_get_private($pem, $passphrase);

        if ($key === false) {
            throw new InvalidArgument('OpenSSL cannot read the private key: ' . self::openSslErrors());
        }

        // An encrypted PEM is exported again, unencrypted, so that a PSS key
        // in it can be rewrapped.
        if ($passphrase !== null) {
            $exported = null;
            openssl_pkey_export($key, $exported);
            $pem = is_string($exported) ? $exported : $pem;
        }

        return new self(self::detectType($key, $pem), $key);
    }

    /**
     * @throws InvalidArgument when the secret is empty
     */
    public static function fromSecret(
        #[SensitiveParameter]
        string $secret,
    ): self {
        if ($secret === '') {
            throw new InvalidArgument('The shared secret must not be empty');
        }

        return new self(KeyType::SharedSecret, $secret);
    }

    /**
     * Checks a list of permitted algorithms against this key's type, or
     * supplies the type's default list
     *
     * @param list<Algorithm> | null $algorithms
     *
     * @return non-empty-list<Algorithm>
     *
     * @throws InvalidArgument when the list is empty, holds an algorithm the
     *     key's type cannot run, or holds a duplicate
     */
    public function permittedAlgorithms(?array $algorithms): array
    {
        if ($algorithms === null) {
            return $this->type->defaultAlgorithms();
        }

        if ($algorithms === []) {
            throw new InvalidArgument('The list of permitted algorithms must not be empty');
        }

        $seen = [];

        foreach ($algorithms as $algorithm) {
            if (!$this->type->accepts($algorithm)) {
                throw new InvalidArgument(
                    sprintf('Algorithm %s does not fit a key of type %s', $algorithm->name, $this->type->name),
                );
            }

            if (in_array($algorithm, $seen, true)) {
                throw new InvalidArgument(
                    sprintf('Algorithm %s appears more than once in the permitted list', $algorithm->name),
                );
            }

            $seen[] = $algorithm;
        }

        return $algorithms;
    }

    /**
     * Signs the signature base and returns the raw signature bytes
     *
     * The key classes refuse a permitted list that does not fit the key's
     * type, so the one check here is that a shared secret gets HMAC and a key
     * does not.
     *
     * @throws InvalidArgument when a shared secret is asked for an asymmetric
     *     algorithm or a key for HMAC
     * @throws SigningFailed when OpenSSL fails
     */
    public function sign(Algorithm $algorithm, string $signatureBase): string
    {
        if ($this->material instanceof OpenSSLAsymmetricKey) {
            self::clearOpenSslErrors();
            $signature = '';
            $signed = match ($algorithm) {
                Algorithm::RsaV15Sha256 => openssl_sign($signatureBase, $signature, $this->material, 'sha256'),
                Algorithm::RsaPssSha512 => openssl_sign(
                    $signatureBase,
                    $signature,
                    $this->material,
                    'sha512',
                    OPENSSL_PKCS1_PSS_PADDING,
                ),
                Algorithm::Ed25519 => openssl_sign($signatureBase, $signature, $this->material, 0),
                Algorithm::EcdsaP256Sha256 => openssl_sign($signatureBase, $signature, $this->material, 'sha256'),
                Algorithm::EcdsaP384Sha384 => openssl_sign($signatureBase, $signature, $this->material, 'sha384'),
                Algorithm::HmacSha256 => throw new InvalidArgument('HmacSha256 needs a shared secret, not a key'),
            };

            if (!$signed || !is_string($signature)) {
                throw new SigningFailed('OpenSSL could not sign: ' . self::openSslErrors());
            }

            $integerLength = self::ecdsaIntegerLength($algorithm);

            if ($integerLength === null) {
                return $signature;
            }

            $raw = EcdsaSignature::derToRaw($signature, $integerLength);

            if ($raw === null) {
                throw new SigningFailed('OpenSSL produced an ECDSA signature that does not fit the curve');
            }

            return $raw;
        }

        if ($algorithm !== Algorithm::HmacSha256) {
            throw new InvalidArgument(sprintf('%s needs a key, not a shared secret', $algorithm->name));
        }

        return hash_hmac('sha256', $signatureBase, $this->material, true);
    }

    /**
     * Returns whether the signature is valid for the signature base
     *
     * @throws InvalidArgument when a shared secret is asked for an asymmetric
     *     algorithm or a key for HMAC
     */
    public function verify(Algorithm $algorithm, string $signatureBase, string $signature): bool
    {
        if (!$this->material instanceof OpenSSLAsymmetricKey) {
            if ($algorithm !== Algorithm::HmacSha256) {
                throw new InvalidArgument(sprintf('%s needs a key, not a shared secret', $algorithm->name));
            }

            return hash_equals(hash_hmac('sha256', $signatureBase, $this->material, true), $signature);
        }

        $integerLength = self::ecdsaIntegerLength($algorithm);

        if ($integerLength !== null) {
            $der = EcdsaSignature::rawToDer($signature, $integerLength);

            if ($der === null) {
                return false;
            }

            $signature = $der;
        }

        $result = match ($algorithm) {
            Algorithm::RsaV15Sha256 => openssl_verify($signatureBase, $signature, $this->material, 'sha256'),
            Algorithm::RsaPssSha512 => openssl_verify(
                $signatureBase,
                $signature,
                $this->material,
                'sha512',
                OPENSSL_PKCS1_PSS_PADDING,
            ),
            Algorithm::Ed25519 => openssl_verify($signatureBase, $signature, $this->material, 0),
            Algorithm::EcdsaP256Sha256 => openssl_verify($signatureBase, $signature, $this->material, 'sha256'),
            Algorithm::EcdsaP384Sha384 => openssl_verify($signatureBase, $signature, $this->material, 'sha384'),
            Algorithm::HmacSha256 => throw new InvalidArgument('HmacSha256 needs a shared secret, not a key'),
        };
        self::clearOpenSslErrors();

        return $result === 1;
    }

    /**
     * @return int<1, max> | null
     */
    private static function ecdsaIntegerLength(Algorithm $algorithm): ?int
    {
        return match ($algorithm) {
            Algorithm::EcdsaP256Sha256 => 32,
            Algorithm::EcdsaP384Sha384 => 48,
            default => null,
        };
    }

    /**
     * Detects the key type from `openssl_pkey_get_details()`, after rewrapping
     * a key OpenSSL typed as RSASSA-PSS, which the details do not describe
     *
     * The `$pem` must be what was loaded or, for an encrypted private key,
     * its unencrypted export, and the loaded key is replaced by the rewrapped
     * one so that signing takes the padding argument. The rewrapped key is
     * `KeyType::RsaPss`, so that it stays restricted to RSASSA-PSS.
     *
     * @throws InvalidArgument when the key is of a type the package does not
     *     implement
     */
    private static function detectType(
        OpenSSLAsymmetricKey &$key,
        #[SensitiveParameter]
        string $pem,
    ): KeyType {
        /** @var array{type: int, ec?: array{curve_name?: string}} $details */
        $details = openssl_pkey_get_details($key);

        if ($details['type'] === OPENSSL_KEYTYPE_RSA) {
            return KeyType::Rsa;
        }

        if ($details['type'] === OPENSSL_KEYTYPE_ED25519) {
            return KeyType::Ed25519;
        }

        if ($details['type'] === OPENSSL_KEYTYPE_EC) {
            $curve = $details['ec']['curve_name'] ?? '';

            return match ($curve) {
                'prime256v1' => KeyType::EcP256,
                'secp384r1' => KeyType::EcP384,
                default => throw new InvalidArgument(
                    sprintf('EC keys on the curve %s are not implemented; use P-256 or P-384', $curve),
                ),
            };
        }

        $pkcs1 = RsaPssKey::toPkcs1Pem($pem);

        if ($pkcs1 !== null) {
            $rewrapped = str_contains($pkcs1, 'PRIVATE')
                ? openssl_pkey_get_private($pkcs1)
                : openssl_pkey_get_public($pkcs1);

            if ($rewrapped !== false) {
                $key = $rewrapped;

                return KeyType::RsaPss;
            }
        }

        throw new InvalidArgument(
            sprintf('Keys of OpenSSL type %d are not implemented; use RSA, P-256, P-384, or Ed25519', $details['type']),
        );
    }

    /**
     * The OpenSSL functions read a local file for a string that begins with
     * `file://`; a key is given as PEM text, never as a path.
     *
     * @throws InvalidArgument
     */
    private static function refuseFilePath(
        #[SensitiveParameter]
        string $pem,
    ): void {
        if (str_starts_with($pem, 'file://')) {
            throw new InvalidArgument('A key must be given as PEM text, not as a file path');
        }
    }

    private static function clearOpenSslErrors(): void
    {
        while (openssl_error_string() !== false) {
            continue;
        }
    }

    private static function openSslErrors(): string
    {
        $errors = [];

        while (($error = openssl_error_string()) !== false) {
            if (array_search($error, $errors, true) === false) {
                $errors[] = $error;
            }
        }

        return $errors === [] ? 'no error reported' : implode('; ', $errors);
    }
}
