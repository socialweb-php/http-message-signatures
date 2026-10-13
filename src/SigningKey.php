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

use LogicException;
use SensitiveParameter;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Exception\SigningFailed;

use function in_array;
use function sprintf;

/**
 * A private key or shared secret that signs messages, with the identifier the
 * signature names it by
 *
 * The key material is never exposed, and the key cannot be serialized. A key
 * is built from its PEM each time, which is cheap.
 */
final readonly class SigningKey
{
    public KeyType $type;

    /**
     * The algorithms this key may sign with, in order of preference
     *
     * @var non-empty-list<Algorithm>
     */
    public array $permittedAlgorithms;

    /**
     * @param non-empty-string $keyId the value to put in the `keyId` or
     *     `keyid` parameter
     * @param list<Algorithm> | null $permittedAlgorithms
     */
    private function __construct(
        public string $keyId,
        #[SensitiveParameter]
        private KeyMaterial $material,
        ?array $permittedAlgorithms,
    ) {
        $this->type = $material->type;
        $this->permittedAlgorithms = $material->permittedAlgorithms($permittedAlgorithms);
    }

    /**
     * Builds a key from any private key OpenSSL reads
     *
     * @param string $keyId the value to put in the `keyId` or `keyid` parameter
     * @param string | null $passphrase the passphrase of an encrypted PEM
     * @param list<Algorithm> | null $permittedAlgorithms the algorithms this
     *     key may sign with, or `null` for the type's default list
     *
     * @throws InvalidArgument when the key identifier is empty, when OpenSSL
     *     cannot read the PEM, when the key is of a type the package does not
     *     implement, or when the list is empty, holds an algorithm the type
     *     cannot run, or holds a duplicate
     */
    public static function fromPem(
        string $keyId,
        #[SensitiveParameter]
        string $pem,
        #[SensitiveParameter]
        ?string $passphrase = null,
        ?array $permittedAlgorithms = null,
    ): self {
        return new self(self::checkKeyId($keyId), KeyMaterial::fromPrivatePem($pem, $passphrase), $permittedAlgorithms);
    }

    /**
     * Builds a key from the bytes of a shared secret
     *
     * @param string $keyId the value to put in the `keyId` or `keyid` parameter
     * @param list<Algorithm> | null $permittedAlgorithms the algorithms this
     *     key may sign with, or `null` for the type's default list
     *
     * @throws InvalidArgument when the key identifier or the secret is empty,
     *     or when the list is empty, holds an algorithm the type cannot run,
     *     or holds a duplicate
     */
    public static function fromSharedSecret(
        string $keyId,
        #[SensitiveParameter]
        string $secret,
        ?array $permittedAlgorithms = null,
    ): self {
        return new self(self::checkKeyId($keyId), KeyMaterial::fromSecret($secret), $permittedAlgorithms);
    }

    /**
     * Returns whether the algorithm is in this key's permitted list
     */
    public function permits(Algorithm $algorithm): bool
    {
        return in_array($algorithm, $this->permittedAlgorithms, true);
    }

    /**
     * Signs the signature base and returns the raw signature bytes
     *
     * @throws InvalidArgument when the algorithm is not in the permitted list
     * @throws SigningFailed when OpenSSL fails; the message has OpenSSL's
     *     error text
     */
    public function sign(Algorithm $algorithm, string $signatureBase): string
    {
        if (!$this->permits($algorithm)) {
            throw new InvalidArgument(sprintf('Algorithm %s is not permitted for this key', $algorithm->name));
        }

        return $this->material->sign($algorithm, $signatureBase);
    }

    /**
     * @return array{keyId: string, type: KeyType, permittedAlgorithms: non-empty-list<Algorithm>}
     */
    public function __debugInfo(): array
    {
        return ['keyId' => $this->keyId, 'type' => $this->type, 'permittedAlgorithms' => $this->permittedAlgorithms];
    }

    /**
     * @return array{}
     */
    public function __serialize(): array
    {
        throw new LogicException('A SigningKey cannot be serialized');
    }

    /**
     * @return non-empty-string
     */
    private static function checkKeyId(string $keyId): string
    {
        if ($keyId === '') {
            throw new InvalidArgument('The key identifier must not be empty');
        }

        return $keyId;
    }
}
