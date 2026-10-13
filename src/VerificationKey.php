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

use function in_array;
use function sprintf;

/**
 * A public key or shared secret that verifies signatures
 *
 * The key material is never exposed, and the key cannot be serialized. A key
 * is built from its PEM each time, which is cheap.
 */
final readonly class VerificationKey
{
    public KeyType $type;

    /**
     * The algorithms this key may verify, in order of preference
     *
     * @var non-empty-list<Algorithm>
     */
    public array $permittedAlgorithms;

    /**
     * @param list<Algorithm> | null $permittedAlgorithms
     */
    private function __construct(
        #[SensitiveParameter]
        private KeyMaterial $material,
        ?array $permittedAlgorithms,
    ) {
        $this->type = $material->type;
        $this->permittedAlgorithms = $material->permittedAlgorithms($permittedAlgorithms);
    }

    /**
     * Builds a key from any public key OpenSSL reads, in SubjectPublicKeyInfo
     * or PKCS#1 form
     *
     * @param list<Algorithm> | null $permittedAlgorithms the algorithms this
     *     key may verify, or `null` for the type's default list
     *
     * @throws InvalidArgument when OpenSSL cannot read the PEM, when the key
     *     is of a type the package does not implement, or when the list is
     *     empty, holds an algorithm the type cannot run, or holds a duplicate
     */
    public static function fromPem(string $pem, ?array $permittedAlgorithms = null): self
    {
        return new self(KeyMaterial::fromPublicPem($pem), $permittedAlgorithms);
    }

    /**
     * Builds a key from the bytes of a shared secret
     *
     * @param list<Algorithm> | null $permittedAlgorithms the algorithms this
     *     key may verify, or `null` for the type's default list
     *
     * @throws InvalidArgument when the secret is empty, or when the list is
     *     empty, holds an algorithm the type cannot run, or holds a duplicate
     */
    public static function fromSharedSecret(
        #[SensitiveParameter]
        string $secret,
        ?array $permittedAlgorithms = null,
    ): self {
        return new self(KeyMaterial::fromSecret($secret), $permittedAlgorithms);
    }

    /**
     * Returns whether the algorithm is in this key's permitted list
     */
    public function permits(Algorithm $algorithm): bool
    {
        return in_array($algorithm, $this->permittedAlgorithms, true);
    }

    /**
     * Returns whether the signature is valid for the signature base under the
     * algorithm
     *
     * @throws InvalidArgument when the algorithm is not in the permitted list
     */
    public function verify(Algorithm $algorithm, string $signatureBase, string $signature): bool
    {
        if (!$this->permits($algorithm)) {
            throw new InvalidArgument(sprintf('Algorithm %s is not permitted for this key', $algorithm->name));
        }

        return $this->material->verify($algorithm, $signatureBase, $signature);
    }

    /**
     * @return array{type: KeyType, permittedAlgorithms: non-empty-list<Algorithm>}
     */
    public function __debugInfo(): array
    {
        return ['type' => $this->type, 'permittedAlgorithms' => $this->permittedAlgorithms];
    }

    /**
     * @return array{}
     */
    public function __serialize(): array
    {
        throw new LogicException('A VerificationKey cannot be serialized');
    }
}
