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

use LogicException;
use SensitiveParameter;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\KeyOperation;
use SocialWeb\Jwk\KeyUse;
use SocialWeb\Jwk\OctKey;

use function array_keys;
use function implode;
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
    /**
     * The `alg` names of RFC 7518, RFC 8037, and RFC 9864 for the algorithms
     * the package implements
     */
    private const array JWK_ALGORITHMS = [
        'RS256' => Algorithm::RsaV15Sha256,
        'PS512' => Algorithm::RsaPssSha512,
        'ES256' => Algorithm::EcdsaP256Sha256,
        'ES384' => Algorithm::EcdsaP384Sha384,
        'EdDSA' => Algorithm::Ed25519,
        'Ed25519' => Algorithm::Ed25519,
        'HS256' => Algorithm::HmacSha256,
    ];

    public SigningKeyType $type;

    /**
     * The algorithms this key may verify, in order of preference
     *
     * @var non-empty-list<Algorithm>
     */
    public array $permittedAlgorithms;

    /**
     * Whose key this is, as the resolver that built the key claims it, in
     * whatever form its protocol gives: a user identifier, a URL, an
     * account name; `null` when the resolver has no identity to report
     *
     * The package never computes it and never compares it with anything. The
     * verifier reports it as `VerificationResult::$keyOwner` only when the
     * signature verified under this key.
     *
     * @var non-empty-string | null
     */
    public ?string $owner;

    /**
     * @param list<Algorithm> | null $permittedAlgorithms
     *
     * @throws InvalidArgument when the owner is an empty string
     */
    private function __construct(
        #[SensitiveParameter] private KeyMaterial $material,
        ?array $permittedAlgorithms,
        ?string $owner,
    ) {
        if ($owner === '') {
            throw new InvalidArgument('The key owner must not be empty');
        }

        $this->type = $material->type;
        $this->permittedAlgorithms = $material->permittedAlgorithms($permittedAlgorithms);
        $this->owner = $owner;
    }

    /**
     * Builds a key from any public key OpenSSL reads, in SubjectPublicKeyInfo
     * or PKCS#1 form
     *
     * @param list<Algorithm> | null $permittedAlgorithms the algorithms this
     *     key may verify, or `null` for the type's default list
     * @param string | null $owner whose key this is, as the resolver claims
     *     it, or `null` when it has no identity to report
     *
     * @throws InvalidArgument when OpenSSL cannot read the PEM, when the key
     *     is of a type the package does not implement, when the list is
     *     empty, holds an algorithm the type cannot run, or holds a
     *     duplicate, or when the owner is an empty string
     */
    public static function fromPem(string $pem, ?array $permittedAlgorithms = null, ?string $owner = null): self
    {
        return new self(KeyMaterial::fromPublicPem($pem), $permittedAlgorithms, $owner);
    }

    /**
     * Builds a key from the bytes of a shared secret
     *
     * @param list<Algorithm> | null $permittedAlgorithms the algorithms this
     *     key may verify, or `null` for the type's default list
     * @param string | null $owner whose key this is, as the resolver claims
     *     it, or `null` when it has no identity to report
     *
     * @throws InvalidArgument when the secret is empty, when the list is
     *     empty, holds an algorithm the type cannot run, or holds a
     *     duplicate, or when the owner is an empty string
     */
    public static function fromSharedSecret(
        #[SensitiveParameter] string $secret,
        ?array $permittedAlgorithms = null,
        ?string $owner = null,
    ): self {
        return new self(KeyMaterial::fromSecret($secret), $permittedAlgorithms, $owner);
    }

    /**
     * Builds a key from a JSON Web Key of RFC 7517, read by the socialweb/jwk
     * package, which must be installed to call this method
     *
     * An `RSA`, `EC`, or `OKP` key is read from its SubjectPublicKeyInfo PEM,
     * as `fromPem()` reads one, so a key on a curve the package does not
     * implement is refused the same way. An `oct` key becomes a shared secret,
     * as `fromSharedSecret()` builds one.
     *
     * A key with `alg` permits that algorithm alone, and the list, when given,
     * may name nothing else. A key without `alg` takes the list, or the type's
     * default list. The `kid` member is not read: the resolver that chose the
     * key has matched it already.
     *
     * @link https://github.com/socialweb-php/jwk socialweb/jwk
     *
     * @param list<Algorithm> | null $permittedAlgorithms the algorithms this
     *     key may verify, or `null` for the `alg` member or the type's
     *     default list
     * @param string | null $owner whose key this is, as the resolver claims
     *     it, or `null` when it has no identity to report
     *
     * @throws InvalidArgument when the key holds private members, when its
     *     `use` is not `sig`, when its `key_ops` is present and lacks
     *     `verify`, when its `alg` names an algorithm the package does not
     *     implement, when the list names an algorithm other than the `alg`,
     *     when the key is of a type or on a curve the package does not
     *     implement, when the list is empty, holds an algorithm the type
     *     cannot run, or holds a duplicate, or when the owner is an empty
     *     string
     */
    public static function fromJwk(
        #[SensitiveParameter] Jwk $jwk,
        ?array $permittedAlgorithms = null,
        ?string $owner = null,
    ): self {
        if (!$jwk instanceof OctKey && $jwk->isPrivate()) {
            throw new InvalidArgument('A verification key cannot be built from a JWK with private members');
        }

        if ($jwk->use !== null && $jwk->use !== KeyUse::Signature->value) {
            throw new InvalidArgument(
                sprintf('A JWK with the use "%s" cannot verify signatures; it needs the use "sig"', $jwk->use),
            );
        }

        if ($jwk->keyOperations !== [] && !in_array(KeyOperation::Verify->value, $jwk->keyOperations, true)) {
            throw new InvalidArgument('A JWK whose key operations do not include "verify" cannot verify signatures');
        }

        $permittedAlgorithms = self::jwkAlgorithms($jwk, $permittedAlgorithms);
        $material = $jwk instanceof OctKey
            ? KeyMaterial::fromSecret($jwk->keyValue)
            : KeyMaterial::fromPublicPem($jwk->toPem());

        return new self($material, $permittedAlgorithms, $owner);
    }

    /**
     * Returns the list a JWK permits: the one algorithm its `alg` names, or
     * the given list when it has no `alg`
     *
     * @param list<Algorithm> | null $permittedAlgorithms
     *
     * @return list<Algorithm> | null
     *
     * @throws InvalidArgument when the `alg` names an algorithm the package
     *     does not implement, or when the list names an algorithm other than
     *     the `alg`
     */
    private static function jwkAlgorithms(
        #[SensitiveParameter] Jwk $jwk,
        ?array $permittedAlgorithms,
    ): ?array {
        if ($jwk->algorithm === null) {
            return $permittedAlgorithms;
        }

        $algorithm = self::JWK_ALGORITHMS[$jwk->algorithm] ?? throw new InvalidArgument(sprintf(
            'The JWK algorithm "%s" is not implemented; the package implements %s',
            $jwk->algorithm,
            implode(', ', array_keys(self::JWK_ALGORITHMS)),
        ));

        if ($permittedAlgorithms === []) {
            throw new InvalidArgument('The list of permitted algorithms must not be empty');
        }

        $seen = [];

        foreach ($permittedAlgorithms ?? [] as $permitted) {
            if ($permitted !== $algorithm) {
                throw new InvalidArgument(sprintf(
                    'Algorithm %s is not permitted by a JWK whose alg is "%s"',
                    $permitted->name,
                    $jwk->algorithm,
                ));
            }

            if (in_array($permitted, $seen, true)) {
                throw new InvalidArgument(
                    sprintf('Algorithm %s appears more than once in the permitted list', $permitted->name),
                );
            }

            $seen[] = $permitted;
        }

        return [$algorithm];
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
     * @return array{
     *     type: SigningKeyType,
     *     permittedAlgorithms: non-empty-list<Algorithm>,
     *     owner: non-empty-string | null,
     * }
     */
    public function __debugInfo(): array
    {
        return ['type' => $this->type, 'permittedAlgorithms' => $this->permittedAlgorithms, 'owner' => $this->owner];
    }

    /**
     * @return array{}
     */
    public function __serialize(): array
    {
        throw new LogicException('A VerificationKey cannot be serialized');
    }
}
