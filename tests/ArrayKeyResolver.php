<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use SocialWeb\Http\MessageSignatures\KeyResolver;
use SocialWeb\Http\MessageSignatures\VerificationKey;

/**
 * A resolver over an array of keys, which counts its calls and can hand out
 * different keys on refresh
 */
final class ArrayKeyResolver implements KeyResolver
{
    /**
     * @var list<string>
     */
    public array $resolved = [];

    /**
     * @var list<string>
     */
    public array $refreshed = [];

    /**
     * @param array<string, VerificationKey> $keys what `resolve()` returns
     * @param array<string, VerificationKey> $refreshedKeys what `refresh()`
     *     returns; a key identifier missing here falls back to `$keys`
     */
    public function __construct(
        private readonly array $keys,
        private readonly array $refreshedKeys = [],
    ) {
    }

    public function resolve(string $keyId): ?VerificationKey
    {
        $this->resolved[] = $keyId;

        return $this->keys[$keyId] ?? null;
    }

    public function refresh(string $keyId): ?VerificationKey
    {
        $this->refreshed[] = $keyId;

        return $this->refreshedKeys[$keyId] ?? $this->keys[$keyId] ?? null;
    }
}
