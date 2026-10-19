<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use SocialWeb\Http\MessageSignatures\KeyLookup;
use SocialWeb\Http\MessageSignatures\KeyResolver;
use SocialWeb\Http\MessageSignatures\VerificationKey;

use function array_map;

/**
 * A resolver over an array of keys, which records the lookups it receives and
 * can hand out different keys on refresh
 */
final class ArrayKeyResolver implements KeyResolver
{
    /**
     * The lookups `resolve()` received, in order
     *
     * @var list<KeyLookup>
     */
    public array $resolved = [];

    /**
     * The lookups `refresh()` received, in order
     *
     * @var list<KeyLookup>
     */
    public array $refreshed = [];

    /**
     * @param array<string, VerificationKey> $keys what `resolve()` returns,
     *     by key identifier
     * @param array<string, VerificationKey> $refreshedKeys what `refresh()`
     *     returns; a key identifier missing here falls back to `$keys`
     */
    public function __construct(
        private readonly array $keys,
        private readonly array $refreshedKeys = [],
    ) {
    }

    public function resolve(KeyLookup $lookup): ?VerificationKey
    {
        $this->resolved[] = $lookup;

        return $this->keys[$lookup->keyId] ?? null;
    }

    public function refresh(KeyLookup $lookup): ?VerificationKey
    {
        $this->refreshed[] = $lookup;

        return $this->refreshedKeys[$lookup->keyId] ?? $this->keys[$lookup->keyId] ?? null;
    }

    /**
     * Returns the key identifier of each lookup `resolve()` received, in
     * order
     *
     * @return list<string>
     */
    public function resolvedKeyIds(): array
    {
        return self::keyIds($this->resolved);
    }

    /**
     * Returns the key identifier of each lookup `refresh()` received, in
     * order
     *
     * @return list<string>
     */
    public function refreshedKeyIds(): array
    {
        return self::keyIds($this->refreshed);
    }

    /**
     * @param list<KeyLookup> $lookups
     *
     * @return list<string>
     */
    private static function keyIds(array $lookups): array
    {
        return array_map(static fn (KeyLookup $lookup): string => $lookup->keyId, $lookups);
    }
}
