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

namespace SocialWeb\Http\MessageSignatures\Component;

use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\StreamInterface;
use SocialWeb\Http\MessageSignatures\DigestAlgorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;

use function hash_final;
use function hash_init;
use function hash_update;

/**
 * The content of a message, hashed in chunks and rewound afterward
 *
 * A body of zero length is "no content". The body is read in chunks of 8192
 * bytes and rewound after every read, so the caller's stream is left where it
 * started.
 *
 * @internal
 */
final class Content
{
    private const int CHUNK_SIZE = 8192;

    private readonly StreamInterface $body;

    /**
     * @throws InvalidArgument when the body cannot be rewound, since reading
     *     it would consume it
     */
    public function __construct(MessageInterface $message)
    {
        $body = $message->getBody();

        if (!$body->isSeekable()) {
            throw new InvalidArgument(
                'The message body must be seekable; a stream that cannot be rewound would be consumed',
            );
        }

        $this->body = $body;
    }

    /**
     * Returns whether the body holds at least one byte
     */
    public function hasContent(): bool
    {
        $size = $this->body->getSize();

        return $size === null ? $this->firstByteExists() : $size > 0;
    }

    /**
     * Returns the digest of the content under each algorithm, keyed by the
     * algorithm's RFC 9530 key, with the raw bytes as values
     *
     * @param non-empty-list<DigestAlgorithm> $algorithms
     *
     * @return array<string, string>
     */
    public function digests(array $algorithms): array
    {
        $contexts = [];

        foreach ($algorithms as $algorithm) {
            $contexts[$algorithm->value] = hash_init($algorithm->hashName());
        }

        $this->body->rewind();
        $chunk = $this->body->read(self::CHUNK_SIZE);

        while ($chunk !== '') {
            foreach ($contexts as $context) {
                hash_update($context, $chunk);
            }

            $chunk = $this->body->read(self::CHUNK_SIZE);
        }

        $this->body->rewind();

        $digests = [];

        foreach ($contexts as $key => $context) {
            $digests[$key] = hash_final($context, true);
        }

        return $digests;
    }

    /**
     * For a stream that does not report its size, one byte decides.
     */
    private function firstByteExists(): bool
    {
        $this->body->rewind();
        $first = $this->body->read(1);
        $this->body->rewind();

        return $first !== '';
    }
}
