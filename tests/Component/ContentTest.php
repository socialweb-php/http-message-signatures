<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Component;

use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\Stream;
use Psr\Http\Message\StreamInterface;
use SocialWeb\Http\MessageSignatures\Component\Content;
use SocialWeb\Http\MessageSignatures\DigestAlgorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function array_keys;
use function base64_encode;
use function fopen;
use function hash;
use function str_repeat;
use function strlen;
use function substr;

use const SEEK_SET;

class ContentTest extends TestCase
{
    public function testRejectsABodyThatCannotBeRewound(): void
    {
        $pipe = fopen('php://stdin', 'r');
        $this->assertNotFalse($pipe);
        $request = new Request('POST', 'https://example.com/', [], Stream::create($pipe));

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('The message body must be seekable');

        new Content($request);
    }

    public function testAnEmptyBodyIsNoContent(): void
    {
        $this->assertFalse((new Content(new Request('GET', 'https://example.com/')))->hasContent());
        $this->assertTrue((new Content(new Response(200, [], 'x')))->hasContent());
    }

    public function testReadsTheFirstByteWhenTheSizeIsUnknown(): void
    {
        $body = self::sizeless('abc');
        $body->seek(3);

        $this->assertTrue((new Content(new Response(200, [], $body)))->hasContent());
        $this->assertSame(0, $body->tell());
        $this->assertFalse((new Content(new Response(200, [], self::sizeless(''))))->hasContent());
    }

    public function testHashesTheContentUnderEachAlgorithmAndRewinds(): void
    {
        $body = Stream::create('{"hello": "world"}');
        $body->read(5);
        $content = new Content(new Request('POST', 'https://example.com/foo', [], $body));

        $digests = $content->digests([DigestAlgorithm::Sha512, DigestAlgorithm::Sha256]);

        $this->assertSame(['sha-512', 'sha-256'], array_keys($digests));
        $this->assertSame(
            'WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==',
            base64_encode($digests['sha-512']),
        );
        $this->assertSame(hash('sha256', '{"hello": "world"}', true), $digests['sha-256']);
        $this->assertSame(0, $body->tell());
        $this->assertSame('{"hello": "world"}', (string) $body);
    }

    public function testHashesALargeBodyInChunks(): void
    {
        $text = str_repeat('0123456789', 3000);
        $content = new Content(new Response(200, [], $text));

        $this->assertSame(['sha-256' => hash('sha256', $text, true)], $content->digests([DigestAlgorithm::Sha256]));
    }

    public function testHashesABodyOfUnknownSizeToTheEnd(): void
    {
        $text = str_repeat('x', 8192 * 2 + 1);
        $content = new Content(new Response(200, [], self::sizeless($text)));

        $this->assertSame(['sha-512' => hash('sha512', $text, true)], $content->digests([DigestAlgorithm::Sha512]));
    }

    public function testADuplicateAlgorithmIsHashedOnce(): void
    {
        $content = new Content(new Response(200, [], 'x'));

        $this->assertSame(
            ['sha-256' => hash('sha256', 'x', true)],
            $content->digests([DigestAlgorithm::Sha256, DigestAlgorithm::Sha256]),
        );
    }

    /**
     * A seekable stream that does not know its size, as a stream over a
     * resource without `stat` would be.
     */
    private static function sizeless(string $text): StreamInterface
    {
        return new class ($text) implements StreamInterface {
            private int $position = 0;

            public function __construct(private readonly string $text)
            {
            }

            public function __toString(): string
            {
                return $this->text;
            }

            public function close(): void
            {
            }

            public function detach(): null
            {
                return null;
            }

            public function getSize(): null
            {
                return null;
            }

            public function tell(): int
            {
                return $this->position;
            }

            public function eof(): bool
            {
                return $this->position >= strlen($this->text);
            }

            public function isSeekable(): bool
            {
                return true;
            }

            public function seek(int $offset, int $whence = SEEK_SET): void
            {
                $this->position = $offset;
            }

            public function rewind(): void
            {
                $this->position = 0;
            }

            public function isWritable(): bool
            {
                return false;
            }

            public function write(string $string): int
            {
                return 0;
            }

            public function isReadable(): bool
            {
                return true;
            }

            public function read(int $length): string
            {
                $chunk = substr($this->text, $this->position, $length);
                $this->position += strlen($chunk);

                return $chunk;
            }

            public function getContents(): string
            {
                return $this->read(strlen($this->text));
            }

            public function getMetadata(?string $key = null): null
            {
                return null;
            }
        };
    }
}
