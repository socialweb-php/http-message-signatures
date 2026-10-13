<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Component;

use Nyholm\Psr7\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Component\Content;
use SocialWeb\Http\MessageSignatures\Component\DigestField;
use SocialWeb\Http\MessageSignatures\DigestAlgorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function base64_encode;
use function hash;

class DigestFieldTest extends TestCase
{
    private const string BODY = '{"hello": "world"}';
    private const string SHA256 = 'X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=';
    private const string SHA512 = 'WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyeald'
        . 'VLvRwEmTHWXvJwew==';

    public function testKnowsTheTwoDigestFields(): void
    {
        $this->assertTrue(DigestField::isDigestField('content-digest'));
        $this->assertTrue(DigestField::isDigestField('digest'));
        $this->assertFalse(DigestField::isDigestField('Content-Digest'));
        $this->assertFalse(DigestField::isDigestField('repr-digest'));
    }

    public function testSerializesContentDigestAsADictionaryOfByteSequences(): void
    {
        $digests = self::content()->digests([DigestAlgorithm::Sha512, DigestAlgorithm::Sha256]);

        $this->assertSame(
            'sha-512=:' . self::SHA512 . ':, sha-256=:' . self::SHA256 . ':',
            DigestField::serialize('content-digest', $digests),
        );
    }

    public function testSerializesDigestWithTheRfc5843Tokens(): void
    {
        $digests = self::content()->digests([DigestAlgorithm::Sha256, DigestAlgorithm::Sha512]);

        $this->assertSame(
            'SHA-256=' . self::SHA256 . ', SHA-512=' . self::SHA512,
            DigestField::serialize('digest', $digests),
        );
    }

    public function testRefusesToSerializeNothing(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('There are no digests to serialize');

        DigestField::serialize('digest', []);
    }

    public function testRefusesToSerializeAnUnknownAlgorithm(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('"md5" is not a digest algorithm the package knows');

        DigestField::serialize('digest', ['md5' => hash('md5', '', true)]);
    }

    public function testRefusesToSerializeAnotherField(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('"repr-digest" is not a digest field');

        DigestField::serialize('repr-digest', ['sha-256' => hash('sha256', '', true)]);
    }

    public function testRefusesToCheckAnotherField(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('"repr-digest" is not a digest field');

        DigestField::check('repr-digest', 'sha-256=:' . self::SHA256 . ':', self::content());
    }

    /**
     * @return iterable<string, array{string, string, non-empty-string | null}>
     */
    public static function checksProvider(): iterable
    {
        yield 'content-digest with one matching digest' => ['content-digest', 'sha-512=:' . self::SHA512 . ':', null];
        yield 'content-digest with two matching digests' => [
            'content-digest',
            'sha-256=:' . self::SHA256 . ':, sha-512=:' . self::SHA512 . ':',
            null,
        ];
        yield 'content-digest with a known digest beside an unknown one' => [
            'content-digest',
            'md5=:' . base64_encode(hash('md5', self::BODY, true)) . ':, sha-256=:' . self::SHA256 . ':',
            null,
        ];
        yield 'content-digest with a wrong digest' => [
            'content-digest',
            'sha-256=:' . self::SHA512 . ':',
            'the sha-256 digest in content-digest does not match the content',
        ];
        yield 'content-digest with one right and one wrong digest' => [
            'content-digest',
            'sha-512=:' . self::SHA512 . ':, sha-256=:' . base64_encode(hash('sha256', 'x', true)) . ':',
            'the sha-256 digest in content-digest does not match the content',
        ];
        yield 'content-digest that does not parse' => [
            'content-digest',
            'sha-256=',
            'content-digest does not parse as a Dictionary: ',
        ];
        yield 'content-digest with an uppercase key does not parse' => [
            'content-digest',
            'SHA-256=:' . self::SHA256 . ':',
            'content-digest does not parse as a Dictionary: ',
        ];
        yield 'content-digest whose member is a String' => [
            'content-digest',
            'sha-256="' . self::SHA256 . '"',
            'the sha-256 member of content-digest is not a Byte Sequence',
        ];
        yield 'content-digest whose member is an Inner List' => [
            'content-digest',
            'sha-256=(:' . self::SHA256 . ':)',
            'the sha-256 member of content-digest is not a Byte Sequence',
        ];
        yield 'content-digest with no known algorithm' => [
            'content-digest',
            'md5=:' . base64_encode(hash('md5', self::BODY, true)) . ':, adler=:AAAA:',
            'content-digest names no algorithm the package knows; it offered: md5, adler',
        ];
        yield 'content-digest that is empty' => [
            'content-digest',
            '',
            'content-digest names no algorithm the package knows; it offered: ',
        ];
        yield 'digest with the RFC 5843 token' => ['digest', 'SHA-256=' . self::SHA256, null];
        yield 'digest with a lowercase token' => ['digest', 'sha-512=' . self::SHA512, null];
        yield 'digest with two digests and whitespace' => [
            'digest',
            'SHA-256=' . self::SHA256 . ' ,  sha-512=' . self::SHA512 . ' ,',
            null,
        ];
        yield 'digest with a known token beside an unknown one' => [
            'digest',
            'MD5=' . base64_encode(hash('md5', self::BODY, true)) . ', SHA-256=' . self::SHA256,
            null,
        ];
        yield 'digest with a wrong digest' => [
            'digest',
            'SHA-256=' . base64_encode(hash('sha256', 'x', true)),
            'the sha-256 digest in digest does not match the content',
        ];
        yield 'digest whose value is not Base64' => [
            'digest',
            'SHA-256=not*base64',
            'the SHA-256 value in digest is not valid Base64',
        ];
        yield 'digest whose value has the wrong length' => [
            'digest',
            'SHA-256=' . self::SHA512,
            'the SHA-256 value in digest has the wrong length',
        ];
        yield 'digest without an equals sign' => [
            'digest',
            'SHA-256',
            'digest is not a list of token=value entries',
        ];
        yield 'digest with an empty token' => [
            'digest',
            '=' . self::SHA256,
            'digest is not a list of token=value entries',
        ];
        yield 'digest with the deprecated SHA-1 only' => [
            'digest',
            'SHA=' . base64_encode(hash('sha1', self::BODY, true)),
            'digest names no algorithm the package knows; it offered: SHA',
        ];
        yield 'digest that is empty' => ['digest', '', 'digest names no algorithm the package knows; it offered: '];
        yield 'digest with a leading empty entry' => ['digest', ', SHA-256=' . self::SHA256, null];
    }

    /**
     * @param non-empty-string | null $detail
     */
    #[DataProvider('checksProvider')]
    public function testChecksACoveredDigestAgainstTheContent(string $field, string $value, ?string $detail): void
    {
        $result = DigestField::check($field, $value, self::content());

        if ($detail === null) {
            $this->assertNull($result);
        } else {
            $this->assertNotNull($result);
            $this->assertStringStartsWith($detail, $result);
        }
    }

    public function testADigestOverEmptyContentIsChecked(): void
    {
        $content = new Content(new Request('GET', 'https://example.com/'));
        $empty = base64_encode(hash('sha256', '', true));

        $this->assertNull(DigestField::check('content-digest', 'sha-256=:' . $empty . ':', $content));
        $this->assertNotNull(DigestField::check('content-digest', 'sha-256=:' . self::SHA256 . ':', $content));
    }

    private static function content(): Content
    {
        return new Content(new Request('POST', 'https://example.com/foo', [], self::BODY));
    }
}
