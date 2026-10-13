<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Component;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Component\QueryParameters;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

class QueryParametersTest extends TestCase
{
    public function testParsesTheRfc9421Section228Examples(): void
    {
        $this->assertSame(
            [['param', 'value'], ['foo', 'bar'], ['baz', 'batman'], ['qux', '']],
            QueryParameters::parse('param=value&foo=bar&baz=batman&qux='),
        );

        $this->assertSame(
            [
                ['var', 'this%20is%20a%20big%0Amultiline%20value'],
                ['bar', 'with%20plus%20whitespace'],
                ['fa%C3%A7ade%22%3A%20', 'something'],
            ],
            QueryParameters::parse(
                'var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something',
            ),
        );
    }

    /**
     * @return iterable<string, array{string, list<array{string, string}>}>
     */
    public static function queriesProvider(): iterable
    {
        yield 'empty' => ['', []];
        yield 'empty sequences are skipped' => ['&a=1&&b=2&', [['a', '1'], ['b', '2']]];
        yield 'a name without a value' => ['flag', [['flag', '']]];
        yield 'a value with an equals sign' => ['a=b=c', [['a', 'b%3Dc']]];
        yield 'a repeated name keeps every occurrence' => ['a=1&a=2', [['a', '1'], ['a', '2']]];
        yield 'the name is decoded and re-encoded' => ['a%20b=1', [['a%20b', '1']]];
        yield 'a plus in the name is a space' => ['a+b=1', [['a%20b', '1']]];
        yield 'an invalid percent escape is kept' => ['a=%zz', [['a', '%25zz']]];
        yield 'lowercase hex is normalized' => ['a=%2f', [['a', '%2F']]];
    }

    /**
     * @param list<array{string, string}> $expected
     */
    #[DataProvider('queriesProvider')]
    public function testParsesAQueryString(string $query, array $expected): void
    {
        $this->assertSame($expected, QueryParameters::parse($query));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function encodingsProvider(): iterable
    {
        yield 'unreserved characters stay' => ['AZaz09*-._', 'AZaz09*-._'];
        yield 'a space is %20, not a plus' => ['a b', 'a%20b'];
        yield 'a plus is encoded' => ['a+b', 'a%2Bb'];
        yield 'a tilde is encoded' => ['~', '%7E'];
        yield 'the sub-delimiters are encoded' => ["!'()", '%21%27%28%29'];
        yield 'a newline is encoded' => ["a\nb", 'a%0Ab'];
        yield 'UTF-8 bytes are encoded in uppercase hex' => ["fa\u{e7}ade", 'fa%C3%A7ade'];
        yield 'a percent sign is encoded' => ['100%', '100%25'];
    }

    #[DataProvider('encodingsProvider')]
    public function testEncodesWithTheFormUrlencodedSet(string $decoded, string $expected): void
    {
        $this->assertSame($expected, QueryParameters::encode($decoded));
    }
}
