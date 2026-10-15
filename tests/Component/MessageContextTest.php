<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Component;

use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;
use SocialWeb\Http\MessageSignatures\Component\ComponentFailure;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

class MessageContextTest extends TestCase
{
    private const string SHA256 = 'X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=';
    private const string SHA512 = 'WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyeald'
        . 'VLvRwEmTHWXvJwew==';

    public function testKnowsTheMessageAndItsKind(): void
    {
        $request = new Request('GET', 'https://example.com/');
        $response = new Response();

        $this->assertSame($request, (new MessageContext($request))->message());
        $this->assertTrue((new MessageContext($request))->isRequest());
        $this->assertFalse((new MessageContext($response))->isRequest());
    }

    public function testFieldValuesFollowRfc9421Section21(): void
    {
        $request = new Request('POST', 'https://www.example.com/', [
            'Host' => 'www.example.com',
            'Date' => 'Tue, 20 Apr 2021 02:07:56 GMT',
            'X-OWS-Header' => '  Leading and trailing whitespace.  ',
            'Cache-Control' => ['max-age=60', '   must-revalidate'],
            'Example-Dict' => ' a=1,    b=2;x=1;y=2,   c=(a   b   c)',
            'X-Empty-Header' => '',
        ]);
        $context = new MessageContext($request);

        $this->assertSame('www.example.com', $context->field('host'));
        $this->assertSame('Tue, 20 Apr 2021 02:07:56 GMT', $context->field('Date'));
        $this->assertSame('Leading and trailing whitespace.', $context->field('x-ows-header'));
        $this->assertSame('max-age=60, must-revalidate', $context->field('cache-control'));
        $this->assertSame('a=1,    b=2;x=1;y=2,   c=(a   b   c)', $context->field('example-dict'));
        $this->assertSame('', $context->field('x-empty-header'));
        $this->assertTrue($context->hasField('X-Empty-Header'));
        $this->assertFalse($context->hasField('x-absent'));
    }

    public function testTrimsEachLineOfAFieldTheImplementationLeftPadded(): void
    {
        // PSR-7 implementations usually trim field values themselves; this
        // one does not.
        $message = $this->createStub(MessageInterface::class);
        $message->method('hasHeader')->willReturn(true);
        $message->method('getHeader')->willReturn(["  one \t", "\ttwo  "]);
        $context = new MessageContext($message);

        $this->assertSame('one, two', $context->field('x-padded'));
        $this->assertSame(':b25l:, :dHdv:', $context->fieldBinaryWrapped('x-padded'));
    }

    public function testAFieldPresentWithNoLinesIsOneEmptyLine(): void
    {
        $message = $this->createStub(MessageInterface::class);
        $message->method('hasHeader')->willReturn(true);
        $message->method('getHeader')->willReturn([]);
        $context = new MessageContext($message);

        $this->assertSame('', $context->field('x-empty'));
        $this->assertSame('::', $context->fieldBinaryWrapped('x-empty'));
    }

    public function testLowercasesTheHostAndSchemeTheImplementationLeftAsIs(): void
    {
        $uri = $this->createStub(UriInterface::class);
        $uri->method('getScheme')->willReturn('HTTPS');
        $uri->method('getHost')->willReturn('EXAMPLE.COM');
        $uri->method('getPort')->willReturn(8443);
        $request = $this->createStub(RequestInterface::class);
        $request->method('getUri')->willReturn($uri);
        $context = new MessageContext($request);

        $this->assertSame('https', $context->derived('@scheme'));
        $this->assertSame('example.com:8443', $context->derived('@authority'));
    }

    public function testAnAbsentFieldIsMissing(): void
    {
        $context = new MessageContext(new Request('GET', 'https://example.com/'));

        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage('MissingComponent: the field "x-absent" is not in the message');

        $context->field('X-Absent');
    }

    public function testBinaryWrappingFollowsSection213(): void
    {
        $two = new Request('GET', 'https://example.com/', ['Example-Header' => ['value, with, lots', 'of, commas']]);
        $one = new Request('GET', 'https://example.com/', ['Example-Header' => 'value, with, lots, of, commas']);

        $this->assertSame(
            ':dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:',
            (new MessageContext($two))->fieldBinaryWrapped('example-header'),
        );
        $this->assertSame(
            ':dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:',
            (new MessageContext($one))->fieldBinaryWrapped('example-header'),
        );
    }

    public function testBinaryWrappingOfAnAbsentFieldIsMissing(): void
    {
        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage('MissingComponent: the field "x-absent" is not in the message');

        (new MessageContext(new Request('GET', 'https://example.com/')))->fieldBinaryWrapped('x-absent');
    }

    public function testStrictSerializationFollowsSection211(): void
    {
        $request = new Request('GET', 'https://example.com/', [
            'Content-Digest' => ['sha-256=:' . self::SHA256 . ':', 'sha-512=:' . self::SHA512 . ':'],
            'Signature-Input' => 'sig1=("@method"  "@path");created=1618884473',
        ]);
        $context = new MessageContext($request);

        $this->assertSame(
            'sha-256=:' . self::SHA256 . ':, sha-512=:' . self::SHA512 . ':',
            $context->fieldStructured('Content-Digest'),
        );
        $this->assertSame('sig1=("@method" "@path");created=1618884473', $context->fieldStructured('signature-input'));
    }

    public function testDictionaryMembersFollowSection212(): void
    {
        // The RFC's example field is a Dictionary the application knows; the
        // package knows four, so the example uses one of them.
        $request = new Request('GET', 'https://example.com/', [
            'Accept-Signature' => 'a=1, b=2;x=1;y=2, c=(a   b    c), d',
        ]);
        $context = new MessageContext($request);

        $this->assertSame('1', $context->dictionaryMember('accept-signature', 'a'));
        $this->assertSame('?1', $context->dictionaryMember('accept-signature', 'd'));
        $this->assertSame('2;x=1;y=2', $context->dictionaryMember('accept-signature', 'b'));
        $this->assertSame('(a b c)', $context->dictionaryMember('accept-signature', 'c'));
    }

    /**
     * @return iterable<string, array{string, string, string, FailureReason, non-empty-string}>
     */
    public static function structuredFailuresProvider(): iterable
    {
        yield 'sf on a field the package does not know' => [
            'fieldStructured',
            'Example-Dict',
            'a=1',
            FailureReason::UnsupportedSignature,
            'the field "example-dict" is not one the package knows as a Structured Field',
        ];
        yield 'key on a field the package does not know' => [
            'dictionaryMember',
            'Cache-Control',
            'max-age=60',
            FailureReason::UnsupportedSignature,
            'the field "cache-control" is not one the package knows as a Structured Field',
        ];
        yield 'sf on a field that does not parse' => [
            'fieldStructured',
            'Signature',
            'sig1=',
            FailureReason::MissingComponent,
            'the field "signature" does not parse as a Dictionary: ',
        ];
        yield 'key on a field that does not parse' => [
            'dictionaryMember',
            'Signature',
            'sig1=:not base64:',
            FailureReason::MissingComponent,
            'the field "signature" does not parse as a Dictionary: ',
        ];
        yield 'key whose member is absent' => [
            'dictionaryMember',
            'Signature-Input',
            'sig1=()',
            FailureReason::MissingComponent,
            'the field "signature-input" has no member "sig2"',
        ];
    }

    /**
     * @param non-empty-string $detail
     */
    #[DataProvider('structuredFailuresProvider')]
    public function testStructuredFieldFailures(
        string $method,
        string $field,
        string $value,
        FailureReason $reason,
        string $detail,
    ): void {
        $context = new MessageContext(new Request('GET', 'https://example.com/', [$field => $value]));

        try {
            $method === 'fieldStructured'
                ? $context->fieldStructured($field)
                : $context->dictionaryMember($field, 'sig2');
            $this->fail('Expected a ComponentFailure');
        } catch (ComponentFailure $failure) {
            $this->assertSame($reason, $failure->reason);
            $this->assertStringStartsWith($detail, $failure->detail);
        }
    }

    public function testAnAbsentStructuredFieldIsMissing(): void
    {
        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage('MissingComponent: the field "signature" is not in the message');

        (new MessageContext(new Request('GET', 'https://example.com/')))->fieldStructured('Signature');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function derivedComponentsProvider(): iterable
    {
        yield '@method' => ['@method', 'POST'];
        yield '@target-uri' => ['@target-uri', 'https://www.example.com/path?param=value'];
        yield '@authority' => ['@authority', 'www.example.com'];
        yield '@scheme' => ['@scheme', 'https'];
        yield '@request-target' => ['@request-target', '/path?param=value'];
        yield '@path' => ['@path', '/path'];
        yield '@query' => ['@query', '?param=value'];
    }

    #[DataProvider('derivedComponentsProvider')]
    public function testDerivesTheRfc9421Section22Examples(string $name, string $expected): void
    {
        $request = new Request('POST', 'https://www.example.com/path?param=value', ['Host' => 'www.example.com']);

        $this->assertSame($expected, (new MessageContext($request))->derived($name));
    }

    public function testDerivedValuesAreTakenAsReceived(): void
    {
        $request = new Request('get', 'HTTPS://EXAMPLE.COM:8443/P%41th?param=value&foo=bar&baz=bat%2Dman');
        $context = new MessageContext($request);

        $this->assertSame('get', $context->derived('@method'));
        $this->assertSame(
            'https://example.com:8443/P%41th?param=value&foo=bar&baz=bat%2Dman',
            $context->derived('@target-uri'),
        );
        $this->assertSame('example.com:8443', $context->derived('@authority'));
        $this->assertSame('https', $context->derived('@scheme'));
        $this->assertSame('/P%41th?param=value&foo=bar&baz=bat%2Dman', $context->derived('@request-target'));
        $this->assertSame('/P%41th', $context->derived('@path'));
        $this->assertSame('?param=value&foo=bar&baz=bat%2Dman', $context->derived('@query'));
    }

    public function testTheDefaultPortIsOmittedFromTheAuthority(): void
    {
        $this->assertSame(
            'example.com',
            (new MessageContext(new Request('GET', 'http://example.com:80/')))->derived('@authority'),
        );
    }

    /**
     * PSR-7 says `getPort()` SHOULD return `null` for the scheme's default
     * port; an implementation that reports it anyway gets the same value.
     *
     * @return iterable<string, array{string, int | null, string, string}>
     */
    public static function reportedPortsProvider(): iterable
    {
        yield 'https with 443 reported' => ['https', 443, 'example.com', 'https://example.com/'];
        yield 'http with 80 reported' => ['http', 80, 'example.com', 'http://example.com/'];
        yield 'https with 80 reported' => ['https', 80, 'example.com:80', 'https://example.com:80/'];
        yield 'http with 443 reported' => ['http', 443, 'example.com:443', 'http://example.com:443/'];
        yield 'HTTPS in uppercase with 443 reported' => ['HTTPS', 443, 'example.com', 'https://example.com/'];
        yield 'a scheme with no default port' => ['ws', 80, 'example.com:80', 'ws://example.com:80/'];
        yield 'no port reported' => ['https', null, 'example.com', 'https://example.com/'];
    }

    #[DataProvider('reportedPortsProvider')]
    public function testTheDefaultPortIsOmittedWhateverTheUriReports(
        string $scheme,
        ?int $port,
        string $authority,
        string $targetUri,
    ): void {
        $uri = $this->createStub(UriInterface::class);
        $uri->method('getScheme')->willReturn($scheme);
        $uri->method('getHost')->willReturn('example.com');
        $uri->method('getPort')->willReturn($port);
        $uri->method('getPath')->willReturn('');
        $uri->method('getQuery')->willReturn('');
        $request = $this->createStub(RequestInterface::class);
        $request->method('getUri')->willReturn($uri);
        $context = new MessageContext($request);

        $this->assertSame($authority, $context->derived('@authority'));
        $this->assertSame($targetUri, $context->derived('@target-uri'));
    }

    /**
     * The target URI is the one RFC 9110 section 7.1 defines and a server
     * reconstructs: an empty path is `/`, and user information and the
     * fragment, which never reach a server, are left out.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function targetUrisProvider(): iterable
    {
        yield 'an empty path' => ['https://example.com', 'https://example.com/'];
        yield 'an empty path with a query' => ['https://example.com?a=1', 'https://example.com/?a=1'];
        yield 'user information' => ['https://user:secret@example.com/path', 'https://example.com/path'];
        yield 'a fragment' => ['https://example.com/path?a=1#top', 'https://example.com/path?a=1'];
        yield 'an uppercase scheme and host' => ['HTTPS://EXAMPLE.COM/Path', 'https://example.com/Path'];
        yield 'a port that is not the default' => ['https://example.com:8443/', 'https://example.com:8443/'];
        yield 'percent-encoding left as is' => ['https://example.com/a%20b?c=%41', 'https://example.com/a%20b?c=%41'];
    }

    #[DataProvider('targetUrisProvider')]
    public function testTheTargetUriIsTheOneAServerReconstructs(string $uri, string $expected): void
    {
        $this->assertSame($expected, (new MessageContext(new Request('GET', $uri)))->derived('@target-uri'));
    }

    public function testTheTargetUriNeedsAnAuthority(): void
    {
        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage('MissingComponent: the request URI has no authority');

        (new MessageContext(new Request('GET', '/path')))->derived('@target-uri');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function lineBreaksProvider(): iterable
    {
        yield 'a line feed' => ["\n"];
        yield 'a carriage return' => ["\r"];
    }

    #[DataProvider('lineBreaksProvider')]
    public function testAFieldLineWithALineBreakIsMissing(string $break): void
    {
        $message = $this->createStub(MessageInterface::class);
        $message->method('hasHeader')->willReturn(true);
        $message->method('getHeader')->willReturn(['one', 'two' . $break . 'three']);

        try {
            (new MessageContext($message))->field('X-Broken');
            $this->fail('Expected a ComponentFailure');
        } catch (ComponentFailure $failure) {
            $this->assertSame(FailureReason::MissingComponent, $failure->reason);
            $this->assertSame(
                'the value of x-broken holds a line break, which a component value cannot',
                $failure->detail,
            );
        }
    }

    #[DataProvider('lineBreaksProvider')]
    public function testAMethodWithALineBreakIsMissing(string $break): void
    {
        $uri = $this->createStub(UriInterface::class);
        $request = $this->createStub(RequestInterface::class);
        $request->method('getUri')->willReturn($uri);
        $request->method('getMethod')->willReturn('GET' . $break . 'X');
        $request->method('getRequestTarget')->willReturn('/');

        try {
            (new MessageContext($request))->derived('@method');
            $this->fail('Expected a ComponentFailure');
        } catch (ComponentFailure $failure) {
            $this->assertSame(FailureReason::MissingComponent, $failure->reason);
            $this->assertSame(
                'the value of @method holds a line break, which a component value cannot',
                $failure->detail,
            );
        }

        try {
            (new MessageContext($request))->cavageRequestTarget();
            $this->fail('Expected a ComponentFailure');
        } catch (ComponentFailure $failure) {
            $this->assertSame(FailureReason::MissingComponent, $failure->reason);
            $this->assertSame(
                'the value of (request-target) holds a line break, which a component value cannot',
                $failure->detail,
            );
        }
    }

    #[DataProvider('lineBreaksProvider')]
    public function testARequestTargetWithALineBreakIsMissing(string $break): void
    {
        $uri = $this->createStub(UriInterface::class);
        $request = $this->createStub(RequestInterface::class);
        $request->method('getUri')->willReturn($uri);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn('/a' . $break . 'b');

        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage('MissingComponent: the value of @request-target holds a line break');

        (new MessageContext($request))->derived('@request-target');
    }

    public function testAnEmptyPathIsASlashAndAnAbsentQueryIsAQuestionMark(): void
    {
        $context = new MessageContext(new Request('GET', 'https://example.com'));

        $this->assertSame('/', $context->derived('@path'));
        $this->assertSame('?', $context->derived('@query'));
        $this->assertSame('/', $context->derived('@request-target'));
    }

    public function testAnEmptyQueryIsAQuestionMarkWithNothingAfterIt(): void
    {
        $this->assertSame(
            '?',
            (new MessageContext(new Request('POST', 'https://example.com/path?')))->derived('@query'),
        );
        $this->assertSame(
            '?queryString',
            (new MessageContext(new Request('POST', 'https://example.com/path?queryString')))->derived('@query'),
        );
    }

    public function testTheRequestTargetTakesEveryForm(): void
    {
        $asterisk = (new Request('OPTIONS', 'https://example.com'))->withRequestTarget('*');
        $absolute = (new Request('GET', 'https://www.example.com/path?param=value'))
            ->withRequestTarget('https://www.example.com/path?param=value');
        $authority = (new Request('CONNECT', 'https://www.example.com'))->withRequestTarget('www.example.com:80');

        $this->assertSame('*', (new MessageContext($asterisk))->derived('@request-target'));
        $this->assertSame(
            'https://www.example.com/path?param=value',
            (new MessageContext($absolute))->derived('@request-target'),
        );
        $this->assertSame('www.example.com:80', (new MessageContext($authority))->derived('@request-target'));
    }

    public function testStatusIsTheThreeDigitCode(): void
    {
        $this->assertSame('200', (new MessageContext(new Response(200)))->derived('@status'));
        $this->assertSame('404', (new MessageContext(new Response(404)))->derived('@status'));
    }

    /**
     * @return iterable<string, array{MessageInterface, string, FailureReason, string}>
     */
    public static function derivedFailuresProvider(): iterable
    {
        $request = new Request('GET', 'https://example.com/');
        $response = new Response();

        $unsupported = FailureReason::UnsupportedSignature;

        yield '@status of a request' => [$request, '@status', $unsupported, '@status is a response component'];
        yield '@method of a response' => [$response, '@method', $unsupported, '@method is a request component'];
        yield '@path of a response' => [$response, '@path', $unsupported, '@path is a request component'];
        yield '@query-param without a name' => [
            $request,
            '@query-param',
            FailureReason::UnsupportedSignature,
            '@query-param needs a name parameter',
        ];
        yield 'an unknown derived component' => [
            $request,
            '@signature-params',
            FailureReason::UnsupportedSignature,
            'the derived component @signature-params is not implemented',
        ];
        yield 'a URI without an authority' => [
            new Request('GET', '/path'),
            '@authority',
            FailureReason::MissingComponent,
            'the request URI has no authority',
        ];
        yield 'a URI without a scheme' => [
            new Request('GET', '//example.com/path'),
            '@scheme',
            FailureReason::MissingComponent,
            'the request URI has no scheme',
        ];
    }

    #[DataProvider('derivedFailuresProvider')]
    public function testDerivedFailures(
        MessageInterface $message,
        string $name,
        FailureReason $reason,
        string $detail,
    ): void {
        try {
            (new MessageContext($message))->derived($name);
            $this->fail('Expected a ComponentFailure');
        } catch (ComponentFailure $failure) {
            $this->assertSame($reason, $failure->reason);
            $this->assertSame($detail, $failure->detail);
        }
    }

    public function testQueryParametersFollowSection228(): void
    {
        $context = new MessageContext(
            new Request('GET', 'https://example.com/path?param=value&foo=bar&baz=batman&qux='),
        );

        $this->assertSame('batman', $context->queryParameter('baz'));
        $this->assertSame('', $context->queryParameter('qux'));
        $this->assertSame('value', $context->queryParameter('param'));

        $encoded = new MessageContext(new Request(
            'GET',
            'https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value'
            . '&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something',
        ));

        $this->assertSame('this%20is%20a%20big%0Amultiline%20value', $encoded->queryParameter('var'));
        $this->assertSame('with%20plus%20whitespace', $encoded->queryParameter('bar'));
        $this->assertSame('something', $encoded->queryParameter('fa%C3%A7ade%22%3A%20'));
    }

    public function testTheAppendixB22QueryParameterIsCaseSensitive(): void
    {
        $context = new MessageContext(new Request('POST', 'https://example.com/foo?param=Value&Pet=dog'));

        $this->assertSame('dog', $context->queryParameter('Pet'));
        $this->assertSame('Value', $context->queryParameter('param'));
    }

    public function testAnAbsentQueryParameterIsMissing(): void
    {
        $context = new MessageContext(new Request('GET', 'https://example.com/path?param=value'));

        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage('MissingComponent: the query has no parameter "pet"');

        $context->queryParameter('pet');
    }

    public function testARepeatedQueryParameterIsUnsupported(): void
    {
        $context = new MessageContext(new Request('GET', 'https://example.com/path?a=1&b=2&a=3'));

        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage('UnsupportedSignature: the query parameter "a" occurs more than once');

        $context->queryParameter('a');
    }

    public function testAQueryParameterOfAResponseIsUnsupported(): void
    {
        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage('UnsupportedSignature: @query-param is a request component');

        (new MessageContext(new Response()))->queryParameter('a');
    }

    public function testTheDraftRequestTargetLowercasesTheMethod(): void
    {
        $context = new MessageContext(new Request('POST', 'https://example.com/foo?param=value&pet=dog'));

        $this->assertSame('post /foo?param=value&pet=dog', $context->cavageRequestTarget());
        $this->assertSame('post /foo?param=value&pet=dog', $context->cavageRequestTarget(true));
        $this->assertSame('post /foo', $context->cavageRequestTarget(false));
    }

    public function testTheDraftRequestTargetWithoutAQueryIsUnchangedByTheRetry(): void
    {
        $context = new MessageContext(new Request('GET', 'https://example.com/foo'));

        $this->assertSame('get /foo', $context->cavageRequestTarget(false));
    }

    public function testTheDraftRequestTargetOfAResponseIsUnsupported(): void
    {
        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage('UnsupportedSignature: (request-target) is a request component');

        (new MessageContext(new Response()))->cavageRequestTarget();
    }

    public function testTheRelatedRequestAnswersForReqComponents(): void
    {
        $request = new Request('POST', 'https://example.com/foo?a=1', ['Date' => 'Tue, 20 Apr 2021 02:07:55 GMT']);
        $response = new Response(200, ['Date' => 'Tue, 20 Apr 2021 02:07:56 GMT']);
        $related = (new MessageContext($response, $request))->forRelatedRequest();

        $this->assertTrue($related->isRequest());
        $this->assertSame('POST', $related->derived('@method'));
        $this->assertSame('Tue, 20 Apr 2021 02:07:55 GMT', $related->field('date'));
    }

    public function testReqOnARequestIsUnsupported(): void
    {
        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage(
            'UnsupportedSignature: the req parameter cannot be used when the target message is a request',
        );

        (new MessageContext(new Request('GET', 'https://example.com/')))->forRelatedRequest();
    }

    public function testReqWithoutARelatedRequestIsMissing(): void
    {
        $this->expectException(ComponentFailure::class);
        $this->expectExceptionMessage(
            'MissingComponent: a component with the req parameter needs the related request, which was not given',
        );

        (new MessageContext(new Response()))->forRelatedRequest();
    }
}
