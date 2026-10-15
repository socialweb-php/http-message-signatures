<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Rfc9421;

use Bakame\Http\StructuredFields\InnerList;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\Rfc9421\SignatureBase;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function array_map;
use function substr;

class SignatureBaseTest extends TestCase
{
    private const string REQUEST_DIGEST = 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNy'
        . 'ealdVLvRwEmTHWXvJwew==:';
    private const string BUSY_DIGEST = 'sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwnHJDbkkWWQz6PhhU9kxsTbARtY2'
        . 'PTBOzq24uJFpHsMuAg==:';

    private static function testRequest(): Request
    {
        return new Request('POST', 'https://example.com/foo?param=Value&Pet=dog', [
            'Host' => 'example.com',
            'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
            'Content-Type' => 'application/json',
            'Content-Digest' => self::REQUEST_DIGEST,
            'Content-Length' => '18',
        ], '{"hello": "world"}');
    }

    /**
     * @param list<string> $covered
     */
    private static function build(
        MessageInterface $message,
        array $covered,
        string $params,
        ?RequestInterface $related = null,
    ): string {
        return SignatureBase::build(
            new MessageContext($message, $related),
            array_map(static fn (string $c): ComponentIdentifier => ComponentIdentifier::parse($c), $covered),
            InnerList::fromHttpValue($params),
        );
    }

    public function testBuildsTheFigure1ExampleOfSection25(): void
    {
        $base = self::build(
            self::testRequest(),
            ['@method', '@authority', '@path', 'content-digest', 'content-length', 'content-type'],
            '("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473'
            . ';keyid="test-key-rsa-pss"',
        );

        $this->assertSame(
            "\"@method\": POST\n"
            . "\"@authority\": example.com\n"
            . "\"@path\": /foo\n"
            . '"content-digest": ' . self::REQUEST_DIGEST . "\n"
            . "\"content-length\": 18\n"
            . "\"content-type\": application/json\n"
            . '"@signature-params": ("@method" "@authority" "@path" "content-digest" "content-length" "content-type")'
            . ';created=1618884473;keyid="test-key-rsa-pss"',
            $base,
        );
    }

    public function testBuildsTheAppendixB22ExampleWithAQueryParameter(): void
    {
        $base = self::build(
            self::testRequest(),
            ['@authority', 'content-digest', '@query-param;name="Pet"'],
            '("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss"'
            . ';tag="header-example"',
        );

        $this->assertSame(
            "\"@authority\": example.com\n"
            . '"content-digest": ' . self::REQUEST_DIGEST . "\n"
            . "\"@query-param\";name=\"Pet\": dog\n"
            . '"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473'
            . ';keyid="test-key-rsa-pss";tag="header-example"',
            $base,
        );
    }

    public function testBuildsTheSection24ExampleWithRequestComponentsInAResponse(): void
    {
        $response = new Response(503, [
            'Date' => 'Tue, 20 Apr 2021 02:07:56 GMT',
            'Content-Type' => 'application/json',
            'Content-Length' => '62',
            'Content-Digest' => self::BUSY_DIGEST,
        ], '{"busy": true, "message": "Your call is very important to us"}');

        $base = self::build(
            $response,
            [
                '@status',
                'content-digest',
                'content-type',
                '@authority;req',
                '@method;req',
                '@path;req',
                'content-digest;req',
            ],
            '("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req'
            . ' "content-digest";req);created=1618884479;keyid="test-key-ecc-p256"',
            self::testRequest(),
        );

        $this->assertSame(
            "\"@status\": 503\n"
            . '"content-digest": ' . self::BUSY_DIGEST . "\n"
            . "\"content-type\": application/json\n"
            . "\"@authority\";req: example.com\n"
            . "\"@method\";req: POST\n"
            . "\"@path\";req: /foo\n"
            . '"content-digest";req: ' . self::REQUEST_DIGEST . "\n"
            . '"@signature-params": ("@status" "content-digest" "content-type" "@authority";req "@method";req'
            . ' "@path";req "content-digest";req);created=1618884479;keyid="test-key-ecc-p256"',
            $base,
        );
    }

    public function testAnEmptyCoveredListGivesTheSignatureParamsLineAlone(): void
    {
        $base = self::build(
            self::testRequest(),
            [],
            '();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
        );

        $this->assertSame(
            '"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
            $base,
        );
    }

    public function testTheSignatureParamsLineIsTheInnerListAsParsed(): void
    {
        // A parameter the package does not know, and the order received, both
        // stay as they are.
        $base = self::build(self::testRequest(), ['@method'], '("@method");keyid="k";future=1;created=1618884473');

        $this->assertSame(
            "\"@method\": POST\n\"@signature-params\": (\"@method\");keyid=\"k\";future=1;created=1618884473",
            $base,
        );
    }

    public function testAppliesTheFieldParametersOfSection21(): void
    {
        $request = new Request('GET', 'https://example.com/', [
            'Example-Dict' => ' a=1,    b=2;x=1;y=2,   c=(a   b   c)',
            'Example-Header' => ['value, with, lots', 'of, commas'],
            'Content-Digest' => self::REQUEST_DIGEST,
        ]);

        $base = self::build(
            $request,
            ['content-digest;sf', 'content-digest;key="sha-512"', 'example-header;bs', 'example-dict'],
            '("content-digest";sf "content-digest";key="sha-512" "example-header";bs "example-dict");keyid="k"',
        );

        $this->assertSame(
            '"content-digest";sf: ' . self::REQUEST_DIGEST . "\n"
            . '"content-digest";key="sha-512": ' . substr(self::REQUEST_DIGEST, 8) . "\n"
            . "\"example-header\";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:\n"
            . "\"example-dict\": a=1,    b=2;x=1;y=2,   c=(a   b   c)\n"
            . '"@signature-params": ("content-digest";sf "content-digest";key="sha-512" "example-header";bs'
            . ' "example-dict");keyid="k"',
            $base,
        );
    }

    public function testTakesAQueryParameterFromTheRelatedRequest(): void
    {
        $base = self::build(
            new Response(200),
            ['@query-param;name="Pet";req'],
            '("@query-param";name="Pet";req);keyid="k"',
            self::testRequest(),
        );

        $this->assertSame(
            "\"@query-param\";name=\"Pet\";req: dog\n"
            . '"@signature-params": ("@query-param";name="Pet";req);keyid="k"',
            $base,
        );
    }

    /**
     * @return iterable<string, array{MessageInterface, list<string>, FailureReason, string}>
     */
    public static function failuresProvider(): iterable
    {
        $request = self::testRequest();
        $response = new Response(200, ['Content-Digest' => self::REQUEST_DIGEST]);

        yield 'a component identifier that appears twice' => [
            $request,
            ['@method', '@path', '@method'],
            FailureReason::MalformedSignature,
            'the component identifier "@method" appears more than once',
        ];
        yield '@signature-params among the covered components' => [
            $request,
            ['@method', '@signature-params'],
            FailureReason::MalformedSignature,
            '@signature-params must not be among the covered components',
        ];
        yield 'a parameter the package does not know' => [
            $request,
            ['@method;future'],
            FailureReason::UnsupportedSignature,
            'the parameter "future" of "@method";future is not one the package knows',
        ];
        yield 'sf on a derived component' => [
            $request,
            ['@method;sf'],
            FailureReason::UnsupportedSignature,
            'the parameter "sf" does not apply to the derived component "@method";sf',
        ];
        yield 'bs on a derived component' => [
            $request,
            ['@path;bs'],
            FailureReason::UnsupportedSignature,
            'the parameter "bs" does not apply to the derived component "@path";bs',
        ];
        yield 'name on a derived component other than @query-param' => [
            $request,
            ['@method;name="x"'],
            FailureReason::UnsupportedSignature,
            'the name parameter applies to @query-param only, not to "@method";name="x"',
        ];
        yield '@query-param without a name' => [
            $request,
            ['@query-param'],
            FailureReason::UnsupportedSignature,
            '@query-param needs a name parameter',
        ];
        yield '@query-param whose name is not a String' => [
            $request,
            ['@query-param;name=1'],
            FailureReason::MalformedSignature,
            'the name parameter of "@query-param";name=1 is not a String',
        ];
        yield '@query-param for a parameter the query lacks' => [
            $request,
            ['@query-param;name="Cat"'],
            FailureReason::MissingComponent,
            'the query has no parameter "Cat"',
        ];
        yield 'a derived component the package does not implement' => [
            $request,
            ['@future'],
            FailureReason::UnsupportedSignature,
            'the derived component @future is not implemented',
        ];
        yield 'name on a field' => [
            $request,
            ['date;name="x"'],
            FailureReason::UnsupportedSignature,
            'the name parameter applies to @query-param only, not to "date";name="x"',
        ];
        yield 'tr on a field' => [
            $request,
            ['date;tr'],
            FailureReason::UnsupportedSignature,
            'trailer fields are not implemented, so "date";tr cannot be covered',
        ];
        yield 'bs with sf' => [
            $request,
            ['content-digest;bs;sf'],
            FailureReason::MalformedSignature,
            'the bs parameter of "content-digest";bs;sf cannot be combined with sf or key',
        ];
        yield 'bs with key' => [
            $request,
            ['content-digest;key="sha-512";bs'],
            FailureReason::MalformedSignature,
            'the bs parameter of "content-digest";key="sha-512";bs cannot be combined with sf or key',
        ];
        yield 'key that is not a String' => [
            $request,
            ['content-digest;key=1'],
            FailureReason::MalformedSignature,
            'the key parameter of "content-digest";key=1 is not a String',
        ];
        yield 'key whose member is absent' => [
            $request,
            ['content-digest;key="sha-256"'],
            FailureReason::MissingComponent,
            'the field "content-digest" has no member "sha-256"',
        ];
        yield 'sf on a field the package does not know' => [
            $request,
            ['date;sf'],
            FailureReason::UnsupportedSignature,
            'the field "date" is not one the package knows as a Structured Field',
        ];
        yield 'a field the message lacks' => [
            $request,
            ['x-absent'],
            FailureReason::MissingComponent,
            'the field "x-absent" is not in the message',
        ];
        yield 'req on a request' => [
            $request,
            ['@method;req'],
            FailureReason::UnsupportedSignature,
            'the req parameter cannot be used when the target message is a request',
        ];
        yield 'req without a related request' => [
            $response,
            ['content-digest;req'],
            FailureReason::MissingComponent,
            'a component with the req parameter needs the related request, which was not given',
        ];
        yield '@status of a request' => [
            $request,
            ['@status'],
            FailureReason::UnsupportedSignature,
            '@status is a response component',
        ];
        yield 'a field value outside ASCII' => [
            $request->withHeader('X-Latin', "caf\u{e9}"),
            ['x-latin'],
            FailureReason::MissingComponent,
            'the value of "x-latin" holds a byte outside ASCII, which the signature base cannot hold',
        ];
    }

    /**
     * @param list<string> $covered
     */
    #[DataProvider('failuresProvider')]
    public function testEachErrorCaseOfSection25HasAReason(
        MessageInterface $message,
        array $covered,
        FailureReason $reason,
        string $detail,
    ): void {
        try {
            self::build($message, $covered, '();keyid="k"');
            $this->fail('Expected a Failure');
        } catch (Failure $failure) {
            $this->assertSame($reason, $failure->reason);
            $this->assertSame($detail, $failure->detail);
        }
    }
}
