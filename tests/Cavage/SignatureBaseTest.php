<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Cavage;

use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\MessageInterface;
use SocialWeb\Http\MessageSignatures\Cavage\SignatureBase;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function array_map;
use function explode;

class SignatureBaseTest extends TestCase
{
    /**
     * The request of draft-cavage-http-signatures-12 appendix C
     */
    private static function appendixCRequest(): Request
    {
        return new Request(
            'POST',
            'https://example.com/foo?param=value&pet=dog',
            [
                'Host' => 'example.com',
                'Date' => 'Sun, 05 Jan 2014 21:31:40 GMT',
                'Content-Type' => 'application/json',
                'Digest' => 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
                'Content-Length' => '18',
            ],
            '{"hello": "world"}',
        );
    }

    /**
     * @return list<ComponentIdentifier>
     */
    private static function names(string $headers): array
    {
        return array_map(
            static fn (string $name): ComponentIdentifier => ComponentIdentifier::fromCavageName($name),
            explode(' ', $headers),
        );
    }

    public function testBuildsTheStringOfAppendixC1(): void
    {
        $base = SignatureBase::build(
            new MessageContext(self::appendixCRequest()),
            self::names('date'),
            'rsa-sha256',
            null,
            null,
        );

        $this->assertSame('date: Sun, 05 Jan 2014 21:31:40 GMT', $base);
    }

    public function testBuildsTheStringOfAppendixC2WithAndWithoutTheQuery(): void
    {
        $context = new MessageContext(self::appendixCRequest());
        $names = self::names('(request-target) host date');

        $this->assertSame(
            "(request-target): post /foo?param=value&pet=dog\nhost: example.com\ndate: Sun, 05 Jan 2014 21:31:40 GMT",
            SignatureBase::build($context, $names, 'rsa-sha256', null, null),
        );
        $this->assertSame(
            "(request-target): post /foo\nhost: example.com\ndate: Sun, 05 Jan 2014 21:31:40 GMT",
            SignatureBase::build($context, $names, 'rsa-sha256', null, null, false),
        );
    }

    public function testBuildsTheExampleOfSection23(): void
    {
        $request = new Request('GET', 'https://example.org/foo', [
            'Host' => 'example.org',
            'Date' => 'Tue, 07 Jun 2014 20:51:35 GMT',
            'X-Example' => 'Example header with some whitespace.',
            'X-EmptyHeader' => '',
            'Cache-Control' => ['max-age=60', 'must-revalidate'],
        ]);

        $base = SignatureBase::build(
            new MessageContext($request),
            self::names('(request-target) (created) host date cache-control x-emptyheader x-example'),
            'hs2019',
            '1402170695',
            null,
        );

        $this->assertSame(
            "(request-target): get /foo\n(created): 1402170695\nhost: example.org\n"
                . "date: Tue, 07 Jun 2014 20:51:35 GMT\ncache-control: max-age=60, must-revalidate\n"
                . "x-emptyheader: \nx-example: Example header with some whitespace.",
            $base,
        );
    }

    public function testCoversTheTimesWhenTheKeyDecides(): void
    {
        $base = SignatureBase::build(
            new MessageContext(self::appendixCRequest()),
            self::names('(created) (expires)'),
            null,
            '1402170695',
            '1402170699',
        );

        $this->assertSame("(created): 1402170695\n(expires): 1402170699", $base);
    }

    /**
     * @return iterable<string, array{MessageInterface, string, string | null, string | null, string | null, FailureReason, string}>
     */
    public static function rejectedProvider(): iterable
    {
        $request = self::appendixCRequest();

        yield '(created) under rsa-sha256' => [
            $request,
            '(created)',
            'rsa-sha256',
            '1402170695',
            null,
            FailureReason::MalformedSignature,
            '(created) cannot be covered under the algorithm rsa-sha256',
        ];
        yield '(expires) under hmac-sha256' => [
            $request,
            '(expires)',
            'hmac-sha256',
            null,
            '1402170699',
            FailureReason::MalformedSignature,
            '(expires) cannot be covered under the algorithm hmac-sha256',
        ];
        yield '(created) under ecdsa-sha256' => [
            $request,
            '(created)',
            'ecdsa-sha256',
            '1402170695',
            null,
            FailureReason::MalformedSignature,
            '(created) cannot be covered under the algorithm ecdsa-sha256',
        ];
        yield '(created) without the parameter' => [
            $request,
            '(created)',
            'hs2019',
            null,
            null,
            FailureReason::MalformedSignature,
            '(created) is covered and the created parameter is absent',
        ];
        yield '(expires) with a decimal parameter' => [
            $request,
            '(expires)',
            'hs2019',
            null,
            '1402170699.5',
            FailureReason::MalformedSignature,
            '(expires) is covered and the expires parameter is not an integer',
        ];
        yield '(request-target) of a response' => [
            new Response(200),
            '(request-target)',
            'rsa-sha256',
            null,
            null,
            FailureReason::UnsupportedSignature,
            '(request-target) is a request component',
        ];
        yield 'a field the message lacks' => [
            $request,
            'date x-missing',
            'rsa-sha256',
            null,
            null,
            FailureReason::MissingComponent,
            'the field "x-missing" is not in the message',
        ];
    }

    #[DataProvider('rejectedProvider')]
    public function testRejectsWhatItCannotBuild(
        MessageInterface $message,
        string $headers,
        ?string $algorithm,
        ?string $created,
        ?string $expires,
        FailureReason $reason,
        string $detail,
    ): void {
        try {
            SignatureBase::build(new MessageContext($message), self::names($headers), $algorithm, $created, $expires);
            $this->fail('Expected a Failure');
        } catch (Failure $failure) {
            $this->assertSame($reason, $failure->reason);
            $this->assertSame($detail, $failure->detail);
        }
    }
}
