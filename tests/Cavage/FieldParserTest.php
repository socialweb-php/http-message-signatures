<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Cavage;

use Nyholm\Psr7\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;
use SocialWeb\Http\MessageSignatures\Cavage\FieldParser;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function base64_decode;
use function strtolower;

class FieldParserTest extends TestCase
{
    /**
     * The signature of draft-cavage-http-signatures-12 appendix C.2
     */
    private const string C2_SIGNATURE = 'qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7'
        . 'ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=';

    /**
     * @param array<string, string> $headers
     */
    private static function context(array $headers): MessageContext
    {
        return new MessageContext(new Request('POST', 'https://example.com/foo?param=value&pet=dog', $headers));
    }

    public function testParsesTheAuthorizationFieldOfAppendixC2(): void
    {
        $parsed = FieldParser::parse(self::context([
            'Authorization' => 'Signature keyId="Test",algorithm="rsa-sha256",'
                . ' headers="(request-target) host date", signature="' . self::C2_SIGNATURE . '"',
        ]));

        $this->assertSame('Test', $parsed->keyId);
        $this->assertSame('rsa-sha256', $parsed->algorithm);
        $this->assertNull($parsed->created);
        $this->assertNull($parsed->expires);
        $this->assertSame(['(request-target)', 'host', 'date'], $parsed->coveredComponentNames());
        $this->assertSame(base64_decode(self::C2_SIGNATURE, true), $parsed->signature);
    }

    public function testParsesTheSignatureFieldWithItsTimes(): void
    {
        $parsed = FieldParser::parse(self::context([
            'Signature' => 'keyId="https://example.com/key",algorithm="hs2019",created=1402170695,'
                . 'expires="1402170699.5",headers="(request-target) (created) (expires) Host Date",'
                . 'signature="c2lnbmF0dXJl"',
        ]));

        $this->assertSame('https://example.com/key', $parsed->keyId);
        $this->assertSame('hs2019', $parsed->algorithm);
        $this->assertSame('1402170695', $parsed->created);
        $this->assertSame('1402170699.5', $parsed->expires);
        $this->assertSame(
            ['(request-target)', '(created)', '(expires)', 'host', 'date'],
            $parsed->coveredComponentNames(),
        );
        $this->assertSame('signature', $parsed->signature);
    }

    public function testTheSignatureFieldIsReadBeforeTheAuthorizationField(): void
    {
        $parsed = FieldParser::parse(self::context([
            'Signature' => 'keyId="from-signature",signature="c2lnbmF0dXJl"',
            'Authorization' => 'Signature keyId="from-authorization",signature="c2lnbmF0dXJl"',
        ]));

        $this->assertSame('from-signature', $parsed->keyId);
    }

    public function testTheSchemeIsMatchedInAnyCaseAfterLeadingWhitespace(): void
    {
        $request = $this->withField(
            new Request('GET', 'https://example.com/'),
            'Authorization',
            "\t SIGNATURE  keyId=\"a\",signature=\"c2lnbmF0dXJl\"",
        );

        $this->assertSame('a', FieldParser::parse(new MessageContext($request))->keyId);
    }

    public function testFollowsTheAuthParamGrammar(): void
    {
        $parsed = FieldParser::parse(self::context([
            'Signature' => ' , KeyId = "a\"b\\\\c" ,, ALGORITHM=hmac-sha256 , extension="ignored",'
                . 'SIGNATURE="c2lnbmF0dXJl" ,',
        ]));

        $this->assertSame('a"b\c', $parsed->keyId);
        $this->assertSame('hmac-sha256', $parsed->algorithm);
        $this->assertSame(['date'], $parsed->coveredComponentNames());
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function defaultHeadersProvider(): iterable
    {
        yield 'no algorithm' => ['', ['(created)']];
        yield 'hs2019' => [',algorithm="hs2019"', ['(created)']];
        yield 'rsa-sha256' => [',algorithm="rsa-sha256"', ['date']];
        yield 'hmac-sha256' => [',algorithm="hmac-sha256"', ['date']];
        yield 'an algorithm the package does not know' => [',algorithm="rsa-sha1"', ['date']];
    }

    /**
     * @param list<string> $names
     */
    #[DataProvider('defaultHeadersProvider')]
    public function testTheDefaultHeadersDependOnTheAlgorithm(string $algorithm, array $names): void
    {
        $parsed = FieldParser::parse(self::context([
            'Signature' => 'keyId="a",signature="c2lnbmF0dXJl"' . $algorithm,
        ]));

        $this->assertSame($names, $parsed->coveredComponentNames());
    }

    /**
     * @return iterable<string, array{string, FailureReason, string}>
     */
    public static function rejectedProvider(): iterable
    {
        yield 'parameters with no comma between them' => [
            'keyId="a" signature="c2lnbmF0dXJl"',
            FailureReason::MalformedSignature,
            'the signature field is not a list of auth-params',
        ];
        yield 'the scheme name inside the field' => [
            'Signature keyId="a",signature="c2lnbmF0dXJl"',
            FailureReason::MalformedSignature,
            'the signature field is not a list of auth-params',
        ];
        yield 'a quoted-string with no end' => [
            'keyId="a,signature="c2lnbmF0dXJl',
            FailureReason::MalformedSignature,
            'the signature field is not a list of auth-params',
        ];
        yield 'a token value with a slash' => [
            'keyId=a/b,signature="c2lnbmF0dXJl"',
            FailureReason::MalformedSignature,
            'the signature field is not a list of auth-params',
        ];
        yield 'a duplicated parameter in another case' => [
            'keyId="a",KEYID="b",signature="c2lnbmF0dXJl"',
            FailureReason::MalformedSignature,
            'the parameter keyid appears more than once',
        ];
        yield 'no keyId' => [
            'signature="c2lnbmF0dXJl"',
            FailureReason::MalformedSignature,
            'the keyId parameter is absent or empty',
        ];
        yield 'an empty keyId' => [
            'keyId="",signature="c2lnbmF0dXJl"',
            FailureReason::MalformedSignature,
            'the keyId parameter is absent or empty',
        ];
        yield 'no signature' => [
            'keyId="a"',
            FailureReason::MalformedSignature,
            'the signature parameter is absent or empty',
        ];
        yield 'a signature outside the alphabet' => [
            'keyId="a",signature="c2ln$mF0dXJl"',
            FailureReason::MalformedSignature,
            'the signature parameter is not strict Base64',
        ];
        yield 'a signature without its padding' => [
            'keyId="a",signature="YWI"',
            FailureReason::MalformedSignature,
            'the signature parameter is not strict Base64',
        ];
        yield 'a signature with a space' => [
            'keyId="a",signature="c2ln bmF0dXJl"',
            FailureReason::MalformedSignature,
            'the signature parameter is not strict Base64',
        ];
        yield 'a decimal created' => [
            'keyId="a",signature="c2lnbmF0dXJl",created=1402170695.5',
            FailureReason::MalformedSignature,
            'the created parameter is not an integer',
        ];
        yield 'a created of sixteen digits' => [
            'keyId="a",signature="c2lnbmF0dXJl",created=1000000000000000',
            FailureReason::MalformedSignature,
            'the created parameter is not an integer',
        ];
        yield 'a negative created' => [
            'keyId="a",signature="c2lnbmF0dXJl",created="-1"',
            FailureReason::MalformedSignature,
            'the created parameter is not an integer',
        ];
        yield 'an expires that is not a number' => [
            'keyId="a",signature="c2lnbmF0dXJl",expires="soon"',
            FailureReason::MalformedSignature,
            'the expires parameter is not a number of seconds',
        ];
        yield 'an expires with a bare decimal point' => [
            'keyId="a",signature="c2lnbmF0dXJl",expires="1402170699."',
            FailureReason::MalformedSignature,
            'the expires parameter is not a number of seconds',
        ];
        yield 'an empty headers' => [
            'keyId="a",signature="c2lnbmF0dXJl",headers=""',
            FailureReason::MalformedSignature,
            'the headers parameter is empty',
        ];
        yield 'two spaces in headers' => [
            'keyId="a",signature="c2lnbmF0dXJl",headers="date  host"',
            FailureReason::MalformedSignature,
            'the headers parameter has an empty name',
        ];
        yield 'a name in headers that is not a field name' => [
            'keyId="a",signature="c2lnbmF0dXJl",headers="date @method"',
            FailureReason::MalformedSignature,
            '"@method" is not a field name',
        ];
        yield 'a name in parentheses the draft does not define' => [
            'keyId="a",signature="c2lnbmF0dXJl",headers="(request-target) (nonce)"',
            FailureReason::UnsupportedSignature,
            '(nonce) is not a name the draft form defines',
        ];
    }

    #[DataProvider('rejectedProvider')]
    public function testRejectsASignatureFieldItCannotParse(string $value, FailureReason $reason, string $detail): void
    {
        $this->assertFailure(self::context(['Signature' => $value]), $reason, $detail);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherSchemesProvider(): iterable
    {
        yield 'another scheme' => ['Bearer abc'];
        yield 'the Signature scheme after another' => ['Bearer Signature keyId="a",signature="c2lnbmF0dXJl"'];
    }

    public function testAMessageWithNeitherFieldHasNoSignature(): void
    {
        $this->assertFailure(
            self::context(['Content-Type' => 'application/json']),
            FailureReason::NoSignature,
            'the message has neither a Signature field nor an Authorization field',
        );
    }

    #[DataProvider('otherSchemesProvider')]
    public function testRejectsAnAuthorizationFieldWithAnotherScheme(string $value): void
    {
        $this->assertFailure(
            self::context(['Authorization' => $value]),
            FailureReason::MalformedSignature,
            'the Authorization field does not have the Signature scheme',
        );
    }

    public function testRejectsASignatureFieldWithALineBreak(): void
    {
        $request = $this->withField(
            new Request('GET', 'https://example.com/'),
            'Signature',
            "keyId=\"a\",\r\nsignature=\"c2lnbmF0dXJl\"",
        );

        $this->assertFailure(
            new MessageContext($request),
            FailureReason::MalformedSignature,
            'the value of signature holds a line break, which a component value cannot',
        );
    }

    private function assertFailure(MessageContext $context, FailureReason $reason, string $detail): void
    {
        try {
            FieldParser::parse($context);
            $this->fail('Expected a Failure');
        } catch (Failure $failure) {
            $this->assertSame($reason, $failure->reason);
            $this->assertSame($detail, $failure->detail);
        }
    }

    /**
     * A PSR-7 implementation that, unlike nyholm/psr7, takes a field value
     * as given: the request as given, with one field set to the value
     */
    private function withField(Request $request, string $name, string $value): RequestInterface
    {
        $message = $this->createStub(RequestInterface::class);
        $message->method('hasHeader')->willReturnCallback(
            static fn (string $field): bool => strtolower($field) === strtolower($name) || $request->hasHeader($field),
        );
        $message->method('getHeader')->willReturnCallback(
            static fn (string $field): array => strtolower($field) === strtolower($name)
                ? [$value]
                : $request->getHeader($field),
        );

        return $message;
    }
}
