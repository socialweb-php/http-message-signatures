<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Rfc9421;

use Nyholm\Psr7\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\Rfc9421\FieldParser;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function base64_decode;

class FieldParserTest extends TestCase
{
    private const string INPUT = 'sig1=("@method" "@authority" "@path" "content-digest" "content-type"'
        . ' "content-length");created=1618884475;keyid="test-key-ecc-p256", proxy_sig=("@method" "@authority" "@path"'
        . ' "content-digest"'
        . ' "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256"'
        . ';expires=1618884540';
    private const string SIGNATURE = 'sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNal'
        . 'zA8ESSaHD3A==:, proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iH'
        . 'gxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7'
        . 'LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJv'
        . 'ye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:';

    private static function context(?string $input, ?string $signature): MessageContext
    {
        $headers = [];

        if ($input !== null) {
            $headers['Signature-Input'] = $input;
        }

        if ($signature !== null) {
            $headers['Signature'] = $signature;
        }

        return new MessageContext(new Request('GET', 'https://example.com/', $headers));
    }

    public function testParsesTheSection43FieldsInOrder(): void
    {
        $parsed = FieldParser::parse(self::context(self::INPUT, self::SIGNATURE), 3);

        $this->assertCount(2, $parsed);

        $this->assertSame('sig1', $parsed[0]->label);
        $this->assertSame(
            ['@method', '@authority', '@path', 'content-digest', 'content-type', 'content-length'],
            $parsed[0]->coveredComponentNames(),
        );
        $this->assertSame('test-key-ecc-p256', $parsed[0]->keyId);
        $this->assertSame(1618884475, $parsed[0]->created);
        $this->assertNull($parsed[0]->expires);
        $this->assertNull($parsed[0]->nonce);
        $this->assertNull($parsed[0]->algorithm);
        $this->assertNull($parsed[0]->tag);
        $this->assertSame(
            base64_decode(
                'X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==',
                true,
            ),
            $parsed[0]->signature,
        );
        $this->assertSame(
            '("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884475'
            . ';keyid="test-key-ecc-p256"',
            $parsed[0]->signatureParams->toHttpValue(),
        );

        $this->assertSame('proxy_sig', $parsed[1]->label);
        $this->assertSame('test-key-rsa', $parsed[1]->keyId);
        $this->assertSame(1618884480, $parsed[1]->created);
        $this->assertSame(1618884540, $parsed[1]->expires);
        $this->assertSame('rsa-v1_5-sha256', $parsed[1]->algorithm);
    }

    public function testReadsOnlyAsManyLabelsAsTheLimit(): void
    {
        $parsed = FieldParser::parse(self::context(self::INPUT, self::SIGNATURE), 1);

        $this->assertCount(1, $parsed);
        $this->assertSame('sig1', $parsed[0]->label);
    }

    public function testReadsEveryParameterWithItsType(): void
    {
        $parsed = FieldParser::parse(self::context(
            'sig1=("@method");created=1618884473;expires=1618884773;nonce="n";alg="ed25519";keyid="k";tag="t"',
            'sig1=:AQ==:',
        ), 1);

        $this->assertSame(1618884473, $parsed[0]->created);
        $this->assertSame(1618884773, $parsed[0]->expires);
        $this->assertSame('n', $parsed[0]->nonce);
        $this->assertSame('ed25519', $parsed[0]->algorithm);
        $this->assertSame('k', $parsed[0]->keyId);
        $this->assertSame('t', $parsed[0]->tag);
        $this->assertSame("\x01", $parsed[0]->signature);
    }

    public function testKeepsAParameterItDoesNotKnowForTheSignatureParamsLine(): void
    {
        $parsed = FieldParser::parse(self::context(
            'sig1=("@method");created=1618884473;future=?1;keyid="k"',
            'sig1=:AQ==:',
        ), 1);

        $this->assertSame(
            '("@method");created=1618884473;future;keyid="k"',
            $parsed[0]->signatureParams->toHttpValue(),
        );
    }

    public function testKeepsTheCoveredComponentsParameters(): void
    {
        $parsed = FieldParser::parse(self::context(
            'sig1=("@query-param";name="Pet" "content-digest";req "example-dict";key="a");keyid="k"',
            'sig1=:AQ==:',
        ), 1);

        $this->assertSame(
            ['@query-param;name="Pet"', 'content-digest;req', 'example-dict;key="a"'],
            $parsed[0]->coveredComponentNames(),
        );
    }

    /**
     * @return iterable<string, array{string | null, string | null, string}>
     */
    public static function malformedProvider(): iterable
    {
        yield 'no Signature field' => [
            'sig1=("@method");keyid="k"',
            null,
            'the message has a signature-input field and no signature field',
        ];
        yield 'no Signature-Input field' => [
            null,
            'sig1=:AQ==:',
            'the message has a signature field and no signature-input field',
        ];
        yield 'Signature-Input that does not parse' => [
            'sig1=("@method"',
            'sig1=:AQ==:',
            'the signature-input field does not parse as a Dictionary',
        ];
        yield 'Signature that does not parse' => [
            'sig1=("@method");keyid="k"',
            'sig1=:AQ==',
            'the signature field does not parse as a Dictionary',
        ];
        yield 'Signature-Input with no members beside a Signature with one' => [
            '',
            'sig1=:AQ==:',
            'the label "sig1" is in Signature and not in Signature-Input',
        ];
        yield 'a label in Signature-Input only' => [
            'sig1=("@method");keyid="k", sig2=("@method");keyid="k"',
            'sig1=:AQ==:',
            'the label "sig2" is in Signature-Input and not in Signature',
        ];
        yield 'a label in Signature only' => [
            'sig1=("@method");keyid="k"',
            'sig1=:AQ==:, sig2=:AQ==:',
            'the label "sig2" is in Signature and not in Signature-Input',
        ];
        yield 'a Signature-Input member that is not an Inner List' => [
            'sig1="@method";keyid="k"',
            'sig1=:AQ==:',
            'the Signature-Input member "sig1" is not an Inner List',
        ];
        yield 'a Signature member that is an Inner List' => [
            'sig1=("@method");keyid="k"',
            'sig1=(:AQ==:)',
            'the Signature member "sig1" is not a Byte Sequence',
        ];
        yield 'a Signature member that is a String' => [
            'sig1=("@method");keyid="k"',
            'sig1="AQ=="',
            'the Signature member "sig1" is not a Byte Sequence',
        ];
        yield 'a covered component that is a Token' => [
            'sig1=(method);keyid="k"',
            'sig1=:AQ==:',
            'a covered component identifier must be a String, not Token',
        ];
        yield 'no keyid' => [
            'sig1=("@method");created=1',
            'sig1=:AQ==:',
            'the signature "sig1" has no keyid parameter',
        ];
        yield 'keyid that is not a String' => [
            'sig1=("@method");keyid=1',
            'sig1=:AQ==:',
            'the keyid parameter of "sig1" is not a String',
        ];
        yield 'created that is not an Integer' => [
            'sig1=("@method");created="1618884473";keyid="k"',
            'sig1=:AQ==:',
            'the created parameter of "sig1" is not an Integer',
        ];
        yield 'expires that is a Decimal' => [
            'sig1=("@method");expires=1618884473.5;keyid="k"',
            'sig1=:AQ==:',
            'the expires parameter of "sig1" is not an Integer',
        ];
        yield 'nonce that is not a String' => [
            'sig1=("@method");nonce=:AQ==:;keyid="k"',
            'sig1=:AQ==:',
            'the nonce parameter of "sig1" is not a String',
        ];
        yield 'alg that is a Token' => [
            'sig1=("@method");alg=ed25519;keyid="k"',
            'sig1=:AQ==:',
            'the alg parameter of "sig1" is not a String',
        ];
        yield 'tag that is a Boolean' => [
            'sig1=("@method");tag;keyid="k"',
            'sig1=:AQ==:',
            'the tag parameter of "sig1" is not a String',
        ];
        yield 'created with more than 15 digits' => [
            'sig1=("@method");created=1618884473000000;keyid="k"',
            'sig1=:AQ==:',
            'the signature-input field does not parse as a Dictionary',
        ];
    }

    #[DataProvider('malformedProvider')]
    public function testAFieldThatDoesNotHaveTheShapeOfSection4IsMalformed(
        ?string $input,
        ?string $signature,
        string $detail,
    ): void {
        try {
            FieldParser::parse(self::context($input, $signature), 3);
            $this->fail('Expected a Failure');
        } catch (Failure $failure) {
            $this->assertSame(FailureReason::MalformedSignature, $failure->reason);
            $this->assertSame($detail, $failure->detail);
        }
    }

    public function testALabelBeyondTheLimitIsNotRead(): void
    {
        $parsed = FieldParser::parse(self::context(
            'sig1=("@method");keyid="k", sig2="not an inner list"',
            'sig1=:AQ==:, sig2=:AQ==:',
        ), 1);

        $this->assertCount(1, $parsed);
    }

    public function testTheLabelsOfBothFieldsMustMatchEvenBeyondTheLimit(): void
    {
        $this->expectException(Failure::class);
        $this->expectExceptionMessageIsOrContains(
            'MalformedSignature: the label "sig2" is in Signature and not in Signature-Input',
        );

        FieldParser::parse(self::context('sig1=("@method");keyid="k"', 'sig1=:AQ==:, sig2=:AQ==:'), 1);
    }

    public function testTwoEmptyFieldsGiveNoSignatures(): void
    {
        $this->assertSame([], FieldParser::parse(self::context('', ''), 3));
    }

    public function testACreatedParameterOfFifteenDigitsIsRead(): void
    {
        $parsed = FieldParser::parse(self::context('sig1=();created=999999999999999;keyid="k"', 'sig1=:AQ==:'), 1);

        $this->assertSame(999999999999999, $parsed[0]->created);
    }
}
