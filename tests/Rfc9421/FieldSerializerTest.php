<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Rfc9421;

use Bakame\Http\StructuredFields\SyntaxError;
use Nyholm\Psr7\Request;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Rfc9421\FieldSerializer;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

class FieldSerializerTest extends TestCase
{
    public function testSerializesTheSignatureParamsAsAParameterizedInnerList(): void
    {
        $params = FieldSerializer::signatureParams(
            [
                ComponentIdentifier::parse('@method'),
                ComponentIdentifier::parse('@query-param;name="Pet"'),
                ComponentIdentifier::parse('content-digest;req'),
            ],
            [
                'created' => 1618884473,
                'expires' => 1618884773,
                'nonce' => 'n',
                'alg' => 'ed25519',
                'keyid' => 'k',
                'tag' => 't',
            ],
        );

        $this->assertSame(
            '("@method" "@query-param";name="Pet" "content-digest";req);created=1618884473;expires=1618884773;nonce="n"'
            . ';alg="ed25519";keyid="k";tag="t"',
            $params->toHttpValue(),
        );
    }

    public function testSerializesAnEmptyCoveredList(): void
    {
        $params = FieldSerializer::signatureParams([], ['created' => 1618884473, 'keyid' => 'k']);

        $this->assertSame('();created=1618884473;keyid="k"', $params->toHttpValue());
    }

    public function testAddsBothFieldsToAMessageThatHasNeither(): void
    {
        $params = FieldSerializer::signatureParams([ComponentIdentifier::parse('@method')], ['keyid' => 'k']);

        $signed = FieldSerializer::append(new Request('GET', 'https://example.com/'), 'sig1', $params, "\x01\x02");

        $this->assertSame('sig1=("@method");keyid="k"', $signed->getHeaderLine('Signature-Input'));
        $this->assertSame('sig1=:AQI=:', $signed->getHeaderLine('Signature'));
    }

    public function testAppendsALabelToExistingFields(): void
    {
        $message = new Request('GET', 'https://example.com/', [
            'Signature-Input' => 'sig1=("@method");keyid="k"',
            'Signature' => 'sig1=:AQI=:',
        ]);
        $params = FieldSerializer::signatureParams([ComponentIdentifier::parse('@path')], ['keyid' => 'k2']);

        $signed = FieldSerializer::append($message, 'sig2', $params, "\x03");

        $this->assertSame(
            'sig1=("@method");keyid="k", sig2=("@path");keyid="k2"',
            $signed->getHeaderLine('Signature-Input'),
        );
        $this->assertSame('sig1=:AQI=:, sig2=:Aw==:', $signed->getHeaderLine('Signature'));
    }

    public function testRefusesALabelTheMessageAlreadyHasInSignatureInput(): void
    {
        $message = new Request('GET', 'https://example.com/', [
            'Signature-Input' => 'sig1=("@method");keyid="k"',
            'Signature' => 'sig1=:AQI=:',
        ]);
        $params = FieldSerializer::signatureParams([], ['keyid' => 'k']);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The message already has a signature with the label "sig1"');

        FieldSerializer::append($message, 'sig1', $params, "\x01");
    }

    public function testRefusesALabelTheMessageAlreadyHasInSignatureOnly(): void
    {
        $message = new Request('GET', 'https://example.com/', ['Signature' => 'sig1=:AQI=:']);
        $params = FieldSerializer::signatureParams([], ['keyid' => 'k']);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The message already has a signature with the label "sig1"');

        FieldSerializer::append($message, 'sig1', $params, "\x01");
    }

    public function testRefusesAnExistingFieldThatDoesNotParse(): void
    {
        $message = new Request('GET', 'https://example.com/', ['Signature-Input' => 'sig1=(']);
        $params = FieldSerializer::signatureParams([], ['keyid' => 'k']);

        try {
            FieldSerializer::append($message, 'sig2', $params, "\x01");
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertSame(
                'The signature-input field of the message does not parse as a Dictionary',
                $exception->getMessage(),
            );
            $this->assertInstanceOf(SyntaxError::class, $exception->getPrevious());
            $this->assertSame(0, $exception->getCode());
        }
    }

    public function testRefusesAnExistingSignatureFieldThatDoesNotParse(): void
    {
        $message = new Request('GET', 'https://example.com/', ['Signature' => 'sig1=:not base64:']);
        $params = FieldSerializer::signatureParams([], ['keyid' => 'k']);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The signature field of the message does not parse as a Dictionary');

        FieldSerializer::append($message, 'sig2', $params, "\x01");
    }
}
