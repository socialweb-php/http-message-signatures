<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Rfc9421;

use Bakame\Http\StructuredFields\InnerList;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Rfc9421\ParsedSignature;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

class ParsedSignatureTest extends TestCase
{
    public function testNamesItsCoveredComponentsAsTheOptionsWriteThem(): void
    {
        $signature = new ParsedSignature(
            label: 'sig1',
            coveredComponents: [
                ComponentIdentifier::parse('@method'),
                ComponentIdentifier::parse('@query-param;name="Pet"'),
                ComponentIdentifier::parse('content-digest;req'),
            ],
            signatureParams: InnerList::fromHttpValue(
                '("@method" "@query-param";name="Pet" "content-digest";req);keyid="k"',
            ),
            keyId: 'k',
            created: null,
            expires: null,
            nonce: null,
            algorithm: null,
            tag: null,
            signature: "\x01",
        );

        $this->assertSame(
            ['@method', '@query-param;name="Pet"', 'content-digest;req'],
            $signature->coveredComponentNames(),
        );
    }
}
