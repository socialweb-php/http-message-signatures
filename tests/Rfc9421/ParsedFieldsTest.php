<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Rfc9421;

use Bakame\Http\StructuredFields\InnerList;
use SocialWeb\Http\MessageSignatures\Rfc9421\ParsedFields;
use SocialWeb\Http\MessageSignatures\Rfc9421\ParsedSignature;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

/**
 * Checks what the parser reports of the two RFC 9421 fields
 */
final class ParsedFieldsTest extends TestCase
{
    public function testHoldsTheSignaturesAndWhetherLabelsWereLeftUnread(): void
    {
        $signature = new ParsedSignature(
            label: 'sig1',
            coveredComponents: [],
            signatureParams: InnerList::fromHttpValue('();keyid="k"'),
            keyId: 'k',
            created: null,
            expires: null,
            nonce: null,
            algorithm: null,
            tag: null,
            signature: "\x01",
        );

        $fields = new ParsedFields([$signature], true);

        $this->assertSame([$signature], $fields->signatures);
        $this->assertTrue($fields->labelsLeftUnread);
    }

    public function testMayHoldNoSignatures(): void
    {
        $fields = new ParsedFields([], false);

        $this->assertSame([], $fields->signatures);
        $this->assertFalse($fields->labelsLeftUnread);
    }
}
