<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use DateTime;
use DateTimeImmutable;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\KeyLookup;

/**
 * Checks what a key lookup holds for the resolver
 */
final class KeyLookupTest extends TestCase
{
    public function testNeedsOnlyTheMessageTheFormAndTheKeyIdentifier(): void
    {
        $request = new Request('GET', 'https://example.com/');

        $lookup = new KeyLookup($request, Form::Cavage, 'https://example.com/keys/1');

        $this->assertSame($request, $lookup->message);
        $this->assertSame(Form::Cavage, $lookup->form);
        $this->assertSame('https://example.com/keys/1', $lookup->keyId);
        $this->assertNull($lookup->relatedRequest);
        $this->assertNull($lookup->label);
        $this->assertNull($lookup->algorithm);
        $this->assertNull($lookup->created);
        $this->assertNull($lookup->expires);
        $this->assertNull($lookup->nonce);
        $this->assertNull($lookup->tag);
        $this->assertSame([], $lookup->coveredComponents);
    }

    public function testHoldsEverythingTheVerifierKnowsAboutASignature(): void
    {
        $request = new Request('POST', 'https://example.com/foo');
        $response = new Response(200);
        $created = new DateTimeImmutable('@1618884473');
        $expires = new DateTimeImmutable('@1618884773');

        $lookup = new KeyLookup(
            message: $response,
            form: Form::Rfc9421,
            keyId: 'test-key-ed25519',
            relatedRequest: $request,
            label: 'sig1',
            algorithm: Algorithm::Ed25519,
            created: $created,
            expires: $expires,
            nonce: 'n1',
            tag: 'example',
            coveredComponents: ['@status', '@method;req', 'content-digest'],
        );

        $this->assertSame($response, $lookup->message);
        $this->assertSame(Form::Rfc9421, $lookup->form);
        $this->assertSame('test-key-ed25519', $lookup->keyId);
        $this->assertSame($request, $lookup->relatedRequest);
        $this->assertSame('sig1', $lookup->label);
        $this->assertSame(Algorithm::Ed25519, $lookup->algorithm);
        $this->assertEquals($created, $lookup->created);
        $this->assertEquals($expires, $lookup->expires);
        $this->assertSame('n1', $lookup->nonce);
        $this->assertSame('example', $lookup->tag);
        $this->assertSame(['@status', '@method;req', 'content-digest'], $lookup->coveredComponents);
    }

    public function testKeepsItsOwnCopyOfADateItIsGiven(): void
    {
        $created = new DateTime('@1618884473');
        $expires = new DateTime('@1618884773');

        $lookup = new KeyLookup(
            message: new Request('GET', 'https://example.com/'),
            form: Form::Rfc9421,
            keyId: 'test-key-ed25519',
            created: $created,
            expires: $expires,
        );
        $created->modify('+1 day');
        $expires->modify('+1 day');

        $this->assertSame(1618884473, $lookup->created?->getTimestamp());
        $this->assertSame(1618884773, $lookup->expires?->getTimestamp());
    }
}
