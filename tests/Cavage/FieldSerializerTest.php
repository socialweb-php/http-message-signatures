<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Cavage;

use Nyholm\Psr7\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Cavage\FieldParser;
use SocialWeb\Http\MessageSignatures\Cavage\FieldSerializer;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function array_map;
use function base64_decode;

class FieldSerializerTest extends TestCase
{
    /**
     * The signature of draft-cavage-http-signatures-12 appendix C.2
     */
    private const string C2_SIGNATURE = 'qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7'
        . 'ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=';

    /**
     * @param list<string> $names
     *
     * @return list<ComponentIdentifier>
     */
    private static function identifiers(array $names): array
    {
        return array_map(
            static fn (string $name): ComponentIdentifier => ComponentIdentifier::fromCavageName($name),
            $names,
        );
    }

    public function testSerializesTheParametersOfAppendixC2(): void
    {
        $value = FieldSerializer::serialize(
            'Test',
            Algorithm::RsaV15Sha256,
            null,
            null,
            self::identifiers(['(request-target)', 'host', 'date']),
            (string) base64_decode(self::C2_SIGNATURE, true),
        );

        $this->assertSame(
            'keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date",signature="'
                . self::C2_SIGNATURE . '"',
            $value,
        );
    }

    public function testWritesTheTimesAsBareIntegersBeforeTheHeaders(): void
    {
        $value = FieldSerializer::serialize(
            'https://example.com/key',
            Algorithm::Ed25519,
            1402170695,
            1402170699,
            self::identifiers(['(request-target)', '(created)']),
            'signature',
        );

        $this->assertSame(
            'keyId="https://example.com/key",algorithm="hs2019",created=1402170695,expires=1402170699,'
                . 'headers="(request-target) (created)",signature="c2lnbmF0dXJl"',
            $value,
        );
    }

    public function testEscapesTheKeyIdentifierSoThatItParsesBack(): void
    {
        $value = FieldSerializer::serialize(
            'a"b\c',
            Algorithm::HmacSha256,
            null,
            null,
            self::identifiers(['date']),
            'x',
        );
        $parsed = FieldParser::parse(
            new MessageContext(new Request('GET', 'https://example.com/', ['Signature' => $value])),
        );

        $this->assertSame('keyId="a\"b\\\\c",algorithm="hmac-sha256",headers="date",signature="eA=="', $value);
        $this->assertSame('a"b\c', $parsed->keyId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedKeyIdsProvider(): iterable
    {
        yield 'a non-ASCII character' => ["caf\u{e9}"];
        yield 'a line feed' => ["a\nb"];
        yield 'a tab' => ["a\tb"];
    }

    #[DataProvider('rejectedKeyIdsProvider')]
    public function testRejectsAKeyIdentifierAQuotedStringCannotHold(string $keyId): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage(
            'Under the draft form the key identifier must hold only printable ASCII characters',
        );

        FieldSerializer::serialize($keyId, Algorithm::HmacSha256, null, null, self::identifiers(['date']), 'x');
    }

    public function testRefusesAnAlgorithmWithNoNameInTheDraftForm(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage(
            'The algorithm EcdsaP256Sha256 has no name in the form draft-cavage-http-signatures-12',
        );

        FieldSerializer::serialize('a', Algorithm::EcdsaP256Sha256, null, null, self::identifiers(['date']), 'x');
    }
}
