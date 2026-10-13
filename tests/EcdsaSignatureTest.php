<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\EcdsaSignature;

use function hex2bin;
use function str_repeat;
use function strlen;

class EcdsaSignatureTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, int<1, max>}>
     */
    public static function conversionsProvider(): iterable
    {
        // Two one-byte integers on a four-byte curve.
        yield 'short integers are left-padded' => [
            '3006' . '020101' . '020102',
            '00000001' . '00000002',
            4,
        ];

        // An integer whose first bit is set has a leading zero in DER.
        yield 'a leading zero is added when the first bit is set' => [
            '3009' . '020200ff' . '0203010203',
            '000000ff' . '00010203',
            4,
        ];

        yield 'a zero integer is one zero byte' => [
            '3006' . '020100' . '020100',
            '00000000' . '00000000',
            4,
        ];

        yield 'full-size integers' => [
            '300d' . '02047fffffff' . '02050080000000',
            '7fffffff' . '80000000',
            4,
        ];

        yield 'the RFC 9421 B.2.4 signature on P-256' => [
            '3046'
                . '022100c0d9925008706f92f1b4eb4ea4d6ba5b9c63d3aee6e6116b8f45d0e1fbe96822'
                . '022100f1d0d2a87203eab8b8326a19f30e70c0532e5e09d95850490b223fb7da889ab3',
            'c0d9925008706f92f1b4eb4ea4d6ba5b9c63d3aee6e6116b8f45d0e1fbe96822'
                . 'f1d0d2a87203eab8b8326a19f30e70c0532e5e09d95850490b223fb7da889ab3',
            32,
        ];
    }

    /**
     * @param int<1, max> $integerLength
     */
    #[DataProvider('conversionsProvider')]
    public function testConvertsBetweenDerAndRaw(string $derHex, string $rawHex, int $integerLength): void
    {
        $der = (string) hex2bin($derHex);
        $raw = (string) hex2bin($rawHex);

        $this->assertSame($raw, EcdsaSignature::derToRaw($der, $integerLength));
        $this->assertSame($der, EcdsaSignature::rawToDer($raw, $integerLength));
    }

    /**
     * @return iterable<string, array{string, int<1, max>}>
     */
    public static function malformedDerProvider(): iterable
    {
        yield 'empty' => ['', 4];
        yield 'too short to hold two integers' => ['3004020101', 4];
        yield 'not a sequence' => ['3106020101020102', 4];
        yield 'sequence length does not match' => ['3007020101020102', 4];
        yield 'long-form sequence length' => ['308106020101020102', 4];
        yield 'first element is not an integer' => ['3006030101020102', 4];
        yield 'second element is not an integer' => ['3006020101030102', 4];
        yield 'integer of zero length' => ['30080200020401020304', 4];
        yield 'integer runs past the end' => ['3006020401020102', 4];
        yield 'trailing bytes after the integers' => ['300702010102010200', 4];
        yield 'negative integer' => ['3006020180020102', 4];
        yield 'integer with a needless leading zero' => ['300702020001020102', 4];
        yield 'second integer with a needless leading zero' => ['300702010102020001', 4];
        yield 'a length byte in the long form overruns the value' => ['3006028101020102', 4];
        yield 'integer longer than the curve' => ['300a02050102030405020101', 4];
        yield 'second integer longer than the curve' => ['300a02010102050102030405', 4];
    }

    /**
     * @param int<1, max> $integerLength
     */
    #[DataProvider('malformedDerProvider')]
    public function testRefusesMalformedDer(string $derHex, int $integerLength): void
    {
        $this->assertNull(EcdsaSignature::derToRaw((string) hex2bin($derHex), $integerLength));
    }

    public function testRefusesARawValueOfTheWrongLength(): void
    {
        $this->assertNull(EcdsaSignature::rawToDer(str_repeat("\x01", 63), 32));
        $this->assertNull(EcdsaSignature::rawToDer(str_repeat("\x01", 65), 32));
        $this->assertNull(EcdsaSignature::rawToDer('', 32));
    }

    public function testRoundTripsAFullSizeP384Signature(): void
    {
        $raw = str_repeat("\xff", 96);
        $der = EcdsaSignature::rawToDer($raw, 48);

        $this->assertNotNull($der);
        $this->assertSame(2 + 2 * (2 + 49), strlen($der));
        $this->assertSame($raw, EcdsaSignature::derToRaw($der, 48));
    }
}
