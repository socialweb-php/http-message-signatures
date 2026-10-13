<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\RsaPssKey;

use function base64_encode;
use function bin2hex;
use function chunk_split;
use function hex2bin;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function sprintf;
use function str_repeat;
use function str_starts_with;
use function strlen;
use function substr;

use const OPENSSL_KEYTYPE_RSA;

class RsaPssKeyTest extends TestCase
{
    public function testRewrapsThePssPrivateKeyOfAppendixB12AsPkcs1(): void
    {
        $pkcs1 = RsaPssKey::toPkcs1Pem(self::rfc9421Key('test-key-rsa-pss.private.pem'));

        $this->assertNotNull($pkcs1);
        $this->assertStringStartsWith("-----BEGIN RSA PRIVATE KEY-----\n", $pkcs1);
        $this->assertStringEndsWith("-----END RSA PRIVATE KEY-----\n", $pkcs1);

        $key = openssl_pkey_get_private($pkcs1);

        $this->assertNotFalse($key);

        /** @var array{type: int, bits: int} $details */
        $details = openssl_pkey_get_details($key);

        $this->assertSame(OPENSSL_KEYTYPE_RSA, $details['type']);
        $this->assertSame(2048, $details['bits']);
    }

    public function testRewrapsAPssPublicKeyAsPkcs1(): void
    {
        // The public half OpenSSL derives from the PSS private key keeps the
        // PSS algorithm identifier.
        $pssPrivate = openssl_pkey_get_private(self::rfc9421Key('test-key-rsa-pss.private.pem'));

        $this->assertNotFalse($pssPrivate);

        /** @var array{key: string} $details */
        $details = openssl_pkey_get_details($pssPrivate);
        $pkcs1 = RsaPssKey::toPkcs1Pem($details['key']);

        $this->assertNotNull($pkcs1);
        $this->assertStringStartsWith("-----BEGIN RSA PUBLIC KEY-----\n", $pkcs1);

        $key = openssl_pkey_get_public($pkcs1);

        $this->assertNotFalse($key);

        /** @var array{type: int, key: string} $rewrapped */
        $rewrapped = openssl_pkey_get_details($key);

        $this->assertSame(OPENSSL_KEYTYPE_RSA, $rewrapped['type']);

        // The RSA material is the same as the SubjectPublicKeyInfo of B.1.2.
        $public = openssl_pkey_get_public(self::rfc9421Key('test-key-rsa-pss.public.pem'));
        $this->assertNotFalse($public);

        /** @var array{key: string} $expected */
        $expected = openssl_pkey_get_details($public);
        $this->assertSame($expected['key'], $rewrapped['key']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherKeysProvider(): iterable
    {
        yield 'a PKCS#1 RSA private key' => [self::rfc9421Key('test-key-rsa.private.pem')];
        yield 'a PKCS#1 RSA public key' => [self::rfc9421Key('test-key-rsa.public.pem')];
        yield 'an rsaEncryption public key' => [self::rfc9421Key('test-key-rsa-pss.public.pem')];
        yield 'an Ed25519 private key' => [self::rfc9421Key('test-key-ed25519.private.pem')];
        yield 'an Ed25519 public key' => [self::rfc9421Key('test-key-ed25519.public.pem')];
        yield 'an EC private key' => [self::rfc9421Key('test-key-ecc-p256.private.pem')];
        yield 'not a PEM' => ['not a key'];
        yield 'empty' => [''];
        yield 'a PEM that is not Base64' => ["-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n"];
    }

    #[DataProvider('otherKeysProvider')]
    public function testLeavesEveryOtherKeyAlone(string $pem): void
    {
        $this->assertNull(RsaPssKey::toPkcs1Pem($pem));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function malformedDerProvider(): iterable
    {
        $oid = '06092a864886f70d01010a';

        yield 'private: outer element is not a sequence' => ['PRIVATE KEY', '31' . '0e' . '020100' . '300b' . $oid];
        yield 'private: no version' => ['PRIVATE KEY', '30' . '0d' . '300b' . $oid];
        yield 'private: another algorithm' => [
            'PRIVATE KEY',
            '30' . '11' . '020100' . '300b' . '06092a864886f70d010101' . '0400',
        ];
        yield 'private: no octet string' => ['PRIVATE KEY', '30' . '10' . '020100' . '300b' . $oid];
        yield 'private: octet string cut short' => [
            'PRIVATE KEY',
            '30' . '12' . '020100' . '300b' . $oid . '0405' . '00',
        ];
        yield 'private: length in long form over four bytes' => [
            'PRIVATE KEY',
            '30' . '85' . '0000000015' . '020100' . '300b' . $oid . '0403' . 'aabbcc',
        ];
        yield 'private: length in long form past the end' => ['PRIVATE KEY', '30' . '82' . 'ffff'];
        yield 'private: one byte' => ['PRIVATE KEY', '30'];
        yield 'public: outer element is not a sequence' => ['PUBLIC KEY', '31' . '0d' . '300b' . $oid];
        yield 'public: another algorithm' => [
            'PUBLIC KEY',
            '30' . '11' . '300b' . '06092a864886f70d010101' . '030200ff',
        ];
        yield 'public: no bit string' => ['PUBLIC KEY', '30' . '0d' . '300b' . $oid];
        yield 'public: bit string with no content' => ['PUBLIC KEY', '30' . '0f' . '300b' . $oid . '0300'];
        yield 'public: bit string with no key after the unused-bits byte' => [
            'PUBLIC KEY',
            '30' . '10' . '300b' . $oid . '030100',
        ];
        yield 'public: bit string with unused bits' => ['PUBLIC KEY', '30' . '11' . '300b' . $oid . '030201ff'];
    }

    #[DataProvider('malformedDerProvider')]
    public function testRefusesMalformedDer(string $label, string $derHex): void
    {
        $pem = "-----BEGIN $label-----\n" . chunk_split(base64_encode((string) hex2bin($derHex)), 64, "\n")
            . "-----END $label-----\n";

        $this->assertNull(RsaPssKey::toPkcs1Pem($pem));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function wellFormedDerProvider(): iterable
    {
        $oid = '06092a864886f70d01010a';

        yield 'private: an empty octet string' => ['PRIVATE KEY', '30' . '12' . '020100' . '300b' . $oid . '0400', ''];
        yield 'private: attributes after the key are left out' => [
            'PRIVATE KEY',
            '30' . '17' . '020100' . '300b' . $oid . '0403' . 'aabbcc' . 'a000',
            'aabbcc',
        ];
        yield 'public: one byte of key after the unused-bits byte' => [
            'PUBLIC KEY',
            '30' . '11' . '300b' . $oid . '0302' . '00' . 'ff',
            'ff',
        ];
        yield 'public: bytes after the bit string are left out' => [
            'PUBLIC KEY',
            '30' . '14' . '300b' . $oid . '0303' . '00' . 'ffee' . 'a000',
            'ffee',
        ];
        yield 'private: the algorithm identifier has parameters' => [
            'PRIVATE KEY',
            '30' . '14' . '020100' . '300d' . $oid . '3000' . '0400',
            '',
        ];
        yield 'public: the algorithm identifier has parameters' => [
            'PUBLIC KEY',
            '30' . '13' . '300d' . $oid . '3000' . '0302' . '00' . 'ff',
            'ff',
        ];
        yield 'a length in four bytes' => [
            'PRIVATE KEY',
            '30' . '84' . '00000015' . '020100' . '300b' . $oid . '0403' . 'aabbcc',
            'aabbcc',
        ];
    }

    #[DataProvider('wellFormedDerProvider')]
    public function testReadsTheMaterialOutOfTheWrapper(string $label, string $derHex, string $materialHex): void
    {
        $pem = "-----BEGIN $label-----\n" . chunk_split(base64_encode((string) hex2bin($derHex)), 64, "\n")
            . "-----END $label-----\n";
        $rsaLabel = $label === 'PRIVATE KEY' ? 'RSA PRIVATE KEY' : 'RSA PUBLIC KEY';

        $this->assertSame(
            "-----BEGIN $rsaLabel-----\n" . chunk_split(base64_encode((string) hex2bin($materialHex)), 64, "\n")
                . "-----END $rsaLabel-----\n",
            RsaPssKey::toPkcs1Pem($pem),
        );
    }

    public function testAnIndefiniteLengthIsRefused(): void
    {
        // 0x80 is the indefinite length of BER, which DER forbids. Read as a
        // short length of 128 it would describe this wrapper exactly.
        $octets = '04' . '6e' . bin2hex(str_repeat('a', 110));
        $der = (string) hex2bin('30' . '80' . '020100' . '300b' . '06092a864886f70d01010a' . $octets);
        $pem = "-----BEGIN PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PRIVATE KEY-----\n";

        $this->assertSame(130, strlen($der));
        $this->assertNull(RsaPssKey::toPkcs1Pem($pem));
    }

    public function testReadsAOneByteLongFormLength(): void
    {
        $material = str_repeat('b', 200);
        $inner = '020100' . '300b' . '06092a864886f70d01010a' . '0481c8' . bin2hex($material);
        $der = (string) hex2bin('3081' . sprintf('%02x', strlen((string) hex2bin($inner))) . $inner);
        $pem = "-----BEGIN PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PRIVATE KEY-----\n";

        $this->assertSame(
            "-----BEGIN RSA PRIVATE KEY-----\n" . chunk_split(base64_encode($material), 64, "\n")
                . "-----END RSA PRIVATE KEY-----\n",
            RsaPssKey::toPkcs1Pem($pem),
        );
    }

    public function testReadsALongFormLength(): void
    {
        // A PSS private key whose octet string is 300 bytes long, which takes
        // a two-byte length.
        $material = str_repeat('a', 300);
        $inner = '020100' . '300b' . '06092a864886f70d01010a' . '0482012c' . bin2hex($material);
        $der = (string) hex2bin('3082' . sprintf('%04x', strlen((string) hex2bin($inner))) . $inner);
        $pem = "-----BEGIN PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PRIVATE KEY-----\n";

        $pkcs1 = RsaPssKey::toPkcs1Pem($pem);

        $this->assertNotNull($pkcs1);
        $this->assertTrue(str_starts_with(
            $pkcs1,
            "-----BEGIN RSA PRIVATE KEY-----\n" . base64_encode(substr($material, 0, 48)) . "\n",
        ));
    }
}
