<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use LogicException;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\KeyType;
use SocialWeb\Http\MessageSignatures\SigningKey;
use SocialWeb\Http\MessageSignatures\VerificationKey;

use function openssl_pkey_export;
use function openssl_pkey_get_private;
use function print_r;
use function serialize;
use function str_contains;
use function strlen;

class SigningKeyTest extends TestCase
{
    public function testBuildsFromAPemWithTheDefaultAlgorithms(): void
    {
        $key = SigningKey::fromPem('https://example.com/keys/1', self::rfc9421Key('test-key-rsa.private.pem'));

        $this->assertSame('https://example.com/keys/1', $key->keyId);
        $this->assertSame(KeyType::Rsa, $key->type);
        $this->assertSame([Algorithm::RsaV15Sha256, Algorithm::RsaPssSha512], $key->permittedAlgorithms);
        $this->assertTrue($key->permits(Algorithm::RsaPssSha512));
        $this->assertFalse($key->permits(Algorithm::Ed25519));
    }

    public function testBuildsFromAnEncryptedPemWithAChosenList(): void
    {
        $plain = openssl_pkey_get_private(self::rfc9421Key('test-key-ecc-p256.private.pem'));
        $this->assertNotFalse($plain);
        $encrypted = '';
        openssl_pkey_export($plain, $encrypted, 'pass');
        $this->assertIsString($encrypted);

        $key = SigningKey::fromPem('k', $encrypted, 'pass', [Algorithm::EcdsaP256Sha256]);

        $this->assertSame(KeyType::EcP256, $key->type);
        $this->assertSame([Algorithm::EcdsaP256Sha256], $key->permittedAlgorithms);
    }

    public function testBuildsFromASharedSecret(): void
    {
        $key = SigningKey::fromSharedSecret('k', 'secret');

        $this->assertSame('k', $key->keyId);
        $this->assertSame(KeyType::SharedSecret, $key->type);
        $this->assertSame([Algorithm::HmacSha256], $key->permittedAlgorithms);
    }

    public function testRejectsAnEmptyKeyIdForAPem(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The key identifier must not be empty');

        SigningKey::fromPem('', self::rfc9421Key('test-key-rsa.private.pem'));
    }

    public function testRejectsAnEmptyKeyIdForASecret(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The key identifier must not be empty');

        SigningKey::fromSharedSecret('', 'secret');
    }

    public function testRejectsAPemOpenSslCannotRead(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('OpenSSL cannot read the private key');

        SigningKey::fromPem('k', 'not a key');
    }

    public function testRejectsAnEmptySecret(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The shared secret must not be empty');

        SigningKey::fromSharedSecret('k', '');
    }

    public function testRejectsAListThatDoesNotFitTheType(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('Algorithm HmacSha256 does not fit a key of type Ed25519');

        SigningKey::fromPem('k', self::rfc9421Key('test-key-ed25519.private.pem'), null, [Algorithm::HmacSha256]);
    }

    public function testSignsUnderAPermittedAlgorithmAndTheSignatureVerifies(): void
    {
        $key = SigningKey::fromPem('k', self::rfc9421Key('test-key-ecc-p256.private.pem'));
        $public = VerificationKey::fromPem(self::rfc9421Key('test-key-ecc-p256.public.pem'));

        $signature = $key->sign(Algorithm::EcdsaP256Sha256, 'base');

        $this->assertSame(64, strlen($signature));
        $this->assertTrue($public->verify(Algorithm::EcdsaP256Sha256, 'base', $signature));
        $this->assertFalse($public->verify(Algorithm::EcdsaP256Sha256, 'other', $signature));
    }

    public function testRefusesToSignUnderAnAlgorithmTheKeyDoesNotPermit(): void
    {
        $key = SigningKey::fromPem('k', self::rfc9421Key('test-key-rsa.private.pem'), null, [Algorithm::RsaPssSha512]);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('Algorithm RsaV15Sha256 is not permitted for this key');

        $key->sign(Algorithm::RsaV15Sha256, 'base');
    }

    public function testDoesNotExposeItsMaterialWhenDumped(): void
    {
        $key = SigningKey::fromSharedSecret('k', 'the secret bytes');

        $this->assertSame(
            ['keyId' => 'k', 'type' => KeyType::SharedSecret, 'permittedAlgorithms' => [Algorithm::HmacSha256]],
            $key->__debugInfo(),
        );
        $this->assertFalse(str_contains(print_r($key, true), 'the secret bytes'));
    }

    public function testCannotBeSerialized(): void
    {
        $key = SigningKey::fromSharedSecret('k', 'the secret bytes');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('A SigningKey cannot be serialized');

        serialize($key);
    }
}
