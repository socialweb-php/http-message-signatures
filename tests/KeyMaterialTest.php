<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Exception\SigningFailed;
use SocialWeb\Http\MessageSignatures\KeyMaterial;
use SocialWeb\Http\MessageSignatures\KeyType;

use function explode;
use function ini_set;
use function openssl_error_string;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_pkey_new;
use function openssl_verify;
use function str_repeat;
use function strlen;
use function substr;
use function substr_count;

use const OPENSSL_KEYTYPE_DSA;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_ED448;
use const OPENSSL_KEYTYPE_X25519;
use const OPENSSL_PKCS1_PSS_PADDING;

class KeyMaterialTest extends TestCase
{
    /**
     * @return iterable<string, array{string, KeyType}>
     */
    public static function publicKeysProvider(): iterable
    {
        yield 'RSA in PKCS#1 form (B.1.1)' => ['test-key-rsa.public.pem', KeyType::Rsa];
        yield 'RSA in SubjectPublicKeyInfo form (B.1.2)' => ['test-key-rsa-pss.public.pem', KeyType::Rsa];
        yield 'P-256 (B.1.3)' => ['test-key-ecc-p256.public.pem', KeyType::EcP256];
        yield 'Ed25519 (B.1.4)' => ['test-key-ed25519.public.pem', KeyType::Ed25519];
    }

    #[DataProvider('publicKeysProvider')]
    public function testDetectsThePublicKeyType(string $file, KeyType $expected): void
    {
        $this->assertSame($expected, KeyMaterial::fromPublicPem(self::rfc9421Key($file))->type);
    }

    /**
     * @return iterable<string, array{string, KeyType}>
     */
    public static function privateKeysProvider(): iterable
    {
        yield 'RSA in PKCS#1 form (B.1.1)' => ['test-key-rsa.private.pem', KeyType::Rsa];
        yield 'RSA in PKCS#8 form with the PSS identifier (B.1.2)' => ['test-key-rsa-pss.private.pem', KeyType::Rsa];
        yield 'P-256 (B.1.3)' => ['test-key-ecc-p256.private.pem', KeyType::EcP256];
        yield 'Ed25519 (B.1.4)' => ['test-key-ed25519.private.pem', KeyType::Ed25519];
    }

    #[DataProvider('privateKeysProvider')]
    public function testDetectsThePrivateKeyType(string $file, KeyType $expected): void
    {
        $this->assertSame($expected, KeyMaterial::fromPrivatePem(self::rfc9421Key($file), null)->type);
    }

    public function testDetectsAP384Key(): void
    {
        [$private, $public] = self::generate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);

        $this->assertSame(KeyType::EcP384, KeyMaterial::fromPrivatePem($private, null)->type);
        $this->assertSame(KeyType::EcP384, KeyMaterial::fromPublicPem($public)->type);
    }

    public function testReadsAnEncryptedPrivateKey(): void
    {
        $key = openssl_pkey_get_private(self::rfc9421Key('test-key-rsa-pss.private.pem'));
        $this->assertNotFalse($key);
        $encrypted = '';
        openssl_pkey_export($key, $encrypted, 'secret');
        $this->assertIsString($encrypted);

        $material = KeyMaterial::fromPrivatePem($encrypted, 'secret');

        $this->assertSame(KeyType::Rsa, $material->type);

        $signature = $material->sign(Algorithm::RsaPssSha512, 'base');
        $public = KeyMaterial::fromPublicPem(self::rfc9421Key('test-key-rsa-pss.public.pem'));
        $this->assertTrue($public->verify(Algorithm::RsaPssSha512, 'base', $signature));
    }

    public function testRejectsTheWrongPassphrase(): void
    {
        $key = openssl_pkey_get_private(self::rfc9421Key('test-key-rsa.private.pem'));
        $this->assertNotFalse($key);
        $encrypted = '';
        openssl_pkey_export($key, $encrypted, 'secret');
        $this->assertIsString($encrypted);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('OpenSSL cannot read the private key: error:');

        KeyMaterial::fromPrivatePem($encrypted, 'wrong');
    }

    public function testRejectsAPublicPemOpenSslCannotRead(): void
    {
        self::fillTheOpenSslErrorQueue();

        try {
            KeyMaterial::fromPublicPem('not a key');
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            // Only the errors of this load are reported, not stale ones.
            $this->assertStringStartsWith('OpenSSL cannot read the public key: error:', $exception->getMessage());
            $this->assertSame(1, substr_count($exception->getMessage(), 'error:'));
        }
    }

    public function testRejectsAPrivatePemOpenSslCannotRead(): void
    {
        self::fillTheOpenSslErrorQueue();

        try {
            KeyMaterial::fromPrivatePem('not a key', null);
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertStringStartsWith('OpenSSL cannot read the private key: error:', $exception->getMessage());
            $this->assertSame(1, substr_count($exception->getMessage(), 'error:'));
        }
    }

    public function testSignsAndVerifiesOnP384(): void
    {
        [$private, $public] = self::generate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
        $signer = KeyMaterial::fromPrivatePem($private, null);
        $verifier = KeyMaterial::fromPublicPem($public);

        $signature = $signer->sign(Algorithm::EcdsaP384Sha384, 'base');

        $this->assertSame(96, strlen($signature));
        $this->assertTrue($verifier->verify(Algorithm::EcdsaP384Sha384, 'base', $signature));
        $this->assertFalse($verifier->verify(Algorithm::EcdsaP384Sha384, 'other', $signature));
        $this->assertFalse($verifier->verify(Algorithm::EcdsaP384Sha384, 'base', substr($signature, 0, 64)));
        $this->assertFalse($verifier->verify(Algorithm::EcdsaP256Sha256, 'base', substr($signature, 0, 64)));
    }

    public function testLeavesTheOpenSslErrorQueueEmptyAfterAFailedVerification(): void
    {
        $public = KeyMaterial::fromPublicPem(self::rfc9421Key('test-key-rsa-pss.public.pem'));

        $this->assertFalse($public->verify(Algorithm::RsaPssSha512, 'base', str_repeat('x', 256)));
        $this->assertFalse(openssl_error_string());
    }

    public function testRejectsAPrivatePemGivenAsAPublicKey(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('OpenSSL cannot read the public key');

        KeyMaterial::fromPublicPem(self::rfc9421Key('test-key-rsa.private.pem'));
    }

    public function testRejectsAPublicPemGivenAsAPrivateKey(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('OpenSSL cannot read the private key');

        KeyMaterial::fromPrivatePem(self::rfc9421Key('test-key-rsa.public.pem'), null);
    }

    public function testRejectsAnEcKeyOnAnotherCurve(): void
    {
        [$private] = self::generate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1']);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('EC keys on the curve secp521r1 are not implemented; use P-256 or P-384');

        KeyMaterial::fromPrivatePem($private, null);
    }

    public function testRejectsAnEd448Key(): void
    {
        [, $public] = self::generate(['private_key_type' => OPENSSL_KEYTYPE_ED448]);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('Keys of OpenSSL type 7 are not implemented; use RSA, P-256, P-384, or Ed25519');

        KeyMaterial::fromPublicPem($public);
    }

    public function testRejectsAnX25519Key(): void
    {
        [$private] = self::generate(['private_key_type' => OPENSSL_KEYTYPE_X25519]);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('Keys of OpenSSL type 4 are not implemented');

        KeyMaterial::fromPrivatePem($private, null);
    }

    public function testRejectsADsaKey(): void
    {
        [, $public] = self::generate(['private_key_type' => OPENSSL_KEYTYPE_DSA, 'private_key_bits' => 1024]);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('Keys of OpenSSL type 1 are not implemented');

        KeyMaterial::fromPublicPem($public);
    }

    public function testRejectsAnEmptySecret(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The shared secret must not be empty');

        KeyMaterial::fromSecret('');
    }

    public function testASecretIsASharedSecret(): void
    {
        $this->assertSame(KeyType::SharedSecret, KeyMaterial::fromSecret('s')->type);
    }

    public function testSuppliesTheDefaultAlgorithmsForNull(): void
    {
        $material = KeyMaterial::fromPublicPem(self::rfc9421Key('test-key-rsa.public.pem'));

        $this->assertSame([Algorithm::RsaV15Sha256, Algorithm::RsaPssSha512], $material->permittedAlgorithms(null));
        $this->assertSame([Algorithm::RsaPssSha512], $material->permittedAlgorithms([Algorithm::RsaPssSha512]));
        $this->assertSame(
            [Algorithm::RsaPssSha512, Algorithm::RsaV15Sha256],
            $material->permittedAlgorithms([Algorithm::RsaPssSha512, Algorithm::RsaV15Sha256]),
        );
    }

    public function testRejectsAnEmptyPermittedList(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('The list of permitted algorithms must not be empty');

        KeyMaterial::fromSecret('s')->permittedAlgorithms([]);
    }

    public function testRejectsAnAlgorithmThatDoesNotFitTheType(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('Algorithm HmacSha256 does not fit a key of type Rsa');

        KeyMaterial::fromPublicPem(self::rfc9421Key('test-key-rsa.public.pem'))
            ->permittedAlgorithms([Algorithm::RsaV15Sha256, Algorithm::HmacSha256]);
    }

    public function testRejectsADuplicateInThePermittedList(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('Algorithm RsaPssSha512 appears more than once in the permitted list');

        KeyMaterial::fromPublicPem(self::rfc9421Key('test-key-rsa.public.pem'))
            ->permittedAlgorithms([Algorithm::RsaPssSha512, Algorithm::RsaPssSha512]);
    }

    public function testASharedSecretCannotSignWithAnAsymmetricAlgorithm(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('Ed25519 needs a key, not a shared secret');

        KeyMaterial::fromSecret('s')->sign(Algorithm::Ed25519, 'base');
    }

    public function testASharedSecretCannotVerifyWithAnAsymmetricAlgorithm(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('RsaV15Sha256 needs a key, not a shared secret');

        KeyMaterial::fromSecret('s')->verify(Algorithm::RsaV15Sha256, 'base', 'sig');
    }

    public function testAKeyCannotSignWithHmac(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('HmacSha256 needs a shared secret, not a key');

        KeyMaterial::fromPrivatePem(self::rfc9421Key('test-key-rsa.private.pem'), null)
            ->sign(Algorithm::HmacSha256, 'b');
    }

    public function testAKeyCannotVerifyWithHmac(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('HmacSha256 needs a shared secret, not a key');

        KeyMaterial::fromPublicPem(self::rfc9421Key('test-key-rsa.public.pem'))
            ->verify(Algorithm::HmacSha256, 'b', 's');
    }

    public function testSigningFailsWhenOpenSslRefusesTheKey(): void
    {
        // An Ed25519 key cannot run RSA; OpenSSL refuses and the failure
        // has its error text, without stale errors from earlier calls.
        $material = KeyMaterial::fromPrivatePem(self::rfc9421Key('test-key-ed25519.private.pem'), null);
        self::fillTheOpenSslErrorQueue();

        try {
            $material->sign(Algorithm::RsaV15Sha256, 'base');
            $this->fail('Expected a SigningFailed');
        } catch (SigningFailed $exception) {
            $this->assertStringStartsWith('OpenSSL could not sign: error:', $exception->getMessage());
            $this->assertSame(1, substr_count($exception->getMessage(), 'error:'));
        }
    }

    public function testVerifyingWithTheWrongKindOfKeyIsFalseNotAnError(): void
    {
        $public = KeyMaterial::fromPublicPem(self::rfc9421Key('test-key-ed25519.public.pem'));

        $this->assertFalse($public->verify(Algorithm::RsaV15Sha256, 'base', str_repeat('x', 256)));
        $this->assertFalse($public->verify(Algorithm::EcdsaP256Sha256, 'base', str_repeat('x', 64)));
        $this->assertFalse($public->verify(Algorithm::Ed25519, 'base', 'short'));
    }

    public function testAnEcdsaSignatureOfTheWrongLengthIsFalse(): void
    {
        $public = KeyMaterial::fromPublicPem(self::rfc9421Key('test-key-ecc-p256.public.pem'));

        $this->assertFalse($public->verify(Algorithm::EcdsaP256Sha256, 'base', str_repeat('x', 63)));
    }

    public function testAnHmacIsComparedInConstantTime(): void
    {
        $material = KeyMaterial::fromSecret(self::rfc9421SharedSecret());
        $signature = $material->sign(Algorithm::HmacSha256, 'base');

        $this->assertSame(32, strlen($signature));
        $this->assertTrue($material->verify(Algorithm::HmacSha256, 'base', $signature));
        $this->assertFalse($material->verify(Algorithm::HmacSha256, 'base', ''));
        $this->assertFalse($material->verify(Algorithm::HmacSha256, 'other', $signature));
    }

    public function testKeepsAPrivatePemOutOfTheTraceOfAnUnsupportedKey(): void
    {
        [$private] = self::generate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1']);
        $line = self::bodyLineOf($private);
        $previous = ini_set('zend.exception_ignore_args', '0');
        $this->assertNotFalse($previous);

        try {
            KeyMaterial::fromPrivatePem($private, null);
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertTraceHidesSecrets($exception, $line);
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }

    public function testKeepsADecryptedPemAndItsPassphraseOutOfTheTraceOfAnUnsupportedKey(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1']);
        $this->assertNotFalse($key);
        $plain = '';
        openssl_pkey_export($key, $plain);
        $this->assertIsString($plain);
        $encrypted = '';
        openssl_pkey_export($key, $encrypted, 'a passphrase to keep');
        $this->assertIsString($encrypted);
        $line = self::bodyLineOf($plain);
        $previous = ini_set('zend.exception_ignore_args', '0');
        $this->assertNotFalse($previous);

        try {
            KeyMaterial::fromPrivatePem($encrypted, 'a passphrase to keep');
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertTraceHidesSecrets($exception, $line, 'a passphrase to keep');
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }

    /**
     * Leaves several distinct errors in OpenSSL's error queue, as a failed
     * verification of garbage does.
     */
    private static function fillTheOpenSslErrorQueue(): void
    {
        $public = openssl_pkey_get_public(self::rfc9421Key('test-key-rsa-pss.public.pem'));
        self::assertNotFalse($public);
        openssl_verify('base', str_repeat('x', 256), $public, 'sha512', OPENSSL_PKCS1_PSS_PADDING);
        self::assertNotFalse(openssl_error_string());
    }

    /**
     * Returns one line from the Base64 body of a PEM
     */
    private static function bodyLineOf(string $pem): string
    {
        $line = explode("\n", $pem)[1];
        self::assertGreaterThan(20, strlen($line));

        return $line;
    }

    /**
     * @param array<string, int | string> $options
     *
     * @return array{string, string}
     */
    private static function generate(array $options): array
    {
        $key = openssl_pkey_new($options);
        self::assertNotFalse($key);
        $private = '';
        openssl_pkey_export($key, $private);
        self::assertIsString($private);

        /** @var array{key: string} $details */
        $details = openssl_pkey_get_details($key);

        return [$private, $details['key']];
    }
}
