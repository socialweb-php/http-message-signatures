<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use LogicException;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\KeyType;
use SocialWeb\Http\MessageSignatures\VerificationKey;

use function base64_decode;
use function ini_set;
use function print_r;
use function serialize;
use function str_contains;

class VerificationKeyTest extends TestCase
{
    public function testBuildsFromAPemWithTheDefaultAlgorithms(): void
    {
        $key = VerificationKey::fromPem(self::rfc9421Key('test-key-ecc-p256.public.pem'));

        $this->assertSame(KeyType::EcP256, $key->type);
        $this->assertSame([Algorithm::EcdsaP256Sha256], $key->permittedAlgorithms);
        $this->assertTrue($key->permits(Algorithm::EcdsaP256Sha256));
        $this->assertFalse($key->permits(Algorithm::EcdsaP384Sha384));
    }

    public function testBuildsFromAPemWithAChosenList(): void
    {
        $key = VerificationKey::fromPem(self::rfc9421Key('test-key-rsa.public.pem'), [Algorithm::RsaPssSha512]);

        $this->assertSame(KeyType::Rsa, $key->type);
        $this->assertSame([Algorithm::RsaPssSha512], $key->permittedAlgorithms);
        $this->assertFalse($key->permits(Algorithm::RsaV15Sha256));
    }

    public function testBuildsFromASharedSecret(): void
    {
        $key = VerificationKey::fromSharedSecret('secret');

        $this->assertSame(KeyType::SharedSecret, $key->type);
        $this->assertSame([Algorithm::HmacSha256], $key->permittedAlgorithms);
    }

    public function testRejectsAPemOpenSslCannotRead(): void
    {
        $this->expectException(InvalidArgument::class);

        VerificationKey::fromPem('not a key');
    }

    public function testRejectsAnEmptySecret(): void
    {
        $this->expectException(InvalidArgument::class);

        VerificationKey::fromSharedSecret('');
    }

    public function testRejectsAListThatDoesNotFitTheType(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('Algorithm RsaV15Sha256 does not fit a key of type SharedSecret');

        VerificationKey::fromSharedSecret('secret', [Algorithm::RsaV15Sha256]);
    }

    public function testKeepsTheSecretOutOfTheTraceWhenTheListDoesNotFit(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');
        $this->assertNotFalse($previous);

        try {
            VerificationKey::fromSharedSecret('the secret bytes', [Algorithm::RsaV15Sha256]);
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertTraceHidesSecrets($exception, 'the secret bytes');
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }

    public function testVerifiesUnderAPermittedAlgorithm(): void
    {
        $key = VerificationKey::fromSharedSecret(self::rfc9421SharedSecret());
        $signature = (string) base64_decode('pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=', true);
        $base = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@authority\": example.com\n"
            . "\"content-type\": application/json\n"
            . '"@signature-params": ("date" "@authority" "content-type");created=1618884473'
            . ';keyid="test-shared-secret"';

        $this->assertTrue($key->verify(Algorithm::HmacSha256, $base, $signature));
        $this->assertFalse($key->verify(Algorithm::HmacSha256, $base . ' ', $signature));
    }

    public function testRefusesToVerifyUnderAnAlgorithmTheKeyDoesNotPermit(): void
    {
        $key = VerificationKey::fromPem(self::rfc9421Key('test-key-rsa.public.pem'), [Algorithm::RsaPssSha512]);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('Algorithm RsaV15Sha256 is not permitted for this key');

        $key->verify(Algorithm::RsaV15Sha256, 'base', 'signature');
    }

    public function testDoesNotExposeItsMaterialWhenDumped(): void
    {
        $key = VerificationKey::fromSharedSecret('the secret bytes');

        $this->assertSame(
            ['type' => KeyType::SharedSecret, 'permittedAlgorithms' => [Algorithm::HmacSha256]],
            $key->__debugInfo(),
        );
        $this->assertFalse(str_contains(print_r($key, true), 'the secret bytes'));
    }

    public function testCannotBeSerialized(): void
    {
        $key = VerificationKey::fromSharedSecret('the secret bytes');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('A VerificationKey cannot be serialized');

        serialize($key);
    }
}
