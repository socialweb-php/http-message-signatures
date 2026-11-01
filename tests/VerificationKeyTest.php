<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\KeyType;
use SocialWeb\Http\MessageSignatures\VerificationKey;
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\KeyOperation;
use SocialWeb\Jwk\KeyUse;
use SocialWeb\Jwk\OctKey;

use function base64_decode;
use function ini_set;
use function openssl_pkey_get_private;
use function openssl_pkey_new;
use function openssl_sign;
use function print_r;
use function serialize;
use function str_contains;

use const OPENSSL_KEYTYPE_EC;

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

    public function testHasNoOwnerUnlessOneIsGiven(): void
    {
        $this->assertNull(VerificationKey::fromPem(self::rfc9421Key('test-key-rsa.public.pem'))->owner);
        $this->assertNull(VerificationKey::fromSharedSecret('secret')->owner);
    }

    public function testNamesItsOwnerFromAPem(): void
    {
        $key = VerificationKey::fromPem(
            self::rfc9421Key('test-key-rsa.public.pem'),
            owner: 'https://example.com/users/alice',
        );

        $this->assertSame('https://example.com/users/alice', $key->owner);
        $this->assertSame([Algorithm::RsaV15Sha256, Algorithm::RsaPssSha512], $key->permittedAlgorithms);
    }

    public function testNamesItsOwnerFromASharedSecret(): void
    {
        $key = VerificationKey::fromSharedSecret('secret', [Algorithm::HmacSha256], 'alice');

        $this->assertSame('alice', $key->owner);
    }

    public function testRejectsAnEmptyOwnerForAPem(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('The key owner must not be empty');

        VerificationKey::fromPem(self::rfc9421Key('test-key-rsa.public.pem'), owner: '');
    }

    public function testRejectsAnEmptyOwnerForASecret(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('The key owner must not be empty');

        VerificationKey::fromSharedSecret('secret', owner: '');
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
        $key = VerificationKey::fromSharedSecret('the secret bytes', owner: 'alice');

        $this->assertSame(
            ['type' => KeyType::SharedSecret, 'permittedAlgorithms' => [Algorithm::HmacSha256], 'owner' => 'alice'],
            $key->__debugInfo(),
        );
        $this->assertFalse(str_contains(print_r($key, true), 'the secret bytes'));
        $this->assertTrue(str_contains(print_r($key, true), 'alice'));
    }

    public function testCannotBeSerialized(): void
    {
        $key = VerificationKey::fromSharedSecret('the secret bytes');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('A VerificationKey cannot be serialized');

        serialize($key);
    }

    public function testBuildsFromAnRsaJwkWithTheDefaultAlgorithms(): void
    {
        $key = VerificationKey::fromJwk(Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem')));

        $this->assertSame(KeyType::Rsa, $key->type);
        $this->assertSame([Algorithm::RsaV15Sha256, Algorithm::RsaPssSha512], $key->permittedAlgorithms);
        $this->assertNull($key->owner);
    }

    public function testBuildsFromAnEcJwk(): void
    {
        $key = VerificationKey::fromJwk(Jwk::fromPem(self::rfc9421Key('test-key-ecc-p256.public.pem')));

        $this->assertSame(KeyType::EcP256, $key->type);
        $this->assertSame([Algorithm::EcdsaP256Sha256], $key->permittedAlgorithms);
    }

    public function testBuildsFromAnEd25519Jwk(): void
    {
        $key = VerificationKey::fromJwk(Jwk::fromPem(self::rfc9421Key('test-key-ed25519.public.pem')));

        $this->assertSame(KeyType::Ed25519, $key->type);
        $this->assertSame([Algorithm::Ed25519], $key->permittedAlgorithms);
    }

    public function testBuildsFromAnOctJwkAsASharedSecret(): void
    {
        $key = VerificationKey::fromJwk(new OctKey(self::rfc9421SharedSecret()));
        $signature = (string) base64_decode('pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=', true);
        $base = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@authority\": example.com\n"
            . "\"content-type\": application/json\n"
            . '"@signature-params": ("date" "@authority" "content-type");created=1618884473'
            . ';keyid="test-shared-secret"';

        $this->assertSame(KeyType::SharedSecret, $key->type);
        $this->assertSame([Algorithm::HmacSha256], $key->permittedAlgorithms);
        $this->assertTrue($key->verify(Algorithm::HmacSha256, $base, $signature));
    }

    public function testVerifiesUnderAKeyBuiltFromAJwk(): void
    {
        $privateKey = openssl_pkey_get_private(self::rfc9421Key('test-key-ed25519.private.pem'));
        $this->assertNotFalse($privateKey);
        $this->assertTrue(openssl_sign('the signature base', $signature, $privateKey, 0));
        $this->assertIsString($signature);

        $key = VerificationKey::fromJwk(Jwk::fromPem(self::rfc9421Key('test-key-ed25519.public.pem')));

        $this->assertTrue($key->verify(Algorithm::Ed25519, 'the signature base', $signature));
        $this->assertFalse($key->verify(Algorithm::Ed25519, 'another base', $signature));
    }

    /**
     * @param non-empty-string $pemFile
     */
    #[DataProvider('jwkAlgorithms')]
    public function testPermitsOnlyTheAlgorithmTheJwkNames(string $pemFile, string $alg, Algorithm $expected): void
    {
        $jwk = $pemFile === 'test-shared-secret.base64'
            ? new OctKey(self::rfc9421SharedSecret(), algorithm: $alg)
            : Jwk::fromPem(self::rfc9421Key($pemFile))->withAlgorithm($alg);

        $key = VerificationKey::fromJwk($jwk);

        $this->assertSame([$expected], $key->permittedAlgorithms);
    }

    /**
     * @return iterable<string, array{string, string, Algorithm}>
     */
    public static function jwkAlgorithms(): iterable
    {
        yield 'RS256' => ['test-key-rsa.public.pem', 'RS256', Algorithm::RsaV15Sha256];
        yield 'PS512' => ['test-key-rsa.public.pem', 'PS512', Algorithm::RsaPssSha512];
        yield 'ES256' => ['test-key-ecc-p256.public.pem', 'ES256', Algorithm::EcdsaP256Sha256];
        yield 'EdDSA' => ['test-key-ed25519.public.pem', 'EdDSA', Algorithm::Ed25519];
        yield 'Ed25519' => ['test-key-ed25519.public.pem', 'Ed25519', Algorithm::Ed25519];
        yield 'HS256' => ['test-shared-secret.base64', 'HS256', Algorithm::HmacSha256];
    }

    public function testPermitsEcdsaP384FromAJwkThatNamesIt(): void
    {
        $generated = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
        $this->assertNotFalse($generated);

        $key = VerificationKey::fromJwk(Jwk::fromOpenSslKey($generated)->toPublic()->withAlgorithm('ES384'));

        $this->assertSame(KeyType::EcP384, $key->type);
        $this->assertSame([Algorithm::EcdsaP384Sha384], $key->permittedAlgorithms);
    }

    public function testRejectsAJwkAlgorithmThePackageDoesNotImplement(): void
    {
        $jwk = Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem'))->withAlgorithm('RS384');

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains(
            'The JWK algorithm "RS384" is not implemented; the package implements RS256, PS512, ES256, ES384, EdDSA, '
            . 'Ed25519, HS256',
        );

        VerificationKey::fromJwk($jwk);
    }

    public function testAcceptsAListThatNamesOnlyTheJwkAlgorithm(): void
    {
        $jwk = Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem'))->withAlgorithm('PS512');

        $key = VerificationKey::fromJwk($jwk, [Algorithm::RsaPssSha512]);

        $this->assertSame([Algorithm::RsaPssSha512], $key->permittedAlgorithms);
    }

    public function testRejectsAListThatNamesAnAlgorithmTheJwkDoesNot(): void
    {
        $jwk = Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem'))->withAlgorithm('PS512');

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains(
            'Algorithm RsaV15Sha256 is not permitted by a JWK whose alg is "PS512"',
        );

        VerificationKey::fromJwk($jwk, [Algorithm::RsaPssSha512, Algorithm::RsaV15Sha256]);
    }

    public function testTakesTheListWhenTheJwkNamesNoAlgorithm(): void
    {
        $key = VerificationKey::fromJwk(
            Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem')),
            [Algorithm::RsaPssSha512],
        );

        $this->assertSame([Algorithm::RsaPssSha512], $key->permittedAlgorithms);
    }

    public function testRejectsAJwkWithPrivateMembers(): void
    {
        $jwk = Jwk::fromPem(self::rfc9421Key('test-key-rsa.private.pem'));

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('A verification key cannot be built from a JWK with private members');

        VerificationKey::fromJwk($jwk);
    }

    public function testRejectsAJwkMeantForEncryption(): void
    {
        $jwk = Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem'))->withUse(KeyUse::Encryption);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains(
            'A JWK with the use "enc" cannot verify signatures; it needs the use "sig"',
        );

        VerificationKey::fromJwk($jwk);
    }

    public function testAcceptsAJwkMeantForSignatures(): void
    {
        $jwk = Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem'))->withUse(KeyUse::Signature);

        $this->assertSame(KeyType::Rsa, VerificationKey::fromJwk($jwk)->type);
    }

    public function testRejectsAJwkWhoseOperationsLackVerify(): void
    {
        $jwk = Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem'))
            ->withKeyOperations([KeyOperation::Encrypt, KeyOperation::Decrypt]);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains(
            'A JWK whose key operations do not include "verify" cannot verify signatures',
        );

        VerificationKey::fromJwk($jwk);
    }

    public function testAcceptsAJwkWhoseOperationsIncludeVerify(): void
    {
        $jwk = Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem'))
            ->withKeyOperations([KeyOperation::Verify]);

        $this->assertSame(KeyType::Rsa, VerificationKey::fromJwk($jwk)->type);
    }

    public function testRejectsAJwkOnACurveThePackageDoesNotImplement(): void
    {
        $generated = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1']);
        $this->assertNotFalse($generated);
        $jwk = Jwk::fromOpenSslKey($generated)->toPublic();

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains(
            'EC keys on the curve secp521r1 are not implemented; use P-256 or P-384',
        );

        VerificationKey::fromJwk($jwk);
    }

    public function testNamesItsOwnerFromAJwk(): void
    {
        $key = VerificationKey::fromJwk(
            Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem')),
            owner: 'https://example.com/users/alice',
        );

        $this->assertSame('https://example.com/users/alice', $key->owner);
    }

    public function testRejectsAnEmptyOwnerForAJwk(): void
    {
        $jwk = Jwk::fromPem(self::rfc9421Key('test-key-rsa.public.pem'));

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('The key owner must not be empty');

        VerificationKey::fromJwk($jwk, owner: '');
    }

    public function testKeepsAnOctJwkOutOfTheTraceWhenTheListDoesNotFit(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');
        $this->assertNotFalse($previous);

        try {
            VerificationKey::fromJwk(new OctKey('the secret bytes'), [Algorithm::RsaV15Sha256]);
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertTraceHidesSecrets($exception, 'the secret bytes');
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }
}
