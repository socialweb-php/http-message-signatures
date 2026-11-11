<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use Closure;
use DateTime;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\VerificationResult;

/**
 * Checks what a verification result holds and the combinations it refuses
 */
final class VerificationResultTest extends TestCase
{
    public function testASuccessHasWhatAReplayStoreNeeds(): void
    {
        $created = new DateTimeImmutable('@1618884473');
        $expires = new DateTimeImmutable('@1618884773');
        $result = new VerificationResult(
            verified: true,
            form: Form::Rfc9421,
            algorithm: Algorithm::Ed25519,
            keyId: 'test-key-ed25519',
            keyOwner: 'https://example.com/users/alice',
            label: 'sig-b26',
            coveredComponents: ['date', '@method'],
            created: $created,
            expires: $expires,
            nonce: 'n',
            signature: 'bytes',
            keyRefreshed: true,
            requestTargetVerifiedWithoutQuery: false,
            maxSignaturesExceeded: true,
        );

        $this->assertTrue($result->verified);
        $this->assertNull($result->reason);
        $this->assertSame('', $result->detail);
        $this->assertSame(Form::Rfc9421, $result->form);
        $this->assertSame(Algorithm::Ed25519, $result->algorithm);
        $this->assertSame('test-key-ed25519', $result->keyId);
        $this->assertSame('https://example.com/users/alice', $result->keyOwner);
        $this->assertSame('sig-b26', $result->label);
        $this->assertSame(['date', '@method'], $result->coveredComponents);
        $this->assertEquals($created, $result->created);
        $this->assertEquals($expires, $result->expires);
        $this->assertSame('n', $result->nonce);
        $this->assertSame('bytes', $result->signature);
        $this->assertTrue($result->keyRefreshed);
        $this->assertFalse($result->requestTargetVerifiedWithoutQuery);
        $this->assertTrue($result->maxSignaturesExceeded);
    }

    public function testKeepsItsOwnCopyOfADateItIsGiven(): void
    {
        $created = new DateTime('@1618884473');
        $expires = new DateTime('@1618884773');

        $result = new VerificationResult(verified: true, form: Form::Rfc9421, created: $created, expires: $expires);
        $created->modify('+1 day');
        $expires->modify('+1 day');

        $this->assertSame(1618884473, $result->created?->getTimestamp());
        $this->assertSame(1618884773, $result->expires?->getTimestamp());
    }

    public function testASuccessUnderAKeyWithNoOwnerHasNone(): void
    {
        $result = new VerificationResult(verified: true, form: Form::Cavage, keyId: 'test-key-rsa');

        $this->assertTrue($result->verified);
        $this->assertSame('test-key-rsa', $result->keyId);
        $this->assertNull($result->keyOwner);
    }

    public function testAFailureDefaultsEverythingElse(): void
    {
        $result = new VerificationResult(verified: false, reason: FailureReason::NoSignature);

        $this->assertFalse($result->verified);
        $this->assertSame(FailureReason::NoSignature, $result->reason);
        $this->assertSame('', $result->detail);
        $this->assertNull($result->form);
        $this->assertNull($result->algorithm);
        $this->assertNull($result->keyId);
        $this->assertNull($result->keyOwner);
        $this->assertNull($result->label);
        $this->assertSame([], $result->coveredComponents);
        $this->assertNull($result->created);
        $this->assertNull($result->expires);
        $this->assertNull($result->nonce);
        $this->assertNull($result->signature);
        $this->assertFalse($result->keyRefreshed);
        $this->assertFalse($result->requestTargetVerifiedWithoutQuery);
        $this->assertFalse($result->maxSignaturesExceeded);
    }

    public function testAFailureNamesWhatItConcerns(): void
    {
        $result = new VerificationResult(
            verified: false,
            reason: FailureReason::SignatureInvalid,
            detail: 'sig1',
            form: Form::Cavage,
            requestTargetVerifiedWithoutQuery: true,
        );

        $this->assertSame('sig1', $result->detail);
        $this->assertSame(Form::Cavage, $result->form);
        $this->assertTrue($result->requestTargetVerifiedWithoutQuery);
    }

    /**
     * @return iterable<string, array{Closure(): VerificationResult, string}>
     */
    public static function inconsistentResults(): iterable
    {
        yield 'verified with a reason' => [
            static fn (): VerificationResult => new VerificationResult(
                verified: true,
                reason: FailureReason::Expired,
                form: Form::Rfc9421,
            ),
            'A verified result cannot have a failure reason',
        ];
        yield 'verified with a detail' => [
            static fn (): VerificationResult => new VerificationResult(
                verified: true,
                detail: 'sig1',
                form: Form::Rfc9421,
            ),
            'A verified result cannot have a detail',
        ];
        yield 'failed without a reason' => [
            static fn (): VerificationResult => new VerificationResult(verified: false, form: Form::Rfc9421),
            'A failed result must have a failure reason',
        ];
        yield 'failed with a key owner' => [
            static fn (): VerificationResult => new VerificationResult(
                verified: false,
                reason: FailureReason::SignatureInvalid,
                form: Form::Rfc9421,
                keyId: 'test-key-ed25519',
                keyOwner: 'https://example.com/users/alice',
            ),
            'A failed result cannot have a key owner',
        ];
        yield 'verified with an empty key owner' => [
            static fn (): VerificationResult => new VerificationResult(
                verified: true,
                form: Form::Rfc9421,
                // @phpstan-ignore argument.type (the constructor must refuse the empty owner its type forbids)
                keyOwner: '',
            ),
            'The key owner must not be empty',
        ];
        yield 'verified without a form' => [
            static fn (): VerificationResult => new VerificationResult(verified: true),
            'The form is absent exactly when the reason is NoSignature',
        ];
        yield 'failed without a form' => [
            static fn (): VerificationResult => new VerificationResult(verified: false, reason: FailureReason::Expired),
            'The form is absent exactly when the reason is NoSignature',
        ];
        yield 'more labels than the limit under the Cavage form' => [
            static fn (): VerificationResult => new VerificationResult(
                verified: true,
                form: Form::Cavage,
                maxSignaturesExceeded: true,
            ),
            'maxSignatures can be exceeded under RFC 9421 only',
        ];
        yield 'more labels than the limit without a signature' => [
            static fn (): VerificationResult => new VerificationResult(
                verified: false,
                reason: FailureReason::NoSignature,
                maxSignaturesExceeded: true,
            ),
            'maxSignatures can be exceeded under RFC 9421 only',
        ];
        yield 'no signature with a form' => [
            static fn (): VerificationResult => new VerificationResult(
                verified: false,
                reason: FailureReason::NoSignature,
                form: Form::Cavage,
            ),
            'The form is absent exactly when the reason is NoSignature',
        ];
    }

    /**
     * @param Closure(): VerificationResult $build
     */
    #[DataProvider('inconsistentResults')]
    public function testRejectsAnInconsistentResult(Closure $build, string $message): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains($message);

        $build();
    }
}
