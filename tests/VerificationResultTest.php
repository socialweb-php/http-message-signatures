<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use Closure;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\VerificationResult;

class VerificationResultTest extends TestCase
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
            label: 'sig-b26',
            coveredComponents: ['date', '@method'],
            created: $created,
            expires: $expires,
            nonce: 'n',
            signature: 'bytes',
            keyRefreshed: true,
            requestTargetVerifiedWithoutQuery: false,
        );

        $this->assertTrue($result->verified);
        $this->assertNull($result->reason);
        $this->assertSame('', $result->detail);
        $this->assertSame(Form::Rfc9421, $result->form);
        $this->assertSame(Algorithm::Ed25519, $result->algorithm);
        $this->assertSame('test-key-ed25519', $result->keyId);
        $this->assertSame('sig-b26', $result->label);
        $this->assertSame(['date', '@method'], $result->coveredComponents);
        $this->assertSame($created, $result->created);
        $this->assertSame($expires, $result->expires);
        $this->assertSame('n', $result->nonce);
        $this->assertSame('bytes', $result->signature);
        $this->assertTrue($result->keyRefreshed);
        $this->assertFalse($result->requestTargetVerifiedWithoutQuery);
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
        $this->assertNull($result->label);
        $this->assertSame([], $result->coveredComponents);
        $this->assertNull($result->created);
        $this->assertNull($result->expires);
        $this->assertNull($result->nonce);
        $this->assertNull($result->signature);
        $this->assertFalse($result->keyRefreshed);
        $this->assertFalse($result->requestTargetVerifiedWithoutQuery);
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
    public static function inconsistentResultsProvider(): iterable
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
        yield 'verified without a form' => [
            static fn (): VerificationResult => new VerificationResult(verified: true),
            'The form is absent exactly when the reason is NoSignature',
        ];
        yield 'failed without a form' => [
            static fn (): VerificationResult => new VerificationResult(verified: false, reason: FailureReason::Expired),
            'The form is absent exactly when the reason is NoSignature',
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
    #[DataProvider('inconsistentResultsProvider')]
    public function testRejectsAnInconsistentResult(Closure $build, string $message): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage($message);

        $build();
    }
}
