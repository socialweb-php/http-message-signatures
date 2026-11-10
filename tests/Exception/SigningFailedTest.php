<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Exception;

use RuntimeException;
use SocialWeb\Http\MessageSignatures\Exception\MessageSignaturesException;
use SocialWeb\Http\MessageSignatures\Exception\SigningFailed;
use SocialWeb\Http\MessageSignatures\Exception\SigningFailedReason;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

/**
 * Checks the exception raised when signing fails
 */
final class SigningFailedTest extends TestCase
{
    public function testCanBeCaughtAsAMessageSignaturesException(): void
    {
        $this->expectException(MessageSignaturesException::class);

        throw new SigningFailed(SigningFailedReason::OpenSslError, 'OpenSSL could not sign');
    }

    public function testCanBeCaughtAsARuntimeException(): void
    {
        $this->expectException(RuntimeException::class);

        throw new SigningFailed(SigningFailedReason::OpenSslError, 'OpenSSL could not sign');
    }

    public function testHasTheReasonTheMessageAndThePrevious(): void
    {
        $previous = new RuntimeException('cause');
        $exception = new SigningFailed(
            SigningFailedReason::SignatureDoesNotFitCurve,
            'OpenSSL produced an ECDSA signature that does not fit the curve',
            $previous,
        );

        $this->assertSame(SigningFailedReason::SignatureDoesNotFitCurve, $exception->reason);
        $this->assertSame('OpenSSL produced an ECDSA signature that does not fit the curve', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
        $this->assertSame(0, $exception->getCode());
    }

    public function testThePreviousIsOptional(): void
    {
        $exception = new SigningFailed(SigningFailedReason::OpenSslError, 'OpenSSL could not sign');

        $this->assertNull($exception->getPrevious());
    }
}
