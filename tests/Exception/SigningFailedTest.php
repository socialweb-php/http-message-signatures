<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Exception;

use RuntimeException;
use SocialWeb\Http\MessageSignatures\Exception\MessageSignaturesException;
use SocialWeb\Http\MessageSignatures\Exception\SigningFailed;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

class SigningFailedTest extends TestCase
{
    public function testCanBeCaughtAsAMessageSignaturesException(): void
    {
        $this->expectException(MessageSignaturesException::class);

        throw new SigningFailed('OpenSSL could not sign');
    }

    public function testCanBeCaughtAsARuntimeException(): void
    {
        $this->expectException(RuntimeException::class);

        throw new SigningFailed('OpenSSL could not sign');
    }

    public function testHasTheMessageAndThePrevious(): void
    {
        $previous = new RuntimeException('cause');
        $exception = new SigningFailed('OpenSSL could not sign', 0, $previous);

        $this->assertSame('OpenSSL could not sign', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
