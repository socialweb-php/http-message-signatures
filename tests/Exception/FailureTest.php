<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Exception;

use RuntimeException;
use SocialWeb\Http\MessageSignatures\Exception\Failure;
use SocialWeb\Http\MessageSignatures\Exception\MessageSignaturesException;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function get_parent_class;

/**
 * Checks the exception raised inside the package when a message cannot be
 * verified
 */
final class FailureTest extends TestCase
{
    public function testCanBeCaughtAsAMessageSignaturesException(): void
    {
        $this->expectException(MessageSignaturesException::class);

        throw new Failure(FailureReason::MalformedSignature, 'the label "sig1" is in one field only');
    }

    public function testIsNotAComponentFailure(): void
    {
        $failure = new Failure(FailureReason::MissingComponent, 'the message has no Date field');

        $this->assertSame(RuntimeException::class, get_parent_class($failure));
    }

    public function testHoldsTheReasonAndTheDetail(): void
    {
        $previous = new RuntimeException('cause');
        $failure = new Failure(FailureReason::MalformedSignature, 'the label "sig1" is in one field only', $previous);

        $this->assertSame(FailureReason::MalformedSignature, $failure->reason);
        $this->assertSame('the label "sig1" is in one field only', $failure->detail);
        $this->assertSame('MalformedSignature: the label "sig1" is in one field only', $failure->getMessage());
        $this->assertSame(0, $failure->getCode());
        $this->assertSame($previous, $failure->getPrevious());
    }
}
