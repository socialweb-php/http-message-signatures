<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Exception;

use RuntimeException;
use SocialWeb\Http\MessageSignatures\Exception\ComponentFailure;
use SocialWeb\Http\MessageSignatures\Exception\MessageSignaturesException;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function get_parent_class;

/**
 * Checks the exception raised for a component value that cannot be taken from
 * the message
 */
final class ComponentFailureTest extends TestCase
{
    public function testCanBeCaughtAsAMessageSignaturesException(): void
    {
        $this->expectException(MessageSignaturesException::class);

        throw new ComponentFailure(FailureReason::MissingComponent, 'the field "date" is not in the message');
    }

    public function testExtendsRuntimeExceptionAndNotFailure(): void
    {
        $failure = new ComponentFailure(FailureReason::MissingComponent, 'the field "date" is not in the message');

        $this->assertSame(RuntimeException::class, get_parent_class($failure));
    }

    public function testHasTheReasonAndTheDetail(): void
    {
        $previous = new RuntimeException('cause');
        $failure = new ComponentFailure(
            FailureReason::UnsupportedSignature,
            '@status is a response component',
            $previous,
        );

        $this->assertSame(FailureReason::UnsupportedSignature, $failure->reason);
        $this->assertSame('@status is a response component', $failure->detail);
        $this->assertSame('UnsupportedSignature: @status is a response component', $failure->getMessage());
        $this->assertSame(0, $failure->getCode());
        $this->assertSame($previous, $failure->getPrevious());
    }
}
