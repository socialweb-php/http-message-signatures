<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use RuntimeException;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\FailureReason;

class FailureTest extends TestCase
{
    public function testHoldsTheReasonAndTheDetail(): void
    {
        $previous = new RuntimeException('cause');
        $failure = new Failure(FailureReason::MalformedSignature, 'the label "sig1" is in one field only', $previous);

        $this->assertSame(FailureReason::MalformedSignature, $failure->reason);
        $this->assertSame('the label "sig1" is in one field only', $failure->detail);
        $this->assertSame('MalformedSignature: the label "sig1" is in one field only', $failure->getMessage());
        $this->assertSame($previous, $failure->getPrevious());
    }
}
