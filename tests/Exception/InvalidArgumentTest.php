<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Exception;

use InvalidArgumentException;
use RuntimeException;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Exception\MessageSignaturesException;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

class InvalidArgumentTest extends TestCase
{
    public function testCanBeCaughtAsAMessageSignaturesException(): void
    {
        $this->expectException(MessageSignaturesException::class);

        throw new InvalidArgument('bad input');
    }

    public function testCanBeCaughtAsAnInvalidArgumentException(): void
    {
        $this->expectException(InvalidArgumentException::class);

        throw new InvalidArgument('bad input');
    }

    public function testHasTheMessageAndThePrevious(): void
    {
        $previous = new RuntimeException('cause');
        $exception = new InvalidArgument('bad input', 0, $previous);

        $this->assertSame('bad input', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
