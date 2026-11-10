<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Exception;

use SocialWeb\Http\MessageSignatures\Exception\SigningFailedReason;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

use function array_map;

/**
 * Checks that the reasons signing fails are the documented ones
 */
final class SigningFailedReasonTest extends TestCase
{
    public function testHasOneCasePerDocumentedReason(): void
    {
        $this->assertSame(
            ['OpenSslError', 'SignatureDoesNotFitCurve'],
            array_map(static fn (SigningFailedReason $reason): string => $reason->name, SigningFailedReason::cases()),
        );
    }
}
