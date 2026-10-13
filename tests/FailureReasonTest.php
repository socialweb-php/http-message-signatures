<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use SocialWeb\Http\MessageSignatures\FailureReason;

use function array_map;

class FailureReasonTest extends TestCase
{
    public function testHasOneCasePerDocumentedReason(): void
    {
        $this->assertSame(
            [
                'NoSignature',
                'MalformedSignature',
                'UnsupportedSignature',
                'MissingComponent',
                'PolicyViolation',
                'KeyNotFound',
                'AlgorithmNotPermitted',
                'SignatureInvalid',
                'NotYetValid',
                'Expired',
                'DigestMismatch',
            ],
            array_map(static fn (FailureReason $reason): string => $reason->name, FailureReason::cases()),
        );
    }
}
