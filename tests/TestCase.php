<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\TestCase as BaseTestCase;
use RuntimeException;

use function base64_decode;
use function file_get_contents;
use function trim;

/**
 * A base test case for common test functionality
 */
class TestCase extends BaseTestCase
{
    /**
     * Returns the contents of a key file transcribed from RFC 9421 appendix
     * B.1
     */
    protected static function rfc9421Key(string $file): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/rfc9421/' . $file);

        if ($contents === false) {
            throw new RuntimeException('Cannot read the fixture ' . $file);
        }

        return $contents;
    }

    /**
     * Returns the bytes of the shared secret of RFC 9421 appendix B.1.5
     */
    protected static function rfc9421SharedSecret(): string
    {
        $secret = base64_decode(trim(self::rfc9421Key('test-shared-secret.base64')), true);

        if ($secret === false) {
            throw new RuntimeException('The shared secret fixture is not valid Base64');
        }

        return $secret;
    }
}
