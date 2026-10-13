<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use PHPUnit\Framework\TestCase as BaseTestCase;
use RuntimeException;
use SensitiveParameterValue;
use SocialWeb\Http\MessageSignatures\KeyMaterial;
use Throwable;

use function array_filter;
use function base64_decode;
use function file_get_contents;
use function is_string;
use function str_contains;
use function str_starts_with;
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

    /**
     * Returns the arguments recorded in the frames of the exception's trace
     * that belong to the package, in order
     *
     * The frames of PHPUnit and of the tests are left out, so that the result
     * does not depend on them. The arguments are recorded only when the
     * `zend.exception_ignore_args` setting is off.
     *
     * @return list<mixed>
     */
    protected static function packageFrameArguments(Throwable $exception): array
    {
        $arguments = [];

        foreach ($exception->getTrace() as $frame) {
            if (!str_starts_with($frame['class'] ?? '', 'SocialWeb\\Http\\MessageSignatures\\')) {
                continue;
            }

            foreach ($frame['args'] ?? [] as $argument) {
                $arguments[] = $argument;
            }
        }

        return $arguments;
    }

    /**
     * Asserts that the package's frames in the exception's trace recorded their
     * arguments, redacted the sensitive ones, and hold none of the secrets
     * and no key material object
     */
    protected function assertTraceHidesSecrets(Throwable $exception, string ...$secrets): void
    {
        $arguments = self::packageFrameArguments($exception);

        $redacted = array_filter(
            $arguments,
            static fn (mixed $argument): bool => $argument instanceof SensitiveParameterValue,
        );
        $this->assertNotEmpty($redacted, 'The trace recorded no redacted argument, so it proves nothing');

        $material = array_filter($arguments, static fn (mixed $argument): bool => $argument instanceof KeyMaterial);
        $this->assertEmpty($material, 'A KeyMaterial object is in the trace');

        foreach ($secrets as $secret) {
            $leaked = array_filter(
                $arguments,
                static fn (mixed $argument): bool => is_string($argument) && str_contains($argument, $secret),
            );
            $this->assertEmpty($leaked, 'A secret is in the trace');
        }
    }
}
