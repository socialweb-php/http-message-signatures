<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use Closure;
use DateInterval;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\TimePolicy;
use SocialWeb\Http\MessageSignatures\VerifierOptions;

use function array_map;

class VerifierOptionsTest extends TestCase
{
    public function testHasTheDocumentedDefaults(): void
    {
        $options = new VerifierOptions();

        $this->assertSame([Form::Cavage, Form::Rfc9421], $options->forms);
        $this->assertSame(3600, (new DateTimeImmutable('@0'))->add($options->timePolicy->clockSkew)->getTimestamp());
        $this->assertTrue($options->requireTarget);
        $this->assertTrue($options->requireCreationTime);
        $this->assertTrue($options->requireContentDigest);
        $this->assertSame([], $options->requiredComponents);
        $this->assertFalse($options->requireNonce);
        $this->assertTrue($options->retryWithRefreshedKey);
        $this->assertTrue($options->acceptRequestTargetWithoutQuery);
        $this->assertSame(3, $options->maxSignatures);
        $this->assertTrue($options->accepts(Form::Cavage));
        $this->assertTrue($options->accepts(Form::Rfc9421));
    }

    public function testAcceptsEveryOption(): void
    {
        $policy = new TimePolicy(clockSkew: new DateInterval('PT1S'));
        $options = new VerifierOptions(
            forms: [Form::Rfc9421],
            timePolicy: $policy,
            requireTarget: false,
            requireCreationTime: false,
            requireContentDigest: false,
            requiredComponents: ['@authority', 'date'],
            requireNonce: true,
            retryWithRefreshedKey: false,
            acceptRequestTargetWithoutQuery: false,
            maxSignatures: 1,
        );

        $this->assertSame([Form::Rfc9421], $options->forms);
        $this->assertSame($policy, $options->timePolicy);
        $this->assertFalse($options->requireTarget);
        $this->assertFalse($options->requireCreationTime);
        $this->assertFalse($options->requireContentDigest);
        $this->assertSame(['@authority', 'date'], $options->requiredComponents);
        $this->assertTrue($options->requireNonce);
        $this->assertFalse($options->retryWithRefreshedKey);
        $this->assertFalse($options->acceptRequestTargetWithoutQuery);
        $this->assertSame(1, $options->maxSignatures);
        $this->assertFalse($options->accepts(Form::Cavage));
        $this->assertTrue($options->accepts(Form::Rfc9421));
    }

    /**
     * @return iterable<string, array{Closure(): VerifierOptions, string}>
     */
    public static function rejectedOptionsProvider(): iterable
    {
        yield 'no forms' => [
            /** @phpstan-ignore-next-line argument.type */
            static fn (): VerifierOptions => new VerifierOptions(forms: []),
            'The list of forms must not be empty',
        ];
        yield 'a duplicate form' => [
            static fn (): VerifierOptions => new VerifierOptions(forms: [Form::Rfc9421, Form::Rfc9421]),
            'The form rfc9421 appears more than once',
        ];
        yield 'an empty required component' => [
            static fn (): VerifierOptions => new VerifierOptions(requiredComponents: ['date', '']),
            'A component identifier must not be empty',
        ];
        yield 'a required component whose parameters do not parse' => [
            static fn (): VerifierOptions => new VerifierOptions(requiredComponents: ['content-digest;req=']),
            'The parameters of the component identifier "content-digest;req=" do not parse',
        ];
        yield 'a required name in parentheses the draft does not define' => [
            static fn (): VerifierOptions => new VerifierOptions(requiredComponents: ['(foo)']),
            '"(foo)" is not a component name of the draft form',
        ];
        yield 'zero signatures' => [
            static fn (): VerifierOptions => new VerifierOptions(maxSignatures: 0),
            'maxSignatures must be at least 1; 0 given',
        ];
        yield 'negative signatures' => [
            static fn (): VerifierOptions => new VerifierOptions(maxSignatures: -1),
            'maxSignatures must be at least 1; -1 given',
        ];
    }

    /**
     * @param Closure(): VerifierOptions $build
     */
    #[DataProvider('rejectedOptionsProvider')]
    public function testRejectsAnOptionItCannotAccept(Closure $build, string $message): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage($message);

        $build();
    }

    public function testEachRequiredComponentAppliesToTheFormsItCanBeWrittenIn(): void
    {
        $options = new VerifierOptions(
            requiredComponents: ['host', '(request-target)', '@method', 'content-digest;req', 'Digest'],
        );
        $names = static fn (Form $form): array => array_map(
            static fn (ComponentIdentifier $identifier): string => $identifier->toString(),
            $options->requiredComponentIdentifiers($form),
        );

        $this->assertSame(['host', '(request-target)', 'digest'], $names(Form::Cavage));
        $this->assertSame(['host', '@method', 'content-digest;req', 'digest'], $names(Form::Rfc9421));
    }
}
