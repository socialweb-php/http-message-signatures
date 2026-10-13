<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use Closure;
use DateInterval;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Algorithm;
use SocialWeb\Http\MessageSignatures\DigestAlgorithm;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Form;
use SocialWeb\Http\MessageSignatures\SigningOptions;

class SigningOptionsTest extends TestCase
{
    public function testHasTheDocumentedDefaults(): void
    {
        $options = new SigningOptions(form: Form::Rfc9421);

        $this->assertSame(Form::Rfc9421, $options->form);
        $this->assertNull($options->coveredComponents);
        $this->assertNull($options->algorithm);
        $this->assertSame('sig1', $options->label);
        $this->assertTrue($options->created);
        $this->assertNull($options->expires);
        $this->assertNull($options->nonce);
        $this->assertNull($options->tag);
        $this->assertSame([DigestAlgorithm::Sha256], $options->digestAlgorithms);
    }

    public function testAcceptsEveryOptionUnderRfc9421(): void
    {
        $expires = new DateInterval('PT5M');
        $options = new SigningOptions(
            form: Form::Rfc9421,
            coveredComponents: ['@method', '@target-uri', 'content-digest'],
            algorithm: Algorithm::EcdsaP256Sha256,
            label: 'proxy_sig.2',
            created: false,
            expires: $expires,
            nonce: 'b3k2pp5k7z-50gnwp.yemd',
            tag: 'header-example',
            digestAlgorithms: [DigestAlgorithm::Sha512, DigestAlgorithm::Sha256],
        );

        $this->assertSame(['@method', '@target-uri', 'content-digest'], $options->coveredComponents);
        $this->assertSame(Algorithm::EcdsaP256Sha256, $options->algorithm);
        $this->assertSame('proxy_sig.2', $options->label);
        $this->assertFalse($options->created);
        $this->assertSame($expires, $options->expires);
        $this->assertSame('b3k2pp5k7z-50gnwp.yemd', $options->nonce);
        $this->assertSame('header-example', $options->tag);
        $this->assertSame([DigestAlgorithm::Sha512, DigestAlgorithm::Sha256], $options->digestAlgorithms);
    }

    public function testAcceptsAnEmptyCoveredListAndADraftAlgorithm(): void
    {
        $options = new SigningOptions(form: Form::Cavage, coveredComponents: [], algorithm: Algorithm::Ed25519);

        $this->assertSame([], $options->coveredComponents);
        $this->assertSame(Algorithm::Ed25519, $options->algorithm);
    }

    /**
     * @return iterable<string, array{Closure(): SigningOptions, string}>
     */
    public static function rejectedOptionsProvider(): iterable
    {
        yield 'an empty component identifier' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, coveredComponents: ['@method', '']),
            'A covered component identifier must not be empty',
        ];
        yield 'an algorithm with no draft name' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Cavage, algorithm: Algorithm::RsaPssSha512),
            'Algorithm RsaPssSha512 has no name in the form draft-cavage-http-signatures-12',
        ];
        yield 'a label with an uppercase letter' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, label: 'Sig1'),
            'The label "Sig1" is not a valid Dictionary key',
        ];
        yield 'a label that starts with a digit' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, label: '1sig'),
            'The label "1sig" is not a valid Dictionary key',
        ];
        yield 'an empty label' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, label: ''),
            'The label "" is not a valid Dictionary key',
        ];
        yield 'a label with a trailing newline' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, label: "sig1\n"),
            "The label \"sig1\n\" is not a valid Dictionary key",
        ];
        yield 'a nonce with a trailing newline' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, nonce: "abc\n"),
            'The nonce must hold only printable ASCII characters',
        ];
        yield 'a tag with a trailing newline' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, tag: "t\n"),
            'The tag must hold only printable ASCII characters',
        ];
        yield 'a negative expiry' => [
            static fn (): SigningOptions => new SigningOptions(
                form: Form::Rfc9421,
                expires: DateInterval::createFromDateString('-1 hour'),
            ),
            'expires must not be negative',
        ];
        yield 'a nonce with a non-ASCII character' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, nonce: "caf\u{e9}"),
            'The nonce must hold only printable ASCII characters',
        ];
        yield 'a nonce with a control character' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, nonce: "a\nb"),
            'The nonce must hold only printable ASCII characters',
        ];
        yield 'a tag with DEL' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, tag: "a\x7fb"),
            'The tag must hold only printable ASCII characters',
        ];
        yield 'a label under the draft' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Cavage, label: 'sig2'),
            'The draft form has no signature labels; leave label at its default',
        ];
        yield 'a nonce under the draft' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Cavage, nonce: 'n'),
            'The draft form has no nonce parameter',
        ];
        yield 'a tag under the draft' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Cavage, tag: 't'),
            'The draft form has no tag parameter',
        ];
        yield 'an empty digest list' => [
            static fn (): SigningOptions => new SigningOptions(form: Form::Rfc9421, digestAlgorithms: []),
            'The list of digest algorithms must not be empty',
        ];
        yield 'a duplicate digest algorithm' => [
            static fn (): SigningOptions => new SigningOptions(
                form: Form::Rfc9421,
                digestAlgorithms: [DigestAlgorithm::Sha256, DigestAlgorithm::Sha256],
            ),
            'Digest algorithm sha-256 appears more than once',
        ];
    }

    /**
     * @param Closure(): SigningOptions $build
     */
    #[DataProvider('rejectedOptionsProvider')]
    public function testRejectsAnOptionThatDoesNotFit(Closure $build, string $message): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage($message);

        $build();
    }

    public function testAnInvertedExpiryIsNegative(): void
    {
        $expires = new DateInterval('PT1H');
        $expires->invert = 1;

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage('expires must not be negative');

        new SigningOptions(form: Form::Rfc9421, expires: $expires);
    }

    public function testAZeroExpiryIsAccepted(): void
    {
        $options = new SigningOptions(form: Form::Rfc9421, expires: new DateInterval('PT0S'));

        $this->assertNotNull($options->expires);
    }
}
