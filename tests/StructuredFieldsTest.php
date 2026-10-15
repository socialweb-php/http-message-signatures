<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use Bakame\Http\StructuredFields\Dictionary;
use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\MissingFeature;
use Bakame\Http\StructuredFields\OuterList;
use Bakame\Http\StructuredFields\Parameters;
use Bakame\Http\StructuredFields\SyntaxError;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\StructuredFields;

use function error_clear_last;
use function error_get_last;
use function restore_error_handler;
use function set_error_handler;

class StructuredFieldsTest extends TestCase
{
    public function testParsesADictionaryInRfc8941Mode(): void
    {
        $dictionary = StructuredFields::parseDictionary('a=1,    b=2;x=1;y=2,   c=(a   b   c)');

        $this->assertSame('a=1, b=2;x=1;y=2, c=(a b c)', StructuredFields::serialize($dictionary));
    }

    public function testRefusesTheRfc9651TypesTheCitedEditionLacks(): void
    {
        $this->expectException(MissingFeature::class);

        StructuredFields::parseDictionary('a=@1618884473');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedProvider(): iterable
    {
        yield 'an empty member value' => ['a='];
        yield 'an empty parameter value' => ['a=1;b='];
        yield 'an uppercase key' => ['A=1'];
        yield 'a trailing comma' => ['a=1,'];
        yield 'an unterminated string' => ['a="x'];
    }

    #[DataProvider('malformedProvider')]
    public function testThrowsSyntaxErrorWithoutAPhpWarning(string $value): void
    {
        $warnings = [];
        set_error_handler(static function (int $number, string $message) use (&$warnings): bool {
            $warnings[] = $message;

            return true;
        });
        error_clear_last();

        try {
            StructuredFields::parseDictionary($value);
            $this->fail('Expected a SyntaxError');
        } catch (SyntaxError) {
            // Neither the handler installed around the call nor PHP's own
            // handler saw a warning.
            $this->assertSame([], $warnings);
            $this->assertNull(error_get_last());
        } finally {
            restore_error_handler();
        }
    }

    public function testParsesParametersInRfc8941Mode(): void
    {
        $parameters = StructuredFields::parseParameters(';req;name="Pet"');

        $this->assertSame(['req', 'name'], $parameters->keys());
        $this->assertSame(';req;name="Pet"', StructuredFields::serialize($parameters));
    }

    public function testRefusesParametersOfTheRfc9651TypesTheCitedEditionLacks(): void
    {
        $this->expectException(MissingFeature::class);

        StructuredFields::parseParameters(';a=@1618884473');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedParametersProvider(): iterable
    {
        yield 'an empty parameter value' => [';b='];
        yield 'an uppercase key' => [';B=1'];
        yield 'no leading semicolon' => ['b=1'];
        yield 'an unterminated string' => [';a="x'];
    }

    #[DataProvider('malformedParametersProvider')]
    public function testParametersThrowSyntaxErrorWithoutAPhpWarning(string $value): void
    {
        $warnings = [];
        set_error_handler(static function (int $number, string $message) use (&$warnings): bool {
            $warnings[] = $message;

            return true;
        });
        error_clear_last();

        try {
            StructuredFields::parseParameters($value);
            $this->fail('Expected a SyntaxError');
        } catch (SyntaxError) {
            $this->assertSame([], $warnings);
            $this->assertNull(error_get_last());
        } finally {
            restore_error_handler();
        }
    }

    public function testSerializesEveryContainer(): void
    {
        $this->assertSame('(1 2);p', StructuredFields::serialize(InnerList::fromAssociative([1, 2], ['p' => true])));
        $this->assertSame(';p;q=1', StructuredFields::serialize(Parameters::fromAssociative(['p' => true, 'q' => 1])));
        $this->assertSame(
            ':AQ==:, "s"',
            StructuredFields::serialize(OuterList::new(Item::fromDecodedBytes("\x01"), 's')),
        );
        $this->assertSame('?1', StructuredFields::serialize(Item::true()));
        $this->assertSame('k', StructuredFields::serialize(Dictionary::fromAssociative(['k' => true])));
    }
}
