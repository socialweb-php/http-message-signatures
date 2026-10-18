<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures\Component;

use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\SyntaxError;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Failure;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Test\Http\MessageSignatures\TestCase;

class ComponentIdentifierTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, string, string}>
     */
    public static function identifiersProvider(): iterable
    {
        yield 'a derived component' => ['@method', '@method', '"@method"', '@method'];
        yield 'a field' => ['content-digest', 'content-digest', '"content-digest"', 'content-digest'];
        yield 'a field in another case' => ['Content-Type', 'content-type', '"content-type"', 'content-type'];
        yield 'a flag parameter' => ['@method;req', '@method', '"@method";req', '@method;req'];
        yield 'a String parameter' => [
            '@query-param;name="Pet"',
            '@query-param',
            '"@query-param";name="Pet"',
            '@query-param;name="Pet"',
        ];
        yield 'two parameters' => [
            'example-dict;req;key="a"',
            'example-dict',
            '"example-dict";req;key="a"',
            'example-dict;req;key="a"',
        ];
        yield 'a flag written out' => ['@status;req=?1', '@status', '"@status";req', '@status;req'];
    }

    #[DataProvider('identifiersProvider')]
    public function testParsesTheOptionsForm(string $given, string $name, string $serialized, string $string): void
    {
        $identifier = ComponentIdentifier::parse($given);

        $this->assertSame($name, $identifier->name);
        $this->assertSame($serialized, $identifier->serialize());
        $this->assertSame($string, $identifier->toString());
        $this->assertSame($serialized, $identifier->toItem()->toHttpValue());
    }

    #[DataProvider('identifiersProvider')]
    public function testBuildsFromAParsedItem(string $given, string $name, string $serialized, string $string): void
    {
        $item = InnerList::fromHttpValue('(' . $serialized . ')')->getByIndex(0);
        $identifier = ComponentIdentifier::fromItem($item);

        $this->assertSame($name, $identifier->name);
        $this->assertSame($serialized, $identifier->serialize());
        $this->assertSame($string, $identifier->toString());
        $this->assertTrue($identifier->equals(ComponentIdentifier::parse($given)));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function rejectedProvider(): iterable
    {
        yield 'empty' => ['', 'A component identifier must not be empty'];
        yield 'only parameters' => [';req', 'A component identifier must not be empty'];
        yield 'a quoted name' => ['"@method"', '""@method"" is not a component name'];
        yield 'a derived name with an uppercase letter' => ['@Method', '"@Method" is not a component name'];
        yield 'a derived name with nothing after the at sign' => ['@', '"@" is not a component name'];
        yield 'a name with a space' => ['content digest', '"content digest" is not a component name'];
        yield 'a name with a non-ASCII character' => ["d\u{e9}j\u{e0}", "\"d\u{e9}j\u{e0}\" is not a component name"];
        yield 'parameters that do not parse' => [
            '@method;req=',
            'The parameters of the component identifier "@method;req=" do not parse',
        ];
        yield 'a parameter key with an uppercase letter' => [
            '@query-param;Name="Pet"',
            'The parameters of the component identifier "@query-param;Name="Pet"" do not parse',
        ];
    }

    #[DataProvider('rejectedProvider')]
    public function testRejectsWhatIsNotAnIdentifier(string $given, string $message): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage($message);

        ComponentIdentifier::parse($given);
    }

    public function testParsingLeavesNoPhpWarningBehind(): void
    {
        try {
            ComponentIdentifier::parse('@method;req=');
            $this->fail('Expected an InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertInstanceOf(SyntaxError::class, $exception->getPrevious());
            $this->assertSame(0, $exception->getCode());
        }
    }

    /**
     * @return iterable<string, array{Item, string}>
     */
    public static function rejectedItemsProvider(): iterable
    {
        yield 'a Token' => [
            InnerList::fromHttpValue('(method)')->getByIndex(0),
            'a covered component identifier must be a String, not Token',
        ];
        yield 'an Integer' => [
            InnerList::fromHttpValue('(1)')->getByIndex(0),
            'a covered component identifier must be a String, not Integer',
        ];
        yield 'a field name with an uppercase letter' => [
            InnerList::fromHttpValue('("Content-Type")')->getByIndex(0),
            '"Content-Type" is not a component name',
        ];
        yield 'an empty String' => [InnerList::fromHttpValue('("")')->getByIndex(0), '"" is not a component name'];
        yield 'a derived name with a space' => [
            InnerList::fromHttpValue('("@query param")')->getByIndex(0),
            '"@query param" is not a component name',
        ];
    }

    #[DataProvider('rejectedItemsProvider')]
    public function testRejectsAnItemThatIsNotAnIdentifier(Item $item, string $detail): void
    {
        try {
            ComponentIdentifier::fromItem($item);
            $this->fail('Expected a Failure');
        } catch (Failure $failure) {
            $this->assertSame(FailureReason::MalformedSignature, $failure->reason);
            $this->assertSame($detail, $failure->detail);
        }
    }

    public function testKnowsADerivedComponentAndAPlainOne(): void
    {
        $method = ComponentIdentifier::parse('@method');
        $methodOfTheRequest = ComponentIdentifier::parse('@method;req');
        $date = ComponentIdentifier::parse('date');

        $this->assertTrue($method->isDerived());
        $this->assertFalse($date->isDerived());
        $this->assertTrue($method->isPlain('@method'));
        $this->assertFalse($method->isPlain('@path'));
        $this->assertFalse($methodOfTheRequest->isPlain('@method'));
        $this->assertTrue($methodOfTheRequest->hasParameter('req'));
        $this->assertFalse($method->hasParameter('req'));
    }

    public function testEqualityIsOnTheSerializedForm(): void
    {
        $this->assertTrue(ComponentIdentifier::parse('Date')->equals(ComponentIdentifier::parse('date')));
        $this->assertTrue(
            ComponentIdentifier::parse('@status;req=?1')->equals(ComponentIdentifier::parse('@status;req')),
        );
        $this->assertFalse(ComponentIdentifier::parse('@method')->equals(ComponentIdentifier::parse('@method;req')));
        $this->assertFalse(
            ComponentIdentifier::parse('@query-param;name="Pet"')
                ->equals(ComponentIdentifier::parse('@query-param;name="pet"')),
        );
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function cavageNamesProvider(): iterable
    {
        yield 'the request target' => ['(request-target)', '(request-target)', true];
        yield 'the creation time in another case' => ['(Created)', '(created)', true];
        yield 'the expiry' => ['(expires)', '(expires)', true];
        yield 'a field in another case' => ['Content-Type', 'content-type', false];
    }

    #[DataProvider('cavageNamesProvider')]
    public function testParsesADraftName(string $given, string $name, bool $isPseudoHeader): void
    {
        $identifier = ComponentIdentifier::parseCavage($given);

        $this->assertSame($name, $identifier->name);
        $this->assertSame($name, $identifier->toString());
        $this->assertSame($isPseudoHeader, $identifier->isPseudoHeader());
        $this->assertFalse($identifier->isDerived());
        $this->assertTrue($identifier->isPlain($name));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function rejectedCavageNamesProvider(): iterable
    {
        yield 'empty' => ['', 'A component identifier must not be empty'];
        yield 'a derived component' => ['@method', '"@method" is not a component name of the draft form'];
        yield 'a name in parentheses the draft does not define' => [
            '(foo)',
            '"(foo)" is not a component name of the draft form',
        ];
        yield 'a field with a parameter' => ['date;req', '"date;req" is not a component name of the draft form'];
        yield 'a name with a space' => ['content type', '"content type" is not a component name of the draft form'];
    }

    #[DataProvider('rejectedCavageNamesProvider')]
    public function testRejectsWhatIsNotADraftName(string $given, string $message): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage($message);

        ComponentIdentifier::parseCavage($given);
    }

    public function testBuildsFromANameOfTheHeadersParameter(): void
    {
        $this->assertTrue(ComponentIdentifier::fromCavageName('(expires)')->isPseudoHeader());
        $this->assertTrue(ComponentIdentifier::fromCavageName('digest')->isPlain('digest'));
        $this->assertTrue(
            ComponentIdentifier::fromCavageName('(request-target)')
                ->equals(ComponentIdentifier::parseCavage('(Request-Target)')),
        );
    }

    /**
     * @return iterable<string, array{string, FailureReason, string}>
     */
    public static function rejectedHeadersNamesProvider(): iterable
    {
        yield 'a name in parentheses the draft does not define' => [
            '(foo)',
            FailureReason::UnsupportedSignature,
            '(foo) is not a name the draft form defines',
        ];
        yield 'a quoted name' => ['"date"', FailureReason::MalformedSignature, '""date"" is not a field name'];
        yield 'a field name followed by parentheses' => [
            'date(foo)',
            FailureReason::MalformedSignature,
            '"date(foo)" is not a field name',
        ];
        yield 'a derived component' => ['@method', FailureReason::MalformedSignature, '"@method" is not a field name'];
    }

    #[DataProvider('rejectedHeadersNamesProvider')]
    public function testRejectsANameOfTheHeadersParameterItCannotUse(
        string $name,
        FailureReason $reason,
        string $detail,
    ): void {
        try {
            ComponentIdentifier::fromCavageName($name);
            $this->fail('Expected a Failure');
        } catch (Failure $failure) {
            $this->assertSame($reason, $failure->reason);
            $this->assertSame($detail, $failure->detail);
        }
    }
}
