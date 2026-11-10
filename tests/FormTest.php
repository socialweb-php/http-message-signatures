<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use SocialWeb\Http\MessageSignatures\Form;

/**
 * Checks the two signature forms
 */
final class FormTest extends TestCase
{
    public function testNamesTheDraftByItsIdentifier(): void
    {
        $this->assertSame('draft-cavage-http-signatures-12', Form::Cavage->value);
        $this->assertSame('rfc9421', Form::Rfc9421->value);
    }

    public function testHasTwoForms(): void
    {
        $this->assertCount(2, Form::cases());
    }
}
