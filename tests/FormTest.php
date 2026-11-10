<?php

declare(strict_types=1);

namespace SocialWeb\Test\Http\MessageSignatures;

use SocialWeb\Http\MessageSignatures\Form;

use function array_map;

/**
 * Checks the two signature forms
 */
final class FormTest extends TestCase
{
    public function testHasTwoFormsNamedByTheirCases(): void
    {
        $this->assertSame(
            ['Cavage', 'Rfc9421'],
            array_map(static fn (Form $form): string => $form->name, Form::cases()),
        );
    }
}
