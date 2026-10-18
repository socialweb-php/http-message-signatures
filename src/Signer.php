<?php

/**
 * This file is part of socialweb/http-message-signatures
 *
 * socialweb/http-message-signatures is free software: you can redistribute it
 * and/or modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * socialweb/http-message-signatures is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with socialweb/http-message-signatures. If not, see
 * <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

declare(strict_types=1);

namespace SocialWeb\Http\MessageSignatures;

use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Component\Content;
use SocialWeb\Http\MessageSignatures\Component\DigestField;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Exception\SigningFailed;
use SocialWeb\Http\MessageSignatures\Rfc9421\FieldSerializer;
use SocialWeb\Http\MessageSignatures\Rfc9421\SignatureBase;

use function array_map;
use function sprintf;

/**
 * Signs a message
 *
 * Signing is a pure function of its arguments and the clock, so a caller signs
 * the same message in both forms by calling `sign()` twice. The return value is
 * the message it was given, of the same class, with the digest field added
 * when the covered components include it and the signature fields of the
 * chosen form added.
 */
final class Signer
{
    /**
     * The IMF-fixdate of RFC 9110 section 5.6.7, for a `Date` field the
     * signer adds
     */
    private const string DATE_FORMAT = 'D, d M Y H:i:s \G\M\T';

    public function __construct(private readonly ClockInterface $clock)
    {
    }

    /**
     * Returns the message with a signature added in the form the options
     * choose
     *
     * When the covered components include a digest field, it is computed
     * over the content and set, replacing any existing one. When `date` is
     * covered and the message has no `Date` field, one is added from the
     * clock; an existing one is never replaced. Under RFC 9421 a label the
     * message already has is `InvalidArgument`; under the draft the
     * `Signature` field is replaced, since the draft has one.
     *
     * @param T $message the request or response to sign
     * @param RequestInterface | null $relatedRequest the request a response
     *     answers, for a covered component with the `req` parameter
     *
     * @return T
     *
     * @throws InvalidArgument when the message body cannot be rewound, when
     *     the key permits no algorithm that has a name in the form, when the
     *     label is already present under RFC 9421, when the key identifier has
     *     a character outside printable ASCII under the draft form, or when a
     *     covered component cannot be taken from the message
     * @throws SigningFailed when OpenSSL fails
     *
     * @template T of MessageInterface
     */
    public function sign(
        MessageInterface $message,
        SigningKey $key,
        SigningOptions $options,
        ?RequestInterface $relatedRequest = null,
    ): MessageInterface {
        $content = new Content($message);
        [$algorithm, $algorithmName] = self::algorithm($key, $options);
        $covered = $options->coveredComponentIdentifiers()
            ?? self::defaultComponents($message, $content, $options->form);

        foreach ($covered as $identifier) {
            if (!self::isDigestOfTheMessage($identifier)) {
                continue;
            }

            $message = $message->withHeader(
                $identifier->name,
                DigestField::serialize($identifier->name, $content->digests($options->digestAlgorithms)),
            );
        }

        $now = $this->clock->now();

        if (!$message->hasHeader('Date') && self::coversPlain($covered, 'date')) {
            $date = $now->setTimezone(new DateTimeZone('UTC'))->format(self::DATE_FORMAT);
            $message = $message->withHeader('Date', $date);
        }

        if ($options->form === Form::Cavage) {
            return self::signCavage($message, $key, $options, $algorithm, $algorithmName, $covered, $now);
        }

        $parameters = [];

        if ($options->created) {
            $parameters['created'] = $now->getTimestamp();
        }

        if ($options->expires !== null) {
            $parameters['expires'] = $now->add($options->expires)->getTimestamp();
        }

        if ($options->nonce !== null) {
            $parameters['nonce'] = $options->nonce;
        }

        $parameters['alg'] = $algorithmName;
        $parameters['keyid'] = $key->keyId;

        if ($options->tag !== null) {
            $parameters['tag'] = $options->tag;
        }

        $signatureParams = FieldSerializer::signatureParams($covered, $parameters);

        try {
            $base = SignatureBase::build(new MessageContext($message, $relatedRequest), $covered, $signatureParams);
        } catch (Failure $failure) {
            throw new InvalidArgument('Cannot sign the message: ' . $failure->detail, 0, $failure);
        }

        return FieldSerializer::append($message, $options->label, $signatureParams, $key->sign($algorithm, $base));
    }

    /**
     * Signs in the draft form and sets the `Signature` field, replacing any
     * existing one
     *
     * The draft signs a parameter only through its pseudo-header, so `created`
     * and `expires` are emitted only when `(created)` and `(expires)` are
     * covered; a parameter the signature does not cover would be unsigned.
     * The draft forbids those pseudo-headers under the named algorithms, so
     * the parameters are emitted under `hs2019` alone. The signer never uses
     * the `Authorization` field.
     *
     * @param T $message
     * @param list<ComponentIdentifier> $covered
     *
     * @return T
     *
     * @throws InvalidArgument
     *
     * @template T of MessageInterface
     */
    private static function signCavage(
        MessageInterface $message,
        SigningKey $key,
        SigningOptions $options,
        Algorithm $algorithm,
        string $algorithmName,
        array $covered,
        DateTimeImmutable $now,
    ): MessageInterface {
        $created = $options->created && self::coversPlain($covered, '(created)') ? $now->getTimestamp() : null;
        $expires = $options->expires !== null && self::coversPlain($covered, '(expires)')
            ? $now->add($options->expires)->getTimestamp()
            : null;

        try {
            $base = Cavage\SignatureBase::build(
                new MessageContext($message),
                $covered,
                $algorithmName,
                $created === null ? null : (string) $created,
                $expires === null ? null : (string) $expires,
            );
        } catch (Failure $failure) {
            throw new InvalidArgument('Cannot sign the message: ' . $failure->detail, 0, $failure);
        }

        return $message->withHeader(
            'Signature',
            Cavage\FieldSerializer::serialize(
                $key->keyId,
                $algorithm,
                $created,
                $expires,
                $covered,
                $key->sign($algorithm, $base),
            ),
        );
    }

    /**
     * The algorithm the options name, or the first the key permits that has
     * a name in the form, with that name
     *
     * @return array{Algorithm, string}
     *
     * @throws InvalidArgument when the key permits no algorithm that has a
     *     name in the form, as for an ECDSA key under the draft
     */
    private static function algorithm(SigningKey $key, SigningOptions $options): array
    {
        // The options refuse an algorithm with no name in the form, so the
        // one they name is always found.
        $candidates = $options->algorithm === null ? $key->permittedAlgorithms : [$options->algorithm];

        foreach ($candidates as $algorithm) {
            $name = $algorithm->name($options->form);

            if ($name !== null) {
                return [$algorithm, $name];
            }
        }

        throw new InvalidArgument(
            sprintf('The key permits no algorithm that has a name in the form %s', $options->form->value),
        );
    }

    /**
     * The default covered components: under RFC 9421, `@method`,
     * `@target-uri`, `host`, and `date` for a request and `@status` and
     * `date` for a response; under the draft, `(request-target)`, `host`, and
     * `date` for a request and `date` for a response; and the form's digest
     * field when the message has content
     *
     * A response has no `Host` field, so `host` is a request component here.
     *
     * @return list<ComponentIdentifier>
     */
    private static function defaultComponents(MessageInterface $message, Content $content, Form $form): array
    {
        $isRequest = $message instanceof RequestInterface;

        if ($form === Form::Cavage) {
            $names = $isRequest ? ['(request-target)', 'host', 'date'] : ['date'];

            if ($content->hasContent()) {
                $names[] = DigestField::DIGEST;
            }

            return array_map(
                static fn (string $name): ComponentIdentifier => ComponentIdentifier::parseCavage($name),
                $names,
            );
        }

        $names = $isRequest ? ['@method', '@target-uri', 'host', 'date'] : ['@status', 'date'];

        if ($content->hasContent()) {
            $names[] = DigestField::CONTENT_DIGEST;
        }

        return array_map(static fn (string $name): ComponentIdentifier => ComponentIdentifier::parse($name), $names);
    }

    /**
     * A digest field of the message itself; one taken from the related
     * request is a plain field read
     */
    private static function isDigestOfTheMessage(ComponentIdentifier $identifier): bool
    {
        return !$identifier->isDerived()
            && DigestField::isDigestField($identifier->name)
            && !$identifier->hasParameter('req');
    }

    /**
     * @param list<ComponentIdentifier> $covered
     */
    private static function coversPlain(array $covered, string $name): bool
    {
        foreach ($covered as $identifier) {
            if ($identifier->isPlain($name)) {
                return true;
            }
        }

        return false;
    }
}
