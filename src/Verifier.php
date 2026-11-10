<?php

/**
 * This file is part of socialweb/http-message-signatures
 *
 * Copyright © socialweb/http-message-signatures Contributors
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

use DateInterval;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Component\Content;
use SocialWeb\Http\MessageSignatures\Component\DigestField;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Exception\ComponentFailure;
use SocialWeb\Http\MessageSignatures\Exception\Failure;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Rfc9421\FieldParser;
use SocialWeb\Http\MessageSignatures\Rfc9421\ParsedSignature;
use SocialWeb\Http\MessageSignatures\Rfc9421\SignatureBase;

use function assert;
use function in_array;
use function preg_match;
use function sprintf;
use function trim;

/**
 * Verifies the signature of a message
 *
 * The checks run cheapest and least revealing first, so that a message bound
 * to be rejected never causes a key lookup and the resolver is never an oracle
 * for malformed input: the form, the fields, an algorithm name the package
 * does not know, the policy that needs no key, the time policy, the signature
 * base, a covered digest, the key, the algorithm, and last the bytes. Under
 * RFC 9421 the labels are tried in the order of `Signature-Input` until one
 * verifies or the limit is reached, and the result reports the last label
 * tried. Under the draft, a signature that fails is tried once more with the
 * query string removed from `(request-target)` when
 * `acceptRequestTargetWithoutQuery` is on, and the `created` and `expires`
 * parameters count only when `(created)` and `(expires)` are covered, since
 * the draft signs a parameter only through its pseudo-header.
 *
 * The target rule is a rule and not a literal list, so that the ways the
 * specifications allow all satisfy it. Under the draft, a request satisfies it
 * when `(request-target)` is covered. Under RFC 9421, a request satisfies it
 * when `@method` is covered together with `@target-uri`, with `@authority` and
 * `@path`, or with `@authority` and `@request-target`. A response satisfies it
 * when `@status` is covered under RFC 9421, and always under the draft, which
 * has no response target. The creation-time rule is satisfied by a `created`
 * parameter in either form, or by a covered `date` field under the draft,
 * which is where the implementations put it when `created` is absent.
 *
 * Each required component applies to the forms it can be written in: a field
 * name with no parameters to both, a name in parentheses such as
 * `(request-target)` to the draft only, and a derived component or a
 * component with parameters to RFC 9421 only.
 *
 * The creation time is the `created` parameter, or in the draft form without
 * one, the covered `Date` field. The effective expiry is the `expires`
 * parameter when present and the creation time plus `defaultLifetime` when
 * not, limited to the creation time plus `maximumLifetime` either way. The
 * default intervals are what the largest implementation enforces; RFC 9421
 * section 3.2.1 leaves the values to the application.
 */
final class Verifier
{
    /**
     * @var non-empty-list<Form>
     */
    private readonly array $forms;

    private readonly TimePolicy $timePolicy;

    /**
     * @var list<ComponentIdentifier>
     */
    private readonly array $requiredComponents;

    /**
     * @param KeyResolver $resolver finds the key a signature names
     * @param ClockInterface $clock gives the current time for the time checks
     * @param non-empty-list<Form> $forms forms the verifier accepts; a
     *     message in another form is `UnsupportedSignature`; must not be
     *     empty
     * @param DateInterval $clockSkew how far the signer's clock may differ
     *     from the clock, in either direction
     * @param DateInterval $defaultLifetime how long a signature without
     *     `expires` is valid after its creation time
     * @param DateInterval $maximumLifetime an `expires` further from the
     *     creation time than this is limited to it
     * @param bool $requireTarget the signature must cover the request target
     * @param bool $requireCreationTime the signature must have a creation time
     * @param bool $requireContentDigest a message with content must cover its
     *     digest field
     * @param list<string> $requiredComponents component identifiers that must
     *     be covered, in addition to the rules above, each a component name
     *     followed by its parameters in the syntax of RFC 8941, as in
     *     `content-digest;req`, or one of the draft form's
     *     `(request-target)`, `(created)`, and `(expires)`
     * @param bool $requireNonce the `nonce` parameter must be present; RFC
     *     9421 only
     * @param bool $retryWithRefreshedKey call the resolver's `refresh()` once
     *     after a failure a rotated key could explain
     * @param bool $acceptRequestTargetWithoutQuery under the draft, try the
     *     signature base once more with the query string removed from
     *     `(request-target)` after a failure
     * @param int $maxSignatures how many RFC 9421 labels are tried before
     *     giving up; at least 1. A message with more labels gets a result
     *     whose `maxSignaturesExceeded` is set
     *
     * @throws InvalidArgument when the list of forms is empty or holds a
     *     duplicate, when an interval is negative, when a required component
     *     identifier is empty or does not parse, or when `maxSignatures` is
     *     below 1
     */
    public function __construct(
        private readonly KeyResolver $resolver,
        private readonly ClockInterface $clock,
        array $forms = [Form::Cavage, Form::Rfc9421],
        DateInterval $clockSkew = new DateInterval('PT1H'),
        DateInterval $defaultLifetime = new DateInterval('PT5M'),
        DateInterval $maximumLifetime = new DateInterval('PT12H'),
        private readonly bool $requireTarget = true,
        private readonly bool $requireCreationTime = true,
        private readonly bool $requireContentDigest = true,
        array $requiredComponents = [],
        private readonly bool $requireNonce = false,
        private readonly bool $retryWithRefreshedKey = true,
        private readonly bool $acceptRequestTargetWithoutQuery = true,
        private readonly int $maxSignatures = 3,
    ) {
        if ($forms === []) {
            throw new InvalidArgument('The list of forms must not be empty');
        }

        $seen = [];

        foreach ($forms as $form) {
            if (in_array($form, $seen, true)) {
                throw new InvalidArgument(sprintf('The form %s appears more than once', $form->name));
            }

            $seen[] = $form;
        }

        $timePolicy = new TimePolicy($clockSkew, $defaultLifetime, $maximumLifetime);
        $identifiers = [];

        foreach ($requiredComponents as $component) {
            $identifiers[] = ComponentIdentifier::fromEitherForm($component);
        }

        if ($maxSignatures < 1) {
            throw new InvalidArgument(sprintf('maxSignatures must be at least 1; %d given', $maxSignatures));
        }

        $this->forms = $seen;
        $this->timePolicy = $timePolicy;
        $this->requiredComponents = $identifiers;
    }

    /**
     * Verifies the message and reports what was found; nothing about the
     * message throws
     *
     * @param MessageInterface $message the request or response to verify
     * @param RequestInterface | null $relatedRequest the request a response
     *     answers, for a covered component with the `req` parameter
     *
     * @throws InvalidArgument when the message body cannot be rewound, since
     *     reading it would consume it; anything the resolver throws passes
     *     through unchanged
     */
    public function verify(MessageInterface $message, ?RequestInterface $relatedRequest = null): VerificationResult
    {
        $content = new Content($message);
        $context = new MessageContext($message, $relatedRequest);
        $form = self::detectForm($message);

        if ($form === null) {
            return new VerificationResult(
                verified: false,
                reason: FailureReason::NoSignature,
                detail: 'the message has neither Signature-Input nor Signature',
            );
        }

        if (!in_array($form, $this->forms, true)) {
            return new VerificationResult(
                verified: false,
                reason: FailureReason::UnsupportedSignature,
                detail: sprintf('the form %s is not accepted', $form->name),
                form: $form,
            );
        }

        if ($form === Form::Cavage) {
            return $this->verifyCavage($context, $content);
        }

        try {
            $fields = FieldParser::parse($context, $this->maxSignatures);
        } catch (ComponentFailure | Failure $failure) {
            return new VerificationResult(
                verified: false,
                reason: $failure->reason,
                detail: $failure->detail,
                form: $form,
            );
        }

        $result = null;

        foreach ($fields->signatures as $signature) {
            $result = $this->verifyOne($signature, $context, $content, $fields->labelsLeftUnread);

            if ($result->verified) {
                break;
            }
        }

        return $result ?? new VerificationResult(
            verified: false,
            reason: FailureReason::MalformedSignature,
            detail: 'the Signature-Input field has no members',
            form: $form,
        );
    }

    /**
     * Step 1 of the procedure: `Signature-Input` means RFC 9421, as the RFC's
     * appendix A advises; otherwise `Signature` or an `Authorization` field
     * with the `Signature` scheme means the draft
     *
     * Only the first word of `Authorization` is read here, after any leading
     * whitespace, as the message gives it; a line break later in the value is
     * met when the field is taken as a component value.
     */
    private static function detectForm(MessageInterface $message): ?Form
    {
        if ($message->hasHeader('Signature-Input')) {
            return Form::Rfc9421;
        }

        if ($message->hasHeader('Signature')) {
            return Form::Cavage;
        }

        if ($message->hasHeader('Authorization')) {
            return preg_match('/^\s*signature\s/i', $message->getHeaderLine('Authorization')) === 1
                ? Form::Cavage
                : null;
        }

        return null;
    }

    /**
     * Steps 2 to 10 of the procedure under the draft form
     *
     * The creation time is the `created` parameter when `(created)` is
     * covered, or, when it is not, the covered `Date` field read as an HTTP
     * date; a `created` parameter that `(created)` does not cover is unsigned
     * and is ignored, as is an `expires` parameter that `(expires)` does not
     * cover. A `Date` field that is not an HTTP date gives no creation time.
     */
    private function verifyCavage(MessageContext $context, Content $content): VerificationResult
    {
        try {
            $signature = Cavage\FieldParser::parse($context);
        } catch (Failure $failure) {
            return new VerificationResult(
                verified: false,
                reason: $failure->reason,
                detail: $failure->detail,
                form: Form::Cavage,
            );
        }

        $covered = $signature->coveredComponents;
        $now = $this->clock->now();
        $created = self::coversPlain($covered, '(created)') ? $signature->createdTime() : null;
        $expires = self::coversPlain($covered, '(expires)') ? $signature->expiresTime() : null;

        if (
            $created === null
            && !self::coversPlain($covered, '(created)')
            && self::coversPlain($covered, 'date')
            && $context->hasField('date')
        ) {
            // The field as the signature string reads it: one line with its
            // outer whitespace removed; a value with a line break is not an
            // HTTP date.
            $created = Cavage\HttpDate::parse(trim($context->message()->getHeaderLine('Date'), " \t"), $now);
        }

        $result = function (
            ?FailureReason $reason,
            string $detail = '',
            ?Algorithm $algorithm = null,
            bool $keyRefreshed = false,
            bool $withoutQuery = false,
            ?string $keyOwner = null,
        ) use (
            $signature,
            $created,
            $expires,
        ): VerificationResult {
            assert($keyOwner !== '');

            return new VerificationResult(
                verified: $reason === null,
                reason: $reason,
                detail: $detail,
                form: Form::Cavage,
                algorithm: $algorithm,
                keyId: $signature->keyId,
                keyOwner: $keyOwner,
                coveredComponents: $signature->coveredComponentNames(),
                created: $created,
                expires: $expires,
                signature: $signature->signature,
                keyRefreshed: $keyRefreshed,
                requestTargetVerifiedWithoutQuery: $withoutQuery,
            );
        };

        $named = $signature->keyDecidesAlgorithm() ? null : $signature->algorithm;
        $algorithm = $named === null ? null : Algorithm::tryFromName($named, Form::Cavage);

        if ($named !== null && $algorithm === null) {
            return $result(
                FailureReason::UnsupportedSignature,
                sprintf('the algorithm "%s" is not one the package knows', $named),
            );
        }

        $violation = $this->cavagePolicyViolation($signature, $context, $content, $created);

        if ($violation !== null) {
            return $result(FailureReason::PolicyViolation, $violation);
        }

        $timing = $this->timePolicy->evaluate($now, $created, $expires);

        if ($timing !== null) {
            return $result($timing, self::timingDetail($timing));
        }

        try {
            $base = Cavage\SignatureBase::build(
                $context,
                $covered,
                $signature->algorithm,
                $signature->created,
                $signature->expires,
            );
            $bases = [$base];

            if ($this->acceptRequestTargetWithoutQuery) {
                $withoutQuery = Cavage\SignatureBase::build(
                    $context,
                    $covered,
                    $signature->algorithm,
                    $signature->created,
                    $signature->expires,
                    false,
                );

                if ($withoutQuery !== $base) {
                    $bases[] = $withoutQuery;
                }
            }

            self::checkDigests($covered, $context, $content);
        } catch (ComponentFailure | Failure $failure) {
            return $result($failure->reason, $failure->detail);
        }

        $outcome = $this->checkWithKey(
            new KeyLookup(
                message: $context->message(),
                form: Form::Cavage,
                keyId: $signature->keyId,
                relatedRequest: $context->relatedRequest(),
                algorithm: $algorithm,
                created: $created,
                expires: $expires,
                coveredComponents: $signature->coveredComponentNames(),
            ),
            $signature->signature,
            $bases,
            'the signature',
        );

        return $result(...$outcome);
    }

    /**
     * Steps 3 to 10 of the procedure for one RFC 9421 label
     *
     * @param bool $maxSignaturesExceeded whether the message has labels
     *     beyond the limit, which the result reports
     */
    private function verifyOne(
        ParsedSignature $signature,
        MessageContext $context,
        Content $content,
        bool $maxSignaturesExceeded,
    ): VerificationResult {
        $created = $signature->created === null ? null : new DateTimeImmutable('@' . $signature->created);
        $expires = $signature->expires === null ? null : new DateTimeImmutable('@' . $signature->expires);

        $result =
            function (
                ?FailureReason $reason,
                string $detail = '',
                ?Algorithm $algorithm = null,
                bool $keyRefreshed = false,
                bool $withoutQuery = false,
                ?string $keyOwner = null,
            ) use (
                $signature,
                $created,
                $expires,
                $maxSignaturesExceeded,
            ): VerificationResult {
                assert($keyOwner !== '');

                return new VerificationResult(
                    verified: $reason === null,
                    reason: $reason,
                    detail: $detail,
                    form: Form::Rfc9421,
                    algorithm: $algorithm,
                    keyId: $signature->keyId,
                    keyOwner: $keyOwner,
                    label: $signature->label,
                    coveredComponents: $signature->coveredComponentNames(),
                    created: $created,
                    expires: $expires,
                    nonce: $signature->nonce,
                    signature: $signature->signature,
                    keyRefreshed: $keyRefreshed,
                    requestTargetVerifiedWithoutQuery: $withoutQuery,
                    maxSignaturesExceeded: $maxSignaturesExceeded,
                );
            };

        $algorithm = $signature->algorithm === null
            ? null
            : Algorithm::tryFromName($signature->algorithm, Form::Rfc9421);

        if ($signature->algorithm !== null && $algorithm === null) {
            return $result(
                FailureReason::UnsupportedSignature,
                sprintf('the algorithm "%s" is not one the package knows', $signature->algorithm),
            );
        }

        $violation = $this->policyViolation($signature, $context, $content, $created);

        if ($violation !== null) {
            return $result(FailureReason::PolicyViolation, $violation);
        }

        $timing = $this->timePolicy->evaluate($this->clock->now(), $created, $expires);

        if ($timing !== null) {
            return $result($timing, self::timingDetail($timing));
        }

        try {
            $base = SignatureBase::build($context, $signature->coveredComponents, $signature->signatureParams);
            self::checkDigests($signature->coveredComponents, $context, $content);
        } catch (ComponentFailure | Failure $failure) {
            return $result($failure->reason, $failure->detail);
        }

        $outcome = $this->checkWithKey(
            new KeyLookup(
                message: $context->message(),
                form: Form::Rfc9421,
                keyId: $signature->keyId,
                relatedRequest: $context->relatedRequest(),
                label: $signature->label,
                algorithm: $algorithm,
                created: $created,
                expires: $expires,
                nonce: $signature->nonce,
                tag: $signature->tag,
                coveredComponents: $signature->coveredComponentNames(),
            ),
            $signature->signature,
            [$base],
            sprintf('the signature "%s"', $signature->label),
        );

        return $result(...$outcome);
    }

    private static function timingDetail(FailureReason $timing): string
    {
        return $timing === FailureReason::NotYetValid
            ? 'the created parameter is beyond the clock skew'
            : 'the effective expiry has passed';
    }

    /**
     * Step 3 under RFC 9421: the policy that needs no key, each rule naming
     * what is missing
     */
    private function policyViolation(
        ParsedSignature $signature,
        MessageContext $context,
        Content $content,
        ?DateTimeImmutable $created,
    ): ?string {
        $covered = $signature->coveredComponents;

        if ($this->requireTarget && !self::coversTarget($covered, $context)) {
            return $context->isRequest()
                ? 'the signature does not cover the request target'
                : 'the signature does not cover @status';
        }

        if ($this->requireCreationTime && $created === null) {
            return 'the signature has no created parameter';
        }

        if ($this->requireContentDigest && $content->hasContent() && !self::coversDigest($covered)) {
            return 'the message has content and the signature does not cover its digest field';
        }

        if ($this->requireNonce && $signature->nonce === null) {
            return 'the signature has no nonce parameter';
        }

        return self::uncoveredRequirement($this->requiredComponentsFor(Form::Rfc9421), $covered);
    }

    /**
     * Step 3 under the draft form: a request satisfies the target rule when
     * `(request-target)` is covered, and a response always does; the
     * creation-time rule is satisfied by a covered `(created)` or by a
     * covered `Date` field that is an HTTP date; `requireNonce` applies to RFC
     * 9421 only, since the draft has no nonce
     */
    private function cavagePolicyViolation(
        Cavage\ParsedSignature $signature,
        MessageContext $context,
        Content $content,
        ?DateTimeImmutable $created,
    ): ?string {
        $covered = $signature->coveredComponents;

        if ($this->requireTarget && $context->isRequest() && !self::coversPlain($covered, '(request-target)')) {
            return 'the signature does not cover (request-target)';
        }

        if ($this->requireCreationTime && $created === null) {
            return self::missingCreationTime($covered, $context);
        }

        if ($this->requireContentDigest && $content->hasContent() && !self::coversDigest($covered)) {
            return 'the message has content and the signature does not cover its digest field';
        }

        return self::uncoveredRequirement($this->requiredComponentsFor(Form::Cavage), $covered);
    }

    /**
     * The required components, as parsed, that apply to the form: a field
     * name with no parameters to both forms, a name in parentheses to the
     * draft only, and a derived component or a component with parameters to
     * RFC 9421 only
     *
     * @return list<ComponentIdentifier>
     */
    private function requiredComponentsFor(Form $form): array
    {
        $applying = [];

        foreach ($this->requiredComponents as $identifier) {
            $applies = match ($form) {
                Form::Cavage => $identifier->isPseudoHeader()
                    || (!$identifier->isDerived() && $identifier->parameters->isEmpty()),
                Form::Rfc9421 => !$identifier->isPseudoHeader(),
            };

            if ($applies) {
                $applying[] = $identifier;
            }
        }

        return $applying;
    }

    /**
     * Why a draft signature has no creation time, for the policy's detail
     *
     * @param list<ComponentIdentifier> $covered
     */
    private static function missingCreationTime(array $covered, MessageContext $context): string
    {
        if (self::coversPlain($covered, '(created)')) {
            return '(created) is covered and the created parameter is absent';
        }

        if (!self::coversPlain($covered, 'date')) {
            return 'the signature covers neither (created) nor date';
        }

        return $context->hasField('date')
            ? 'the signature does not cover (created) and its date field is not an HTTP date'
            : 'the signature covers date and the message has no Date field';
    }

    /**
     * @param list<ComponentIdentifier> $required
     * @param list<ComponentIdentifier> $covered
     */
    private static function uncoveredRequirement(array $required, array $covered): ?string
    {
        foreach ($required as $identifier) {
            if (!self::covers($covered, $identifier)) {
                return sprintf('the required component %s is not covered', $identifier->toString());
            }
        }

        return null;
    }

    /**
     * Under RFC 9421, a request satisfies the target rule when `@method` is
     * covered together with `@target-uri`, with `@authority` and `@path`, or
     * with `@authority` and `@request-target`; a response satisfies it when
     * `@status` is covered
     *
     * @param list<ComponentIdentifier> $covered
     */
    private static function coversTarget(array $covered, MessageContext $context): bool
    {
        if (!$context->isRequest()) {
            return self::coversPlain($covered, '@status');
        }

        if (!self::coversPlain($covered, '@method')) {
            return false;
        }

        if (self::coversPlain($covered, '@target-uri')) {
            return true;
        }

        return self::coversPlain($covered, '@authority')
            && (self::coversPlain($covered, '@path') || self::coversPlain($covered, '@request-target'));
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

    /**
     * @param list<ComponentIdentifier> $covered
     */
    private static function covers(array $covered, ComponentIdentifier $required): bool
    {
        foreach ($covered as $identifier) {
            if ($identifier->equals($required)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<ComponentIdentifier> $covered
     */
    private static function coversDigest(array $covered): bool
    {
        foreach ($covered as $identifier) {
            if (self::isCoveredDigest($identifier)) {
                return true;
            }
        }

        return false;
    }

    /**
     * A digest field of the target message itself; one taken from the related
     * request vouches for content this verifier does not have
     */
    private static function isCoveredDigest(ComponentIdentifier $identifier): bool
    {
        return !$identifier->isDerived()
            && DigestField::isDigestField($identifier->name)
            && !$identifier->hasParameter('req');
    }

    /**
     * Step 6: every covered digest field of the message is checked against
     * the content
     *
     * @param list<ComponentIdentifier> $covered
     *
     * @throws ComponentFailure `MissingComponent` for a field value with a
     *     line break
     * @throws Failure `DigestMismatch` when a digest does not match the
     *     content
     */
    private static function checkDigests(array $covered, MessageContext $context, Content $content): void
    {
        foreach ($covered as $identifier) {
            if (!self::isCoveredDigest($identifier)) {
                continue;
            }

            $mismatch = DigestField::check($identifier->name, $context->field($identifier->name), $content);

            if ($mismatch !== null) {
                throw new Failure(FailureReason::DigestMismatch, $mismatch);
            }
        }
    }

    /**
     * Steps 7 to 10: resolve the key, check the signature with it, and on a
     * failure a rotated key could explain, once more with a refreshed key
     *
     * The same lookup goes to `resolve()` and then to `refresh()`. On success
     * the outcome's `keyOwner` is the owner of the key that verified, which
     * is the refreshed key's when the refresh is what verified.
     *
     * @param KeyLookup $lookup what the resolver is given, whose `algorithm`
     *     is the one the message names, resolved, or `null` when the key
     *     decides
     * @param non-empty-list<string> $bases the signature base, and under the
     *     draft the one without the query string
     * @param string $signatureName what the detail calls the signature
     *
     * @return array{reason: FailureReason | null, detail: string, algorithm: Algorithm | null, keyRefreshed: bool, withoutQuery: bool, keyOwner: non-empty-string | null}
     */
    private function checkWithKey(
        KeyLookup $lookup,
        string $signature,
        array $bases,
        string $signatureName,
    ): array {
        $key = $this->resolver->resolve($lookup);

        if ($key === null) {
            return [
                'reason' => FailureReason::KeyNotFound,
                'detail' => sprintf('the resolver has no key "%s"', $lookup->keyId),
                'algorithm' => null,
                'keyRefreshed' => false,
                'withoutQuery' => false,
                'keyOwner' => null,
            ];
        }

        $outcome = self::check($key, $lookup->algorithm, $lookup->form, $signature, $bases, $signatureName);

        if (
            $outcome['reason'] === null
            || !$this->retryWithRefreshedKey
            || !self::aRotatedKeyCouldExplain($outcome['reason'])
        ) {
            return $outcome;
        }

        $refreshed = $this->resolver->refresh($lookup);
        $outcome = $refreshed === null
            ? $outcome
            : self::check($refreshed, $lookup->algorithm, $lookup->form, $signature, $bases, $signatureName);
        $outcome['keyRefreshed'] = true;

        return $outcome;
    }

    /**
     * Steps 8 and 9: resolve the algorithm against the key and verify the
     * bytes against each base in turn
     *
     * @param Algorithm | null $algorithm the algorithm the message names,
     *     resolved, or `null` when the key decides
     * @param non-empty-list<string> $bases
     *
     * @return array{reason: FailureReason | null, detail: string, algorithm: Algorithm | null, keyRefreshed: bool, withoutQuery: bool, keyOwner: non-empty-string | null}
     */
    private static function check(
        VerificationKey $key,
        ?Algorithm $algorithm,
        Form $form,
        string $signature,
        array $bases,
        string $signatureName,
    ): array {
        $outcome = [
            'reason' => null,
            'detail' => '',
            'algorithm' => $algorithm ?? self::firstAlgorithmInTheForm($key, $form),
            'keyRefreshed' => false,
            'withoutQuery' => false,
            'keyOwner' => null,
        ];

        if ($outcome['algorithm'] === null) {
            $outcome['reason'] = FailureReason::AlgorithmNotPermitted;
            $outcome['detail'] = sprintf('the key permits no algorithm that has a name in the form %s', $form->name);

            return $outcome;
        }

        if (!$key->permits($outcome['algorithm'])) {
            $outcome['reason'] = FailureReason::AlgorithmNotPermitted;
            $outcome['detail'] = sprintf('the key does not permit %s', $outcome['algorithm']->name($form));

            return $outcome;
        }

        foreach ($bases as $index => $base) {
            if ($key->verify($outcome['algorithm'], $base, $signature)) {
                $outcome['withoutQuery'] = $index > 0;
                $outcome['keyOwner'] = $key->owner;

                return $outcome;
            }
        }

        $outcome['reason'] = FailureReason::SignatureInvalid;
        $outcome['detail'] = sprintf(
            '%s does not verify under %s',
            $signatureName,
            $outcome['algorithm']->name($form),
        );

        return $outcome;
    }

    /**
     * The first algorithm the key permits that has a name in the form; under
     * RFC 9421 every algorithm has one
     */
    private static function firstAlgorithmInTheForm(VerificationKey $key, Form $form): ?Algorithm
    {
        foreach ($key->permittedAlgorithms as $algorithm) {
            if ($algorithm->name($form) !== null) {
                return $algorithm;
            }
        }

        return null;
    }

    /**
     * Step 10: the failures after which the key is refreshed once
     */
    private static function aRotatedKeyCouldExplain(FailureReason $reason): bool
    {
        return in_array($reason, [FailureReason::SignatureInvalid, FailureReason::AlgorithmNotPermitted], true);
    }
}
