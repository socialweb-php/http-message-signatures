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
use Psr\Clock\ClockInterface;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;
use SocialWeb\Http\MessageSignatures\Component\Content;
use SocialWeb\Http\MessageSignatures\Component\DigestField;
use SocialWeb\Http\MessageSignatures\Component\MessageContext;
use SocialWeb\Http\MessageSignatures\Exception\InvalidArgument;
use SocialWeb\Http\MessageSignatures\Rfc9421\FieldParser;
use SocialWeb\Http\MessageSignatures\Rfc9421\ParsedSignature;
use SocialWeb\Http\MessageSignatures\Rfc9421\SignatureBase;

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
 * query string removed from `(request-target)` when the options allow it, and
 * the `created` and `expires` parameters count only when `(created)` and
 * `(expires)` are covered, since the draft signs a parameter only through its
 * pseudo-header.
 */
final class Verifier
{
    public function __construct(
        private readonly KeyResolver $resolver,
        private readonly ClockInterface $clock,
        private readonly VerifierOptions $options = new VerifierOptions(),
    ) {
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

        if (!$this->options->accepts($form)) {
            return new VerificationResult(
                verified: false,
                reason: FailureReason::UnsupportedSignature,
                detail: sprintf('the form %s is not accepted', $form->value),
                form: $form,
            );
        }

        if ($form === Form::Cavage) {
            return $this->verifyCavage($context, $content);
        }

        try {
            $signatures = FieldParser::parse($context, $this->options->maxSignatures);
        } catch (Failure $failure) {
            return new VerificationResult(
                verified: false,
                reason: $failure->reason,
                detail: $failure->detail,
                form: $form,
            );
        }

        $result = null;

        foreach ($signatures as $signature) {
            $result = $this->verifyOne($signature, $context, $content);

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

        $result = fn (
            ?FailureReason $reason,
            string $detail = '',
            ?Algorithm $algorithm = null,
            bool $keyRefreshed = false,
            bool $withoutQuery = false,
        ): VerificationResult => new VerificationResult(
            verified: $reason === null,
            reason: $reason,
            detail: $detail,
            form: Form::Cavage,
            algorithm: $algorithm,
            keyId: $signature->keyId,
            coveredComponents: $signature->coveredComponentNames(),
            created: $created,
            expires: $expires,
            signature: $signature->signature,
            keyRefreshed: $keyRefreshed,
            requestTargetVerifiedWithoutQuery: $withoutQuery,
        );

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

        $timing = $this->options->timePolicy->evaluate($now, $created, $expires);

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

            if ($this->options->acceptRequestTargetWithoutQuery) {
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
        } catch (Failure $failure) {
            return $result($failure->reason, $failure->detail);
        }

        $outcome = $this->checkWithKey(
            $signature->keyId,
            $algorithm,
            Form::Cavage,
            $signature->signature,
            $bases,
            'the signature',
        );

        return $result(...$outcome);
    }

    /**
     * Steps 3 to 10 of the procedure for one RFC 9421 label
     */
    private function verifyOne(
        ParsedSignature $signature,
        MessageContext $context,
        Content $content,
    ): VerificationResult {
        $created = $signature->created === null ? null : new DateTimeImmutable('@' . $signature->created);
        $expires = $signature->expires === null ? null : new DateTimeImmutable('@' . $signature->expires);

        $result = fn (
            ?FailureReason $reason,
            string $detail = '',
            ?Algorithm $algorithm = null,
            bool $keyRefreshed = false,
            bool $withoutQuery = false,
        ): VerificationResult => new VerificationResult(
            verified: $reason === null,
            reason: $reason,
            detail: $detail,
            form: Form::Rfc9421,
            algorithm: $algorithm,
            keyId: $signature->keyId,
            label: $signature->label,
            coveredComponents: $signature->coveredComponentNames(),
            created: $created,
            expires: $expires,
            nonce: $signature->nonce,
            signature: $signature->signature,
            keyRefreshed: $keyRefreshed,
            requestTargetVerifiedWithoutQuery: $withoutQuery,
        );

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

        $timing = $this->options->timePolicy->evaluate($this->clock->now(), $created, $expires);

        if ($timing !== null) {
            return $result($timing, self::timingDetail($timing));
        }

        try {
            $base = SignatureBase::build($context, $signature->coveredComponents, $signature->signatureParams);
            self::checkDigests($signature->coveredComponents, $context, $content);
        } catch (Failure $failure) {
            return $result($failure->reason, $failure->detail);
        }

        $outcome = $this->checkWithKey(
            $signature->keyId,
            $algorithm,
            Form::Rfc9421,
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
        $options = $this->options;
        $covered = $signature->coveredComponents;

        if ($options->requireTarget && !self::coversTarget($covered, $context)) {
            return $context->isRequest()
                ? 'the signature does not cover the request target'
                : 'the signature does not cover @status';
        }

        if ($options->requireCreationTime && $created === null) {
            return 'the signature has no created parameter';
        }

        if ($options->requireContentDigest && $content->hasContent() && !self::coversDigest($covered)) {
            return 'the message has content and the signature does not cover its digest field';
        }

        if ($options->requireNonce && $signature->nonce === null) {
            return 'the signature has no nonce parameter';
        }

        return self::uncoveredRequirement($options->requiredComponentIdentifiers(Form::Rfc9421), $covered);
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
        $options = $this->options;
        $covered = $signature->coveredComponents;

        if ($options->requireTarget && $context->isRequest() && !self::coversPlain($covered, '(request-target)')) {
            return 'the signature does not cover (request-target)';
        }

        if ($options->requireCreationTime && $created === null) {
            return self::missingCreationTime($covered, $context);
        }

        if ($options->requireContentDigest && $content->hasContent() && !self::coversDigest($covered)) {
            return 'the message has content and the signature does not cover its digest field';
        }

        return self::uncoveredRequirement($options->requiredComponentIdentifiers(Form::Cavage), $covered);
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
     * @throws Failure `DigestMismatch`, or `MissingComponent` for a field
     *     value with a line break
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
     * @param Algorithm | null $algorithm the algorithm the message names,
     *     resolved, or `null` when the key decides
     * @param non-empty-list<string> $bases the signature base, and under the
     *     draft the one without the query string
     * @param string $signatureName what the detail calls the signature
     *
     * @return array{reason: FailureReason | null, detail: string, algorithm: Algorithm | null, keyRefreshed: bool, withoutQuery: bool}
     */
    private function checkWithKey(
        string $keyId,
        ?Algorithm $algorithm,
        Form $form,
        string $signature,
        array $bases,
        string $signatureName,
    ): array {
        $key = $this->resolver->resolve($keyId);

        if ($key === null) {
            return [
                'reason' => FailureReason::KeyNotFound,
                'detail' => sprintf('the resolver has no key "%s"', $keyId),
                'algorithm' => null,
                'keyRefreshed' => false,
                'withoutQuery' => false,
            ];
        }

        $outcome = self::check($key, $algorithm, $form, $signature, $bases, $signatureName);

        if (
            $outcome['reason'] === null
            || !$this->options->retryWithRefreshedKey
            || !self::aRotatedKeyCouldExplain($outcome['reason'])
        ) {
            return $outcome;
        }

        $refreshed = $this->resolver->refresh($keyId);
        $outcome = $refreshed === null
            ? $outcome
            : self::check($refreshed, $algorithm, $form, $signature, $bases, $signatureName);
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
     * @return array{reason: FailureReason | null, detail: string, algorithm: Algorithm | null, keyRefreshed: bool, withoutQuery: bool}
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
        ];

        if ($outcome['algorithm'] === null) {
            $outcome['reason'] = FailureReason::AlgorithmNotPermitted;
            $outcome['detail'] = sprintf('the key permits no algorithm that has a name in the form %s', $form->value);

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
