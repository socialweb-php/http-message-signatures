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

/**
 * Verifies the signature of a message
 *
 * The checks run cheapest and least revealing first, so that a message bound
 * to be rejected never causes a key lookup and the resolver is never an oracle
 * for malformed input: the form, the fields, the policy that needs no key, the
 * time policy, the signature base, a covered digest, the key, the algorithm,
 * and last the bytes. Under RFC 9421 the labels are tried in the order of
 * `Signature-Input` until one verifies or the limit is reached, and the result
 * reports the last label tried.
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
        $form = self::detectForm($context);

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
            return new VerificationResult(
                verified: false,
                reason: FailureReason::UnsupportedSignature,
                detail: 'the draft form is not implemented',
                form: $form,
            );
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
     */
    private static function detectForm(MessageContext $context): ?Form
    {
        if ($context->hasField('Signature-Input')) {
            return Form::Rfc9421;
        }

        if ($context->hasField('Signature')) {
            return Form::Cavage;
        }

        if ($context->hasField('Authorization')) {
            return preg_match('/^signature\s/i', $context->field('Authorization')) === 1 ? Form::Cavage : null;
        }

        return null;
    }

    /**
     * Steps 3 to 10 of the procedure for one label
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
            return $result($timing, $timing === FailureReason::NotYetValid
                ? 'the created parameter is beyond the clock skew'
                : 'the effective expiry has passed');
        }

        try {
            $base = SignatureBase::build($context, $signature->coveredComponents, $signature->signatureParams);
        } catch (Failure $failure) {
            return $result($failure->reason, $failure->detail);
        }

        foreach ($signature->coveredComponents as $identifier) {
            if (!self::isCoveredDigest($identifier)) {
                continue;
            }

            $mismatch = DigestField::check($identifier->name, $context->field($identifier->name), $content);

            if ($mismatch !== null) {
                return $result(FailureReason::DigestMismatch, $mismatch);
            }
        }

        $key = $this->resolver->resolve($signature->keyId);

        if ($key === null) {
            return $result(FailureReason::KeyNotFound, sprintf('the resolver has no key "%s"', $signature->keyId));
        }

        [$algorithm, $reason, $detail] = self::check($signature, $key, $algorithm, $base);

        if ($reason === null) {
            return $result(null, '', $algorithm);
        }

        if (!$this->options->retryWithRefreshedKey || !self::aRotatedKeyCouldExplain($reason)) {
            return $result($reason, $detail, $algorithm);
        }

        $refreshed = $this->resolver->refresh($signature->keyId);

        if ($refreshed === null) {
            return $result($reason, $detail, $algorithm, true);
        }

        [$algorithm, $reason, $detail] = self::check($signature, $refreshed, $algorithm, $base);

        return $result($reason, $detail, $algorithm, true);
    }

    /**
     * Step 3: the policy that needs no key, each rule naming what is missing
     */
    private function policyViolation(
        ParsedSignature $signature,
        MessageContext $context,
        Content $content,
        ?DateTimeImmutable $created,
    ): ?string {
        $options = $this->options;

        if ($options->requireTarget && !self::coversTarget($signature, $context)) {
            return $context->isRequest()
                ? 'the signature does not cover the request target'
                : 'the signature does not cover @status';
        }

        if ($options->requireCreationTime && $created === null) {
            return 'the signature has no created parameter';
        }

        if ($options->requireContentDigest && $content->hasContent() && !self::coversDigest($signature)) {
            return 'the message has content and the signature does not cover its digest field';
        }

        if ($options->requireNonce && $signature->nonce === null) {
            return 'the signature has no nonce parameter';
        }

        foreach ($options->requiredComponentIdentifiers() as $required) {
            if (!self::covers($signature, $required)) {
                return sprintf('the required component %s is not covered', $required->toString());
            }
        }

        return null;
    }

    /**
     * Under RFC 9421, a request satisfies the target rule when `@method` is
     * covered together with `@target-uri`, with `@authority` and `@path`, or
     * with `@authority` and `@request-target`; a response satisfies it when
     * `@status` is covered
     */
    private static function coversTarget(ParsedSignature $signature, MessageContext $context): bool
    {
        if (!$context->isRequest()) {
            return self::coversPlain($signature, '@status');
        }

        if (!self::coversPlain($signature, '@method')) {
            return false;
        }

        if (self::coversPlain($signature, '@target-uri')) {
            return true;
        }

        return self::coversPlain($signature, '@authority')
            && (self::coversPlain($signature, '@path') || self::coversPlain($signature, '@request-target'));
    }

    private static function coversPlain(ParsedSignature $signature, string $name): bool
    {
        foreach ($signature->coveredComponents as $identifier) {
            if ($identifier->isPlain($name)) {
                return true;
            }
        }

        return false;
    }

    private static function covers(ParsedSignature $signature, ComponentIdentifier $required): bool
    {
        foreach ($signature->coveredComponents as $identifier) {
            if ($identifier->equals($required)) {
                return true;
            }
        }

        return false;
    }

    private static function coversDigest(ParsedSignature $signature): bool
    {
        foreach ($signature->coveredComponents as $identifier) {
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
     * Steps 8 and 9: resolve the algorithm against the key and verify the
     * bytes
     *
     * @param Algorithm | null $algorithm the `alg` parameter, resolved, or
     *     `null` when the key decides
     *
     * @return array{Algorithm, FailureReason | null, string}
     */
    private static function check(
        ParsedSignature $signature,
        VerificationKey $key,
        ?Algorithm $algorithm,
        string $signatureBase,
    ): array {
        if ($algorithm === null) {
            // Every algorithm has a name in RFC 9421, so the key's first
            // permitted algorithm is the first that has a name in the form.
            $algorithm = $key->permittedAlgorithms[0];
        } elseif (!$key->permits($algorithm)) {
            return [
                $algorithm,
                FailureReason::AlgorithmNotPermitted,
                sprintf('the key does not permit %s', $algorithm->rfc9421Name()),
            ];
        }

        if ($key->verify($algorithm, $signatureBase, $signature->signature)) {
            return [$algorithm, null, ''];
        }

        return [
            $algorithm,
            FailureReason::SignatureInvalid,
            sprintf('the signature "%s" does not verify under %s', $signature->label, $algorithm->rfc9421Name()),
        ];
    }

    /**
     * Step 10: the failures after which the key is refreshed once
     */
    private static function aRotatedKeyCouldExplain(FailureReason $reason): bool
    {
        return in_array($reason, [FailureReason::SignatureInvalid, FailureReason::AlgorithmNotPermitted], true);
    }
}
