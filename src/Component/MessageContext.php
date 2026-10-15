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

namespace SocialWeb\Http\MessageSignatures\Component;

use Bakame\Http\StructuredFields\Dictionary;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\OuterList;
use Bakame\Http\StructuredFields\SyntaxError;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
use SocialWeb\Http\MessageSignatures\FailureReason;
use SocialWeb\Http\MessageSignatures\StructuredFields;

use function array_map;
use function implode;
use function in_array;
use function preg_match;
use function sprintf;
use function strpos;
use function strtolower;
use function substr;
use function trim;

/**
 * The message a signature covers, and the optional request it answers, as a
 * source of component values
 *
 * Both forms read through this class, so the rule that values are taken as
 * received lives in one place. A component the message cannot supply raises
 * `ComponentFailure` with the reason the verifier reports.
 *
 * @internal
 */
final class MessageContext
{
    /**
     * The fields the package knows to be Dictionaries, for the `sf` and
     * `key` parameters
     */
    private const array DICTIONARY_FIELDS = ['content-digest', 'signature', 'signature-input', 'accept-signature'];

    /**
     * The default port of each scheme, left out of `@authority` and
     * `@target-uri` whatever the URI reports, as RFC 9110 section 4.2.3
     * normalizes
     */
    private const array DEFAULT_PORTS = ['http' => 80, 'https' => 443];

    public function __construct(
        private readonly MessageInterface $message,
        private readonly ?RequestInterface $relatedRequest = null,
    ) {
    }

    public function message(): MessageInterface
    {
        return $this->message;
    }

    public function isRequest(): bool
    {
        return $this->message instanceof RequestInterface;
    }

    /**
     * Returns a context over the related request, for a component that
     * has the `req` parameter
     *
     * @throws ComponentFailure `UnsupportedSignature` when the target message
     *     is a request, which RFC 9421 section 2.5 makes an error, and
     *     `MissingComponent` when no related request was given
     */
    public function forRelatedRequest(): self
    {
        if ($this->isRequest()) {
            throw new ComponentFailure(
                FailureReason::UnsupportedSignature,
                'the req parameter cannot be used when the target message is a request',
            );
        }

        if ($this->relatedRequest === null) {
            throw new ComponentFailure(
                FailureReason::MissingComponent,
                'a component with the req parameter needs the related request, which was not given',
            );
        }

        return new self($this->relatedRequest);
    }

    /**
     * Returns whether the message has the field
     */
    public function hasField(string $name): bool
    {
        return $this->message->hasHeader($name);
    }

    /**
     * Returns the value of a field: each line with leading and trailing
     * whitespace removed, joined with a comma and a space
     *
     * @param string $name the field name in any case
     *
     * @throws ComponentFailure `MissingComponent` when the field is absent or
     *     a line holds a line break
     */
    public function field(string $name): string
    {
        return self::withoutLineBreak(implode(', ', $this->fieldLines($name)), strtolower($name));
    }

    /**
     * Returns the value of a field under the `bs` parameter: each line wrapped
     * as a Byte Sequence in a List, as RFC 9421 section 2.1.3 says
     *
     * @throws ComponentFailure `MissingComponent` when the field is absent
     */
    public function fieldBinaryWrapped(string $name): string
    {
        $items = array_map(static fn (string $line): Item => Item::fromDecodedBytes($line), $this->fieldLines($name));

        return StructuredFields::serialize(OuterList::new(...$items));
    }

    /**
     * Returns the value of a field under the `sf` parameter: parsed as the
     * Structured Field type the package knows for it and serialized again
     *
     * @throws ComponentFailure `UnsupportedSignature` for a field the package
     *     does not know as a Structured Field, and `MissingComponent` when the
     *     field is absent or does not parse
     */
    public function fieldStructured(string $name): string
    {
        return StructuredFields::serialize($this->dictionary($name));
    }

    /**
     * Returns the value of one member of a Dictionary field under the `key`
     * parameter: the member's value with its parameters, serialized
     *
     * @throws ComponentFailure `UnsupportedSignature` for a field the package
     *     does not know as a Dictionary, and `MissingComponent` when the field
     *     is absent, does not parse, or has no such member
     */
    public function dictionaryMember(string $name, string $key): string
    {
        $dictionary = $this->dictionary($name);

        if (!$dictionary->hasKeys($key)) {
            throw new ComponentFailure(
                FailureReason::MissingComponent,
                sprintf('the field "%s" has no member "%s"', strtolower($name), $key),
            );
        }

        return StructuredFields::serialize($dictionary->getByKey($key));
    }

    /**
     * Returns the value of a derived component of RFC 9421 section 2.2 that
     * takes no parameter
     *
     * `@target-uri` is the target URI as RFC 9110 section 7.1 defines it and
     * a server reconstructs it: the scheme, the authority as `@authority`
     * gives it, the path with an empty path written as `/`, and the query;
     * user information and the fragment never reach a server and are left
     * out.
     *
     * @throws ComponentFailure `UnsupportedSignature` for a name the package
     *     does not implement or a component asked of the wrong message type,
     *     and `MissingComponent` when the message cannot supply the value or
     *     the value holds a line break
     */
    public function derived(string $name): string
    {
        if ($name === '@status') {
            if (!$this->message instanceof ResponseInterface) {
                throw new ComponentFailure(FailureReason::UnsupportedSignature, '@status is a response component');
            }

            return (string) $this->message->getStatusCode();
        }

        $request = $this->request($name);
        $uri = $request->getUri();

        $value = match ($name) {
            '@method' => $request->getMethod(),
            '@target-uri' => $this->targetUri($request),
            '@authority' => $this->authority($request),
            '@scheme' => $this->scheme($request),
            '@request-target' => $request->getRequestTarget(),
            '@path' => self::path($uri),
            '@query' => '?' . $uri->getQuery(),
            '@query-param' => throw new ComponentFailure(
                FailureReason::UnsupportedSignature,
                '@query-param needs a name parameter',
            ),
            default => throw new ComponentFailure(
                FailureReason::UnsupportedSignature,
                sprintf('the derived component %s is not implemented', $name),
            ),
        };

        return self::withoutLineBreak($value, $name);
    }

    /**
     * Returns the value of `@query-param` for the named parameter, after the
     * decode-and-re-encode steps of RFC 9421 section 2.2.8
     *
     * @param string $name the `name` parameter, as the signature gives it
     *
     * @throws ComponentFailure `UnsupportedSignature` when asked of a response
     *     or when the name occurs more than once, which the section forbids,
     *     and `MissingComponent` when the query has no such parameter
     */
    public function queryParameter(string $name): string
    {
        $request = $this->request('@query-param');
        $found = null;

        foreach (QueryParameters::parse($request->getUri()->getQuery()) as [$pairName, $value]) {
            if ($pairName !== $name) {
                continue;
            }

            if ($found !== null) {
                throw new ComponentFailure(
                    FailureReason::UnsupportedSignature,
                    sprintf('the query parameter "%s" occurs more than once', $name),
                );
            }

            $found = $value;
        }

        if ($found === null) {
            throw new ComponentFailure(
                FailureReason::MissingComponent,
                sprintf('the query has no parameter "%s"', $name),
            );
        }

        return $found;
    }

    /**
     * Returns the value of the draft form's `(request-target)`: the method
     * lowercased, a space, and the request target as is, or with its query
     * string removed
     *
     * @throws ComponentFailure `UnsupportedSignature` when asked of a response,
     *     and `MissingComponent` when the value holds a line break
     */
    public function cavageRequestTarget(bool $includeQuery = true): string
    {
        $request = $this->request('(request-target)');
        $target = $request->getRequestTarget();
        $question = strpos($target, '?');

        if (!$includeQuery && $question !== false) {
            $target = substr($target, 0, $question);
        }

        return self::withoutLineBreak(strtolower($request->getMethod()) . ' ' . $target, '(request-target)');
    }

    /**
     * @return non-empty-list<string>
     */
    private function fieldLines(string $name): array
    {
        if (!$this->message->hasHeader($name)) {
            throw new ComponentFailure(
                FailureReason::MissingComponent,
                sprintf('the field "%s" is not in the message', strtolower($name)),
            );
        }

        $lines = [];

        foreach ($this->message->getHeader($name) as $line) {
            $lines[] = trim($line, " \t");
        }

        return $lines === [] ? [''] : $lines;
    }

    private function dictionary(string $name): Dictionary
    {
        $lower = strtolower($name);

        if (!in_array($lower, self::DICTIONARY_FIELDS, true)) {
            throw new ComponentFailure(
                FailureReason::UnsupportedSignature,
                sprintf('the field "%s" is not one the package knows as a Structured Field', $lower),
            );
        }

        try {
            return StructuredFields::parseDictionary($this->field($name));
        } catch (SyntaxError $error) {
            throw new ComponentFailure(
                FailureReason::MissingComponent,
                sprintf('the field "%s" does not parse as a Dictionary: %s', $lower, $error->getMessage()),
                $error,
            );
        }
    }

    private function request(string $component): RequestInterface
    {
        if (!$this->message instanceof RequestInterface) {
            throw new ComponentFailure(
                FailureReason::UnsupportedSignature,
                sprintf('%s is a request component', $component),
            );
        }

        return $this->message;
    }

    /**
     * The host lowercased, with the port only when it is not the scheme's
     * default, whatever the URI reports for it
     */
    private function authority(RequestInterface $request): string
    {
        $uri = $request->getUri();
        $host = strtolower($uri->getHost());

        if ($host === '') {
            throw new ComponentFailure(FailureReason::MissingComponent, 'the request URI has no authority');
        }

        $port = $uri->getPort();

        if ($port === null || $port === (self::DEFAULT_PORTS[strtolower($uri->getScheme())] ?? null)) {
            return $host;
        }

        return $host . ':' . $port;
    }

    private function targetUri(RequestInterface $request): string
    {
        $uri = $request->getUri();
        $authority = $this->authority($request);

        return $this->scheme($request) . '://' . $authority . self::path($uri)
            . ($uri->getQuery() === '' ? '' : '?' . $uri->getQuery());
    }

    private static function path(UriInterface $uri): string
    {
        return $uri->getPath() === '' ? '/' : $uri->getPath();
    }

    /**
     * A component value never holds a line break, as RFC 9421 section 2 and
     * the draft's section 2.3 both require, since one would add a line to the
     * signature base.
     *
     * @throws ComponentFailure `MissingComponent`
     */
    private static function withoutLineBreak(string $value, string $component): string
    {
        if (preg_match('/[\r\n]/', $value) === 1) {
            throw new ComponentFailure(
                FailureReason::MissingComponent,
                sprintf('the value of %s holds a line break, which a component value cannot', $component),
            );
        }

        return $value;
    }

    private function scheme(RequestInterface $request): string
    {
        $scheme = strtolower($request->getUri()->getScheme());

        if ($scheme === '') {
            throw new ComponentFailure(FailureReason::MissingComponent, 'the request URI has no scheme');
        }

        return $scheme;
    }
}
