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

namespace SocialWeb\Http\MessageSignatures\Rfc9421;

use Bakame\Http\StructuredFields\InnerList;
use SocialWeb\Http\MessageSignatures\Component\ComponentIdentifier;

use function array_map;

/**
 * One signature of a message, as the `Signature-Input` and `Signature`
 * fields gave it under its label
 *
 * @internal
 */
final readonly class ParsedSignature
{
    /**
     * @param string $label the Dictionary key the signature has in both fields
     * @param list<ComponentIdentifier> $coveredComponents in the order the
     *     Inner List gave them
     * @param InnerList $signatureParams the Inner List as parsed, whose
     *     serialization is the value of the `@signature-params` line
     * @param string $keyId the `keyid` parameter
     * @param int | null $created the `created` parameter
     * @param int | null $expires the `expires` parameter
     * @param string | null $nonce the `nonce` parameter
     * @param string | null $algorithm the `alg` parameter, as sent
     * @param string | null $tag the `tag` parameter
     * @param string $signature the raw signature bytes
     */
    public function __construct(
        public string $label,
        public array $coveredComponents,
        public InnerList $signatureParams,
        public string $keyId,
        public ?int $created,
        public ?int $expires,
        public ?string $nonce,
        public ?string $algorithm,
        public ?string $tag,
        public string $signature,
    ) {
    }

    /**
     * Returns the covered component identifiers as the options write them,
     * for the result
     *
     * @return list<string>
     */
    public function coveredComponentNames(): array
    {
        return array_map(
            static fn (ComponentIdentifier $identifier): string => $identifier->toString(),
            $this->coveredComponents,
        );
    }
}
