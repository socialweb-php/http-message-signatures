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

/**
 * Why a verification failed
 *
 * A consumer mapping reasons to HTTP status codes will find that
 * `MalformedSignature` and `UnsupportedSignature` describe the request and the
 * rest describe its authentication; the package does not choose status codes.
 */
enum FailureReason
{
    /**
     * Neither form's fields are present
     */
    case NoSignature;

    /**
     * The fields are present but cannot be parsed, a parameter is duplicated,
     * a label is in one RFC 9421 field and not the other, or the signature
     * bytes are not valid Base64
     */
    case MalformedSignature;

    /**
     * Parsed but outside what the package or the options accept: a form the
     * options exclude, an algorithm name the package does not know, a derived
     * component or field parameter the package does not implement, or a
     * component asked of the wrong message type
     */
    case UnsupportedSignature;

    /**
     * A covered component is not in the message, or needs a related request
     * that was not given
     */
    case MissingComponent;

    /**
     * A rule of the verifier options is not met: target, creation time,
     * digest, nonce, or a required component not covered
     */
    case PolicyViolation;

    /**
     * The resolver returned `null`
     */
    case KeyNotFound;

    /**
     * The message's algorithm is known but not in the key's list
     */
    case AlgorithmNotPermitted;

    /**
     * The cryptographic check failed
     */
    case SignatureInvalid;

    /**
     * The creation time is beyond the future skew
     */
    case NotYetValid;

    /**
     * The effective expiry has passed
     */
    case Expired;

    /**
     * A covered digest does not match the content, or names no algorithm the
     * package knows
     */
    case DigestMismatch;
}
