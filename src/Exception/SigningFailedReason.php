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

namespace SocialWeb\Http\MessageSignatures\Exception;

/**
 * Why signing failed
 */
enum SigningFailedReason
{
    /**
     * OpenSSL reported an error while it signed; the message has OpenSSL's
     * error text
     */
    case OpenSslError;

    /**
     * OpenSSL returned an ECDSA signature whose two integers do not fit the
     * length the curve gives them, so it has no fixed-length form
     */
    case SignatureDoesNotFitCurve;
}
