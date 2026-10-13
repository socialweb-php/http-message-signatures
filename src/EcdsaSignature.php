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

use function chr;
use function ltrim;
use function ord;
use function pack;
use function str_pad;
use function strlen;
use function substr;

use const STR_PAD_LEFT;

/**
 * Converts ECDSA signatures between the DER form OpenSSL produces and the
 * fixed-length form RFC 9421 uses
 *
 * RFC 9421 sections 3.3.4 and 3.3.5 define the signature as the integers r
 * and s, each big-endian and zero-padded to the size of the curve, written one
 * after the other. OpenSSL signs and verifies with the DER encoding of the
 * ASN.1 sequence of the two integers. For P-256 and P-384 the sequence holds
 * at most 102 bytes, so every length in the DER form fits in one byte; a
 * length byte in the long form is read as a short length and leads to an
 * integer that overruns the value or exceeds the curve, which is refused.
 *
 * @internal
 */
final class EcdsaSignature
{
    private const int SEQUENCE = 0x30;
    private const int INTEGER = 0x02;

    /**
     * Converts a DER signature to the fixed-length form, or returns `null`
     * when the DER is malformed or an integer does not fit the curve
     *
     * @param int<1, max> $integerLength the size of the curve in bytes: 32 for
     *     P-256, 48 for P-384
     */
    public static function derToRaw(string $der, int $integerLength): ?string
    {
        $length = strlen($der);

        if ($length < 8 || ord($der[0]) !== self::SEQUENCE || ord($der[1]) !== $length - 2) {
            return null;
        }

        $position = 2;
        $raw = '';

        for ($i = 0; $i < 2; $i++) {
            $head = substr($der, $position, 2);

            if (strlen($head) !== 2 || ord($head[0]) !== self::INTEGER) {
                return null;
            }

            $integerLengthInDer = ord($head[1]);
            $position += 2;

            if ($integerLengthInDer === 0) {
                return null;
            }

            $integer = substr($der, $position, $integerLengthInDer);

            if (strlen($integer) !== $integerLengthInDer) {
                return null;
            }

            $position += $integerLengthInDer;

            // A DER integer is positive here, so its first bit is clear, and
            // it is minimal, so a leading zero byte appears only before a byte
            // whose first bit is set.
            if (ord($integer[0]) > 127) {
                return null;
            }

            if ($integerLengthInDer > 1 && $integer[0] === "\x00" && ord($integer[1]) < 128) {
                return null;
            }

            $integer = ltrim($integer, "\x00");

            if (strlen($integer) > $integerLength) {
                return null;
            }

            $raw .= str_pad($integer, $integerLength, "\x00", STR_PAD_LEFT);
        }

        return $position === $length ? $raw : null;
    }

    /**
     * Converts a fixed-length signature to DER, or returns `null` when the
     * value is not exactly two integers of the curve's size
     *
     * @param int<1, max> $integerLength the size of the curve in bytes: 32 for
     *     P-256, 48 for P-384
     */
    public static function rawToDer(string $raw, int $integerLength): ?string
    {
        if (strlen($raw) !== 2 * $integerLength) {
            return null;
        }

        $body = self::encodeInteger(substr($raw, 0, $integerLength))
            . self::encodeInteger(substr($raw, $integerLength));

        return chr(self::SEQUENCE) . pack('C', strlen($body)) . $body;
    }

    private static function encodeInteger(string $bigEndian): string
    {
        $integer = ltrim($bigEndian, "\x00");

        if ($integer === '') {
            $integer = "\x00";
        }

        if (ord($integer[0]) > 127) {
            $integer = "\x00" . $integer;
        }

        return chr(self::INTEGER) . pack('C', strlen($integer)) . $integer;
    }
}
