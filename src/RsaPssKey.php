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

use function base64_decode;
use function base64_encode;
use function chunk_split;
use function ord;
use function preg_match;
use function preg_replace;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * Rewraps an RSA key whose PEM names the RSASSA-PSS algorithm as a plain RSA
 * key
 *
 * A key encoded with the algorithm identifier id-RSASSA-PSS, as the RFC 9421
 * appendix B.1.2 private key is, holds the same RSA material as a key encoded
 * with rsaEncryption. OpenSSL loads it as a distinct key type that
 * `openssl_pkey_get_details()` does not describe and that `openssl_sign()`
 * refuses to take a padding argument for. This class reads the ASN.1 wrapper,
 * takes the RSA material out, and writes it in the PKCS#1 form, which OpenSSL
 * loads as an ordinary RSA key.
 *
 * @internal
 */
final class RsaPssKey
{
    private const string PSS_OID = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a";

    private const int SEQUENCE = 0x30;
    private const int INTEGER = 0x02;
    private const int BIT_STRING = 0x03;
    private const int OCTET_STRING = 0x04;

    /**
     * Returns the PKCS#1 PEM of the RSA key inside an unencrypted PKCS#8
     * private key or a SubjectPublicKeyInfo public key whose algorithm is
     * id-RSASSA-PSS, or `null` for any other input
     */
    public static function toPkcs1Pem(string $pem): ?string
    {
        if (preg_match('/-----BEGIN (PRIVATE KEY|PUBLIC KEY)-----(.*?)-----END \1-----/s', $pem, $matches) !== 1) {
            return null;
        }

        $der = base64_decode((string) preg_replace('/\s+/', '', $matches[2]), true);

        if ($der === false) {
            return null;
        }

        return $matches[1] === 'PRIVATE KEY'
            ? self::wrap(self::privateKeyMaterial($der), 'RSA PRIVATE KEY')
            : self::wrap(self::publicKeyMaterial($der), 'RSA PUBLIC KEY');
    }

    /**
     * PrivateKeyInfo is the sequence of a version, an AlgorithmIdentifier,
     * and the private key as an octet string (RFC 5208 section 5).
     */
    private static function privateKeyMaterial(string $der): ?string
    {
        $outer = self::read($der, 0, self::SEQUENCE);

        if ($outer === null) {
            return null;
        }

        $version = self::read($outer[0], 0, self::INTEGER);

        if ($version === null) {
            return null;
        }

        $algorithm = self::read($outer[0], $version[1], self::SEQUENCE);

        if ($algorithm === null || !self::isRsaPss($algorithm[0])) {
            return null;
        }

        $key = self::read($outer[0], $algorithm[1], self::OCTET_STRING);

        return $key === null ? null : $key[0];
    }

    /**
     * SubjectPublicKeyInfo is the sequence of an AlgorithmIdentifier and the
     * public key as a bit string whose first byte counts unused bits (RFC 5280
     * section 4.1).
     */
    private static function publicKeyMaterial(string $der): ?string
    {
        $outer = self::read($der, 0, self::SEQUENCE);

        if ($outer === null) {
            return null;
        }

        $algorithm = self::read($outer[0], 0, self::SEQUENCE);

        if ($algorithm === null || !self::isRsaPss($algorithm[0])) {
            return null;
        }

        $key = self::read($outer[0], $algorithm[1], self::BIT_STRING);

        if ($key === null || strlen($key[0]) < 2 || $key[0][0] !== "\x00") {
            return null;
        }

        return substr($key[0], 1);
    }

    /**
     * An AlgorithmIdentifier is the object identifier followed by optional
     * parameters; id-RSASSA-PSS may have the hash, mask generation function,
     * and salt length, which the plain RSA key does not keep.
     */
    private static function isRsaPss(string $algorithmIdentifier): bool
    {
        return str_starts_with($algorithmIdentifier, self::PSS_OID);
    }

    /**
     * Reads one tag-length-value element, checking its tag, and returns its
     * content and the offset of the element after it; or `null` when the
     * element is not there or is cut short
     *
     * @return array{string, int} | null
     */
    private static function read(string $der, int $offset, int $expectedTag): ?array
    {
        $head = substr($der, $offset, 2);

        if (strlen($head) !== 2 || ord($head[0]) !== $expectedTag) {
            return null;
        }

        $first = ord($head[1]);
        $position = $offset + 2;
        $contentLength = $first;

        if ($first >= 0x80) {
            $count = $first & 0x7f;
            $lengthBytes = substr($der, $position, $count);

            if ($count > 4 || strlen($lengthBytes) !== $count) {
                return null;
            }

            $contentLength = 0;

            for ($i = 0; $i < $count; $i++) {
                $contentLength = ($contentLength << 8) | ord($lengthBytes[$i]);
            }

            $position += $count;
        }

        $content = substr($der, $position, $contentLength);

        if (strlen($content) !== $contentLength) {
            return null;
        }

        return [$content, $position + $contentLength];
    }

    private static function wrap(?string $der, string $label): ?string
    {
        if ($der === null) {
            return null;
        }

        return "-----BEGIN $label-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $label-----\n";
    }
}
