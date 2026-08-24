<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use ParagonIE\ConstantTime\Base64UrlSafe;

final class Base64Url
{
    public static function encode(string $value): string
    {
        return Base64UrlSafe::encodeUnpadded($value);
    }

    public static function decode(string $value): string
    {
        if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
            throw WebAuthnException::invalidInput();
        }

        try {
            return Base64UrlSafe::decodeNoPadding($value);
        } catch (\Throwable $exception) {
            throw WebAuthnException::invalidInput($exception);
        }
    }
}
