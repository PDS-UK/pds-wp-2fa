<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

final class SafeCliData
{
    /** @param array<string, mixed>|list<array<string, mixed>> $data */
    public static function assertSafe(array $data): void
    {
        self::walk($data, 0);
    }

    private static function walk(mixed $value, int $depth): void
    {
        if ($depth > 4) {
            throw new CliException('Command output is too deeply nested.', CliExitCode::CONFLICT);
        }
        if (is_array($value)) {
            foreach ($value as $key => $nested) {
                if (is_string($key) && self::isForbiddenKey($key)) {
                    throw new CliException('Command output contains prohibited credential material.', CliExitCode::CONFLICT);
                }
                self::walk($nested, $depth + 1);
            }
            return;
        }
        if (is_string($value) && (strlen($value) > 2048 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value))) {
            throw new CliException('Command output contains unsafe text.', CliExitCode::CONFLICT);
        }
        if (!is_scalar($value) && $value !== null) {
            throw new CliException('Command output contains unsafe data.', CliExitCode::CONFLICT);
        }
    }

    private static function isForbiddenKey(string $key): bool
    {
        return in_array(strtolower($key), [
            'password', 'password_confirmation', 'totp', 'secret', 'seed', 'otpauth',
            'recovery_code', 'code_hash', 'webauthn_response', 'client_data_json',
            'authenticator_data', 'signature', 'challenge', 'session_token', 'cookie',
            'nonce', 'private_key', 'encryption_key', 'request_body', 'headers',
        ], true);
    }
}
