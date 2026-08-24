<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class SecretEnvelope
{
    public const VERSION = 1;

    private function __construct(
        private readonly string $keyVersion,
        private readonly string $nonce,
        private readonly string $ciphertext,
    ) {
    }

    public static function create(string $keyVersion, string $nonce, string $ciphertext): self
    {
        self::assertKeyVersion($keyVersion);

        if (strlen($nonce) !== 24 || strlen($ciphertext) < 16) {
            throw new \InvalidArgumentException('Invalid secret envelope contents.');
        }

        return new self($keyVersion, $nonce, $ciphertext);
    }

    public static function parse(string $encoded): self
    {
        $parts = explode(':', $encoded);

        if (count($parts) !== 5 || $parts[0] !== 'pds-wp-2fa' || $parts[1] !== 'v1') {
            throw new \InvalidArgumentException('Invalid secret envelope.');
        }

        $nonce = self::decodeBase64Url($parts[3]);
        $ciphertext = self::decodeBase64Url($parts[4]);

        return self::create($parts[2], $nonce, $ciphertext);
    }

    public function encode(): string
    {
        return 'pds-wp-2fa:v1:' . $this->keyVersion . ':'
            . self::encodeBase64Url($this->nonce) . ':'
            . self::encodeBase64Url($this->ciphertext);
    }

    public function keyVersion(): string
    {
        return $this->keyVersion;
    }

    public function nonce(): string
    {
        return $this->nonce;
    }

    public function ciphertext(): string
    {
        return $this->ciphertext;
    }

    private static function assertKeyVersion(string $keyVersion): void
    {
        if (preg_match('/\A[a-zA-Z0-9._-]{1,32}\z/D', $keyVersion) !== 1) {
            throw new \InvalidArgumentException('Invalid secret key version.');
        }
    }

    private static function encodeBase64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function decodeBase64Url(string $value): string
    {
        if ($value === '' || preg_match('/\A[A-Za-z0-9_-]+\z/D', $value) !== 1 || strlen($value) % 4 === 1) {
            throw new \InvalidArgumentException('Invalid secret envelope encoding.');
        }

        $padding = (4 - (strlen($value) % 4)) % 4;
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', $padding), true);

        if (!is_string($decoded) || self::encodeBase64Url($decoded) !== $value) {
            throw new \InvalidArgumentException('Invalid secret envelope encoding.');
        }

        return $decoded;
    }
}
