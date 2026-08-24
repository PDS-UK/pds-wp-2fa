<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class SecretBinding
{
    public function __construct(
        public readonly string $installationIdentityHash,
        public readonly int $installationEpoch,
        public readonly int $userId,
        public readonly string $methodId,
        public readonly string $providerKey = 'totp',
    ) {
        if ($this->installationIdentityHash === '' || strlen($this->installationIdentityHash) > 256) {
            throw new \InvalidArgumentException('Invalid installation binding.');
        }

        if ($this->installationEpoch < 0 || $this->userId < 1) {
            throw new \InvalidArgumentException('Invalid secret binding.');
        }

        if ($this->methodId === '' || strlen($this->methodId) > 256) {
            throw new \InvalidArgumentException('Invalid method binding.');
        }

        if (preg_match('/\A[a-z][a-z0-9_-]{0,31}\z/D', $this->providerKey) !== 1) {
            throw new \InvalidArgumentException('Invalid provider binding.');
        }
    }

    public function additionalData(int $envelopeVersion, string $keyVersion): string
    {
        if ($envelopeVersion !== 1 || preg_match('/\A[a-zA-Z0-9._-]{1,32}\z/D', $keyVersion) !== 1) {
            throw new \InvalidArgumentException('Invalid secret envelope version.');
        }

        return 'PDS-WP-2FA-AAD' . pack('C', $envelopeVersion)
            . self::field('totp-secret')
            . self::field($keyVersion)
            . self::field($this->providerKey)
            . self::field($this->installationIdentityHash)
            . self::field((string) $this->installationEpoch)
            . self::field((string) $this->userId)
            . self::field($this->methodId);
    }

    private static function field(string $value): string
    {
        return pack('N', strlen($value)) . $value;
    }
}
