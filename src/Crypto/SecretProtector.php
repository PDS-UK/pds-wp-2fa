<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class SecretProtector
{
    private const KDF_INFO = 'pds-wp-2fa/totp-secret/v1';
    private const KDF_SALT_LENGTH = 32;

    private readonly SecretKey $masterKey;

    public function __construct(string $masterKey, private readonly string $kdfSalt, private readonly string $keyVersion = '1')
    {
        self::assertAvailable();
        $this->masterKey = SecretKey::fromRaw($masterKey);

        if (strlen($this->kdfSalt) !== self::KDF_SALT_LENGTH) {
            throw new \InvalidArgumentException('Invalid encryption KDF salt.');
        }

        if (preg_match('/\A[a-zA-Z0-9._-]{1,32}\z/D', $this->keyVersion) !== 1) {
            throw new \InvalidArgumentException('Invalid encryption key version.');
        }
    }

    public static function fromBase64Key(string $encodedKey, string $kdfSalt, string $keyVersion = '1'): self
    {
        return new self(SecretKey::fromBase64($encodedKey)->raw(), $kdfSalt, $keyVersion);
    }

    public static function isAvailable(): bool
    {
        return function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')
            && function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt')
            && function_exists('hash_hkdf');
    }

    public static function generateKdfSalt(): string
    {
        self::assertAvailable();

        try {
            return random_bytes(self::KDF_SALT_LENGTH);
        } catch (\Throwable) {
            throw new SecretProtectionException();
        }
    }

    public function encrypt(string $plaintext, SecretBinding $binding): string
    {
        self::assertAvailable();

        if ($plaintext === '') {
            throw new \InvalidArgumentException('Cannot encrypt an empty secret.');
        }

        $key = $this->deriveKey();

        try {
            $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                $binding->additionalData(SecretEnvelope::VERSION, $this->keyVersion),
                $nonce,
                $key,
            );

            return SecretEnvelope::create($this->keyVersion, $nonce, $ciphertext)->encode();
        } catch (\Throwable) {
            throw new SecretProtectionException();
        } finally {
            sodium_memzero($key);
        }
    }

    public function decrypt(string $encodedEnvelope, SecretBinding $binding): string
    {
        self::assertAvailable();

        try {
            $envelope = SecretEnvelope::parse($encodedEnvelope);

            if ($envelope->keyVersion() !== $this->keyVersion) {
                throw new SecretProtectionException();
            }

            $key = $this->deriveKey();

            try {
                $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                    $envelope->ciphertext(),
                    $binding->additionalData(SecretEnvelope::VERSION, $envelope->keyVersion()),
                    $envelope->nonce(),
                    $key,
                );
            } finally {
                sodium_memzero($key);
            }

            if (!is_string($plaintext) || $plaintext === '') {
                throw new SecretProtectionException();
            }

            return $plaintext;
        } catch (SecretProtectionException $exception) {
            throw $exception;
        } catch (\Throwable) {
            throw new SecretProtectionException();
        }
    }

    private function deriveKey(): string
    {
        try {
            $key = hash_hkdf('sha256', $this->masterKey->raw(), 32, self::KDF_INFO, $this->kdfSalt);
        } catch (\Throwable) {
            throw new SecretProtectionException();
        }

        if (!is_string($key) || strlen($key) !== 32) {
            throw new SecretProtectionException();
        }

        return $key;
    }

    private static function assertAvailable(): void
    {
        if (!self::isAvailable()) {
            throw new SecretProtectionUnavailable();
        }
    }
}
