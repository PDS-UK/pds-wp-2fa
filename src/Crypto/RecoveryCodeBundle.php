<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class RecoveryCodeBundle
{
    /** @param array<int, string> $codes */
    public function __construct(private readonly array $codes)
    {
        if (count($this->codes) !== 10) {
            throw new \InvalidArgumentException('Invalid recovery-code bundle.');
        }

        foreach ($this->codes as $code) {
            if (preg_match('/\A[0-9A-F]{32}\z/D', $code) !== 1) {
                throw new \InvalidArgumentException('Invalid recovery-code bundle.');
            }
        }
    }

    /** @return array<int, string> */
    public function codes(): array
    {
        return $this->codes;
    }

    /** @return array<int, string> */
    public function formattedCodes(): array
    {
        return array_map(
            static fn (string $code): string => implode('-', str_split($code, 4)),
            $this->codes,
        );
    }

    public function __debugInfo(): array
    {
        return ['count' => count($this->codes)];
    }
}
