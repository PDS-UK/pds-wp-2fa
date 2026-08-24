<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

final class FactorOperationResult
{
    public const SUCCESS = 'success';
    public const FAILURE = 'failure';
    public const EXPIRED = 'expired';

    /** @param array<string, mixed> $payload */
    private function __construct(
        private readonly string $status,
        private readonly ?string $code,
        private readonly array $payload,
        private readonly bool $countsAsFailure,
    ) {
    }

    /** @param array<string, mixed> $payload */
    public static function success(array $payload = []): self
    {
        return new self(self::SUCCESS, null, $payload, false);
    }

    public static function failure(string $code, bool $countsAsFailure = true): self
    {
        return new self(self::FAILURE, $code, [], $countsAsFailure);
    }

    public static function expired(string $code = 'pds_wp_2fa_enrollment_expired'): self
    {
        return new self(self::EXPIRED, $code, [], false);
    }

    public function status(): string { return $this->status; }
    public function code(): ?string { return $this->code; }
    /** @return array<string, mixed> */
    public function payload(): array { return $this->payload; }
    public function succeeded(): bool { return $this->status === self::SUCCESS; }
    public function countsAsFailure(): bool { return $this->countsAsFailure; }
}
