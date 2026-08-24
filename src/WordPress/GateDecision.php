<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

final class GateDecision
{
    public const ALLOW = 'allow';
    public const BYPASS = 'bypass';
    public const REDIRECT = 'redirect';
    public const DENY = 'deny';

    private function __construct(
        private readonly string $outcome,
        private readonly ?string $target,
        private readonly ?int $status,
        private readonly ?string $code,
        private readonly ?string $message,
    ) {
    }

    public static function allow(): self
    {
        return new self(self::ALLOW, null, null, null, null);
    }

    public static function bypass(): self
    {
        return new self(self::BYPASS, null, null, null, null);
    }

    public static function redirect(string $target, int $status = 302): self
    {
        return new self(self::REDIRECT, $target, $status, null, null);
    }

    public static function deny(int $status, string $code, string $message): self
    {
        return new self(self::DENY, null, $status, $code, $message);
    }

    public function outcome(): string
    {
        return $this->outcome;
    }

    public function target(): ?string
    {
        return $this->target;
    }

    public function status(): ?int
    {
        return $this->status;
    }

    public function code(): ?string
    {
        return $this->code;
    }

    public function message(): ?string
    {
        return $this->message;
    }
}
