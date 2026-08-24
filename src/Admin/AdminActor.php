<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class AdminActor
{
    private function __construct(
        private readonly string $kind,
        private readonly ?int $userId,
        private readonly string $source,
    ) {
        if ($userId !== null && $userId < 1) {
            throw new \InvalidArgumentException('Actor user IDs must be positive.');
        }
    }

    public static function user(int $userId, string $source = 'web'): self
    {
        return new self('user', $userId, $source);
    }

    public static function cli(): self
    {
        return new self('cli', null, 'cli');
    }

    public static function system(string $source = 'system'): self
    {
        return new self('system', null, $source);
    }

    public static function cron(): self
    {
        return new self('cron', null, 'cron');
    }

    public function kind(): string
    {
        return $this->kind;
    }

    public function userId(): ?int
    {
        return $this->userId;
    }

    public function source(): string
    {
        return $this->source;
    }
}
