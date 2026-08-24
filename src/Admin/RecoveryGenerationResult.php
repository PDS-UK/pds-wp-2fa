<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class RecoveryGenerationResult
{
    /** @param list<string> $codes */
    public function __construct(
        private readonly string $generationId,
        private array $codes,
    ) {
        if ($generationId === '' || $codes === []) {
            throw new \InvalidArgumentException('A recovery generation must contain an ID and codes.');
        }
    }

    public function generationId(): string { return $this->generationId; }

    /** @return list<string> */
    public function displayOnce(): array
    {
        $codes = $this->codes;
        $this->codes = [];
        return $codes;
    }

    /** @return array<string, mixed> */
    public function status(): array
    {
        return ['generation_id' => $this->generationId, 'code_count' => count($this->codes)];
    }
}
