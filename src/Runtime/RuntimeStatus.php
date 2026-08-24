<?php

declare(strict_types=1);

namespace PDS\WP2FA\Runtime;

use PDS\WP2FA\Identity\IdentityBindingState;

/**
 * Safe, request-local description of the plugin runtime.
 *
 * This object intentionally exposes diagnostics rather than the configured
 * installation identity. It is also the single readiness decision used by
 * the request gate, so a missing dependency cannot accidentally become an
 * allow decision in one integration path.
 */
final class RuntimeStatus
{
    public const READY = 'ready';
    public const UNAVAILABLE = 'unavailable';

    public function __construct(
        private readonly IdentityBindingState $identity,
        private readonly bool $persistenceAvailable,
        private readonly bool $schemaReady,
        private readonly bool $hooksReady,
        private readonly string $reason = 'not_ready',
    ) {
    }

    public function identity(): IdentityBindingState
    {
        return $this->identity;
    }

    public function persistenceAvailable(): bool
    {
        return $this->persistenceAvailable;
    }

    public function schemaReady(): bool
    {
        return $this->schemaReady;
    }

    public function hooksReady(): bool
    {
        return $this->hooksReady;
    }

    public function isReady(): bool
    {
        return $this->identity->isActive()
            && $this->persistenceAvailable
            && $this->schemaReady
            && $this->hooksReady;
    }

    public function state(): string
    {
        return $this->isReady() ? self::READY : self::UNAVAILABLE;
    }

    public function reason(): string
    {
        if (!$this->identity->isActive()) {
            return $this->identity->reason();
        }

        return $this->reason;
    }

    /** @return array<string, mixed> */
    public function diagnostics(): array
    {
        return [
            'state' => $this->state(),
            'reason' => $this->reason(),
            'identity' => $this->identity->diagnostics(),
            'persistence_available' => $this->persistenceAvailable,
            'schema_ready' => $this->schemaReady,
            'hooks_ready' => $this->hooksReady,
        ];
    }

    public function __debugInfo(): array
    {
        return $this->diagnostics();
    }
}
