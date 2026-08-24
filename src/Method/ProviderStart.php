<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class ProviderStart
{
    private ?InteractionReference $reference;

    public function __construct(
        ?InteractionReference $reference,
        private ProviderPublicPayload $publicPayload,
        private ProviderServerState $serverState,
    ) {
        $this->reference = $reference;
    }

    public static function withoutReference(ProviderPublicPayload $publicPayload, ProviderServerState $serverState): self
    {
        return new self(null, $publicPayload, $serverState);
    }

    public function withReference(InteractionReference $reference): self
    {
        return new self($reference, $this->publicPayload, $this->serverState);
    }

    public function reference(): InteractionReference
    {
        if ($this->reference === null) {
            throw new \LogicException('The core must bind a provider start to an interaction reference.');
        }

        return $this->reference;
    }

    public function hasReference(): bool
    {
        return $this->reference !== null;
    }

    public function publicPayload(): ProviderPublicPayload
    {
        return $this->publicPayload;
    }

    public function serverState(): ProviderServerState
    {
        return $this->serverState;
    }

    /** @return array<string, mixed> */
    public function clientPayload(): array
    {
        return $this->publicPayload->toArray();
    }
}
